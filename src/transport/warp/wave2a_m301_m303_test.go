package transportwarp

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

// ---- M3-01: closed-channel ok-semantics ----

// After Close, ReadPacket and TryRead must report ErrSessionClosed — never a
// zero-value (nil, nil) that would fabricate a false-alive or a false PASS.
func TestReadPacketAfterCloseReturnsErrSessionClosed(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()
	sess, _, err := DialSession(context.Background(), cfgForServer(t, fs))
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	// Allow readerLoop to observe the closed stream and close packets.
	waitFor(t, 2*time.Second, "reader closes packets", func() bool {
		_, err := sess.ReadPacket(context.Background())
		return errors.Is(err, ErrSessionClosed)
	})
	if pkt, ok, err := sess.TryRead(); !ok || err == nil || !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("TryRead after close = (%q, %v, %v), want ErrSessionClosed", pkt, ok, err)
	}
}

// The same contract holds for the H3 carrier (parity with H2).
func TestH3ReadPacketAfterCloseReturnsErrSessionClosed(t *testing.T) {
	e := newFakeH3Edge(t)
	cfg := h3SessionCfg(t, e, nil)
	sess, _, err := DialH3Session(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 2*time.Second, "h3 reader closes packets", func() bool {
		_, err := sess.ReadPacket(context.Background())
		return errors.Is(err, ErrSessionClosed)
	})
}

// The KPI-4 main test: the server answers 200 and then drops the stream
// before any data reply. A pre-M3-01 bug returned a PASS because ReadPacket
// yielded (nil, nil). Now teardown mid-validation must FAIL the validation.
func TestValidateDataPlaneFailsOnMidValidationTeardown(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()
	// Echo a finite number of capsules then hard-close the stream, fast.
	fs.setBehavior(200, false, false, 1)
	sess, _, err := DialSession(context.Background(), cfgForServer(t, fs))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	vctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	if err := sess.ValidateDataPlane(vctx); err == nil {
		t.Fatal("ValidateDataPlane PASSed on a session torn down mid-validation; want FAIL (KPI-4)")
	}
}

// ---- M3-03: tap lifecycle ----

// SubscribePackets on a closed session must refuse (closed channel + no-op
// cancel), never register a ghost subscription on a re-created subs map.
func TestSubscribePacketsAfterCloseRejectsGhost(t *testing.T) {
	for name, dial := range map[string]func(*testing.T) packetTransport{
		"h2": func(t *testing.T) packetTransport {
			fs := newFakeServer(t)
			t.Cleanup(fs.close)
			s, _, err := DialSession(context.Background(), cfgForServer(t, fs))
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
		"h3": func(t *testing.T) packetTransport {
			e := newFakeH3Edge(t)
			s, _, err := DialH3Session(context.Background(), h3SessionCfg(t, e, nil))
			if err != nil {
				t.Fatal(err)
			}
			return s
		},
	} {
		t.Run(name, func(t *testing.T) {
			sess := dial(t)
			sess.Close()
			ch, cancel := sess.SubscribePackets()
			cancel() // must be idempotent/no-op safe
			select {
			case _, open := <-ch:
				if open {
					t.Fatal("SubscribePackets after Close returned a live (ghost) channel")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("SubscribePackets after Close did not return a closed channel")
			}
		})
	}
}

// H3Session.Close must close remaining taps (parity with Session.Close), so a
// consumer select on the tap channel unblocks.
func TestH3CloseClosesTaps(t *testing.T) {
	e := newFakeH3Edge(t)
	sess, _, err := DialH3Session(context.Background(), h3SessionCfg(t, e, nil))
	if err != nil {
		t.Fatal(err)
	}
	tap, _ := sess.SubscribePackets()
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, open := <-tap:
		if open {
			t.Fatal("H3 tap still open after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("H3 tap not closed by H3Session.Close")
	}
	// Idempotency: double Close must not panic.
	if err := sess.Close(); err != nil {
		t.Fatalf("second Close error: %v", err)
	}
}

// H2Session.Close must also close its taps (regression guard for the parity
// contract; Session.Close already does this, assert it).
func TestH2CloseClosesTaps(t *testing.T) {
	fs := newFakeServer(t)
	defer fs.close()
	sess, _, err := DialSession(context.Background(), cfgForServer(t, fs))
	if err != nil {
		t.Fatal(err)
	}
	tap, _ := sess.SubscribePackets()
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case _, open := <-tap:
		if open {
			t.Fatal("H2 tap still open after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("H2 tap not closed by Session.Close")
	}
}

// ---- M3-02 + M3-03: goroutine stability ----

// readerFloodTransport is a controllable packetTransport for M3-02: it
// streams packets fast enough to fill healthLoop's internal pktCh (cap 16),
// then reports session death by closing its done channel. It records how
// many times its ReadPacket has been entered so a test can confirm the
// health reader has fully terminated.
type readerFloodTransport struct {
	done chan struct{}
	mu   sync.Mutex
	read int
}

func (r *readerFloodTransport) WritePacket([]byte) error { return nil }
func (r *readerFloodTransport) TryRead() ([]byte, bool, error) {
	return nil, false, nil
}
func (r *readerFloodTransport) ValidateDataPlane(context.Context) error { return nil }
func (r *readerFloodTransport) SubscribePackets() (<-chan []byte, func()) {
	ch := make(chan []byte)
	close(ch)
	return ch, func() {}
}
func (r *readerFloodTransport) Done() <-chan struct{} { return r.done }
func (r *readerFloodTransport) Close() error {
	select {
	case <-r.done:
	default:
		close(r.done)
	}
	return nil
}

func (r *readerFloodTransport) ReadPacket(context.Context) ([]byte, error) {
	r.mu.Lock()
	r.read++
	r.mu.Unlock()
	select {
	case <-r.done:
		// Session dead: M3-01 ok-semantics lets the health reader terminate.
		return nil, ErrSessionClosed
	default:
	}
	return []byte{0x45, 0x00, 0x00, 0x14}, nil
}

// reads counts how many times the health reader has entered ReadPacket.
func (r *readerFloodTransport) reads() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.read
}

// The M3-02 regression fence: when the session dies with a FULL health
// pktCh, the health reader must terminate (M3-01's ok-semantics + the
// pktCh drain in healthLoop release it). We drive healthLoop directly with
// a fake transport whose packets out-pace the reader, then kill the session.
func TestHealthReaderTerminatesWhenSessionDiesUnderFullQueue(t *testing.T) {
	// helper runs one healthLoop in the background and returns when it exits.
	runHealth := func(t *testing.T, ft *readerFloodTransport) chan struct{} {
		done := make(chan struct{})
		go func() {
			defer close(done)
			// Long health interval: ticker never drains pktCh before death.
			sup := &Supervisor{cfg: SupervisorConfig{HealthInterval: time.Hour}}
			sup.healthLoop(context.Background(), ft, [4]byte{100, 96, 0, 1})
		}()
		return done
	}

	const cycles = 6
	baseline := runtime.NumGoroutine()
	for i := 0; i < cycles; i++ {
		ft := &readerFloodTransport{done: make(chan struct{})}
		hd := runHealth(t, ft)
		// Reader fills pktCh (cap 16) and blocks on the 17th send.
		for {
			if ft.reads() >= 17 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		// Session dies with a full queue: healthLoop must return (drains pktCh,
		// the reader's pending send is released, then ReadPacket returns
		// ErrSessionClosed and the reader exits).
		ft.Close()
		select {
		case <-hd:
		case <-time.After(3 * time.Second):
			t.Fatalf("healthLoop leaked on cycle %d (reader leak)", i)
		}
	}
	waitFor(t, 3*time.Second, "goroutines stabilize", func() bool {
		return runtime.NumGoroutine() <= baseline+1
	})
}
