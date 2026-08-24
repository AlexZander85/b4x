// WG3 session integration: establishment through the trust gate against the
// fake edge, structural loss classification on silent drop, and flap
// recovery via generation restarts. Windows are shrunk for CI; production
// numbers stay the design defaults.
package transportwg

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// tuntestPing injects one ICMP echo into the current generation's TUN.
func tuntestPing(ch *testChannel, dst, src netip.Addr) error {
	return ch.inject(tuntest.Ping(dst, src))
}

type sessionRecorder struct {
	mu     sync.Mutex
	events []SessionEvent
	lost   []Failure
	est    int
}

func (r *sessionRecorder) onEvent(ev SessionEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}
func (r *sessionRecorder) onEstablished() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.est++
}
func (r *sessionRecorder) onLost(f Failure) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lost = append(r.lost, f)
}
func (r *sessionRecorder) establishedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.est
}
func (r *sessionRecorder) lostList() []Failure {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Failure(nil), r.lost...)
}
func (r *sessionRecorder) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.events))
	for _, e := range r.events {
		out = append(out, e.Name)
	}
	return out
}

// testChannel exposes the channel TUN's raw surfaces for session tests.
type testChannel struct {
	Device   tun.Device
	Inbound  <-chan []byte // decrypted packets arriving FROM the tunnel
	Outbound chan<- []byte // packets injected INTO the tunnel
	inject   func([]byte) error
}

// chanTUN is a self-owned channel TUN with truly idempotent close (upstream
// tuntest.ChannelTUN panics on double close, and both our session teardown
// AND upstream's fatal-read auto-close path call Close).
type chanTUN struct {
	inbound   chan []byte // decrypted packets arriving FROM the tunnel
	outbound  chan []byte // packets injected INTO the tunnel
	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

func newTestChannelTUN() *testChannel {
	c := &chanTUN{
		inbound:  make(chan []byte, 4096),
		outbound: make(chan []byte, 256),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
	}
	c.events <- tun.EventUp
	tc := &testChannel{Device: c, Inbound: c.inbound, Outbound: c.outbound}
	tc.inject = c.inject
	return tc
}

// inject publishes an outbound packet without ever blocking indefinitely:
// a generation teardown may leave the device reader gone mid-flight.
func (c *chanTUN) inject(b []byte) error {
	select {
	case <-c.closed:
		return os.ErrClosed
	default:
	}
	select {
	case <-c.closed:
		return os.ErrClosed
	case c.outbound <- b:
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("transportwg: inject timeout (device reader gone)")
	}
}

func (c *chanTUN) File() *os.File { return nil }

func (c *chanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// NOTE: must never return a transient error — upstream treats ANY read
	// error as fatal and tears the whole device down (send.go:398-412).
	select {
	case <-c.closed:
		return 0, os.ErrClosed
	case msg := <-c.outbound:
		n := copy(bufs[0][offset:], msg)
		sizes[0] = n
		return 1, nil
	}
}

func (c *chanTUN) Write(bufs [][]byte, offset int) (int, error) {
	for i, data := range bufs {
		msg := make([]byte, len(data)-offset)
		copy(msg, data[offset:])
		select {
		case <-c.closed:
			return i, os.ErrClosed
		case c.inbound <- msg:
		}
	}
	return len(bufs), nil
}

func (c *chanTUN) MTU() (int, error)        { return DefaultMTU, nil }
func (c *chanTUN) Name() (string, error)    { return "wgtest0", nil }
func (c *chanTUN) Events() <-chan tun.Event { return c.events }
func (c *chanTUN) BatchSize() int           { return 1 }
func (c *chanTUN) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// onceCloseTUN remains as belt-and-braces for any other tun.Device.
type onceCloseTUN struct {
	tun.Device
	once sync.Once
}

func (w *onceCloseTUN) Close() error {
	var err error
	w.once.Do(func() { err = w.Device.Close() })
	return err
}

func newTestSession(t *testing.T, edge *fakeEdge, opts ...func(*SessionConfig)) (*Session, *sessionRecorder, func() *testChannel) {
	t.Helper()
	edgePriv, edgePub := edgeKeyPair(t)
	id, err := NewIdentity(mustB64Key(t), edgePub.B64(), "uS9/", clientTunnelIP, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := edge.Configure(edgePriv, mustPub(t, id.PrivateKey), netip.MustParseAddr(clientTunnelIP)); err != nil {
		t.Fatal(err)
	}

	rec := &sessionRecorder{}
	var curMu sync.Mutex
	var cur *testChannel
	current := func() *testChannel {
		curMu.Lock()
		defer curMu.Unlock()
		return cur
	}
	sc := SessionConfig{
		Ident:    id,
		Endpoint: edge.addr(),
		SockOpts: SocketOptions{},
		Tunnel:   TunnelConfig{Mode: ModeNetstack}, // label only; overridden below
		Health: HealthConfig{
			HandshakeTimeout: 8 * time.Second,
			Gate: TrustGate{
				LocalV4:    [4]byte{172, 16, 0, 2},
				RoundTrips: 2,
				Gap:        30 * time.Millisecond,
				Window:     3 * time.Second,
			},
			Watchdog: WatchdogConfig{
				RXIdle: 10 * time.Minute, // quiet post-establish must not churn gens
				Window: 5 * time.Second,
				Tick:   100 * time.Millisecond,
			},
			RestartBackoff: 200 * time.Millisecond,
			KeepaliveSec:   1,
		},
		VerboseDiagnostics: true,
		Callbacks: SessionCallbacks{
			OnEvent:       rec.onEvent,
			OnEstablished: rec.onEstablished,
			OnLost:        rec.onLost,
		},
	}
	for _, opt := range opts {
		opt(&sc)
	}
	sess, err := NewSession(sc)
	if err != nil {
		t.Fatal(err)
	}
	sess.newTunnelFn = func(TunnelConfig) (*Tunnel, error) {
		gch := newTestChannelTUN()
		curMu.Lock()
		cur = gch
		curMu.Unlock()
		return &Tunnel{
			Device: &onceCloseTUN{Device: gch.Device},
			Inject: gch.inject,
			Capture: func(ctx context.Context) ([]byte, error) {
				select {
				case pkt := <-gch.Inbound:
					return pkt, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		}, nil
	}
	t.Cleanup(sess.Stop)
	return sess, rec, current
}

func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func TestSessionEstablishesThroughTrustGate(t *testing.T) {
	edge, err := startFakeEdge(t, [3]byte{0xb9, 0x2f, 0x7f}, true /*require*/, true /*stamp*/)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, current := newTestSession(t, edge)
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}

	if !waitFor(func() bool { return rec.establishedCount() > 0 }, 15*time.Second) {
		t.Fatalf("never established; events=%v lost=%+v", rec.names(), rec.lostList())
	}
	if s := sess.State(); s != StateEstablished {
		t.Fatalf("state=%s", s)
	}

	names := rec.names()
	assertContains(t, names, "wg_handshake_ok")
	assertContains(t, names, "wg_gate_passed")
	assertContains(t, names, "wg_established")

	// (3) PersistentKeepalive from Health must be IN the applied config —
	// otherwise the NAT binding dies between trust-gate cycles.
	ipc, err := sess.IPCSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	wantKA := "persistent_keepalive_interval=" + strconv.FormatUint(uint64(sess.cfg.Health.KeepaliveSec), 10)
	if !strings.Contains(ipc, wantKA+"\n") {
		t.Fatalf("keepalive not applied to the engine: want %q in ipc", wantKA)
	}

	// ...and the engine must actually EMIT keepalives: with ka=1s the edge
	// must record extra datagrams within ~2.2 s of establishment.
	n0, _ := edge.bind.stats()
	time.Sleep(2200 * time.Millisecond)
	n1, _ := edge.bind.stats()
	if len(n1)-len(n0) < 1 {
		t.Fatalf("no keepalive traffic after establishment: %d -> %d", len(n0), len(n1))
	}

	// Data plane: ping client -> edge inner IP must land on the edge TUN.
	// Arrival is asserted via the responder's classified inner log (the
	// responder owns the Inbound channel).
	marker := len(edge.innerStats())
	if err := tuntestPing(current(), netip.MustParseAddr(edgeInnerIP), netip.MustParseAddr(clientTunnelIP)); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool {
		inner := edge.innerStats()
		if len(inner) <= marker {
			return false
		}
		for _, r := range inner[marker:] {
			if r.Kind == "icmp" {
				return true
			}
		}
		return false
	}, 8*time.Second) {
		t.Fatalf("data packet did not transit to the fake edge (inner=%+v)", edge.innerStats()[marker:])
	}

	seen, dropped := edge.bind.stats()
	if dropped != 0 || len(seen) == 0 {
		t.Fatalf("edge stats: seen=%d dropped=%d", len(seen), dropped)
	}
	reserved := [3]byte{0xb9, 0x2f, 0x7f}
	for i, s := range seen {
		if s.Res != reserved {
			t.Fatalf("datagram %d reserved=%v want %v", i, s.Res, reserved)
		}
	}
}

func assertContains(t *testing.T, list []string, want string) {
	t.Helper()
	for _, v := range list {
		if v == want {
			return
		}
	}
	t.Fatalf("missing event %q in %v", want, list)
}

func itoaU64(v uint64) string { return strconv.FormatUint(v, 10) }

// (4г) Cold-start ordering: a user packet that arrives during handshake wait
// must ship at keypair establishment BEFORE the first trust-gate probe.
func TestSessionColdStartUserPacketShipsBeforeGateProbes(t *testing.T) {
	edge, err := startFakeEdge(t, [3]byte{0xb9, 0x2f, 0x7f}, true /*require*/, true /*stamp*/)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, current := newTestSession(t, edge)

	// As soon as the edge sees our initiation, queue the user packet: it is
	// staged behind the bootstrap probe and flushes at keypair establishment.
	go func() {
		waitFor(func() bool {
			s, _ := edge.bind.stats()
			for _, r := range s {
				if r.Kind == rxInit {
					return true
				}
			}
			return false
		}, 8*time.Second)
		_ = tuntestPing(current(), netip.MustParseAddr(edgeInnerIP), netip.MustParseAddr(clientTunnelIP))
	}()

	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return rec.establishedCount() > 0 }, 15*time.Second) {
		t.Fatalf("never established; events=%v", rec.names())
	}

	// Wait until the FIRST trust-gate probe has been observed decrypted.
	var inner []innerRX
	if !waitFor(func() bool {
		inner = edge.innerStats()
		for _, r := range inner {
			if r.Kind == "dns-gate" {
				return true
			}
		}
		return false
	}, 10*time.Second) {
		t.Fatalf("gate probes never reached the edge")
	}

	icmpIdx, firstGateIdx, bootIdx := -1, -1, -1
	for i, r := range inner {
		switch r.Kind {
		case "icmp":
			if icmpIdx == -1 {
				icmpIdx = i
			}
		case "dns-gate":
			if firstGateIdx == -1 {
				firstGateIdx = i
			}
		case "dns-boot":
			if bootIdx == -1 {
				bootIdx = i
			}
		}
	}
	if bootIdx == -1 || icmpIdx == -1 || firstGateIdx == -1 {
		t.Fatalf("fixture incomplete: boot=%d icmp=%d gate=%d inner=%+v", bootIdx, icmpIdx, firstGateIdx, inner)
	}
	if !(icmpIdx < firstGateIdx) {
		t.Fatalf("user packet shipped AFTER a gate probe (icmp=%d gate=%d)", icmpIdx, firstGateIdx)
	}
}

// TestSessionSilentDropLostThenFlapRecovery proves the full supervisor arc:
// mid-session silent drop -> structural wg-stall-rx loss + restart; when the
// path heals, the next generation re-establishes.
func TestSessionSilentDropLostThenFlapRecovery(t *testing.T) {
	edge, err := startFakeEdge(t, [3]byte{0xb9, 0x2f, 0x7f}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, _ := newTestSession(t, edge, func(sc *SessionConfig) {
		sc.Health.Watchdog.RXIdle = 700 * time.Millisecond // fast stall for the flap arc
	})
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return rec.establishedCount() > 0 }, 15*time.Second) {
		t.Fatalf("never established; events=%v", rec.names())
	}
	gen1 := sess.Generation()

	// Kill the data plane: no more replies at all (silent-DPI fixture).
	edge.SetResponderMode(ResponderSilent)

	if !waitFor(func() bool { return len(rec.lostList()) > 0 }, 10*time.Second) {
		t.Fatalf("no loss detected after silent drop; events=%v", rec.names())
	}
	lost := rec.lostList()
	if len(lost) == 0 {
		t.Fatal("no losses recorded")
	}
	f := lost[0]
	if f.Class != ClassStallRX {
		t.Fatalf("class=%s want wg-stall-rx", f.Class)
	}

	// Heal the path: the next generation must establish again.
	edge.SetResponderMode(ResponderNormal)
	if !waitFor(func() bool { return rec.establishedCount() >= 2 }, 20*time.Second) {
		seen, dropped := edge.bind.stats()
		t.Fatalf("flap recovery failed; events=%v lost=%+v seen=%d dropped=%d",
			rec.names(), rec.lostList(), len(seen), dropped)
	}
	if sess.Generation() <= gen1 {
		t.Fatalf("generation did not advance: %d", sess.Generation())
	}
}

// (4a) Up() without ANY user traffic: the bootstrap probe alone must force
// the handshake initiation, and the fake edge must record it.
func TestSessionBootstrapTriggersHandshakeWithoutTraffic(t *testing.T) {
	edge, err := startFakeEdge(t, [3]byte{0xb9, 0x2f, 0x7f}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, _ := newTestSession(t, edge)
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return edge.handshakeEstablished() }, 10*time.Second) {
		t.Fatal("edge never saw a handshake without user traffic")
	}
	sawInit := false
	for _, r := range func() []edgeRX { s, _ := edge.bind.stats(); return s }() {
		if r.Kind == rxInit {
			sawInit = true
		}
	}
	if !sawInit {
		t.Fatal("edge did not record a handshake initiation")
	}
	if rec.establishedCount() == 0 && !waitFor(func() bool { return rec.establishedCount() > 0 }, 5*time.Second) {
		t.Fatal("session did not reach established")
	}
}

// (4б) Edge answers handshake but silently drops ALL data: the trust gate
// must fail with the structural wg-stall-rx class and the generation must
// be torn down (restart loop advances).
func TestSessionSilentDataGateTimesOutByClass(t *testing.T) {
	edge, err := startFakeEdge(t, [3]byte{0xb9, 0x2f, 0x7f}, true, true)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderSilent)

	sess, rec, _ := newTestSession(t, edge)
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	defer sess.Stop()

	if !waitFor(func() bool { return len(rec.lostList()) > 0 }, 20*time.Second) {
		t.Fatalf("no loss detected; events=%v", rec.names())
	}
	f := rec.lostList()[0]
	if f.Class != ClassStallRX {
		t.Fatalf("class=%s want wg-stall-rx", f.Class)
	}
	if !strings.Contains(f.Reason, "gate-dns") {
		t.Fatalf("reason=%q want gate-dns-*", f.Reason)
	}
	if !waitFor(func() bool { return sess.Generation() >= 2 }, 5*time.Second) {
		t.Fatalf("generation did not advance after loss: %d", sess.Generation())
	}
	if st := sess.State(); st == StateClosed {
		t.Fatalf("unexpected closed state mid-test")
	}
}

// (4в) Refused identity: handshake completes against a permissive edge but
// the far side never answers data — scripted counters make tx grow with rx
// pinned at zero; the stall detector must fire the version-mismatch class
// within its window and the session must restart.
func TestSessionRefusedIdentityStallFiresWithinWindow(t *testing.T) {
	var zeros [3]byte
	edge, err := startFakeEdge(t, zeros, false /*permissive*/, false)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, _ := newTestSession(t, edge)

	start := time.Unix(7777, 0)
	nowT := start
	tx := uint64(0)
	sess.countersOverride = func(context.Context) (CounterSample, error) {
		nowT = nowT.Add(100 * time.Millisecond)
		tx += 60 // every bootstrap/gate probe is ~60 bytes on the wire
		return CounterSample{Time: nowT, TxBytes: tx, RxBytes: 0}, nil
	}
	sess.cfg.Health.Watchdog = WatchdogConfig{
		RXIdle: 10 * time.Hour, // isolate the signature trigger
		Window: 1200 * time.Millisecond,
		MinTX:  128,
		MaxRX:  0,
		Tick:   100 * time.Millisecond,
		Now:    func() time.Time { return nowT },
	}

	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}

	if !waitFor(func() bool {
		for _, l := range rec.lostList() {
			if l.Class == ClassVersionMismatch {
				return true
			}
		}
		return false
	}, 15*time.Second) {
		t.Fatalf("version-mismatch stall never fired within window; lost=%+v", rec.lostList())
	}
	if !waitFor(func() bool { return sess.Generation() >= 2 }, 5*time.Second) {
		t.Fatalf("no restart after version-mismatch stall: %d", sess.Generation())
	}
}
