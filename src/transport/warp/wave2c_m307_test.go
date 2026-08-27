package transportwarp

import (
	"context"
	"testing"
	"time"
)

// ---- M3-07: panic isolation for engine goroutines ----

// panicSubSession is a packetTransport whose SubscribePackets always panics,
// letting us drive a real unrecovered panic through guardTapPump's recover
// frame and observe that the panic is contained (the process survives) and
// surfaced as an EvEnginePanic.
type panicSubSession struct{}

func (panicSubSession) WritePacket([]byte) error { return nil }
func (panicSubSession) ReadPacket(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}
func (panicSubSession) TryRead() ([]byte, bool, error)            { return nil, false, nil }
func (panicSubSession) ValidateDataPlane(context.Context) error   { return nil }
func (panicSubSession) SubscribePackets() (<-chan []byte, func()) { panic("tap-subscribe exploded") }
func (panicSubSession) Done() <-chan struct{}                     { return make(chan struct{}) }
func (panicSubSession) Close() error                              { return nil }

// A real panic inside an engine goroutine must be contained by the recover
// frame: the goroutine returns, the panic hook fires, and an EvEnginePanic
// with the FailureInternalPanic class is emitted — the process never dies.
func TestEnginePanicContainedAndReported(t *testing.T) {
	h := newSupHarness(t)
	var hooked []any
	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.PanicHook = func(r any) { hooked = append(hooked, r) }
		c.HealthInterval = time.Hour
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		sup.guardTapPump(ctx, panicSubSession{})
		close(done)
	}()

	waitFor(t, 3*time.Second, "engine-panic event", func() bool {
		return countName(h.eventNames(), EvEnginePanic) == 1
	})
	// The contained panic let the guarded goroutine return: process alive.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("guardTapPump must return after a contained panic")
	}
	if len(hooked) != 1 {
		t.Fatalf("panic hook must observe exactly one panic, got %d", len(hooked))
	}
	ev := h.events()[0]
	if ev.FailureClass != FailureInternalPanic {
		t.Fatalf("engine-panic event must carry FailureInternalPanic, got %q", ev.FailureClass)
	}
	if !hasState(t, sup, StateBackoff) {
		t.Fatalf("supervisor must back off (not die) after a panic, got %s", sup.Snapshot().State)
	}
}

// Three consecutive recovered panics escalate to an operator pause.
func TestPanicStreakReachesOperatorPause(t *testing.T) {
	h := newSupHarness(t)
	sup := h.newSupervisor(t, nil)
	sup.failSafePanic("p1")
	sup.failSafePanic("p2")
	sup.failSafePanic("p3")

	names := h.eventNames()
	if c := countName(names, EvEnginePanic); c != 3 {
		t.Fatalf("want 3 engine-panic events, got %d (%v)", c, names)
	}
	if c := countName(names, EvOperatorPause); c != 1 {
		t.Fatalf("want 1 operator-pause event, got %d (%v)", c, names)
	}
	if !hasState(t, sup, StateOperatorPause) {
		t.Fatalf("supervisor must reach operator-paused state, got %s", sup.Snapshot().State)
	}
}

// A healthy reconnect (clearPanicStreak) resets the streak: panics on either
// side of a healthy slot never accumulate into an operator pause.
func TestHealthyConnectResetsPanicStreak(t *testing.T) {
	h := newSupHarness(t)
	sup := h.newSupervisor(t, nil)
	sup.failSafePanic("a")
	sup.failSafePanic("b")
	sup.clearPanicStreak()
	sup.failSafePanic("c")
	sup.failSafePanic("d")

	names := h.eventNames()
	if c := countName(names, EvEnginePanic); c != 4 {
		t.Fatalf("want 4 engine-panic events, got %d (%v)", c, names)
	}
	if c := countName(names, EvOperatorPause); c != 0 {
		t.Fatalf("healthy reset must prevent operator-pause, got %d (%v)", c, names)
	}
	if hasState(t, sup, StateOperatorPause) {
		t.Fatal("operator-pause must not fire across a healthy reset")
	}
}
