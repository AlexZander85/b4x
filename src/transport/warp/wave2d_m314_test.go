package transportwarp

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// ---- M3-14: a hung OnRouteRevoke hook must not freeze the gate ----

// Nil hook: no budget, never degraded.
func TestRevokeHookNil(t *testing.T) {
	g := &NonRUGate{cfg: NonRUConfig{}}
	detail, degraded := g.revokeHook("x")
	if degraded || detail != "" {
		t.Fatalf("nil hook: got degraded=%v detail=%q, want clean", degraded, detail)
	}
}

// Fast success: clean, not degraded.
func TestRevokeHookFastSuccess(t *testing.T) {
	g := &NonRUGate{cfg: NonRUConfig{OnRouteRevoke: func(string) error { return nil }}}
	detail, degraded := g.revokeHook("x")
	if degraded {
		t.Fatalf("fast hook reported degraded: %q", detail)
	}
	if detail != "" {
		t.Fatalf("fast hook must have empty detail, got %q", detail)
	}
}

// Fast failure: reported as a normal hook failure (not a hang).
func TestRevokeHookFastFailure(t *testing.T) {
	g := &NonRUGate{cfg: NonRUConfig{OnRouteRevoke: func(string) error { return errors.New("boom") }}}
	detail, degraded := g.revokeHook("x")
	if degraded {
		t.Fatalf("fast failure is a hook error, not a hang: %q", detail)
	}
	if detail == "" {
		t.Fatal("fast-failing hook must surface a detail string")
	}
}

// Hung hook: the budget is enforced — degraded is reported and the hook is
// invoked at most 2 times (one bounded retry). The gate loop is not frozen:
// revokeHook returns within budget rather than blocking forever.
func TestRevokeHookHangIsBoundedAndDegraded(t *testing.T) {
	var mu sync.Mutex
	var calls int
	release := make(chan struct{})
	defer close(release)
	g := &NonRUGate{cfg: NonRUConfig{OnRouteRevoke: func(string) error {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release // never returns until the test releases: simulates a hang
		return nil
	}}}

	start := time.Now()
	detail, degraded := g.revokeHook("x")
	elapsed := time.Since(start)

	if !degraded {
		t.Fatalf("hung hook must be reported degraded (detail %q)", detail)
	}
	// 2 budgets = 2*RouteRevokeTimeout plus scheduling slack.
	if elapsed > 3*RouteRevokeTimeout+500*time.Millisecond {
		t.Fatalf("hung hook must not exceed 2 budgets of blocking, took %v", elapsed)
	}
	mu.Lock()
	n := calls
	mu.Unlock()
	if n > 2 {
		t.Fatalf("hung hook must be invoked at most 2 times (bounded retry), got %d", n)
	}
}
