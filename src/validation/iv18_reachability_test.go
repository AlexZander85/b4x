package validation

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIV18ReverseReachabilityBlocksProductionReadyWhileLegacyReachable pins
// the FB-28 cutover guard: MON_PRODUCTION_READY is impossible while the
// legacy Watchdog mutating path (applyBatchResults) is reachable from
// non-test code. When the legacy path is removed (event-driven cutover),
// this test must be updated to assert the opposite direction.
func TestIV18ReverseReachabilityBlocksProductionReadyWhileLegacyReachable(t *testing.T) {
	res := IV18ReverseReachability("")
	if res.ProductionReady {
		t.Fatalf("MON_PRODUCTION_READY must be impossible while legacy mutating path is reachable: %+v", res)
	}
	if len(res.Hits) == 0 {
		t.Fatalf("expected production call sites of %q, got none", legacyMutatingCall)
	}
	found := false
	for _, h := range res.Hits {
		if h.File == "watchdog/watchdog_heal.go" && h.Line == 111 {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected watchdog/watchdog_heal.go:111 call site, got %+v", res.Hits)
	}
	if MonProductionReady() {
		t.Fatal("mon_production_ready gate must be blocked while legacy path reachable")
	}
}

// TestIV18ReverseReachabilityCleanTreeIsProductionReady proves the scan is
// not trivially fail-closed: an empty tree (post-cutover) is production
// ready, so the gate only blocks on an actually reachable legacy path.
func TestIV18ReverseReachabilityCleanTreeIsProductionReady(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "only_test.go"), []byte("package x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := IV18ReverseReachability(dir)
	if !res.ProductionReady || len(res.Hits) != 0 {
		t.Fatalf("clean tree must be production ready: %+v", res)
	}
}

// TestIV18GateConformanceZeroToleranceAtZeroCounters pins IV-18-MON-12:
// every §84-92 monitor gate is registered as a zero-tolerance promotion
// blocker, and with zero counters in the window no violation exists
// (passive observation never trips a gate).
func TestIV18GateConformanceZeroToleranceAtZeroCounters(t *testing.T) {
	scope := ReleaseScope{MON: true}
	var monZeroTolerance int
	counters := map[string]uint64{}
	produced := map[string]bool{}
	for _, g := range hardGates {
		if g.OwnerFamily != "mon" {
			continue
		}
		if g.Kind != "zero_tolerance_violation_counter" {
			// mon_production_ready is a readiness input, not a counter.
			if g.GateID != "mon_production_ready" || g.Kind != "current_generation_readiness_input" {
				t.Fatalf("unexpected mon gate kind %q for %q", g.Kind, g.GateID)
			}
			continue
		}
		monZeroTolerance++
		if !g.PromotionBlocker {
			t.Fatalf("mon gate %q must be a promotion blocker", g.GateID)
		}
		counters[g.GateID] = 0
		produced[g.GateID] = true
	}
	if monZeroTolerance < 57 {
		t.Fatalf("expected at least 57 zero-tolerance mon gates (§84-92), got %d", monZeroTolerance)
	}
	eval := EvaluateHardGatesWindow(scope, CapabilitySet{}, "test", GenerationSet{}, counters, counters, produced)
	if len(eval.Violations) != 0 || len(eval.Missing) != 0 {
		t.Fatalf("zero counters must not trip gates: %+v", eval)
	}
}
