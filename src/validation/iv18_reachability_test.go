package validation

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIV18ReverseReachabilityCleanAfterCutover pins the FB-28 authoritative
// cutover result: the legacy Watchdog mutating path (applyBatchResults,
// src/watchdog/applier.go) is gone from the production tree, so the static
// reverse-reachability scan reports zero hits. The full mon_production_ready
// gate must STILL not flip to PASS, because the production dependencies of
// the monitoring cutover are not wired (BLOCKED_BY_DEPENDENCY, owner decision
// 2026-08-02).
func TestIV18ReverseReachabilityCleanAfterCutover(t *testing.T) {
	res := IV18ReverseReachability("")
	if !res.ProductionReady {
		t.Fatalf("legacy mutating path must be unreachable after cutover: %+v", res)
	}
	if len(res.Hits) != 0 {
		t.Fatalf("expected zero production call sites of %q after cutover, got %+v", legacyMutatingCall, res.Hits)
	}
	// The gate is fail-closed: reachability clean is necessary but not
	// sufficient — production dependencies keep it BLOCKED.
	if MonProductionReady() {
		t.Fatal("mon_production_ready must stay BLOCKED_BY_DEPENDENCY while production wiring is absent")
	}
}

// TestIV18ReverseReachabilitySeededReactivationCaught proves the gate is not
// trivially permissive: re-introducing a legacy-shaped mutating caller into a
// (temporary) production tree is caught by the scan, so a resurrected legacy
// path can never claim production readiness (restart cannot revive it without
// a detected source change).
func TestIV18ReverseReachabilitySeededReactivationCaught(t *testing.T) {
	dir := t.TempDir()
	fixture := `package seeded

func legacy() {
	// A seeded misuse of the permanently-removed symbol must be detected.
	_ = applyBatchResults(nil, nil, nil, nil)
}
`
	if err := os.WriteFile(filepath.Join(dir, "seeded.go"), []byte(fixture), 0o644); err != nil {
		t.Fatal(err)
	}
	res := IV18ReverseReachability(dir)
	if res.ProductionReady {
		t.Fatalf("seeded legacy reactivation must NOT be production ready: %+v", res)
	}
	if len(res.Hits) != 1 || res.Hits[0].Line == 0 {
		t.Fatalf("expected exactly one seeded hit, got %+v", res.Hits)
	}
	if MonProductionReady() {
		t.Fatal("mon_production_ready must be blocked while a legacy-shaped caller exists")
	}
}

// TestIV18ProductionDependenciesFailClosed keeps the full MON_PRODUCTION_READY
// semantics honest: removing the legacy path alone must NOT flip the gate to
// PASS while the production monitoring chain, the ABD->DDI chain and the
// /api/monitor/v1 endpoint are not yet wired. The gate is BLOCKED_BY_DEPENDENCY
// until every prerequisite exists (owner decision 2026-08-02).
func TestIV18ProductionDependenciesFailClosed(t *testing.T) {
	deps := IV18ProductionDependencies()
	if len(deps) < 4 {
		t.Fatalf("expected at least 4 production dependencies, got %d", len(deps))
	}
	for _, d := range deps {
		if d.ID == "" || (d.Ready && d.Missing != "") || (!d.Ready && d.Missing == "") {
			t.Fatalf("malformed dependency entry: %+v", d)
		}
	}
	blocked := IV18ProductionDependenciesBlocked()
	// On a tree without monitor production wiring all four must currently be
	// not-ready; the test may be updated when the production integration
	// lands, but must never silently pass on an unwired tree.
	if len(blocked) != 4 {
		t.Fatalf("expected 4 blocked production dependencies on unwired tree, got %+v", blocked)
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
