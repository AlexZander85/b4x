package validation

import (
	"os"
	"path/filepath"
	"testing"
)

// TestIV18ReverseReachabilityCleanAfterCutover pins the FB-28 authoritative
// cutover result: the legacy Watchdog mutating path (applyBatchResults,
// src/watchdog/applier.go) is gone from the production tree, so the static
// reverse-reachability scan reports zero hits. With the production monitoring
// chain wired (ObservationBus, DiagnosticScheduler, ABD->DDI, /api/monitor/v1)
// the full mon_production_ready gate must now PASS; a regression that
// resurrects the legacy path flips it back to BLOCKED (owner decision
// 2026-08-02, updated when the production integration landed).
func TestIV18ReverseReachabilityCleanAfterCutover(t *testing.T) {
	res := IV18ReverseReachability("")
	if !res.ProductionReady {
		t.Fatalf("legacy mutating path must be unreachable after cutover: %+v", res)
	}
	if len(res.Hits) != 0 {
		t.Fatalf("expected zero production call sites of %q after cutover, got %+v", legacyMutatingCall, res.Hits)
	}
	if !MonProductionReady() {
		t.Fatal("mon_production_ready must PASS with legacy path removed and production dependencies wired")
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
	// The scan is the single input of the gate: zero hits are both necessary
	// and sufficient on any production tree, so a resurrected legacy-shaped
	// caller can never claim PASS (checked per-tree here; the production tree
	// itself is covered by TestIV18ReverseReachabilityCleanAfterCutover).
	if IV18ReverseReachability(dir).ProductionReady {
		t.Fatal("scan must not report production ready for a seeded tree")
	}
}

// TestIV18ProductionDependenciesFailClosed keeps the full MON_PRODUCTION_READY
// semantics honest: the gate lists every production prerequisite and each must
// be Ready before PASS is possible. With the monitoring chain wired
// (ObservationBus, DiagnosticScheduler, ABD->DDI, /api/monitor/v1) zero
// dependencies are blocked; the test pans if any dependency flips back to
// not-ready without a source of truth (owner decision 2026-08-02, updated
// when the production integration landed).
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
	if len(blocked) != 0 {
		t.Fatalf("expected 0 blocked production dependencies with wiring landed, got %+v", blocked)
	}
	if !MonProductionReady() {
		t.Fatal("mon_production_ready must PASS with all production dependencies wired")
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
