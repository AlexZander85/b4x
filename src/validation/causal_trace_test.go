package validation

import (
	"sort"
	"testing"
)

// TestRequiredCausalTraceGates pins the narrow causal-trace gate set
// (FB-03 / FB-14 decision 9): exactly the warp-family zero-tolerance gates
// of the base_transport class — nothing more.
func TestRequiredCausalTraceGates(t *testing.T) {
	gates := RequiredCausalTraceGates()
	if len(gates) != 10 {
		t.Fatalf("RequiredCausalTraceGates len=%d, want 10: %v", len(gates), gates)
	}
	seen := map[GateID]bool{}
	for _, gid := range gates {
		if seen[gid] {
			t.Errorf("duplicate gate %s", gid)
		}
		seen[gid] = true
		g, ok := HardGateByName(string(gid))
		if !ok {
			t.Errorf("gate %s not in registry", gid)
			continue
		}
		if g.OwnerFamily != "warp" || g.GlobalGateClass != "base_transport" || g.Kind != GateKindZeroTol {
			t.Errorf("gate %s outside narrow set: family=%s class=%s kind=%s",
				gid, g.OwnerFamily, g.GlobalGateClass, g.Kind)
		}
	}
	if !sort.SliceIsSorted(gates, func(i, j int) bool { return gates[i] < gates[j] }) {
		t.Error("causal trace gates not sorted")
	}
}

// TestEvaluateCausalTracePass: all narrow gates produced and zero -> PASS.
func TestEvaluateCausalTracePass(t *testing.T) {
	produced := map[string]bool{}
	for _, gid := range RequiredCausalTraceGates() {
		produced[string(gid)] = true
	}
	eval := EvaluateCausalTrace(map[string]uint64{}, produced)
	if eval.Verdict != GatePass {
		t.Fatalf("verdict=%s want PASS (violations=%d missing=%d)", eval.Verdict, len(eval.Violations), len(eval.Missing))
	}
	if eval.Produced != 10 || eval.Applicable != 10 {
		t.Errorf("produced=%d applicable=%d want 10/10", eval.Produced, eval.Applicable)
	}
}

// TestEvaluateCausalTraceViolation: a produced non-zero counter is FAIL,
// never folded into PASS.
func TestEvaluateCausalTraceViolation(t *testing.T) {
	produced := map[string]bool{}
	for _, gid := range RequiredCausalTraceGates() {
		produced[string(gid)] = true
	}
	eval := EvaluateCausalTrace(map[string]uint64{"warp_secret_leak_total": 1}, produced)
	if eval.Verdict != GateFail {
		t.Fatalf("verdict=%s want FAIL", eval.Verdict)
	}
	if len(eval.Violations) != 1 || eval.Violations[0].GateID != "warp_secret_leak_total" || eval.Violations[0].Count != 1 {
		t.Errorf("violations=%v want single warp_secret_leak_total count=1", eval.Violations)
	}
}

// TestEvaluateCausalTraceMissingProducer: an applicable gate without a
// producer blocks (missing evidence is never PASS — criterion 5).
func TestEvaluateCausalTraceMissingProducer(t *testing.T) {
	eval := EvaluateCausalTrace(map[string]uint64{}, map[string]bool{})
	if eval.Verdict != GateBlocked {
		t.Fatalf("verdict=%s want BLOCKED", eval.Verdict)
	}
	if len(eval.Missing) != 10 {
		t.Errorf("missing=%d want 10", len(eval.Missing))
	}
}

// TestEvaluateCausalTraceWindowDelta: baseline == current yields zero delta
// and PASS; a delta inside the window is a violation.
func TestEvaluateCausalTraceWindowDelta(t *testing.T) {
	produced := map[string]bool{}
	for _, gid := range RequiredCausalTraceGates() {
		produced[string(gid)] = true
	}
	current := map[string]uint64{"warp_secret_leak_total": 1}
	baseline := map[string]uint64{"warp_secret_leak_total": 1}
	eval := EvaluateCausalTraceWindow(current, baseline, produced)
	if eval.Verdict != GatePass {
		t.Fatalf("delta-0 verdict=%s want PASS", eval.Verdict)
	}
	baseline2 := map[string]uint64{"warp_secret_leak_total": 0}
	eval = EvaluateCausalTraceWindow(current, baseline2, produced)
	if eval.Verdict != GateFail {
		t.Fatalf("delta-1 verdict=%s want FAIL", eval.Verdict)
	}
	if eval.WindowBaseline != true {
		t.Error("window baseline flag not set")
	}
}
