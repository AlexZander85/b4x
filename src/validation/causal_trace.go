package validation

import "sort"

// FB-03 / FB-14 decision 9: the WARP_CAUSAL_TRACE_READY verdict is a narrow
// causal-trace claim. It covers only the warp-family zero-tolerance gates of
// the base_transport class; capability verdicts (nested transport, non-RU
// routing, Android validation, production readiness) are separate gates that
// must never be folded into the causal verdict.
//
// The gate set is derived from the canonical registry (single source of
// truth) — it is never a hand-maintained list.

// RequiredCausalTraceGates derives the narrow causal-trace gate set from the
// canonical registry.
func RequiredCausalTraceGates() []GateID {
	var out []GateID
	for _, g := range hardGates {
		if g.OwnerFamily == "warp" && g.GlobalGateClass == "base_transport" && g.Kind == GateKindZeroTol {
			out = append(out, GateID(g.GateID))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// EvaluateCausalTraceWindow evaluates the narrow causal-trace gate set over
// the current validation window (current minus baseline). Scoring and verdict
// semantics are shared with EvaluateHardGatesWindow via evaluateGateSet.
func EvaluateCausalTraceWindow(current, baseline map[string]uint64, produced map[string]bool) GateEvaluation {
	required := RequiredCausalTraceGates()
	if len(required) == 0 {
		return GateEvaluation{Verdict: GateNotApplicable, Applicable: 0, Scanned: len(hardGates)}
	}
	return evaluateGateSet(required, current, baseline, produced)
}

// EvaluateCausalTrace evaluates the narrow causal-trace gate set over the
// process-lifetime window (no baseline), equivalent to
// EvaluateCausalTraceWindow with a nil baseline.
func EvaluateCausalTrace(counters map[string]uint64, produced map[string]bool) GateEvaluation {
	return EvaluateCausalTraceWindow(counters, nil, produced)
}
