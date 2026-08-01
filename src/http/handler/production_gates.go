package handler

import (
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/validation"
)

// evaluateProductionGates is the single production hard-gate evaluation path
// (FB-03 owner decision 2026-08-01, phase E2): internal metrics snapshot ->
// window baseline for the current generation -> delta-window evaluation.
//
// Validation API, reports, canary and PromotePending all evaluate the current
// TestSession/ValidationRun through this function, so they share identical
// values/labels/kinds/produced state/window baseline/delta/generation
// (criterion 4). The process-lifetime wrapper (validation.EvaluateHardGates)
// is intentionally NOT used for session promotion.
func evaluateProductionGates(cfg *config.Config, generationID string) validation.GateEvaluation {
	scope := hardGateScope(cfg)
	if !scope.Enabled() {
		return validation.GateEvaluation{Verdict: validation.GateNotApplicable}
	}
	snap := observability.Default().Metrics.Snapshot(time.Now().UTC())
	counters := make(map[string]uint64, len(snap.Counters))
	produced := make(map[string]bool, len(snap.Counters))
	for _, s := range snap.Counters {
		counters[s.Name] += s.Value
		produced[s.Name] = true
	}
	baseline := validation.BaselineForRun(generationID, counters)
	return validation.EvaluateHardGatesWindow(scope, nil, "", validation.GenerationSet{}, counters, baseline, produced)
}

// productionOwnerStates binds the observed readiness inputs to the live owner
// state for the current-generation readiness derivation.
//
//   - b4_capture_visibility_degrade_total: wired to the PPE visibility gate
//     (complete -> safe, incomplete -> unsafe, unknown -> unknown);
//   - the GSO mode / complete-representation / token-state consumers are
//     DEFERRED dependencies (FB-27/PPE): wired as Unknown so a non-zero input
//     degrades readiness and is never silently READY.
func productionOwnerStates() map[validation.GateID]validation.OwnerReadinessState {
	states := map[validation.GateID]validation.OwnerReadinessState{
		"nfqueue_gso_truncated_total":      validation.OwnerStateUnknown, // DEFERRED: GSO mode consumer (FB-27/PPE)
		"nfqueue_gso_csum_not_ready_total": validation.OwnerStateUnknown, // DEFERRED: complete-representation consumer (FB-27/PPE)
		"nfqueue_gso_token_miss_total":     validation.OwnerStateUnknown, // DEFERRED: normalizer/token-state consumer (FB-27/PPE)
	}
	switch ppe.DefaultVisibilityGate().Snapshot().Mode {
	case ppe.VisibilityComplete:
		states["b4_capture_visibility_degrade_total"] = validation.OwnerStateSafe
	case ppe.VisibilityIncomplete:
		states["b4_capture_visibility_degrade_total"] = validation.OwnerStateUnsafe
	default:
		states["b4_capture_visibility_degrade_total"] = validation.OwnerStateUnknown
	}
	return states
}
