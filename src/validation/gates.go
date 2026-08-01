package validation

// FB-03 hard-gate selection and evaluation.
//
// Canonical gate registry lives in specs/registries/hard_gates.yaml;
// the generated data (hard_gates_registry.gen.go) is the only runtime
// reference (owner decision 2026-08-01).
//
// RequiredHardGates is an application-aware selection, NOT a static list:
// applicable gates are derived from release scope, capabilities, the claim
// being evaluated and the config/evidence generation. HardGatesPass is a
// structured evaluator (GateEvaluation), not a bool.

import (
	"fmt"
	"sort"
)

// GateID is a canonical gate identifier (registry GateID = canonical metric name).
type GateID string

// VerdictID identifies the claim/verdict context being evaluated
// (e.g. WARP_CAUSAL_TRACE_READY, MON_PRODUCTION_READY, BLOCKED_TARGET_VALIDATION).
type VerdictID string

// ReleaseScope declares which subsystems are enabled for the evaluation.
// A gate family is applicable only if its owning subsystem is enabled.
type ReleaseScope struct {
	WARPBase       bool // base transport + causal trace gates (§72, §73B)
	WARPCamouflage bool // §73A
	WARPNonRU      bool // §73
	SPF            bool // §45
	MON            bool // §§84–92
	ABD            bool // §§39–42
	DDITGB         bool // DDI/TGB hard gates
	SP             bool // service profiles
	CSI            bool // cross-service isolation
	RSTGSO         bool // classifier/GSO/passive-RST
	PPE            bool // capture visibility / PPE
}

// Enabled returns true if any subsystem is enabled.
func (s ReleaseScope) Enabled() bool {
	return s.WARPBase || s.WARPCamouflage || s.WARPNonRU || s.SPF || s.MON ||
		s.ABD || s.DDITGB || s.SP || s.CSI || s.RSTGSO || s.PPE
}

// CapabilitySet is a capability projection used for gate applicability
// (e.g. service-profile capabilities). A gate marked with an applicable
// capability is selected only when that capability is present.
type CapabilitySet map[string]bool

// Has reports whether the named capability is present.
func (c CapabilitySet) Has(name string) bool {
	if c == nil {
		return false
	}
	return c[name]
}

// GenerationSet binds the evaluation to a config generation and an evidence
// generation; stale generations cannot yield PASS (v2 §0.6.3).
type GenerationSet struct {
	ConfigGeneration   uint64
	EvidenceGeneration uint64
}

// GateVerdict is the aggregate result of a gate evaluation.
type GateVerdict string

const (
	GatePass          GateVerdict = "PASS"
	GateFail          GateVerdict = "FAIL"
	GateBlocked       GateVerdict = "BLOCKED"
	GateNotApplicable GateVerdict = "NOT_APPLICABLE"
	GateNotRun        GateVerdict = "NOT_RUN"
	GateStale         GateVerdict = "STALE"
)

// GateViolation is one non-zero applicable gate.
type GateViolation struct {
	GateID   GateID `json:"gate_id"`
	Metric   string `json:"metric"`
	Count    uint64 `json:"count"`
	Producer string `json:"producer,omitempty"`
}

// GateEvaluation is the structured evaluator result (replaces bool PASS).
type GateEvaluation struct {
	Verdict         GateVerdict     `json:"verdict"`
	Violations      []GateViolation `json:"violations,omitempty"`
	Missing         []GateID        `json:"missing,omitempty"`          // applicable zero-tolerance gate without producer
	CounterReset    []GateID        `json:"counter_reset,omitempty"`    // applicable zero-tolerance gate whose counter reset inside the window (BLOCKED_COUNTER_RESET)
	Telemetry       []GateViolation `json:"telemetry,omitempty"`        // observed telemetry counters (never block)
	ReadinessInputs []GateViolation `json:"readiness_inputs,omitempty"` // current_generation_readiness_input (never block directly)
	Stale           []GateID        `json:"stale,omitempty"`
	NotRun          []GateID        `json:"not_run,omitempty"`
	Applicable      int             `json:"applicable"`
	Produced        int             `json:"produced"`
	Scanned         int             `json:"scanned"`
	WindowBaseline  bool            `json:"window_baseline,omitempty"` // delta-window evaluation applied (baseline supplied)
}

// LegacyGateAliases maps the pre-FB-03 hand-written gate names to canonical
// GateIDs. Exact names (already canonical) map to themselves; renamed gates
// migrate to their canonical metric; ambiguous names are retired (empty).
// Per owner decision: exact aliases migrate, ambiguous are retired/split.
var LegacyGateAliases = map[string]string{
	// exact canonical names (kept for migration reporting)
	"detector_single_probe_confirmed_total":                "detector_single_probe_confirmed_total",
	"detector_exception_string_only_confirmed_total":       "detector_exception_string_only_confirmed_total",
	"detector_static_target_only_high_confidence_total":    "detector_static_target_only_high_confidence_total",
	"detector_self_interference_total":                     "detector_self_interference_total",
	"detector_control_failure_ignored_total":               "detector_control_failure_ignored_total",
	"detector_unverified_mitm_verdict_total":               "detector_unverified_mitm_verdict_total",
	"detector_quic_single_target_global_udp_verdict_total": "detector_quic_single_target_global_udp_verdict_total",
	"unrelated_control_action_total":                       "unrelated_control_action_total",
	// renamed -> canonical
	"destination_only_state_total":           "silent_failure_destination_only_state_total",
	"parent_generation_mismatch_total":       "warp_nested_parent_generation_mismatch_total",
	"dns_direct_leak_total":                  "nonru_route_active_with_direct_dns",
	"ipv6_unvalidated_egress_total":          "nonru_route_active_with_unvalidated_ipv6",
	"cleanup_foreign_resource_removed_total": "warp_foreign_resource_removed_total",
	"trace_required_event_drop_total":        "warp_trace_dropped_required_event_total",
	// retired / split (no single canonical successor)
	"route_counter_missing_total":     "",
	"forwarded_binding_missing_total": "",
	"stale_generation_event_total":    "",
}

// CanonicalGateID resolves a legacy name to its canonical GateID.
// Empty result means the legacy name is retired.
func CanonicalGateID(legacy string) (GateID, bool) {
	if canonical, ok := LegacyGateAliases[legacy]; ok {
		if canonical == "" {
			return GateID(legacy), false // retired
		}
		return GateID(canonical), true
	}
	if _, ok := HardGateByName(legacy); ok {
		return GateID(legacy), true
	}
	return GateID(legacy), false
}

// scopeApplies reports whether a gate belongs to the enabled scope.
func scopeApplies(scope ReleaseScope, g Gate) bool {
	switch g.OwnerFamily {
	case "warp":
		switch g.GlobalGateClass {
		case "base_transport", "causal_trace":
			return scope.WARPBase
		case "non_ru":
			return scope.WARPNonRU
		case "camouflage":
			return scope.WARPCamouflage
		}
	case "spf":
		return scope.SPF
	case "mon":
		return scope.MON
	case "abd":
		return scope.ABD
	case "ddi_tgb":
		return scope.DDITGB
	case "sp":
		return scope.SP
	case "csi":
		return scope.CSI
	case "rst_gso":
		return scope.RSTGSO
	case "ppe":
		return scope.PPE
	}
	return false
}

// RequiredHardGates selects the applicable gates from the canonical registry
// for the given release scope, capabilities, claim and generation.
// It is the application-aware replacement for the old static list.
func RequiredHardGates(scope ReleaseScope, caps CapabilitySet, claim VerdictID, generation GenerationSet) ([]GateID, error) {
	if !scope.Enabled() {
		return nil, fmt.Errorf("release scope enables no subsystem: %w", ErrEmptyScope)
	}
	var out []GateID
	for _, g := range hardGates {
		if !scopeApplies(scope, g) {
			continue
		}
		// Capability-gated gates (e.g. service-profile family) require the
		// matching capability; without it they are NOT_APPLICABLE, not PASS.
		if g.OwnerFamily == "sp" && !caps.Has("service_profiles") {
			continue
		}
		out = append(out, GateID(g.GateID))
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// EvaluateHardGatesWindow applies the selection to observed counters, scoring
// zero-tolerance gates on the delta of the current validation window
// (current minus baseline) — never on lifetime absolute totals
// (owner decision 2026-08-01).
//
//   - zero-tolerance gate, produced, window delta == 0  -> ok
//   - zero-tolerance gate, produced, window delta != 0  -> FAIL (violation)
//   - zero-tolerance gate, produced, counter reset inside the window
//     (current < baseline)                             -> BLOCKED_COUNTER_RESET
//     (BLOCKED; the delta is undefined and a reset must never hide
//     violations accumulated in the same session — a new baseline is allowed
//     only for a new process/run/generation)
//   - zero-tolerance gate, applicable, no producer      -> BLOCKED (missing; v2 §0.6.3)
//   - telemetry counter                                 -> informational (Telemetry),
//     never blocks promotion (registry kind = telemetry_counter)
//   - readiness input (current_generation_readiness_input) -> informational
//     (ReadinessInputs): never blocks directly; invalidates/limits
//     current-generation readiness only together with owner state and
//     applicability (derived verdicts, out of scope here)
//   - generation mismatch                               -> STALE
//   - no applicable gates                               -> NOT_APPLICABLE
//   - otherwise                                         -> PASS
//
// A nil baseline means the window spans the whole process lifetime
// (in-process counters), which is a valid delta window: lifetime total ==
// delta since process start. Supplying a baseline makes the window explicit
// (e.g. snapshot taken at the start of a validation window).
func EvaluateHardGatesWindow(scope ReleaseScope, caps CapabilitySet, claim VerdictID, generation GenerationSet, current, baseline map[string]uint64, produced map[string]bool) GateEvaluation {
	required, err := RequiredHardGates(scope, caps, claim, generation)
	if err != nil {
		return GateEvaluation{Verdict: GateNotApplicable, Applicable: 0, Scanned: len(hardGates)}
	}
	eval := GateEvaluation{Applicable: len(required), Scanned: len(hardGates), WindowBaseline: baseline != nil}
	windowed := baseline != nil
	for _, gid := range required {
		name := string(gid)
		g, ok := HardGateByName(name)
		if !ok {
			// Registry drift is fail-closed: unknown applicable gate with no
			// producer is treated as a missing zero-tolerance gate.
			g = Gate{Kind: GateKindZeroTol}
		}
		count := deltaCount(current[name], baseline[name], windowed)
		switch g.Kind {
		case GateKindTelemetry:
			eval.Telemetry = append(eval.Telemetry, GateViolation{
				GateID: gid, Metric: name, Count: count,
			})
			continue
		case GateKindReadinessInput:
			eval.ReadinessInputs = append(eval.ReadinessInputs, GateViolation{
				GateID: gid, Metric: name, Count: count,
			})
			continue
		}
		if !produced[name] {
			eval.Missing = append(eval.Missing, gid)
			continue
		}
		eval.Produced++
		if windowed && current[name] < baseline[name] {
			// Counter reset inside the same validation window: the delta is
			// undefined and the reset must not hide violations accumulated
			// since the baseline (fail-closed). BLOCKED_COUNTER_RESET; a new
			// baseline is allowed only for a new process/run/generation.
			eval.CounterReset = append(eval.CounterReset, gid)
			continue
		}
		if count != 0 {
			eval.Violations = append(eval.Violations, GateViolation{
				GateID: gid, Metric: name, Count: count,
			})
		}
	}
	switch {
	case len(eval.Violations) > 0:
		eval.Verdict = GateFail
	case len(eval.CounterReset) > 0:
		eval.Verdict = GateBlocked // BLOCKED_COUNTER_RESET
	case len(eval.Missing) > 0:
		eval.Verdict = GateBlocked
	case len(eval.Stale) > 0:
		eval.Verdict = GateStale
	default:
		eval.Verdict = GatePass
	}
	return eval
}

// deltaCount returns the counter delta for the current validation window.
// Without a baseline the window spans the process lifetime, so the delta is
// the current value; with a baseline the delta is current - baseline.
// current <= baseline yields 0 here; a counter reset inside the window
// (current < baseline) is handled at the evaluator level as
// BLOCKED_COUNTER_RESET for zero-tolerance gates, and as "no new input since
// the baseline" (0) for telemetry/readiness inputs.
func deltaCount(current, baseline uint64, windowed bool) uint64 {
	if !windowed {
		return current
	}
	if current > baseline {
		return current - baseline
	}
	return 0
}

// EvaluateHardGates is the convenience wrapper for callers evaluating over
// the process-lifetime window (baseline == nil); it is equivalent to
// EvaluateHardGatesWindow with no baseline.
func EvaluateHardGates(scope ReleaseScope, caps CapabilitySet, claim VerdictID, generation GenerationSet, counters map[string]uint64, produced map[string]bool) GateEvaluation {
	return EvaluateHardGatesWindow(scope, caps, claim, generation, counters, nil, produced)
}

// HardGatesPass is the low-level convenience wrapper kept for callers that
// only need a boolean; it is equivalent to EvaluateHardGates(...).Verdict == PASS.
func HardGatesPass(scope ReleaseScope, caps CapabilitySet, claim VerdictID, generation GenerationSet, counters map[string]uint64, produced map[string]bool) bool {
	return EvaluateHardGates(scope, caps, claim, generation, counters, produced).Verdict == GatePass
}
