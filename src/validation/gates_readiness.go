package validation

// Readiness owner-state evaluation (FB-03 owner decision 2026-08-01,
// phase E2).
//
// current_generation_readiness_input gates (GSO offload/checksum/token,
// capture visibility degrade) never block promotion directly. They invalidate
// or limit current-generation readiness only together with the owner state
// and applicability:
//
//   - non-zero input + applicable unsafe owner state
//     -> readiness DEGRADED/BLOCKED for the current generation;
//   - successful revalidation of a new generation (owner state returns to
//     safe) restores readiness;
//   - the GSO mode / complete-representation / token-state owner consumers
//     are DEFERRED dependencies (FB-27/PPE); capture-visibility mode is wired
//     into the production evaluation (src/http/handler/production_gates.go).
//
// This file contains no production side effects: it is a pure derivation from
// the observed inputs and the supplied owner-state map.

// OwnerReadinessState is the evaluated owner state of a readiness input.
type OwnerReadinessState string

const (
	// OwnerStateSafe means the owner state was revalidated/confirmed for the
	// current generation (successful revalidation restores readiness).
	OwnerStateSafe OwnerReadinessState = "safe"
	// OwnerStateUnsafe means an applicable unsafe owner state is active
	// (e.g. capture visibility incomplete while degrade events are observed).
	OwnerStateUnsafe OwnerReadinessState = "unsafe"
	// OwnerStateUnknown means the owner state is unavailable: readiness cannot
	// be confirmed, so a non-zero input degrades readiness (never silently
	// READY). DEFERRED dependencies (FB-27/PPE) are wired as Unknown.
	OwnerStateUnknown OwnerReadinessState = "unknown"
)

// ReadinessStatus is the per-gate / aggregate readiness verdict.
type ReadinessStatus string

const (
	ReadinessReady         ReadinessStatus = "READY"
	ReadinessDegraded      ReadinessStatus = "DEGRADED"
	ReadinessBlocked       ReadinessStatus = "BLOCKED"
	ReadinessNotApplicable ReadinessStatus = "NOT_APPLICABLE"
)

// ReadinessGateVerdict is the derived readiness verdict of one input gate.
type ReadinessGateVerdict struct {
	GateID GateID              `json:"gate_id"`
	Metric string              `json:"metric"`
	Input  uint64              `json:"input"`
	Owner  OwnerReadinessState `json:"owner"`
	Status ReadinessStatus     `json:"status"`
}

// ReadinessEvaluation is the aggregate current-generation readiness result.
type ReadinessEvaluation struct {
	Verdict ReadinessStatus        `json:"verdict"`
	Gates   []ReadinessGateVerdict `json:"gates,omitempty"`
}

// EvaluateReadiness derives the current-generation readiness verdict from the
// observed readiness inputs (typically eval.ReadinessInputs of a hard-gate
// evaluation) and the owner-state map:
//
//	gate not applicable                -> excluded
//	input == 0                         -> READY (no new input in the window)
//	input > 0, owner safe              -> READY (revalidation confirmed)
//	input > 0, owner unknown           -> DEGRADED (cannot confirm)
//	input > 0, owner unsafe            -> BLOCKED
//
// The aggregate verdict is the maximum severity across gates.
func EvaluateReadiness(inputs []GateViolation, owner map[GateID]OwnerReadinessState) ReadinessEvaluation {
	eval := ReadinessEvaluation{Verdict: ReadinessReady}
	for _, input := range inputs {
		state := owner[input.GateID]
		status := ReadinessReady
		if input.Count > 0 {
			switch state {
			case OwnerStateUnsafe:
				status = ReadinessBlocked
			case OwnerStateUnknown:
				status = ReadinessDegraded
			default: // safe (or no owner entry) => revalidated => READY
				status = ReadinessReady
			}
		}
		eval.Gates = append(eval.Gates, ReadinessGateVerdict{
			GateID: input.GateID, Metric: input.Metric, Input: input.Count,
			Owner: state, Status: status,
		})
		if readinessSeverity(status) > readinessSeverity(eval.Verdict) {
			eval.Verdict = status
		}
	}
	return eval
}

func readinessSeverity(status ReadinessStatus) int {
	switch status {
	case ReadinessBlocked:
		return 3
	case ReadinessDegraded:
		return 2
	case ReadinessReady:
		return 1
	default:
		return 0
	}
}
