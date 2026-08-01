package fieldtest

import "github.com/daniellavrushin/b4/validation"

// FB-03: the static RequiredHardGates list is removed as source of truth.
// Applicable gates are selected from the canonical hard-gate registry
// (specs/registries/hard_gates.yaml via validation.RequiredHardGates).
// LegacyGateAliases in package validation migrate pre-FB-03 names.

// RequiredHardGates is the application-aware selection from the canonical
// registry (release scope + capabilities + claim + generation).
func RequiredHardGates(scope validation.ReleaseScope, caps validation.CapabilitySet, claim validation.VerdictID, generation validation.GenerationSet) ([]validation.GateID, error) {
	return validation.RequiredHardGates(scope, caps, claim, generation)
}

// HardGatesPass evaluates applicable gates against observed counters and
// produced flags; it returns true only when every applicable gate is produced
// and zero (structured result available via EvaluateHardGates).
func HardGatesPass(scope validation.ReleaseScope, caps validation.CapabilitySet, claim validation.VerdictID, generation validation.GenerationSet, counters map[string]uint64, produced map[string]bool) bool {
	return validation.HardGatesPass(scope, caps, claim, generation, counters, produced)
}

// EvaluateHardGates exposes the structured evaluator (GateEvaluation) for
// Field Test Controller, validation API/CLI, canary/promotion and reports.
func EvaluateHardGates(scope validation.ReleaseScope, caps validation.CapabilitySet, claim validation.VerdictID, generation validation.GenerationSet, counters map[string]uint64, produced map[string]bool) validation.GateEvaluation {
	return validation.EvaluateHardGates(scope, caps, claim, generation, counters, produced)
}

type StageReport struct {
	Stage, Verdict, SourceAddendumHash string
	Requirements                       []string
	HardGates                          []string
	AutomatedTests                     []string
	FieldEvidenceRequired              []string
	// GateVerdict carries the aggregated hard-gate result for the stage
	// (PASS/FAIL/BLOCKED/...); empty when no evaluation was wired (FB-03).
	GateVerdict validation.GateVerdict
}

func (r StageReport) Valid() bool {
	return r.Stage != "" && r.Verdict != "" && r.SourceAddendumHash != "" && len(r.Requirements) > 0 && len(r.HardGates) > 0
}
