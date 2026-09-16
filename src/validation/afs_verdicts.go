package validation

import (
	"fmt"
	"sort"
)

const (
	AFSVerdictBehavioralFingerprint = "BEHAVIORAL_FINGERPRINT_BOUNDED_READY"
	AFSVerdictConstrainedSynthesis  = "CONSTRAINED_SYNTHESIS_READY"
	AFSVerdictSynthesizedDiscovery  = "SYNTHESIZED_DISCOVERY_READY"
	AFSVerdictAutonomousAdaptation  = "AUTONOMOUS_DPI_ADAPTATION_READY"

	AFSReleaseProductionReady = "PRODUCTION_READY"
	AFSReleaseLabBlocked      = "IMPLEMENTED / LAB_VALIDATED / BLOCKED_BY_TARGET_EVIDENCE"
	AFSReleaseBlocked         = "BLOCKED"
)

// AFSZeroToleranceCounters is the normative §84 violation-counter set. The
// evaluator fails closed when a validation window omits any member: missing
// evidence is not equivalent to a zero counter.
var AFSZeroToleranceCounters = []string{
	"synthesis_without_user_opt_in_total",
	"synthesis_without_persistent_regression_total",
	"synthesis_without_fresh_profile_total",
	"synthesis_stale_generation_used_total",
	"synthesis_grammar_escape_total",
	"synthesis_unsafe_operator_emitted_total",
	"synthesis_scope_escape_total",
	"synthesis_candidate_direct_apply_total",
	"synthesis_without_action_authorization_total",
	"synthesis_missing_mandatory_control_total",
	"synthesis_router_origin_promoted_without_android_total",
	"synthesis_candidate_identity_collision_total",
	"synthesis_cleanup_incomplete_total",
	"synthesis_foreign_resource_mutation_total",
	"synthesis_unbounded_execution_total",
	"synthesis_promotion_without_rollback_ready_total",
}

type AFSLabEvidence struct {
	UserOptInContract          bool `json:"user_opt_in_contract"`
	PersistentRegressionGate   bool `json:"persistent_regression_gate"`
	BehavioralPanelBounded     bool `json:"behavioral_panel_bounded"`
	BehavioralEvidenceBound    bool `json:"behavioral_evidence_bound"`
	DDIOperatorConstraints     bool `json:"ddi_operator_constraints"`
	FiniteGrammarValidated     bool `json:"finite_grammar_validated"`
	DeterministicSearch        bool `json:"deterministic_search"`
	ActionPlannerBridge        bool `json:"action_planner_bridge"`
	SharedDiscoveryScoring     bool `json:"shared_discovery_scoring"`
	MandatoryControlsValidated bool `json:"mandatory_controls_validated"`
	NoDirectApplyValidated     bool `json:"no_direct_apply_validated"`
	TransactionalPromotion     bool `json:"transactional_promotion"`
	FaultInjectionValidated    bool `json:"fault_injection_validated"`
}

type AFSTargetEvidence struct {
	Available                    bool `json:"available"`
	KeeneticRouterValidated      bool `json:"keenetic_router_validated"`
	ForwardedAndroidCanaryPassed bool `json:"forwarded_android_canary_passed"`
	TargetAndControlsPassed      bool `json:"target_and_controls_passed"`
	ResourceBoundsValidated      bool `json:"resource_bounds_validated"`
	CleanupValidated             bool `json:"cleanup_validated"`
	RollbackValidated            bool `json:"rollback_validated"`
	RecoveryObserved             bool `json:"recovery_observed"`
	StableWindowValidated        bool `json:"stable_window_validated"`
}

type AFSReadinessEvidence struct {
	Lab AFSLabEvidence `json:"lab"`
	Target AFSTargetEvidence `json:"target"`

	// DependencyVerdicts supplies the current verdicts owned by the existing
	// MON/ABD/DDI/Discovery/WARP validation graph. AFS never fabricates them.
	DependencyVerdicts map[string]Verdict `json:"dependency_verdicts"`

	// ZeroToleranceCounters is a bounded-window snapshot/delta, not lifetime
	// totals. Every normative counter must be present and equal zero.
	ZeroToleranceCounters map[string]uint64 `json:"zero_tolerance_counters"`

	TestRefs     []string `json:"test_refs,omitempty"`
	ArtifactRefs []string `json:"artifact_refs,omitempty"`
}

type AFSPrincipalEvaluation struct {
	Results         map[string]StageResult `json:"results"`
	ReleaseStatus   string                 `json:"release_status"`
	ProductionReady bool                   `json:"production_ready"`
}

// EvaluateAFSPrincipalVerdicts projects AFS evidence into the canonical §83
// principal verdict names already registered by FB-34. It is pure and fail
// closed: missing registry entries, dependencies, counters or target evidence
// can never become PASS.
func EvaluateAFSPrincipalVerdicts(evidence AFSReadinessEvidence) AFSPrincipalEvaluation {
	out := AFSPrincipalEvaluation{Results: make(map[string]StageResult, 4), ReleaseStatus: AFSReleaseBlocked}
	zeroViolations := afsZeroToleranceViolations(evidence.ZeroToleranceCounters)

	behavioral := afsStage(
		AFSVerdictBehavioralFingerprint,
		[]string{"bounded four-way behavioral panel", "fresh exact-scope behavioral evidence", "persistent-regression and opt-in gates"},
		[]bool{evidence.Lab.UserOptInContract, evidence.Lab.PersistentRegressionGate, evidence.Lab.BehavioralPanelBounded, evidence.Lab.BehavioralEvidenceBound},
		evidence,
		zeroViolations,
		out.Results,
	)
	out.Results[AFSVerdictBehavioralFingerprint] = behavioral

	constrained := afsStage(
		AFSVerdictConstrainedSynthesis,
		[]string{"DDI operator constraints", "finite automatic-safe grammar", "deterministic bounded evolution", "existing ActionPlanner bridge"},
		[]bool{evidence.Lab.DDIOperatorConstraints, evidence.Lab.FiniteGrammarValidated, evidence.Lab.DeterministicSearch, evidence.Lab.ActionPlannerBridge},
		evidence,
		zeroViolations,
		out.Results,
	)
	out.Results[AFSVerdictConstrainedSynthesis] = constrained

	synthesized := afsStage(
		AFSVerdictSynthesizedDiscovery,
		[]string{"shared Discovery scoring", "mandatory target/control matrix", "no direct candidate apply", "fault-injection guard coverage"},
		[]bool{evidence.Lab.SharedDiscoveryScoring, evidence.Lab.MandatoryControlsValidated, evidence.Lab.NoDirectApplyValidated, evidence.Lab.FaultInjectionValidated},
		evidence,
		zeroViolations,
		out.Results,
	)
	out.Results[AFSVerdictSynthesizedDiscovery] = synthesized

	autonomousRequirements := []string{
		"existing transactional promotion path",
		"real Keenetic router target evidence",
		"forwarded Android-client canary",
		"target and mandatory controls",
		"resource bounds and owned cleanup",
		"rollback and recovery observation",
		"stable target validation window",
	}
	autonomousBools := []bool{
		evidence.Lab.TransactionalPromotion,
		evidence.Target.Available,
		evidence.Target.KeeneticRouterValidated,
		evidence.Target.ForwardedAndroidCanaryPassed,
		evidence.Target.TargetAndControlsPassed,
		evidence.Target.ResourceBoundsValidated,
		evidence.Target.CleanupValidated,
		evidence.Target.RollbackValidated,
		evidence.Target.RecoveryObserved,
		evidence.Target.StableWindowValidated,
	}
	autonomous := afsStage(
		AFSVerdictAutonomousAdaptation,
		autonomousRequirements,
		autonomousBools,
		evidence,
		zeroViolations,
		out.Results,
	)
	if autonomous.Verdict != Pass && afsLabChainPass(out.Results) && !afsTargetComplete(evidence.Target) {
		autonomous.Limitations = appendUnique(autonomous.Limitations, "BLOCKED_BY_TARGET_EVIDENCE")
	}
	out.Results[AFSVerdictAutonomousAdaptation] = autonomous

	if autonomous.Verdict == Pass {
		out.ReleaseStatus = AFSReleaseProductionReady
		out.ProductionReady = true
	} else if afsLabChainPass(out.Results) && !afsTargetComplete(evidence.Target) {
		out.ReleaseStatus = AFSReleaseLabBlocked
	}
	return out
}

func afsStage(canonical string, requirements []string, local []bool, evidence AFSReadinessEvidence, zeroViolations []string, completed map[string]StageResult) StageResult {
	result := StageResult{
		Stage:        canonical,
		Verdict:      Pass,
		Requirements: append([]string(nil), requirements...),
		Tests:        stableNonEmpty(evidence.TestRefs),
		Artifacts:    stableNonEmpty(evidence.ArtifactRefs),
	}
	entry, ok := PrincipalVerdictByCanonical(canonical)
	if !ok {
		result.Verdict = Blocked
		result.HardGateViolations = append(result.HardGateViolations, "unregistered-principal-verdict:"+canonical)
		return result
	}
	result.Dependencies = append([]string(nil), entry.Dependencies...)

	for i, passed := range local {
		if !passed {
			result.Verdict = Blocked
			label := fmt.Sprintf("requirement-%d-not-proven", i+1)
			if i < len(requirements) {
				label = requirements[i]
			}
			result.Limitations = append(result.Limitations, label)
		}
	}
	for _, dep := range entry.Dependencies {
		if localResult, exists := completed[dep]; exists {
			if localResult.Verdict != Pass && localResult.Verdict != PassWithLimitations {
				result.Verdict = Blocked
				result.Limitations = appendUnique(result.Limitations, "dependency-blocked:"+dep)
			}
			continue
		}
		v, exists := evidence.DependencyVerdicts[dep]
		if !exists || (v != Pass && v != PassWithLimitations) {
			result.Verdict = Blocked
			result.Limitations = appendUnique(result.Limitations, "dependency-blocked:"+dep)
		}
	}
	if len(zeroViolations) > 0 {
		result.Verdict = Blocked
		result.HardGateViolations = append(result.HardGateViolations, zeroViolations...)
	}
	if len(result.Tests) == 0 {
		result.Verdict = Blocked
		result.Limitations = appendUnique(result.Limitations, "missing-test-evidence")
	}
	if len(result.Artifacts) == 0 {
		result.Verdict = Blocked
		result.Limitations = appendUnique(result.Limitations, "missing-artifact-evidence")
	}
	return result
}

func afsZeroToleranceViolations(counters map[string]uint64) []string {
	violations := make([]string, 0)
	for _, name := range AFSZeroToleranceCounters {
		value, ok := counters[name]
		if !ok {
			violations = append(violations, "missing-zero-tolerance-evidence:"+name)
			continue
		}
		if value != 0 {
			violations = append(violations, fmt.Sprintf("%s=%d", name, value))
		}
	}
	sort.Strings(violations)
	return violations
}

func afsTargetComplete(target AFSTargetEvidence) bool {
	return target.Available && target.KeeneticRouterValidated && target.ForwardedAndroidCanaryPassed && target.TargetAndControlsPassed && target.ResourceBoundsValidated && target.CleanupValidated && target.RollbackValidated && target.RecoveryObserved && target.StableWindowValidated
}

func afsLabChainPass(results map[string]StageResult) bool {
	for _, name := range []string{AFSVerdictBehavioralFingerprint, AFSVerdictConstrainedSynthesis, AFSVerdictSynthesizedDiscovery} {
		result, ok := results[name]
		if !ok || (result.Verdict != Pass && result.Verdict != PassWithLimitations) {
			return false
		}
	}
	return true
}

func stableNonEmpty(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, value := range in {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func appendUnique(in []string, value string) []string {
	for _, existing := range in {
		if existing == value {
			return in
		}
	}
	return append(in, value)
}
