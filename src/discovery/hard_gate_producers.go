package discovery

// Hard-gate producers for DDI guided discovery (FB-02 DDI section, §32 of
// the DDI/TGB addendum v1.0). Each guard is a production function that
// models one stage of the guided-discovery profile lifecycle — context
// validation, revalidation, WAN binding, hint planning, target validation,
// promotion and issue publication — reusing the evidence-only model in
// this package (NetworkDiagnosticProfile.Valid, CompareContext,
// CompileHintPlan, GuidedSearchPlan, CausalABComparison).
//
// Every violating branch increments exactly one zero-tolerance counter from
// src/observability/ddi.go; fixtures in hard_gate_producers_test.go drive
// each violating branch and assert the counter moved. No guard authorizes
// packet mutation or production writes; it only records whether a requested
// DDI action would violate a mandatory hard gate.

import (
	"time"

	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/validation"
)

func ddiInc(name string) {
	observability.Default().Metrics.Inc(name, nil, 1)
}

// UseProfileWithContext refuses to drive guided discovery from a profile
// whose context is not an exact match with the current network context
// (§"context validation": mismatch or expired contexts must never drive a
// guided run).
func UseProfileWithContext(p NetworkDiagnosticProfile, c NetworkContext, now time.Time) bool {
	if CompareContext(p, c, now) != ContextExact {
		ddiInc(observability.MetricDiscoveryProfileWithoutContextValidation)
		return false
	}
	return true
}

// UseProfileRevalidated refuses to serve a stale profile that has not been
// revalidated (§32: stale profiles must be revalidated before use).
func UseProfileRevalidated(p NetworkDiagnosticProfile, now time.Time, revalidated bool) bool {
	if !p.Valid(now) && !revalidated {
		ddiInc(observability.MetricDiscoveryProfileStaleWithoutRevalidation)
		return false
	}
	return true
}

// UseProfileSameWAN refuses to apply a profile built for a different WAN
// fingerprint (cross-WAN profile reuse is forbidden).
func UseProfileSameWAN(p NetworkDiagnosticProfile, wanFingerprint string) bool {
	if wanFingerprint != "" && p.Scope.NetworkContextID != wanFingerprint {
		ddiInc(observability.MetricDiscoveryProfileCrossWANUse)
		return false
	}
	return true
}

// RuntimeProfileBinding refuses to hand the runtime a mutable pointer to the
// profile instead of an immutable snapshot (mutable runtime pointers are
// forbidden).
func RuntimeProfileBinding(mutable bool) bool {
	if mutable {
		ddiInc(observability.MetricDiscoveryProfileMutableRuntimePointer)
		return false
	}
	return true
}

// UseSearchHint refuses to apply a hint without provenance. A hint whose
// Candidate is empty is treated as unusable but not as a violation; a hint
// with a candidate but no provenance is the recorded violation.
func UseSearchHint(h SearchHint) bool {
	if h.Candidate != "" && h.Provenance == "" {
		ddiInc(observability.MetricDiscoveryProfileHintWithoutProvenance)
		return false
	}
	return true
}

// HintOrderRespectsBaseline refuses a guided order in which a hint candidate
// displaced the current baseline from the leading position (hints must
// reorder the bounded search, never override the baseline).
func HintOrderRespectsBaseline(plan GuidedSearchPlan) bool {
	if len(plan.Ordered) == 0 || len(plan.Baseline) == 0 {
		ddiInc(observability.MetricDiscoveryProfileHintOverrodeBaseline)
		return false
	}
	leading := plan.Ordered[0]
	leadingIsBaseline := false
	for _, b := range plan.Baseline {
		if b == leading {
			leadingIsBaseline = true
			break
		}
	}
	if !leadingIsBaseline {
		ddiInc(observability.MetricDiscoveryProfileHintOverrodeBaseline)
		return false
	}
	return true
}

// GuidedRunTargetValidated refuses a guided run that skips target-specific
// validation (§32: every guided run retains target validation).
func GuidedRunTargetValidated(validated bool) bool {
	if !validated {
		ddiInc(observability.MetricDiscoveryProfileSkippedTargetValidation)
		return false
	}
	return true
}

// ExhaustiveFallbackEnabled refuses a guided plan that disabled the
// exhaustive fallback.
func ExhaustiveFallbackEnabled(plan GuidedSearchPlan) bool {
	if !plan.ExhaustiveFallback {
		ddiInc(observability.MetricDiscoveryProfileDisabledExhaustiveFallback)
		return false
	}
	return true
}

// GuidedPlanWithinCausalEligibility (FB-31, b4x-cka) refuses a guided plan
// whose ordered candidate set contains a family the causal eligibility
// matrix forbids for the failure family (or a scoped-transport candidate
// the evidence authority does not authorize). Mandatory narrower families
// are always allowed — a hint may reorder, never remove them. Unknown
// failure family fails closed (denied). This is the runtime counterpart of
// the CompileEligiblePlan filter: a plan built by any other path must still
// pass the matrix before the guided run starts.
func GuidedPlanWithinCausalEligibility(plan GuidedSearchPlan, family, authority string) bool {
	entry, ok := validation.CausalEligibilityByFamily(family)
	if !ok {
		ddiInc(observability.MetricDiscoveryProfileOutsideCausalEligibility)
		return false
	}
	for _, c := range plan.Ordered {
		if containsCandidate(entry.MandatoryNarrowerFamilies, c) {
			continue
		}
		if containsCandidate(entry.ForbiddenCandidateFamilies, c) {
			ddiInc(observability.MetricDiscoveryProfileOutsideCausalEligibility)
			return false
		}
		if c == "scoped_transport" && !validation.TransportAuthorized(family, authority) {
			ddiInc(observability.MetricDiscoveryProfileOutsideCausalEligibility)
			return false
		}
	}
	return true
}

// ProfileProductionWrite refuses a direct production write of a profile
// that was not staged/compiled through the DDI pipeline.
func ProfileProductionWrite(staged bool) bool {
	if !staged {
		ddiInc(observability.MetricDiscoveryProfileDirectProductionWrite)
		return false
	}
	return true
}

// PromoteViaSNI refuses an SNI-based direct promotion of a discovery result
// without target validation.
func PromoteViaSNI(targetValidated bool) bool {
	if !targetValidated {
		ddiInc(observability.MetricDiscoveryProfileAllowedSNIDirectPromotion)
		return false
	}
	return true
}

// CheckHintThreshold refuses a hint whose promotion threshold exceeds the
// bounded probe budget.
func CheckHintThreshold(h SearchHint, budget uint64) bool {
	if h.Threshold != 0 && h.Threshold > budget {
		ddiInc(observability.MetricDiscoveryProfileThresholdOutOfBudget)
		return false
	}
	return true
}

// PromotionCaptureGate refuses a discovery promotion while the capture
// visibility gate is not ready (bypassing the capture gate is forbidden).
func PromotionCaptureGate(captureReady bool) bool {
	if !captureReady {
		ddiInc(observability.MetricDiscoveryProfileCaptureGateBypass)
		return false
	}
	return true
}

// ProfileActionScope refuses to apply a profile action whose service scope
// (service profile / component) differs from the target scope.
func ProfileActionScope(p NetworkDiagnosticProfile, target monitor.MonitorScopeKey) bool {
	if target.ServiceProfileID != "" && p.Scope.ServiceProfileID != target.ServiceProfileID {
		ddiInc(observability.MetricDiscoveryProfileCrossServiceAction)
		return false
	}
	if target.ComponentID != "" && p.Scope.ComponentID != target.ComponentID {
		ddiInc(observability.MetricDiscoveryProfileCrossServiceAction)
		return false
	}
	return true
}

// PublishIssue refuses to publish a causal A/B bundle whose comparison
// indicates a false promotion.
func PublishIssue(b IssueBundle) bool {
	if b.Comparison.FalsePromotion || !b.Comparison.Valid() {
		ddiInc(observability.MetricDiscoveryProfileFalsePass)
		return false
	}
	return true
}
