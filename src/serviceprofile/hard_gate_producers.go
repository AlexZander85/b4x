package serviceprofile

// Hard-gate producers for the service-profile WARP recommendation lifecycle
// (FB-02 sp section, §28A.11 of
// B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md).
// Each guard models one mandatory hard gate of the WARP recommendation
// pipeline — IP-path evidence, destination-only scope, origin liveness,
// control health, cross-service scope, profile freshness, causal-trace gate,
// target canary, test-token lifecycle, control regression, failure-policy
// visibility, non-RU geo requirement, camouflage target binding and cleanup —
// reusing the evidence-only models in this package.
//
// Every violating branch increments exactly one zero-tolerance counter from
// src/observability/sp.go; fixtures in hard_gate_producers_test.go drive
// each violating branch and assert the counter moved. No guard mutates
// configuration or takes a production action; guards only record whether a
// requested recommendation/enablement would violate a mandatory hard gate.

import (
	"time"

	"github.com/daniellavrushin/b4/observability"
)

func spInc(name string) {
	observability.Default().Metrics.Inc(name, nil, 1)
}

// ---- §28A.11. Recommendation hard gates ------------------------------------

// RecommendedWithoutIPPathEvidenceAllowed denies a WARP recommendation that
// carries no IP-path evidence: only IP-level filtering hypotheses may be
// recommended (supportedIPHypotheses), never a bare connectivity symptom.
func RecommendedWithoutIPPathEvidenceAllowed(ipPathEvidence bool) bool {
	if !ipPathEvidence {
		spInc(observability.MetricSPRecommendedWithoutIPPathEvidence)
		return false
	}
	return true
}

// RecommendedFromDestinationIPOnlyAllowed denies a recommendation compiled
// from a destination-only scope: the recommendation requires a client-scoped
// evidence graph (CompileRecommendation requires ClientScopeHash).
func RecommendedFromDestinationIPOnlyAllowed(r TransportRecommendation) bool {
	if r.ClientScopeHash == "" {
		spInc(observability.MetricSPRecommendedFromDestinationIPOnly)
		return false
	}
	return true
}

// RecommendedForOriginDeadAllowed denies a recommendation whose origin is
// dead: the origin must be reachable for the direct path to be a meaningful
// candidate.
func RecommendedForOriginDeadAllowed(originAlive bool) bool {
	if !originAlive {
		spInc(observability.MetricSPRecommendedForOriginDead)
		return false
	}
	return true
}

// RecommendedWithUnhealthyControlsAllowed denies a recommendation issued
// while control probes are unhealthy: unhealthy controls always block
// promotion (SP-30 base prohibition).
func RecommendedWithUnhealthyControlsAllowed(controlsHealthy bool) bool {
	if !controlsHealthy {
		spInc(observability.MetricSPRecommendedWithUnhealthyControls)
		return false
	}
	return true
}

// CrossServiceRecommendationAllowed denies a recommendation consumed by a
// service different from the one it was compiled for: a successful
// recommendation for one component never authorizes another component or
// service.
func CrossServiceRecommendationAllowed(serviceProfileID, consumerServiceProfileID string) bool {
	if serviceProfileID != "" && consumerServiceProfileID != "" && serviceProfileID != consumerServiceProfileID {
		spInc(observability.MetricSPCrossService)
		return false
	}
	return true
}

// StaleProfileRecommendationAllowed denies serving an eligible recommendation
// from a profile that is no longer current (expired or without the full
// generation binding required by Fresh).
func StaleProfileRecommendationAllowed(r TransportRecommendation, now time.Time) bool {
	if r.State == RecommendationEligibleToTest && !r.Fresh(now) {
		spInc(observability.MetricSPStaleProfile)
		return false
	}
	return true
}

// WithoutCausalTraceGateAllowed denies a WARP recommendation while the causal
// trace gate is not ready: PROFILE_WARP_RECOMMENDATION_READY requires
// WARP_CAUSAL_TRACE_READY.
func WithoutCausalTraceGateAllowed(p WARPProjection) bool {
	if !p.CausalTraceReady {
		spInc(observability.MetricSPWithoutCausalTraceGate)
		return false
	}
	return true
}

// EnabledWithoutTargetCanaryAllowed denies enabling WARP without a passed
// target canary: the target canary must be supported by the projection and
// must have passed in the current validation (PromoteWARP requires
// targetCanary).
func EnabledWithoutTargetCanaryAllowed(p WARPProjection, forwardedCanaryPassed bool) bool {
	if !p.TargetCanarySupported || !forwardedCanaryPassed {
		spInc(observability.MetricSPEnabledWithoutTargetCanary)
		return false
	}
	return true
}

// TestTokenReusedAsProductionAuthorizationAllowed denies a transaction that
// carries a live test token while authorizing production: a test token must
// never be reused as a production authorization (EnableAfterValidation
// requires the validated state and a cleared token).
func TestTokenReusedAsProductionAuthorizationAllowed(t RecommendationTransaction) bool {
	if t.TestToken != "" && t.ProductionAuthorized {
		spInc(observability.MetricSPTestTokenReusedAsProdAuthorization)
		return false
	}
	return true
}

// IgnoredControlRegressionAllowed denies a validation verdict that reports a
// control regression as healthy: a control regression must fail the
// recommendation, never be ignored.
func IgnoredControlRegressionAllowed(regressionReported, controlsHealthy bool) bool {
	if regressionReported && controlsHealthy {
		spInc(observability.MetricSPIgnoredControlRegression)
		return false
	}
	return true
}

// HiddenFailPolicyAllowed denies a recommendation whose failure policy is not
// explicit: the failure policy preview must be visible to the user before any
// WARP validation or enablement.
func HiddenFailPolicyAllowed(failurePolicyPreview string) bool {
	if failurePolicyPreview == "" {
		spInc(observability.MetricSPHiddenFailPolicy)
		return false
	}
	return true
}

// NonRUSuggestedWithoutGeoRequirementAllowed denies suggesting the non-RU
// option without a geo requirement: a strict non-RU policy must declare its
// geo requirement (ValidateWARPPolicy).
func NonRUSuggestedWithoutGeoRequirementAllowed(p NonRUPolicy) bool {
	if p.Enabled && p.Strict && p.GeoRequirement == "" {
		spInc(observability.MetricSPNonRUSuggestedWithoutGeoRequirement)
		return false
	}
	return true
}

// CamouflageSuggestedForTargetIPBlockAllowed denies suggesting camouflage for
// a target that is IP-block filtered: camouflage must not be presented when
// the blocking profile indicates an IP-level block.
func CamouflageSuggestedForTargetIPBlockAllowed(ipBlockTarget bool, c CamouflagePolicy) bool {
	if ipBlockTarget && c.Enabled {
		spInc(observability.MetricSPCamouflageSuggestedForTargetIPBlock)
		return false
	}
	return true
}

// RecommendationCleanupFailureAllowed denies a validation result that left
// cleanup incomplete: a WARP recommendation that failed cleanup must be
// blocked by safety (ValidateRecommendation returns BlockedBySafety).
func RecommendationCleanupFailureAllowed(v RecommendationValidation) bool {
	if !v.CleanedUp {
		spInc(observability.MetricSPCleanupFailure)
		return false
	}
	return true
}
