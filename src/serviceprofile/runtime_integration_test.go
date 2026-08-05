package serviceprofile

// Integration tests for the production WARP-recommendation lifecycle
// controller (src/serviceprofile/runtime.go, FB-02 sp section §28A.11).
//
// Every test enters through the same production root as the daemon
// (Runtime methods, controller loop from main): a violating lifecycle input
// must be denied by the corresponding §28A.11 guard AND increment exactly
// one zero-tolerance counter. These tests back the
// artifacts/remediation/FB02_SP_PRODUCERS.json call graph and are
// referenced from specs/registries/hard_gates.yaml (test_producer /
// evidence_artifact).

import (
	"testing"
	"time"
)

func newSPRuntime(t *testing.T) *Runtime {
	t.Helper()
	rt := NewRuntime(DefaultConfig())
	rt.Start()
	t.Cleanup(rt.Stop)
	return rt
}

func spCompileCtx() LifecycleEvent {
	return LifecycleEvent{
		IPPathEvidence:  true,
		OriginAlive:     true,
		ControlsHealthy: true,
		ConsumerService: "svc-a",
		Projection:      spWARPProjection(),
	}
}

// TestRuntimeCompileDeniesWithoutIPPathEvidence drives
// RecommendedWithoutIPPathEvidenceAllowed through the production Compile
// root (profile_warp_recommended_without_ip_path_evidence_total).
func TestRuntimeCompileDeniesWithoutIPPathEvidence(t *testing.T) {
	assertSPInc(t, "profile_warp_recommended_without_ip_path_evidence_total", func() {
		rt := newSPRuntime(t)
		ctx := spCompileCtx()
		ctx.IPPathEvidence = false
		if _, err := rt.Compile(time.Now(), spRecommendation(), ctx); err == nil {
			t.Fatal("compile without IP-path evidence must be denied")
		}
	})
}

// TestRuntimeCompileDeniesDestinationIPOnly drives
// RecommendedFromDestinationIPOnlyAllowed through the production Compile
// root (profile_warp_recommended_from_destination_ip_only_total).
func TestRuntimeCompileDeniesDestinationIPOnly(t *testing.T) {
	assertSPInc(t, "profile_warp_recommended_from_destination_ip_only_total", func() {
		rt := newSPRuntime(t)
		r := spRecommendation()
		r.ClientScopeHash = ""
		if _, err := rt.Compile(time.Now(), r, spCompileCtx()); err == nil {
			t.Fatal("destination-only recommendation must be denied")
		}
	})
}

// TestRuntimeCompileDeniesOriginDead drives RecommendedForOriginDeadAllowed
// through the production Compile root
// (profile_warp_recommended_for_origin_dead_total).
func TestRuntimeCompileDeniesOriginDead(t *testing.T) {
	assertSPInc(t, "profile_warp_recommended_for_origin_dead_total", func() {
		rt := newSPRuntime(t)
		ctx := spCompileCtx()
		ctx.OriginAlive = false
		if _, err := rt.Compile(time.Now(), spRecommendation(), ctx); err == nil {
			t.Fatal("origin-dead recommendation must be denied")
		}
	})
}

// TestRuntimeCompileDeniesUnhealthyControls drives
// RecommendedWithUnhealthyControlsAllowed through the production Compile
// root (profile_warp_recommended_with_unhealthy_controls_total).
func TestRuntimeCompileDeniesUnhealthyControls(t *testing.T) {
	assertSPInc(t, "profile_warp_recommended_with_unhealthy_controls_total", func() {
		rt := newSPRuntime(t)
		ctx := spCompileCtx()
		ctx.ControlsHealthy = false
		if _, err := rt.Compile(time.Now(), spRecommendation(), ctx); err == nil {
			t.Fatal("unhealthy-controls recommendation must be denied")
		}
	})
}

// TestRuntimeCompileDeniesCrossService drives
// CrossServiceRecommendationAllowed through the production Compile root
// (profile_warp_recommendation_cross_service_total).
func TestRuntimeCompileDeniesCrossService(t *testing.T) {
	assertSPInc(t, "profile_warp_recommendation_cross_service_total", func() {
		rt := newSPRuntime(t)
		ctx := spCompileCtx()
		ctx.ConsumerService = "svc-b"
		if _, err := rt.Compile(time.Now(), spRecommendation(), ctx); err == nil {
			t.Fatal("cross-service recommendation must be denied")
		}
	})
}

// TestRuntimeCompileDeniesHiddenFailPolicy drives HiddenFailPolicyAllowed
// through the production Compile root
// (profile_warp_recommendation_hidden_fail_policy_total).
func TestRuntimeCompileDeniesHiddenFailPolicy(t *testing.T) {
	assertSPInc(t, "profile_warp_recommendation_hidden_fail_policy_total", func() {
		rt := newSPRuntime(t)
		r := spRecommendation()
		r.FailurePolicyPreview = ""
		if _, err := rt.Compile(time.Now(), r, spCompileCtx()); err == nil {
			t.Fatal("hidden failure policy must be denied")
		}
	})
}

// TestRuntimeCompileDeniesWithoutCausalTraceGate drives
// WithoutCausalTraceGateAllowed through the production Compile root
// (profile_warp_recommendation_without_causal_trace_gate_total).
func TestRuntimeCompileDeniesWithoutCausalTraceGate(t *testing.T) {
	assertSPInc(t, "profile_warp_recommendation_without_causal_trace_gate_total", func() {
		rt := newSPRuntime(t)
		ctx := spCompileCtx()
		ctx.Projection.CausalTraceReady = false
		if _, err := rt.Compile(time.Now(), spRecommendation(), ctx); err == nil {
			t.Fatal("recommendation without causal-trace gate must be denied")
		}
	})
}

// TestRuntimeValidateBlocksIgnoredControlRegression drives
// IgnoredControlRegressionAllowed through the production Validate root
// (profile_warp_recommendation_ignored_control_regression_total).
func TestRuntimeValidateBlocksIgnoredControlRegression(t *testing.T) {
	assertSPInc(t, "profile_warp_recommendation_ignored_control_regression_total", func() {
		rt := newSPRuntime(t)
		v := RecommendationValidation{RecommendationID: "rec-1", CleanedUp: true, ControlsHealthy: true}
		if st := rt.Validate(v, true); st != RecommendationBlockedBySafety {
			t.Fatalf("ignored control regression must block by safety, got %s", st)
		}
	})
}

// TestRuntimeValidateBlocksCleanupFailure drives
// RecommendationCleanupFailureAllowed through the production Validate root
// (profile_warp_recommendation_cleanup_failure_total).
func TestRuntimeValidateBlocksCleanupFailure(t *testing.T) {
	assertSPInc(t, "profile_warp_recommendation_cleanup_failure_total", func() {
		rt := newSPRuntime(t)
		v := RecommendationValidation{RecommendationID: "rec-1", CleanedUp: false}
		if st := rt.Validate(v, false); st != RecommendationBlockedBySafety {
			t.Fatalf("cleanup failure must block by safety, got %s", st)
		}
	})
}

// TestRuntimeBeginTestDeniesStaleProfile drives
// StaleProfileRecommendationAllowed through the production BeginTest root
// (profile_warp_recommendation_stale_profile_total).
func TestRuntimeBeginTestDeniesStaleProfile(t *testing.T) {
	assertSPInc(t, "profile_warp_recommendation_stale_profile_total", func() {
		rt := newSPRuntime(t)
		r := spRecommendation()
		r.ExpiresAt = time.Now().Add(-time.Minute)
		if _, err := rt.BeginTest(time.Now(), r); err == nil {
			t.Fatal("stale-profile begin-test must be denied")
		}
	})
}

// TestRuntimeEnableDeniesTestTokenReuse drives
// TestTokenReusedAsProductionAuthorizationAllowed through the production
// Enable root (profile_warp_test_token_reused_as_production_authorization_total).
func TestRuntimeEnableDeniesTestTokenReuse(t *testing.T) {
	assertSPInc(t, "profile_warp_test_token_reused_as_production_authorization_total", func() {
		rt := newSPRuntime(t)
		r := spRecommendation()
		r.State = RecommendationValidated
		rt.mu.Lock()
		rt.recs["rec-1"] = &recommendationState{
			recommendation: r,
			transaction:    &RecommendationTransaction{Recommendation: r, TestToken: "rec-1/test", ProductionAuthorized: true},
		}
		rt.mu.Unlock()
		if err := rt.Enable("rec-1", spWARPProjection(), true); err == nil {
			t.Fatal("test-token reuse must be denied")
		}
	})
}

// TestRuntimeEnableDeniesWithoutTargetCanary drives
// EnabledWithoutTargetCanaryAllowed through the production Enable root
// (profile_warp_enabled_without_target_canary_total).
func TestRuntimeEnableDeniesWithoutTargetCanary(t *testing.T) {
	assertSPInc(t, "profile_warp_enabled_without_target_canary_total", func() {
		rt := newSPRuntime(t)
		r := spRecommendation()
		r.State = RecommendationValidated
		rt.mu.Lock()
		rt.recs["rec-2"] = &recommendationState{
			recommendation: r,
			transaction:    &RecommendationTransaction{Recommendation: r},
		}
		rt.mu.Unlock()
		if err := rt.Enable("rec-2", spWARPProjection(), false); err == nil {
			t.Fatal("enablement without target canary must be denied")
		}
	})
}

// TestRuntimeValidatePolicyDeniesNonRUWithoutGeo drives
// NonRUSuggestedWithoutGeoRequirementAllowed through the production
// ValidatePolicy root (profile_nonru_suggested_without_geo_requirement_total).
func TestRuntimeValidatePolicyDeniesNonRUWithoutGeo(t *testing.T) {
	assertSPInc(t, "profile_nonru_suggested_without_geo_requirement_total", func() {
		rt := newSPRuntime(t)
		n := NonRUPolicy{Enabled: true, Strict: true, GeoRequirement: ""}
		if err := rt.ValidatePolicy(spWARPProjection(), CamouflagePolicy{}, n, false); err == nil {
			t.Fatal("non-ru without geo requirement must be denied")
		}
	})
}

// TestRuntimeValidatePolicyDeniesCamouflageForIPBlock drives
// CamouflageSuggestedForTargetIPBlockAllowed through the production
// ValidatePolicy root
// (profile_warp_camouflage_suggested_for_target_ip_block_total).
func TestRuntimeValidatePolicyDeniesCamouflageForIPBlock(t *testing.T) {
	assertSPInc(t, "profile_warp_camouflage_suggested_for_target_ip_block_total", func() {
		rt := newSPRuntime(t)
		c := CamouflagePolicy{Enabled: true}
		if err := rt.ValidatePolicy(spWARPProjection(), c, NonRUPolicy{}, true); err == nil {
			t.Fatal("camouflage for target ip block must be denied")
		}
	})
}

// TestRuntimePromoteBlocksWithoutTargetCanary drives the target-canary guard
// through the production Promote root
// (profile_warp_enabled_without_target_canary_total).
func TestRuntimePromoteBlocksWithoutTargetCanary(t *testing.T) {
	assertSPInc(t, "profile_warp_enabled_without_target_canary_total", func() {
		rt := newSPRuntime(t)
		if st := rt.Promote(spWARPProjection(), WARPHealth{}, false, true); st != PromotionBlocked {
			t.Fatalf("promotion without target canary must block, got %s", st)
		}
	})
}

// TestRuntimeLifecycleHappyPath drives a full valid recommendation through
// the production lifecycle: no guard fires and the recommendation reaches
// the validated state.
func TestRuntimeLifecycleHappyPath(t *testing.T) {
	rt := newSPRuntime(t)
	r, err := rt.Compile(time.Now(), spRecommendation(), spCompileCtx())
	if err != nil {
		t.Fatalf("valid compile must pass: %v", err)
	}
	if r.State != RecommendationEligibleToTest {
		t.Fatalf("state = %s, want eligible-to-test", r.State)
	}
	tx, err := rt.BeginTest(time.Now(), r)
	if err != nil {
		t.Fatalf("valid begin-test must pass: %v", err)
	}
	if tx.Recommendation.State != RecommendationTesting {
		t.Fatalf("state = %s, want testing", tx.Recommendation.State)
	}
	v := RecommendationValidation{
		RecommendationID:     r.RecommendationID,
		CleanedUp:            true,
		DirectFailed:         true,
		WARPReached:          true,
		ControlsHealthy:      true,
		PathProofCurrent:     true,
		ForwardedCanaryPassed: true,
		LeaksAbsent:          true,
	}
	if st := rt.Validate(v, false); st != RecommendationValidated {
		t.Fatalf("valid validation must validate, got %s", st)
	}
}
