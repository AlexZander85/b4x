package observability

// SP hard-gate counters (FB-02 sp section, §28A.11 of
// B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md).
// Metric names match the canonical registry gate IDs exactly. Each counter is
// incremented only on the violating branch of the production WARP
// recommendation guards in src/serviceprofile/hard_gate_producers.go
// (IP-path evidence, destination-only scope, origin liveness, control health,
// cross-service scope, profile freshness, causal-trace gate, target canary,
// test-token lifecycle, control regression, failure-policy visibility,
// non-RU geo requirement, camouflage target binding, cleanup).
// All fourteen are zero-tolerance violation counters: the window delta must
// stay 0 for the PROFILE_WARP_RECOMMENDATION_READY promotion verdict.
const (
	MetricSPRecommendedWithoutIPPathEvidence    = "profile_warp_recommended_without_ip_path_evidence_total"
	MetricSPRecommendedFromDestinationIPOnly    = "profile_warp_recommended_from_destination_ip_only_total"
	MetricSPRecommendedForOriginDead            = "profile_warp_recommended_for_origin_dead_total"
	MetricSPRecommendedWithUnhealthyControls    = "profile_warp_recommended_with_unhealthy_controls_total"
	MetricSPCrossService                        = "profile_warp_recommendation_cross_service_total"
	MetricSPStaleProfile                        = "profile_warp_recommendation_stale_profile_total"
	MetricSPWithoutCausalTraceGate              = "profile_warp_recommendation_without_causal_trace_gate_total"
	MetricSPEnabledWithoutTargetCanary          = "profile_warp_enabled_without_target_canary_total"
	MetricSPTestTokenReusedAsProdAuthorization  = "profile_warp_test_token_reused_as_production_authorization_total"
	MetricSPIgnoredControlRegression            = "profile_warp_recommendation_ignored_control_regression_total"
	MetricSPHiddenFailPolicy                    = "profile_warp_recommendation_hidden_fail_policy_total"
	MetricSPNonRUSuggestedWithoutGeoRequirement = "profile_nonru_suggested_without_geo_requirement_total"
	MetricSPCamouflageSuggestedForTargetIPBlock = "profile_warp_camouflage_suggested_for_target_ip_block_total"
	MetricSPCleanupFailure                      = "profile_warp_recommendation_cleanup_failure_total"
	MetricSPRecommendedOutsideCausalEligibility = "profile_warp_recommended_outside_causal_eligibility_total"
)
