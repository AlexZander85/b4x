package observability

// DDI guided-discovery and TGB Telegram-bridge hard-gate counters (FB-02
// DDI_TGB section, §32/§33 of
// B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0).
// Metric names match the canonical registry gate IDs exactly. Each counter
// is incremented only on the violating branch of the production guards in
// src/discovery/hard_gate_producers.go and src/mtproto/hard_gate_producers.go
// (profile lifecycle -> context/revalidation -> hint planning -> guided
// run -> bridge pending/prefix/route lifecycle). All twenty-four are
// zero-tolerance violation counters: the window delta must stay 0 for the
// DDI/TGB production readiness verdict.
const (
	MetricDiscoveryProfileWithoutContextValidation   = "discovery_profile_without_context_validation_total"
	MetricDiscoveryProfileStaleWithoutRevalidation   = "discovery_profile_stale_without_revalidation_total"
	MetricDiscoveryProfileCrossWANUse                = "discovery_profile_cross_wan_use_total"
	MetricDiscoveryProfileMutableRuntimePointer      = "discovery_profile_mutable_runtime_pointer_total"
	MetricDiscoveryProfileHintWithoutProvenance      = "discovery_profile_hint_without_provenance_total"
	MetricDiscoveryProfileHintOverrodeBaseline       = "discovery_profile_hint_overrode_current_baseline_total"
	MetricDiscoveryProfileSkippedTargetValidation    = "discovery_profile_skipped_target_validation_total"
	MetricDiscoveryProfileDisabledExhaustiveFallback = "discovery_profile_disabled_exhaustive_fallback_total"
	MetricDiscoveryProfileDirectProductionWrite      = "discovery_profile_direct_production_write_total"
	MetricDiscoveryProfileAllowedSNIDirectPromotion  = "discovery_profile_allowed_sni_direct_promotion_total"
	MetricDiscoveryProfileThresholdOutOfBudget       = "discovery_profile_threshold_out_of_budget_total"
	MetricDiscoveryProfileCaptureGateBypass          = "discovery_profile_capture_gate_bypass_total"
	MetricDiscoveryProfileCrossServiceAction         = "discovery_profile_cross_service_action_total"
	MetricDiscoveryProfileFalsePass                  = "discovery_profile_false_pass_total"
	MetricDiscoveryProfileOutsideCausalEligibility   = "discovery_profile_guided_plan_outside_causal_eligibility_total"

	MetricMTProtoZeroByteHandledDrop       = "mtproto_bridge_zero_byte_handled_drop_total"
	MetricMTProtoFixed5sDestructiveTimeout = "mtproto_bridge_fixed_5s_destructive_timeout_total"
	MetricMTProtoUnboundedPending          = "mtproto_bridge_unbounded_pending_total"
	MetricMTProtoPendingPerClientBypass    = "mtproto_bridge_pending_per_client_limit_bypass_total"
	MetricMTProtoPrefixLoss                = "mtproto_bridge_prefix_loss_total"
	MetricMTProtoPrefixDuplicate           = "mtproto_bridge_prefix_duplicate_total"
	MetricMTProtoRouteRecursion            = "mtproto_bridge_route_recursion_total"
	MetricMTProtoPrimaryFailureSilentDrop  = "mtproto_bridge_primary_failure_silent_drop_total"
	MetricMTProtoOverflowWithoutReason     = "mtproto_bridge_overflow_without_reason_total"
	MetricMTProtoShutdownLeak              = "mtproto_bridge_shutdown_leak_total"
)
