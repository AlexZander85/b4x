package observability

// Silent-path failure (SPF) hard-gate counters (FB-02 SPF section,
// §45 of B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0).
// Metric names match the canonical registry gate IDs exactly. Each counter
// is incremented only on the violating branch of the production SPF
// lifecycle guards in src/silentpath/hard_gate_producers.go
// (authorization -> visibility -> correlation -> recovery -> rollback).
// All twenty-two are zero-tolerance violation counters: the window delta
// must stay 0 for the production promotion verdict.
const (
	MetricSPFActionWithoutAuthorization    = "silent_failure_action_without_authorization_total"
	MetricSPFActionIncompleteVisibility    = "silent_failure_action_with_incomplete_visibility_total"
	MetricSPFDestinationOnlyState          = "silent_failure_destination_only_state_total"
	MetricSPFCrossClientAction             = "silent_failure_cross_client_action_total"
	MetricSPFCrossServiceAction            = "silent_failure_cross_service_action_total"
	MetricSPFCrossComponentAction          = "silent_failure_cross_component_action_total"
	MetricSPFCrossGenerationAction         = "silent_failure_cross_generation_action_total"
	MetricSPFSingleSignalAutoFallback      = "silent_failure_single_signal_auto_fallback_total"
	MetricSPFNonIndependentAutoFallback    = "silent_failure_non_independent_evidence_auto_fallback_total"
	MetricSPFSuppressorIgnored             = "silent_failure_suppressor_ignored_total"
	MetricSPFFastParallelFalsePositive     = "silent_failure_fast_parallel_false_positive_total"
	MetricSPFRecentSuccessFalsePositive    = "silent_failure_recent_success_false_positive_total"
	MetricSPFExplicitServerErrorMisclass   = "silent_failure_explicit_server_error_misclassified_total"
	MetricSPFGsoMssProgressMismatch        = "silent_failure_gso_mss_progress_mismatch_total"
	MetricSPFPPEVisibilityViolation        = "silent_failure_ppe_visibility_violation_total"
	MetricSPFUnboundedProbe                = "silent_failure_unbounded_probe_total"
	MetricSPFUnboundedRotation             = "silent_failure_unbounded_rotation_total"
	MetricSPFRecursiveTransportFallback    = "silent_failure_recursive_transport_fallback_total"
	MetricSPFRecoveryWithoutRollbackTarget = "silent_failure_recovery_without_rollback_target_total"
	MetricSPFControlRegressionPromoted     = "silent_failure_control_regression_promoted_total"
	MetricSPFFalsePositiveBudgetIgnored    = "silent_failure_false_positive_budget_ignored_total"
	MetricSPFUserRevertNotRolledBack       = "silent_failure_user_revert_not_rolled_back_total"
)
