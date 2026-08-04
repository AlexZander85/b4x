package observability

// WARP base-transport hard-gate counters (FB-02 WARP runtime section).
// Metric names match the canonical registry gate IDs (§72 of the built-in
// WARP/MASQUE transport addendum v1.2); each counter is incremented only on
// the violating branch of the production runtime lifecycle
// (enrollment -> TUN -> routing -> promotion). All ten are
// zero_tolerance_violation_counter gates: window delta must stay 0, and
// EvaluateCausalTraceWindow (FB-03/FB-14 decision 9) evaluates exactly this
// set for the narrow WARP_CAUSAL_TRACE_READY verdict.
const (
	MetricWarpSecretLeak                 = "warp_secret_leak_total"
	MetricWarpForeignInterfaceModified   = "warp_foreign_interface_modified_total"
	MetricWarpRecursiveControlRoute      = "warp_recursive_control_route_total"
	MetricWarpMarkCollision              = "warp_mark_collision_total"
	MetricWarpRouteWithoutLiveness       = "warp_route_without_liveness_total"
	MetricWarpDestinationSetPartialApply = "warp_destination_set_partial_apply_total"
	MetricWarpUnboundedRestart           = "warp_unbounded_restart_total"
	MetricWarpUnboundedRegistration      = "warp_unbounded_registration_total"
	MetricWarpUnrelatedControlAction     = "warp_unrelated_control_action_total"
	MetricWarpRollbackFailure            = "warp_rollback_failure_total"
)
