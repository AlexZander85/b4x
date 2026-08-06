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

// WARP causal-trace hard-gate counters (FB-03 §73B of the built-in WARP/MASQUE
// transport addendum v1.2). Each counter is incremented only on the violating
// branch of the production trace pipeline (Runtime.PublishTrace /
// Runtime.VerifyTraceCompleteness, controller-loop root from main). All six
// are zero_tolerance_violation_counter gates evaluated by the narrow
// WARP_CAUSAL_TRACE_READY verdict (FB-03/FB-14 decision 9).
const (
	MetricWarpTraceSecretLeak           = "warp_trace_secret_leak_total"
	MetricWarpTraceRequiredEventMissing = "warp_trace_required_event_missing_total"
	MetricWarpTraceDroppedRequiredEvent = "warp_trace_dropped_required_event_total"
	MetricWarpTraceEventOrderViolation  = "warp_trace_event_order_violation_total"
	MetricWarpTraceGenerationMismatch   = "warp_trace_generation_mismatch_total"
	MetricWarpTraceStateMismatch        = "warp_trace_state_mismatch_total"
)

// WARP nested dependency-graph hard-gate counters (FB-03 §73B nested block,
// addendum v1.2 §62.4). Each counter is incremented only on the violating
// branch of the production nested lifecycle (Runtime.NestedPromote /
// Runtime.NestedUseParentToken / Runtime.NestedControl). All five are
// zero_tolerance_violation_counter gates evaluated by the narrow
// WARP_CAUSAL_TRACE_READY verdict (FB-03/FB-14 decision 9).
const (
	MetricWarpNestedMissingParentLink              = "warp_nested_missing_parent_link_total"
	MetricWarpNestedParentGenerationMismatch       = "warp_nested_parent_generation_mismatch_total"
	MetricWarpNestedControlDirectLeak              = "warp_nested_control_direct_leak_total"
	MetricWarpNestedRouteActiveWithoutParentHealth = "warp_nested_route_active_without_parent_health_total"
	MetricWarpNestedStaleParentToken               = "warp_nested_stale_parent_token_total"
)

// WARP geo-attestation hard-gate counters (FB-03 §73B geo block, addendum
// v1.2 §62.5 "Geo attestation and non-RU gate"). Each counter is incremented
// only on the violating branch of the production geo lifecycle
// (Runtime.GeoAttestationCommit / Runtime.GeoQuorumDecision /
// Runtime.GeoRouteGateApply): a provider result without a route counter
// delta, a quorum decision without provider events (and path proof), and a
// route-gate state that contradicts the decision. All three are
// zero_tolerance_violation_counter gates evaluated by the narrow
// WARP_CAUSAL_TRACE_READY verdict (FB-03/FB-14 decision 9).
const (
	MetricWarpGeoAttestationWithoutRouteCounterDelta = "warp_geo_attestation_without_route_counter_delta_total"
	MetricWarpGeoQuorumWithoutProviderEvents         = "warp_geo_quorum_without_provider_events_total"
	MetricWarpGeoRouteGateStateMismatch              = "warp_geo_route_gate_state_mismatch_total"
)
