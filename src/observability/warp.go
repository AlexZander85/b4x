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

// WARP path-proof hard-gate counters (FB-03 §73B path-proof block, addendum
// v1.2 §62.2/§62.3/§62.6). Each counter is incremented only on the violating
// branch of the production route/path lifecycle (Runtime.PathProofPromote /
// Runtime.ForwardedSuccess / Runtime.DirectFallback / Runtime.DNSPathProof /
// Runtime.IPv6PathProof): promotion without a path-proof event (route/rule
// existence is not path proof), forwarded success without the binding trace,
// a direct fallback without a path-probe trace, and unproven DNS/IPv6 paths
// under strict non-RU. All five are zero_tolerance_violation_counter gates
// evaluated by the narrow WARP_CAUSAL_TRACE_READY verdict
// (FB-03/FB-14 decision 9).
const (
	MetricWarpRoutePromotedWithoutPathProofEvent  = "warp_route_promoted_without_path_proof_event_total"
	MetricWarpForwardedSuccessWithoutBindingTrace = "warp_forwarded_success_without_binding_trace_total"
	MetricWarpDirectFallbackWithoutTrace          = "warp_direct_fallback_without_trace_total"
	MetricWarpDNSPathUnproven                     = "warp_dns_path_unproven_total"
	MetricWarpIPv6PathUnproven                    = "warp_ipv6_path_unproven_total"
)

// WARP resource-ownership / cleanup / cutoff / non-RU hard-gate counters
// (FB-03 §73B ownership+cleanup block, addendum v1.2 §62.5/§62.7/§62.8).
// Each counter is incremented only on the violating branch of the production
// ownership/cutoff/non-RU lifecycle (Runtime.NonRURevocationDeadline /
// Runtime.NonRUPublicIPChange / Runtime.ConnectIPEvent /
// Runtime.PostCutoffMutation / Runtime.CleanupComplete /
// Runtime.OwnedResourceLeak / Runtime.ForeignResourceRemoved): revocation
// started after its deadline, a public-IP change without attestation refresh,
// a CONNECT-IP event with a wrong claimed generation, a post-cutoff payload
// mutation after an established bypass, a cleanup-completion claim over
// resources without terminal removal records, a leaked generation-owned
// resource, and a successful removed-by-b4 over a foreign resource. All
// seven are zero_tolerance_violation_counter gates evaluated by the narrow
// WARP_CAUSAL_TRACE_READY verdict (FB-03/FB-14 decision 9).
const (
	MetricWarpNonRURevocationExceededDeadline   = "warp_nonru_revocation_exceeded_deadline_total"
	MetricWarpNonRUPublicIPChangeWithoutRefresh = "warp_nonru_public_ip_change_without_refresh_total"
	MetricWarpConnectIPEventWrongGeneration     = "warp_connect_ip_event_wrong_generation_total"
	MetricWarpPostCutoffMutation                = "warp_post_cutoff_mutation_total"
	MetricWarpCleanupIncomplete                 = "warp_cleanup_incomplete_total"
	MetricWarpOwnedResourceLeak                 = "warp_owned_resource_leak_total"
	MetricWarpForeignResourceRemoved            = "warp_foreign_resource_removed_total"
)

// WARP strict non-RU route-gate counters (FB-03 §73 non-RU hard gates,
// addendum v1.2 §62.5 НЕ РФ gate / §62.6 DNS/IPv6 path proof / manifest
// no-silent-fallback). Each counter is incremented only on the violating
// branch of the production non-RU route lifecycle (Runtime.ApplyRoute with
// GeoAttestation/GeoObservation from geo.go): a route active without a fresh
// attestation, with any RU-classified provider, under provider disagreement,
// with direct DNS, with an unvalidated IPv6 path while IPv6 is enabled, or
// after attestation expiry; a strict non-RU silent fallback to the direct
// base path; and identity creation over its budget. All eight are
// zero_tolerance_violation_counter gates evaluated by the narrow
// WARP_CAUSAL_TRACE_READY verdict (FB-03/FB-14 decision 9).
const (
	MetricWarpNonRUActiveWithoutFreshAttestation = "nonru_route_active_without_fresh_attestation"
	MetricWarpNonRUActiveWhileAnyProviderRU      = "nonru_route_active_while_any_provider_ru"
	MetricWarpNonRUActiveWithProviderDisagreement = "nonru_route_active_with_provider_disagreement"
	MetricWarpNonRUActiveWithDirectDNS           = "nonru_route_active_with_direct_dns"
	MetricWarpNonRUActiveWithUnvalidatedIPv6     = "nonru_route_active_with_unvalidated_ipv6"
	MetricWarpNonRUActiveAfterAttestationExpiry  = "nonru_route_active_after_attestation_expiry"
	MetricWarpStrictDirectFallback               = "nonru_strict_direct_fallback_total"
	MetricWarpIdentityCreationBudgetExceeded     = "nonru_identity_creation_budget_exceeded"
)

// WARP MASQUE transport-camouflage hard-gate counters (FB-03 SECT 73A
// transport camouflage hard gates, addendum v1.2 SECT C.2/C.4/C.5/C.7/C.8/
// C.10/62.7). Each counter is incremented only on the violating branch of
// the production camouflage lifecycle (Runtime.CamouflageWithoutControl
// Authorization / CamouflageDestinationOnlyAuthorization /
// EstablishedPayloadMutation / CamouflageCutoffFailure /
// ControlRouteRecursion / CamouflageCrossInstance /
// StrategyPromotedWithoutForwardedProbe /
// StrategyPromotedWithoutStabilityWindow / InsecureTLSCover /
// EndpointPinFailureAccepted / UnboundedCandidateRetry /
// RSTSuppressionWithoutExactAuthorization). All twelve are
// zero_tolerance_violation_counter gates evaluated by the narrow
// WARP_CAUSAL_TRACE_READY verdict (FB-03/FB-14 decision 9).
const (
	MetricWarpMasqueCamouflageWithoutControlAuthorization  = "masque_camouflage_without_control_authorization_total"
	MetricWarpMasqueCamouflageDestinationOnlyAuthorization = "masque_camouflage_destination_only_authorization_total"
	MetricWarpMasqueEstablishedPayloadMutation             = "masque_established_payload_mutation_total"
	MetricWarpMasqueCamouflageCutoffFailure                = "masque_camouflage_cutoff_failure_total"
	MetricWarpMasqueControlRouteRecursion                  = "masque_control_route_recursion_total"
	MetricWarpMasqueCamouflageCrossInstance                = "masque_camouflage_cross_instance_total"
	MetricWarpMasqueStrategyPromotedWithoutForwardedProbe  = "masque_strategy_promoted_without_forwarded_probe_total"
	MetricWarpMasqueStrategyPromotedWithoutStabilityWindow = "masque_strategy_promoted_without_stability_window_total"
	MetricWarpMasqueInsecureTLS                            = "masque_insecure_tls_total"
	MetricWarpMasqueEndpointPinFailureAccepted             = "masque_endpoint_pin_failure_accepted_total"
	MetricWarpMasqueUnboundedCandidateRetry                = "masque_unbounded_candidate_retry_total"
	MetricWarpMasqueRSTSuppressionWithoutExactAuthorization = "masque_rst_suppression_without_exact_authorization_total"
)
