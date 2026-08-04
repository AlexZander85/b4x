package observability

// MON hard-gate counters (FB-02 MON section, §84-§92 of
// B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0).
// Metric names match the canonical registry gate IDs exactly. Each counter is
// incremented only on the violating branch of the production MON lifecycle
// guards in src/monitoring/hard_gate_producers.go (observation authority ->
// scope -> temporal -> resolution -> trigger/resource -> multi-vantage ->
// ABD/DDI/discovery -> legacy migration -> reliability/privacy).
// All fifty-two are zero-tolerance violation counters: the window delta must
// stay 0 for the production promotion verdict. Five additional MON counters
// (resolution-erasure / multi-vantage, FB-29/FB-30) live in mon_fb29.go.
const (
	MetricMONObservationDirectAction           = "monitor_observation_direct_action_total"
	MetricMONProvisionalProfileCompiled        = "monitor_provisional_profile_compiled_total"
	MetricMONPassiveDiscoveryStart             = "monitor_passive_discovery_start_total"
	MetricMONPassiveWarpEnable                 = "monitor_passive_warp_enable_total"
	MetricMONFastLaneAction                    = "monitor_fast_lane_action_total"
	MetricMONFastLanePromotedAsAuthoritative   = "monitor_fast_lane_promoted_as_authoritative_total"
	MetricMONDestinationOnlyDeepTrigger        = "monitor_destination_only_deep_trigger_total"
	MetricMONCrossClientMerge                  = "monitor_cross_client_merge_total"
	MetricMONCrossServiceMerge                 = "monitor_cross_service_merge_total"
	MetricMONCrossComponentMerge               = "monitor_cross_component_merge_total"
	MetricMONCrossWanEvidenceMerge             = "monitor_cross_wan_evidence_merge_total"
	MetricMONCrossGenerationEvidenceMerge      = "monitor_cross_generation_evidence_merge_total"
	MetricMONRouterOriginAsForwardedProof      = "monitor_router_origin_as_forwarded_proof_total"
	MetricMONDupEvidenceIndependence           = "monitor_duplicate_evidence_independence_total"
	MetricMONTemporalPersistenceNoSeparation   = "monitor_temporal_persistence_without_time_separation_total"
	MetricMONSuccessSuppressorIgnored          = "monitor_success_suppressor_ignored_total"
	MetricMONRecoveredSubjectNotDemoted        = "monitor_recovered_subject_not_demoted_total"
	MetricMONExpiredEvidenceUsed               = "monitor_expired_evidence_used_total"
	MetricMONDecayDisabledWithoutPolicy        = "monitor_decay_disabled_without_policy_total"
	MetricMONProbeWithoutResolutionBinding     = "monitor_probe_without_resolution_binding_total"
	MetricMONClientDNSAnswerReplacedSilently   = "monitor_client_dns_answer_replaced_silently_total"
	MetricMONCnameTerminalIPMisattributed      = "monitor_cname_terminal_ip_misattributed_total"
	MetricMONMultiIPPartialFailureHidden       = "monitor_multi_ip_partial_failure_hidden_total"
	MetricMONStaleResolutionExactProof         = "monitor_stale_resolution_used_as_exact_proof_total"
	MetricMONTriggerWithoutVisibility          = "monitor_trigger_without_visibility_total"
	MetricMONTriggerWithoutBudget              = "monitor_trigger_without_budget_total"
	MetricMONTriggerDuringGlobalWanFailure     = "monitor_trigger_during_global_wan_failure_total"
	MetricMONTriggerWithStaleHeartbeat         = "monitor_trigger_with_stale_source_heartbeat_total"
	MetricMONDupConcurrentABDRun               = "monitor_duplicate_concurrent_abd_run_total"
	MetricMONUnboundedTargetIntake             = "monitor_unbounded_target_intake_total"
	MetricMONUnboundedProbeParallelism         = "monitor_unbounded_probe_parallelism_total"
	MetricMONSelfInterference                  = "monitor_self_interference_total"
	MetricMONReferenceResultAsAuthorization    = "monitor_reference_result_as_action_authorization_total"
	MetricMONABDRequestWithoutTargetPlan       = "monitor_abd_request_without_target_plan_total"
	MetricMONABDPartialResultProfileReady      = "monitor_abd_partial_result_profile_ready_total"
	MetricMONABDResultBypassedDDI              = "monitor_abd_result_bypassed_ddi_total"
	MetricMONDiscoveryWithoutAuthProfile       = "monitor_discovery_without_authoritative_profile_total"
	MetricMONDiscoverySkippedMandatoryBaseline = "monitor_discovery_skipped_mandatory_baseline_total"
	MetricMONRecommendationWithoutScope        = "monitor_recommendation_without_scope_total"
	MetricMONWarpRecommendationWithoutIPPath   = "monitor_warp_recommendation_without_ip_path_evidence_total"
	MetricMONLegacyWatchdogDirectApply         = "monitor_legacy_watchdog_direct_apply_total"
	MetricMONLegacyWatchdogUnvalidatedSet      = "monitor_legacy_watchdog_created_unvalidated_set_total"
	MetricMONLegacyWatchdogOverwriteNoCanary   = "monitor_legacy_watchdog_overwrote_set_without_canary_total"
	MetricMONLegacyAPIProjectionMutation       = "monitor_legacy_api_projection_mutation_total"
	MetricMONShadowActiveWriterOverlap         = "monitor_shadow_and_active_writer_overlap_total"
	MetricMONRequiredEventDropHidden           = "monitor_required_event_drop_hidden_total"
	MetricMONSourceHeartbeatStaleAutoDiagnose  = "monitor_source_heartbeat_stale_auto_diagnose_total"
	MetricMONCheckpointCorruptionFalseReady    = "monitor_checkpoint_corruption_false_ready_total"
	MetricMONRestartReusedExpiredLease         = "monitor_restart_reused_expired_lease_total"
	MetricMONSensitiveDNSHistoryExport         = "monitor_sensitive_dns_history_export_total"
	MetricMONSecretTraceLeak                   = "monitor_secret_trace_leak_total"
	MetricMONHighCardinalityMetricLabel        = "monitor_high_cardinality_metric_label_total"
)
