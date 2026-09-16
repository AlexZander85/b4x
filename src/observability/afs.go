package observability

const (
	MetricSynthesisWithoutUserOptIn              = "synthesis_without_user_opt_in_total"
	MetricSynthesisWithoutPersistentRegression   = "synthesis_without_persistent_regression_total"
	MetricSynthesisWithoutFreshProfile           = "synthesis_without_fresh_profile_total"
	MetricSynthesisStaleGenerationUsed           = "synthesis_stale_generation_used_total"
	MetricSynthesisGrammarEscape                 = "synthesis_grammar_escape_total"
	MetricSynthesisUnsafeOperatorEmitted         = "synthesis_unsafe_operator_emitted_total"
	MetricSynthesisScopeEscape                   = "synthesis_scope_escape_total"
	MetricSynthesisCandidateDirectApply          = "synthesis_candidate_direct_apply_total"
	MetricSynthesisWithoutActionAuthorization    = "synthesis_without_action_authorization_total"
	MetricSynthesisMissingMandatoryControl       = "synthesis_missing_mandatory_control_total"
	MetricSynthesisRouterOriginPromotedNoAndroid = "synthesis_router_origin_promoted_without_android_total"
	MetricSynthesisCandidateIdentityCollision    = "synthesis_candidate_identity_collision_total"
	MetricSynthesisCleanupIncomplete             = "synthesis_cleanup_incomplete_total"
	MetricSynthesisForeignResourceMutation       = "synthesis_foreign_resource_mutation_total"
	MetricSynthesisUnboundedExecution            = "synthesis_unbounded_execution_total"
	MetricSynthesisPromotionWithoutRollbackReady = "synthesis_promotion_without_rollback_ready_total"
)

func RecordSynthesisViolation(metric string) {
	Default().Metrics.Inc(metric, nil, 1)
}
