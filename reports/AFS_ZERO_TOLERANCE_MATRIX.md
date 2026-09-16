# AFS zero-tolerance invariant matrix

All counters below are release blockers when non-zero for the validated run.

| Counter | Guard / owner | Validation intent |
|---|---|---|
| `synthesis_without_user_opt_in_total` | Discovery synthesis preflight | automatic synthesis cannot start without canonical config opt-in |
| `synthesis_without_persistent_regression_total` | Discovery synthesis preflight | requires qualified persistent regression |
| `synthesis_without_fresh_profile_total` | Discovery synthesis preflight | fresh monitor/profile/prior/behavioral evidence required |
| `synthesis_stale_generation_used_total` | preflight + candidate/action generation checks | stale config generation rejected |
| `synthesis_grammar_escape_total` | finite grammar validator | unknown operators/params/triggers rejected |
| `synthesis_unsafe_operator_emitted_total` | grammar `AutomaticSafe` + bridge validation | unsafe/unavailable operators rejected |
| `synthesis_scope_escape_total` | exact scope equality checks | no profile/prior/candidate scope escape |
| `synthesis_candidate_direct_apply_total` | shared Discovery evaluation contract | synthesized evaluation always returns no direct apply |
| `synthesis_without_action_authorization_total` | ActionPlanner / promotion proof | non-dry-run execution and promotion require authorization |
| `synthesis_missing_mandatory_control_total` | preflight / Discovery matrix | controls and baselines required |
| `synthesis_router_origin_promoted_without_android_total` | transactional promotion proof | forwarded-client canary required before synthesized promotion |
| `synthesis_candidate_identity_collision_total` | run store / canonical identity | same candidate ID cannot map to different canonical plan |
| `synthesis_cleanup_incomplete_total` | preflight + runtime cleanup ledger | no new run while prior cleanup incomplete |
| `synthesis_foreign_resource_mutation_total` | resource ownership validation | synthesis may mutate only owned candidate resources |
| `synthesis_unbounded_execution_total` | request limits / planner / resource budget | candidates, generations, actions, branches, amplification and runtime are bounded |
| `synthesis_promotion_without_rollback_ready_total` | promotion proof | promotion requires rollback readiness |

The remaining validation wave must add explicit fault-injection tests for every row and demonstrate zero values in the final evidence artifacts.
