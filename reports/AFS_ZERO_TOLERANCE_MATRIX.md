# AFS zero-tolerance invariant matrix

Status: `LAB_VALIDATED`
Last code-bearing focused CI: `35085703795` — `PASS`

All counters below are release blockers when non-zero for the validated target run. Fault-injection tests verify that each violation family is rejected and its counter is raised; the production acceptance run must still demonstrate zero violations.

| Counter | Guard / owner | Fault injection |
|---|---|---|
| `synthesis_without_user_opt_in_total` | Discovery synthesis preflight | PASS |
| `synthesis_without_persistent_regression_total` | Discovery synthesis preflight | PASS |
| `synthesis_without_fresh_profile_total` | fresh monitor/profile/prior/behavioral evidence gate | PASS |
| `synthesis_stale_generation_used_total` | preflight + promotion generation checks | PASS |
| `synthesis_grammar_escape_total` | final finite-grammar emission boundary | PASS |
| `synthesis_unsafe_operator_emitted_total` | automatic-safe emission boundary | PASS |
| `synthesis_scope_escape_total` | exact service/component/profile/prior scope checks | PASS |
| `synthesis_candidate_direct_apply_total` | synthesized Discovery no-direct-apply guard | PASS |
| `synthesis_without_action_authorization_total` | transactional promotion proof | PASS |
| `synthesis_missing_mandatory_control_total` | preflight / target-control matrix / promotion proof | PASS |
| `synthesis_router_origin_promoted_without_android_total` | transactional promotion proof | PASS |
| `synthesis_candidate_identity_collision_total` | run-scoped immutable candidate store | PASS |
| `synthesis_cleanup_incomplete_total` | preflight + promotion cleanup readiness | PASS |
| `synthesis_foreign_resource_mutation_total` | preflight resource ownership proof | PASS |
| `synthesis_unbounded_execution_total` | resource/probe/store bounds | PASS |
| `synthesis_promotion_without_rollback_ready_total` | transactional promotion proof + active rollback state | PASS |

## Acceptance interpretation

`PASS` above means the guard and counter are covered by deterministic lab fault injection and the focused Go suite is green. It does **not** mean the final target run has demonstrated zero violations. The real Keenetic + forwarded Android validation must collect the observability snapshot and show every counter remains zero before `AUTONOMOUS_DPI_ADAPTATION_READY` can become PASS.
