# FB03 — Gate Producer/Consumer Matrix (evidence, registry schema v1.1)

**Task:** FB-03 «Создать canonical hard-gate registry, активировать runtime producers/consumers и подключить meta-suite» (B4X_AUDIT_FIX_TASKS v2.md §FB-03).
**Criterion covered:** §FB-03 п.6 — `artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.*` содержит evidence, а не grep-only proof.
**Commit SHA:** working tree (не закоммичен на момент обновления; см. git status)
**Created:** 2026-08-01 (v1.1 update: kinds, producer_status, machine-readable consumers/tests/evidence)
**Environment:** Windows host + Linux Docker (golang:1.25-alpine) reference CI; `go build ./... && go vet ./... && go test -count=1 ./...` — PASS.
**Semantics (v2 §0.6, registry schema v1.1):**

- `kind: telemetry_counter` — operational telemetry; > 0 is normal; **never** blocks promotion.
- `kind: zero_tolerance_violation_counter` — violation counter; `verified == 0`; **blocks** promotion.
- `producer_status: verified` — producer confirmed by call-site audit **and** negative fixture **and** mutation run.
- `producer_status: missing` — no producer in production code; fail-closed `BLOCKED_MISSING_PRODUCER` when the scope is applicable; `expected_producer_location` = owner-normative wiring target (FB-27 / PPE wiring).
- `runtime_producer` is a **machine-readable descriptor** `{symbol, file, line, mechanism, production_root}`; a declared file is NOT proof — only verified descriptors are non-null.
- `verdict_consumer` is a **machine-readable list** `{kind, symbol, file, line, binding}` (kind: `promotion_blocker` | `aggregation_blocker` | `http_report`).
- `test_producer` — fixtures `{kind, name, file, line, assertion}` (positive/negative/evaluator).
- `mutation_test` — executed mutation runs `{kind, name, file, status}`.
- `evidence_artifact` — backing audit/remediation paths.

## Verification commands (executed, evidence)

```powershell
# 1. Registry integrity + producer/consumer/test/evidence consistency
python tools/gen_hard_gates_registry.py --check
#    -> OK: 282 gates, 9 families, FT view 82 gates, IV view 78 gates, all mapped

# 2. Actual producer call sites per gate name across src
#    (production code only; *_test.go and hard_gates_registry.gen.go excluded)
Select-String -Path src -Pattern "<gate_name>" -SimpleMatch -Recurse

# 3. Full CI reference run
docker run --rm -v D:\b4x:/src -w /src/src -e GOMODCACHE=/gomod `
  -v C:\Users\AlexZander\go\pkg\mod:/gomod golang:1.25-alpine `
  sh -ceu "go build ./... && go vet ./... && go test ./..."
#    -> all packages ok
```

## Methodology (verification methods per gate)

Each gate is checked with **all five** producer-verification methods; a gate is
`verified` only when (a) direct metric producer **or** owner-state producer
exists, (b) production callers are traceable, and (c) an executed negative
fixture + mutation run prove the verdict flips when the producer is removed.

| Method | What is checked | Used for |
|---|---|---|
| Direct metric producer | `Metrics.Inc(name, ...)` call site in production code | `unrelated_control_action_total` (validation.go:392) |
| Owner-state producer | owner-owned state (report field, readiness state, evidence ledger) incremented in the owner path | `unrelated_control_action_total` (report.UnrelatedControlActionTotal++ validation.go:265) |
| Typed wrapper / event reducer | typed method / event reducer that ultimately increments the counter | none wired yet |
| Production callers | call path from production root (handler/control plane) to the increment | Validate -> ValidateAndStore -> handleClassifierIsolation / runtime_control.go |
| Executed negative fixture | a test that asserts the violation verdict when the gate fires | TestValidateRejectsYouTubeStateOnGmailSharedIPFlow (validation_test.go:40) |
| Executed mutation run | removing the producer flips the verdict (test fails), then restored | removed inc at validation.go:265 -> test FAIL -> restored, suite green |

## Matrix (24 rst_gso/ppe/csi gates, registry schema v1.1)

| # | GateID | Family | Kind | producer_status | Expected producer location (normative) | Verification method (result) | Promotion blocker |
|---|--------|--------|------|-----------------|-----------------------------------------|------------------------------|-------------------|
| 1 | `unrelated_control_action_total` | csi | zero_tolerance_violation_counter | **verified** | — | direct metric (validation.go:392) + owner-state (validation.go:265) + production callers + negative fixture + mutation run (all PASS) | yes |
| 2 | `classifier_reassembled_sni_total` | rst_gso | telemetry_counter | missing | nfq/classifier_decision.go | constant only (observability.go:59); 0 Inc call sites | no |
| 3 | `classifier_layout_parity_fail_total` | rst_gso | zero_tolerance_violation_counter | missing | nfq/classifier_decision.go | constant only (observability.go:60); 0 Inc call sites | yes |
| 4 | `nfqueue_gso_packets_total` | rst_gso | telemetry_counter | missing | nfq/offload.go | constant only (observability.go:61); 0 Inc call sites | no |
| 5 | `nfqueue_gso_bytes_total` | rst_gso | telemetry_counter | missing | nfq/offload.go | constant only (observability.go:62); 0 Inc call sites | no |
| 6 | `nfqueue_gso_truncated_total` | rst_gso | zero_tolerance_violation_counter | missing | nfq/offload.go | constant only (observability.go:63); 0 Inc call sites | yes |
| 7 | `nfqueue_gso_csum_not_ready_total` | rst_gso | zero_tolerance_violation_counter | missing | nfq/offload.go | constant only (observability.go:64); 0 Inc call sites | yes |
| 8 | `nfqueue_gso_decision_total` | rst_gso | telemetry_counter | missing | nfq/gso_fastpath.go | constant only (observability.go:65); 0 Inc call sites | no |
| 9 | `nfqueue_gso_normalized_total` | rst_gso | telemetry_counter | missing | nfq/gso_fastpath.go | constant only (observability.go:66); 0 Inc call sites | no |
| 10 | `nfqueue_gso_action_suppressed_total` | rst_gso | telemetry_counter | missing | nfq/gso_fastpath.go | constant only (observability.go:67); 0 Inc call sites | no |
| 11 | `nfqueue_gso_token_miss_total` | rst_gso | zero_tolerance_violation_counter | missing | nfq/gso_normalizer.go | constant only (observability.go:68); 0 Inc call sites | yes |
| 12 | `nfqueue_gso_transition_total` | rst_gso | telemetry_counter | missing | http/handler/runtime_topology.go | constant only (observability.go:69); 0 Inc call sites | no |
| 13 | `passive_rst_observed_total` | rst_gso | telemetry_counter | missing | nfq/passive_rst_observe.go | constant only (observability.go:70); 0 Inc call sites | no |
| 14 | `passive_rst_decision_total` | rst_gso | telemetry_counter | missing | nfq/passive_rst_observe.go | constant only (observability.go:71); 0 Inc call sites | no |
| 15 | `passive_rst_suppressed_total` | rst_gso | telemetry_counter | missing | nfq/passive_rst_observe.go | constant only (observability.go:72); 0 Inc call sites | no |
| 16 | `passive_rst_fail_open_total` | rst_gso | zero_tolerance_violation_counter | missing | nfq/passive_rst_observe.go | constant only (observability.go:73); 0 Inc call sites | yes |
| 17 | `passive_rst_baseline_quality_total` | rst_gso | telemetry_counter | missing | nfq/passive_rst_observe.go | constant only (observability.go:74); 0 Inc call sites | no |
| 18 | `passive_rst_budget_exhausted_total` | rst_gso | telemetry_counter | missing | nfq/passive_rst_observe.go | constant only (observability.go:75); 0 Inc call sites | no |
| 19 | `passive_rst_rollback_total` | rst_gso | telemetry_counter | missing | nfq/passive_rst_rollback.go | constant only (observability.go:76); 0 Inc call sites | no |
| 20 | `passive_rst_reconnect_regression_total` | rst_gso | zero_tolerance_violation_counter | missing | nfq/passive_rst_rollback.go | constant only (observability.go:77); 0 Inc call sites | yes |
| 21 | `b4_ppe_rule_reapply_total` | ppe | telemetry_counter | missing | capture/ppe/product_service.go | constant only (observability/ppe.go:6); 0 Inc call sites | no |
| 22 | `b4_ppe_self_test_total` | ppe | telemetry_counter | missing | capture/ppe/product_service.go | constant only (observability/ppe.go:7-12); 0 Inc call sites | no |
| 23 | `b4_capture_visibility_degrade_total` | ppe | zero_tolerance_violation_counter | missing | capture/ppe/product_service.go | constant only (observability/ppe.go); 0 Inc call sites | yes |
| 24 | `b4_hold_disabled_visibility_total` | ppe | zero_tolerance_violation_counter | missing | capture/ppe/product_service.go | constant only (observability/ppe.go); 0 Inc call sites | yes |

Current production scope (hardGateScope, `runtime_control.go`): WARPBase = `ClassifierV2Enabled`, CSI = true. RSTGSO/PPE families are **not** enabled in the current scope -> their gates are NOT_APPLICABLE. When RSTGSO/PPE are enabled, zero-tolerance gates #3/#6/#7/#11/#16/#20/#23/#24 evaluate to **BLOCKED_MISSING_PRODUCER** until producers are implemented (FB-27 / PPE wiring) — never PASS; telemetry gates #2/#4/#5/#8/#9/#10/#12/#13/#14/#15/#17/#18/#19/#21/#22 evaluate to informational Telemetry and never block.

## Machine-readable consumer chain (registry v1.1, verified)

For the only verified producer (`unrelated_control_action_total`), the consumer chain is encoded in `specs/registries/hard_gates.yaml` and mirrored in `src/validation/hard_gates_registry.gen.go`:

```yaml
verdict_consumer:
- kind: promotion_blocker       # Validate() report.Passed / Store.RequirePromotion (validation.go:312)
  file: src/crossservice/validation.go
  line: 312
  binding: generation; family:csi
- kind: aggregation_blocker     # EvaluateHardGates (gates.go:205), fail-closed
  file: src/validation/gates.go
  line: 205
  binding: scope.csi; fail-closed
- kind: http_report             # GET /api/v2/validation/gates
  file: src/http/handler/validation_gates.go
  line: 0
  binding: live snapshot
test_producer:
- kind: positive_fixture        # TestValidatePassingMatrixAllowsPromotion (validation_test.go:29)
- kind: negative_fixture        # TestValidateRejectsYouTubeStateOnGmailSharedIPFlow (validation_test.go:40)
- kind: evaluator_fixture       # TestEvaluateHardGatesViolation (gates_test.go:117)
mutation_test:
- kind: removed_inc             # removed inc at validation.go:265 -> test FAIL (executed 2026-08-01)
evidence_artifact:
- artifacts/audit/hard_gates_audit.md
- artifacts/audit/csi_ppe_rstgso_audit.md
- artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md
```

Runtime wiring (unchanged, production-rooted):

```
GET /api/v2/validation/gates (http/handler/validation_gates.go)
  └─ hardGateScope(cfg) -> ReleaseScope{WARPBase, CSI}
  └─ observability.Default().Metrics.Snapshot(now)   // live counters
  └─ EvaluateHardGates(scope, nil, "", GenerationSet{}, counters, produced)
  └─ RunMetaSuite(evidenceArtifacts())               // meta-suite (criterion §FB-03 п.4)

PromotePending/Apply (runtimecontrol, Options.HardGateCheck)
  └─ checkHardGates(cfg, generationID)               // runtime_control.go
      └─ EvaluateHardGates(...) -> GateEvaluation
      └─ verdict != PASS -> StagePromote fails -> rollback + close + history
```

Tests proving the chain (all pass, `go test -count=1 ./...`):

- `src/validation/gates_test.go` — selection/evaluator semantics (kind-aware: telemetry informational, zero-tolerance blocks), aliases, forced-zero -> BLOCKED, missing producer -> BLOCKED.
- `src/validation/meta_test.go` — RunMetaSuite: RegistryComplete/APIParity/VerdictMutationDetected/Reproducible (282 gates / 1 applicable)/FalseNegativeDetected/EvidenceIntegrity; missing evidence != PASS.
- `src/http/handler/validation_gates_test.go` — production-root: real `unrelated_control_action_total` violation recorded via observability -> endpoint returns verdict FAIL; meta exposed; 405 on non-GET.
- `src/fieldtest/hard_gates_chain_test.go` — promotion/canary/controller/StageReport consume GateEvaluation; **TestMissingProducerBlocksPromotionEndToEnd**: RSTGSO scope + missing zero-tolerance producer -> BLOCKED -> promotion rejected -> no committed side effect -> clean stop/cleanup.
- `src/runtimecontrol/rollout_hardgate_test.go` — FAIL/BLOCKED -> apply rejected + rollback + close; PASS -> promote.

## Mutation verification (2026-08-01, executed)

1. **Producer mutation (real code, executed):** removed `report.UnrelatedControlActionTotal++` (validation.go:265) -> `TestValidateRejectsYouTubeStateOnGmailSharedIPFlow` FAILS (`UnrelatedControlActionTotal:0` instead of 1) -> restored from backup -> full suite green. Recorded in registry as `mutation_test: [{kind: removed_inc, status: executed}]`.
2. **Registry mutation:** removed a gate from `specs/registries/hard_gates.yaml` -> `python tools/gen_hard_gates_registry.py --check` fails (removed-gate detection); registry restored by regeneration.
3. **Forced zero (no producer, no counter)** -> `EvaluateHardGates` returns BLOCKED, not PASS (meta-suite `VerdictMutationDetected`).
4. **Violation fixture (non-zero produced counter)** -> FAIL, never PASS (meta-suite `FalseNegativeDetected`).

## Honest status vs FB-03 criteria

| Criterion | Status | Evidence |
|---|---|---|
| 1. Registry passes schema/orphan/duplicate validation | **PASS** | `gen_hard_gates_registry.py --check`: 282 gates, 9 families, 0 duplicates, producer/consumer/test/evidence integrity checks; registry_test.go |
| 2. Each required gate has runtime producer + consumer or explicit not_applicable | **PARTIAL** — 1/282 verified (`unrelated_control_action_total`, full machine-readable chain); 15 telemetry (never block); 266 zero-tolerance missing (fail-closed BLOCKED when applicable) | matrix above; registry v1.1 fields |
| 3. Mutation suite makes each gate violated and blocks promotion | **PASS (scoped)** — real producer mutation run + evaluator mutation checks + promotion chain tests | meta_test.go, gates_test.go, hard_gates_chain_test.go, rollout_hardgate_test.go |
| 4. `/metrics`, API and report consistent with internal state | **PARTIAL** — validation API consumes live snapshot; Prometheus export consistency pending | validation_gates_test.go |
| 5. Missing/skipped/stale evidence not PASS | **PASS** — forced-zero -> BLOCKED; missing evidence -> EvidenceIntegrity=false; STALE verdict supported (not yet auto-populated) | meta_test.go, gates_test.go |
| 6. `FB03_GATE_PRODUCER_CONSUMER_MATRIX.*` evidence artifact | **PASS** — this file | executed commands + code refs above |

**FB-03 overall status: IN_PROGRESS (NOT COMPLETE).**
- FB-03_REGISTRY_SCHEMA: PARTIAL/PASS (v1.1: kinds, producer_status, machine-readable consumers/tests/evidence).
- FB-03_PRODUCER_AUDIT: PASS_WITH_FINDINGS (1/282 verified, 15 telemetry, 266 missing).
- FB-03_RUNTIME_PRODUCERS: FAIL/IN_PROGRESS — 19 RST/GSO producers (FB-27), 4 PPE producers (PPE wiring) not implemented.
- FB-03_VERDICT_CONSUMERS: INCOMPLETE — machine-readable chain exists for the 1 verified producer; null for all missing producers until producers land.
- FB-03_MUTATION_COVERAGE: INCOMPLETE — mutation run executed for the 1 verified producer; per-gate runs pending for implemented producers.

**Residual / blockers:** implementing the 23 missing producers is cross-cutting with FB-27 (RST/GSO production wiring) and the PPE production wiring; their zero-tolerance gates are fail-closed (BLOCKED_MISSING_PRODUCER) when the scope is enabled, so the registry/evaluator contract cannot be silently violated. FB-03 cannot be closed before those producers exist and their per-gate negative fixtures + mutation runs are recorded in the registry.
