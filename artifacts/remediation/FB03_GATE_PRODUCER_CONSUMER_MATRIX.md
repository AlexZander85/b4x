# FB03 — Gate Producer/Consumer Matrix (evidence, registry schema v1.1)

**Task:** FB-03 «Создать canonical hard-gate registry, активировать runtime producers/consumers и подключить meta-suite» (B4X_AUDIT_FIX_TASKS v2.md §FB-03).
**Criterion covered:** §FB-03 п.6 — `artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.*` содержит evidence, а не grep-only proof.
**Commit SHA:** closure_commit = `df145b8a` (фаза E2); producer_verified_commit = `bd9db5d5`; classification_implementation_commit = `7c99ec8b`
**Created:** 2026-08-01 (v1.1 update: kinds, producer_status, machine-readable consumers/tests/evidence; фаза E2: window-delta, readiness owner-state, criterion 2 labels)
**Environment:** Windows host + Linux Docker (golang:1.25-alpine) reference CI; `go build ./... && go vet ./... && go test -count=1 ./...` — PASS.
**Semantics (v2 §0.6, registry schema v1.1):**

- `kind: telemetry_counter` — operational telemetry; > 0 is normal; **never** blocks promotion.
- `kind: zero_tolerance_violation_counter` — violation counter; `verified == 0`; **blocks** promotion.
- `producer_status: verified` — producer confirmed by call-site audit **and** negative fixture **and** mutation run.
- `producer_status: missing` — no producer in production code; fail-closed `BLOCKED_MISSING_PRODUCER` when the scope is applicable; `expected_producer_location` = owner-normative wiring target (FB-27 / PPE wiring).
- `runtime_producer` is a **machine-readable descriptor** `{symbol, file, line, mechanism, production_root}`; a declared file is NOT proof — only verified descriptors are non-null.
- `verdict_consumer` is a **machine-readable list** `{kind, symbol, file, line, binding}` (kind: `promotion_blocker` | `aggregation_blocker` | `readiness_observer` | `aggregation_observer` | `http_report`).
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
| Direct metric producer | `Metrics.Inc(name, ...)` call site in production code | all 24 gates (call-site table below; full recursive scan, production files only) |
| Owner-state producer | owner-owned state (report field, readiness state, evidence ledger) incremented in the owner path | `unrelated_control_action_total` (report.UnrelatedControlActionTotal++ validation.go:265) |
| Typed wrapper / event reducer | typed method / event reducer that ultimately increments the counter | `recordObservabilityDecision`, `traceGSOFastPath`, `traceGSONormalizerMiss`, `recordPassiveRSTMetrics`, `RecordHealth`, `productLifecycleMetrics.Reapply`, `ProductService.RunSelfTest`, gate.SubscribeBlocked callback, `ApplyRuntimeControlTopology` defer |
| Production callers | call path from production root (handler/control plane) to the increment | nfq.handlePacket / handleGSOFastPath / observePassiveRSTIncoming / pool.RecordPassiveRSTHealth / API.ApplyRuntimeControlTopology / visibility gate Degrade / lifecycle reapply / self-test controller |
| Executed negative fixture | a test that asserts the violation verdict when the gate fires | 3 zero-tolerance gates (owner decision 2026-08-01): hard_gate_producers_test.go negative fixtures; 4 readiness + 13 telemetry gates carry producer fixtures (violation recorded, never blocks) |
| Executed mutation run | removing the producer flips the verdict (test fails), then restored | 9 removed_inc runs executed 2026-08-01 (one per previously zero-tolerance gate) + 10 removed_delta aggregation tests (window-delta/scope, gates_test.go) |

## Matrix (24 rst_gso/ppe/csi gates, registry schema v1.1)

All 24 producers are **verified** (2026-08-01): every metric has a real
`Metrics.Inc` site reached from a production root, an executed fixture, and
every gate has an executed mutation record (removed_inc and/or removed_delta).
(Note: the previous "constant only; 0 Inc call sites" rows were a **false
negative** — producers call `Metrics.Inc(observability.Metric*, ...)` via
constants, and the earlier grep searched metric-name literals instead.)

| # | GateID | Family | Kind | producer_status | Producer call site (verified) | Fixture / mutation | Promotion blocker |
|---|--------|--------|------|-----------------|-------------------------------|--------------------|-------------------|
| 1 | `unrelated_control_action_total` | csi | zero_tolerance_violation_counter | **verified** | crossservice/validation.go:392 (Inc) + :265 (owner-state) | negative fixture + mutation run (executed) | yes |
| 2 | `classifier_reassembled_sni_total` | rst_gso | telemetry_counter | **verified** | nfq/classifier_decision.go:212 (recordObservabilityDecision) | positive fixture TestHardGateProducer_ClassifierLayoutParity | no |
| 3 | `classifier_layout_parity_fail_total` | rst_gso | zero_tolerance_violation_counter | **verified** | nfq/classifier_decision.go:214 | negative fixture + mutation run (executed) | yes |
| 4 | `nfqueue_gso_packets_total` | rst_gso | telemetry_counter | **verified** | nfq/offload.go:106 (observeOffloadMetadata) | positive fixture TestHardGateProducer_GSOOffloadMetadata | no |
| 5 | `nfqueue_gso_bytes_total` | rst_gso | telemetry_counter | **verified** | nfq/offload.go:107 | positive fixture (same) | no |
| 6 | `nfqueue_gso_truncated_total` | rst_gso | current_generation_readiness_input | **verified** | nfq/offload.go:109 | producer fixture + readiness never-blocks (executed) | no |
| 7 | `nfqueue_gso_csum_not_ready_total` | rst_gso | current_generation_readiness_input | **verified** | nfq/offload.go:112 | producer fixture + readiness never-blocks (executed) | no |
| 8 | `nfqueue_gso_decision_total` | rst_gso | telemetry_counter | **verified** | nfq/gso_fastpath.go:209 (traceGSOFastPath) | positive fixture TestHardGateProducer_GSOFastPathDecisions | no |
| 9 | `nfqueue_gso_normalized_total` | rst_gso | telemetry_counter | **verified** | nfq/gso_fastpath.go:211 | positive fixture (same) | no |
| 10 | `nfqueue_gso_action_suppressed_total` | rst_gso | telemetry_counter | **verified** | nfq/gso_fastpath.go:214 | positive fixture (same) | no |
| 11 | `nfqueue_gso_token_miss_total` | rst_gso | current_generation_readiness_input | **verified** | nfq/gso_normalizer.go:61 (traceGSONormalizerMiss) | producer fixture + readiness never-blocks (executed) | no |
| 12 | `nfqueue_gso_transition_total` | rst_gso | telemetry_counter | **verified** | http/handler/runtime_topology.go:38 (ApplyRuntimeControlTopology defer) | positive fixture TestHardGateProducer_GSOTransition | no |
| 13 | `passive_rst_observed_total` | rst_gso | telemetry_counter | **verified** | nfq/passive_rst_observe.go:106 (recordPassiveRSTMetrics) | positive fixture TestHardGateProducer_PassiveRSTMetrics | no |
| 14 | `passive_rst_decision_total` | rst_gso | telemetry_counter | **verified** | nfq/passive_rst_observe.go:108 | positive fixture (same) | no |
| 15 | `passive_rst_suppressed_total` | rst_gso | telemetry_counter | **verified** | nfq/passive_rst_observe.go:113 | positive fixture (same) | no |
| 16 | `passive_rst_fail_open_total` | rst_gso | telemetry_counter | **verified** | nfq/passive_rst_observe.go:116 | producer fixture + safe-degradation telemetry (executed) | no |
| 17 | `passive_rst_baseline_quality_total` | rst_gso | telemetry_counter | **verified** | nfq/passive_rst_observe.go:109 | positive fixture (same) | no |
| 18 | `passive_rst_budget_exhausted_total` | rst_gso | telemetry_counter | **verified** | nfq/passive_rst_observe.go:118 | positive fixture (same) | no |
| 19 | `passive_rst_rollback_total` | rst_gso | telemetry_counter | **verified** | nfq/passive_rst_rollback.go:134 (RecordHealth) | positive fixture TestHardGateProducer_PassiveRSTRollback | no |
| 20 | `passive_rst_reconnect_regression_total` | rst_gso | zero_tolerance_violation_counter | **verified** | nfq/passive_rst_rollback.go:136 | negative fixture + mutation run (executed) | yes |
| 21 | `b4_ppe_rule_reapply_total` | ppe | telemetry_counter | **verified** | capture/ppe/product_service.go:513 (productLifecycleMetrics.Reapply) | positive fixture TestHardGateProducer_PPERuleReapply | no |
| 22 | `b4_ppe_self_test_total` | ppe | telemetry_counter | **verified** | capture/ppe/product_service.go:348 (RunSelfTest) | positive fixture TestHardGateProducer_PPESelfTest | no |
| 23 | `b4_capture_visibility_degrade_total` | ppe | current_generation_readiness_input | **verified** | capture/ppe/product_service.go:110 (gate.SubscribeBlocked) | producer fixture + readiness never-blocks (executed) | no |
| 24 | `b4_hold_disabled_visibility_total` | ppe | telemetry_counter | **verified** | capture/ppe/product_service.go:111 | producer fixture + safety-guard telemetry (executed) | no |

Zero-tolerance gates evaluate to **FAIL** on any non-zero window delta
(owner decision 2026-08-01: delta of the current validation window, never a
lifetime absolute total; `EvaluateHardGatesWindow` with baseline); readiness
inputs aggregate into informational `ReadinessInputs` and never block
directly (they invalidate current-generation readiness only together with
owner state/applicability); telemetry gates aggregate into informational
`Telemetry` and never block. When the RSTGSO/PPE scope is enabled, all
applicable gates now evaluate with real producers (no BLOCKED_MISSING_PRODUCER
remains in the FB-03 scope).

## Machine-readable consumer chain (registry v1.1, verified)

Every verified producer (24/24) carries a machine-readable consumer chain in
`specs/registries/hard_gates.yaml`, mirrored in
`src/validation/hard_gates_registry.gen.go`. Zero-tolerance gates consume
through the promotion path (`promotion_blocker` + fail-closed
`aggregation_blocker` + `http_report`); telemetry gates through
`aggregation_observer` (informational) + `http_report`. Example
(unrelated_control_action_total; the other 23 follow the same schema):

```yaml
verdict_consumer:
- kind: promotion_blocker       # Validate() report.Passed / Store.RequirePromotion (validation.go:312)
  file: src/crossservice/validation.go
  line: 312
  binding: generation; family:csi
- kind: aggregation_blocker     # EvaluateHardGates (gates.go:239), fail-closed
  file: src/validation/gates.go
  line: 233
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

Producer fixtures (new, 2026-08-01) driving the production emission sites:

- `src/nfq/hard_gate_producers_test.go` — GSO offload metadata (4 metrics),
  GSO fast-path decisions (3), token miss, passive-RST metrics (6),
  passive-RST rollback (2), classifier layout parity (2).
- `src/capture/ppe/hard_gate_producers_test.go` — visibility degrade/hold
  disabled (via NewProductService subscription), self-test, rule reapply.
- `src/http/handler/hard_gate_producers_test.go` — GSO transition (topology
  apply defer).

Tests proving the chain (all pass, `go test -count=1 ./...`):

- `src/validation/gates_test.go` — selection/evaluator semantics (kind-aware: telemetry informational, zero-tolerance blocks), aliases, forced-zero -> BLOCKED, missing producer -> BLOCKED; ApplicableHardGates = 24.
- `src/validation/meta_test.go` — RunMetaSuite: RegistryComplete/APIParity/VerdictMutationDetected/Reproducible (282 gates / 24 applicable)/FalseNegativeDetected/EvidenceIntegrity; missing evidence != PASS.
- `src/http/handler/validation_gates_test.go` — production-root: real `unrelated_control_action_total` violation recorded via observability -> endpoint returns verdict FAIL; meta exposed; 405 on non-GET.
- `src/fieldtest/hard_gates_chain_test.go` — promotion/canary/controller/StageReport consume GateEvaluation; **TestMissingProducerBlocksPromotionEndToEnd**: RSTGSO scope + missing zero-tolerance producer -> BLOCKED -> promotion rejected -> no committed side effect -> clean stop/cleanup.
- `src/runtimecontrol/rollout_hardgate_test.go` — FAIL/BLOCKED -> apply rejected + rollback + close; PASS -> promote.

## Mutation verification (2026-08-01, executed)

1. **Producer mutation (real code, executed):** removed `report.UnrelatedControlActionTotal++` (validation.go:265) -> `TestValidateRejectsYouTubeStateOnGmailSharedIPFlow` FAILS (`UnrelatedControlActionTotal:0` instead of 1) -> restored from backup -> full suite green. Recorded in registry as `mutation_test: [{kind: removed_inc, status: executed}]`.
2. **Producer mutations for the other zero-tolerance-classified gates (real code, executed 2026-08-01):** each `Metrics.Inc` site was disabled one at a time and the corresponding fixture FAILED on that exact gate, then the site was restored:
   - `nfqueue_gso_truncated_total` (offload.go:109) -> TestHardGateProducer_GSOOffloadMetadata FAIL
   - `nfqueue_gso_csum_not_ready_total` (offload.go:112) -> FAIL
   - `nfqueue_gso_token_miss_total` (gso_normalizer.go:61) -> TestHardGateProducer_GSOTokenMiss FAIL
   - `classifier_layout_parity_fail_total` (classifier_decision.go:214) -> TestHardGateProducer_ClassifierLayoutParity FAIL
   - `passive_rst_fail_open_total` (passive_rst_observe.go:116) -> TestHardGateProducer_PassiveRSTMetrics FAIL
   - `passive_rst_reconnect_regression_total` (passive_rst_rollback.go:136) -> TestHardGateProducer_PassiveRSTRollback FAIL
   - `b4_capture_visibility_degrade_total` (product_service.go:110) -> TestHardGateProducer_CaptureVisibilityDegrade FAIL
   - `b4_hold_disabled_visibility_total` (product_service.go:111) -> FAIL
   Restore verified: no `MUTATION-RUN` markers left, full suite green. All recorded in the registry as `mutation_test: [{kind: removed_inc, status: executed}]`.
3. **Aggregation mutations (window-delta / scope, executed; owner requirement 5):** the aggregation semantics themselves are mutation-guarded in `src/validation/gates_test.go`:
   - `TestEvaluateHardGatesWindowDelta` — clean window (lifetime 5, baseline 5) must PASS: removing the baseline subtraction flips it to FAIL; delta 2 -> FAIL with count 2; counter reset in-window -> delta = current (fail-closed).
   - `TestEvaluateHardGatesReadinessInputsNeverBlock` — 4 readiness inputs + 17 telemetry non-zero must yield PASS with them reported in `ReadinessInputs`/`Telemetry`: turning any readiness input into a blocker fails the test.
   - `TestEvaluateHardGatesScopeIsolation` — a zero-tolerance violation in a non-applicable scope must not affect the verdict.
   Recorded in the registry as `mutation_test: [{kind: removed_delta, status: executed}]` for the 3 zero-tolerance gates and the 7 reclassified gates.
4. **Registry mutation:** removed a gate from `specs/registries/hard_gates.yaml` -> `python tools/gen_hard_gates_registry.py --check` fails (removed-gate detection); registry restored by regeneration.
5. **Forced zero (no producer, no counter)** -> `EvaluateHardGates` returns BLOCKED, not PASS (meta-suite `VerdictMutationDetected`).
6. **Violation fixture (non-zero produced counter)** -> FAIL, never PASS (meta-suite `FalseNegativeDetected`).

## Honest status vs FB-03 criteria

| Criterion | Status | Evidence |
|---|---|---|
| 1. Registry passes schema/orphan/duplicate validation | **PASS** | `gen_hard_gates_registry.py --check`: 282 gates, 9 families, 0 duplicates, producer/consumer/test/evidence integrity checks; registry_test.go |
| 2. Each required gate has runtime producer + consumer or explicit not_applicable | **PASS_CURRENT_PRODUCTION_SCOPE (24/24)** + **DEFERRED_DEPENDENCY (258)** — 24/24 verified в текущем production scope (RSTGSO/CSI/PPE: 3 zero-tol + 17 telemetry + 4 readiness inputs); остальные 258 — вне production-графа, без explicit not_applicable/normative basis **global PASS не заявляется** (fail-closed BLOCKED при applicability; FB-02/FB-14 и др.) | matrix above; registry v1.1 fields; ApplicableHardGates() = 24 |
| 3. Mutation suite makes each gate violated and blocks promotion | **PASS (kind-aware)** — zero-tolerance: 9 removed_inc + 10 removed_delta (window-delta/scope, BLOCKED → apply rejected → rollback/cleanup); readiness: инвалидация owner verdict (unsafe → BLOCKED, unknown → DEGRADED, revalidation новой generation → READY); telemetry: producer/export/report consistency (integration test) | hard_gate_producers_test.go (3 files), meta_test.go, gates_test.go, hard_gates_chain_test.go, rollout_hardgate_test.go, production_validation_integration_test.go |
| 4. `/metrics`, API and report consistent with internal state | **PASS** — Prometheus `/metrics` text export (`handler/prometheus.go`) с одинаковыми names/labels/values/kinds/produced state; production-root integration test: snapshot ↔ `/metrics` ↔ Validation API ↔ Field Test/report (одинаковые window baseline/delta/generation) | production_validation_integration_test.go, prometheus.go |
| 5. Missing/skipped/stale evidence not PASS | **PASS** — forced-zero -> BLOCKED; missing evidence -> EvidenceIntegrity=false; STALE verdict supported; **counter reset в окне → BLOCKED_COUNTER_RESET** (baseline=5, current=0 → BLOCKED; TestBaselineForRunWindowSemantics) | meta_test.go, gates_test.go, TestBaselineForRunWindowSemantics |
| 6. `FB03_GATE_PRODUCER_CONSUMER_MATRIX.*` evidence artifact | **PASS** — this file | executed commands + code refs above |

**FB-03 overall status: COMPLETE (owner review 2026-08-01, фаза E2 — все 6 критериев PASS).**
- FB-03_REGISTRY_SCHEMA: PASS (v1.1 + `current_generation_readiness_input` kind; kinds APPROVED).
- FB-03_PRODUCER_AUDIT: PASS — 24/24 verified (call-site audit + production callers + executed fixtures; the earlier "0 Inc call sites" finding was a false negative — producers increment via observability constants).
- FB-03_RUNTIME_PRODUCERS: PASS — all 19 RST/GSO + 4 PPE producers exist and are wired (FB-27 scope: no implementation work left for these metrics).
- FB-03_VERDICT_CONSUMERS: PASS — machine-readable chain for all 24 verified producers (promotion_blocker/aggregation_blocker/readiness_observer/aggregation_observer/http_report).
- FB-03_MUTATION_COVERAGE: PASS — 9 removed_inc + 10 removed_delta executed (counter increments AND scope/window-delta aggregation, owner requirement 5) + readiness owner-state effect + telemetry consistency integration test.
- FB-03_CRITERION_2: PASS_CURRENT_PRODUCTION_SCOPE + DEFERRED_DEPENDENCY (258) — global PASS не заявляется без normative basis.

**Residual / open items (осознанные DEFERRED dependencies, не блокируют COMPLETE):**
- GSO owner-state consumers (truncated/csum_not_ready/token_miss): live state wiring — **FB-27/PPE**; в production wired как Unknown (non-zero → readiness DEGRADED, никогда молчаливый READY).
- Optional separate GateID for "hold remained active under incomplete visibility" (owner requirement 1; not in normative docs).
- Labelled aggregation for `b4_ppe_self_test_total{verdict}` / `b4_ppe_rule_reapply_total{result}` and derived-state gating for `passive_rst_fail_open_total`/`passive_rst_rollback_total` (owner requirements 2/3; reserved kinds, out of evaluator scope).

## Progress note (2026-08-06, FB-03 b4x-q58 — WARP §73B causal-trace producers)

Registry is now **285 gates / 245 verified producers / 40 missing** (was 283/237/46;
+2 verified gates landed with FB-31 discovery gate and FB-31 SP recommendation gate).
This commit adds the **six WARP causal-trace producers** (`FB03_GATE_PRODUCER_CONSUMER_MATRIX.json`
regenerated, `specs/registries/hard_gates.yaml` + `hard_gates_registry.gen.go` regenerated,
`ApplicableHardGates() == 245`):

| Gate | Producer call site | Fixture |
|---|---|---|
| `warp_trace_secret_leak_total` | `Runtime.PublishTrace` deny-list (never-emit payload key, addendum §61.3) — `src/warp/runtime.go:450` | `TestHardGateProducer_WARPTraceSecretLeak` |
| `warp_trace_required_event_missing_total` | `Runtime.VerifyTraceCompleteness` (required-event completeness, §63.2) — `runtime.go:511` | `TestHardGateProducer_WARPTraceRequiredEventMissing` |
| `warp_trace_dropped_required_event_total` | `Runtime.PublishTrace` `HasCapacityFor` pre-check (P0/P1 durability, §61.2) — `runtime.go:482` | `TestHardGateProducer_WARPTraceDroppedRequiredEvent` |
| `warp_trace_event_order_violation_total` | `Runtime.PublishTrace` per-session monotonic sequence (§61.1) — `runtime.go:456` | `TestHardGateProducer_WARPTraceEventOrderViolation` |
| `warp_trace_generation_mismatch_total` | `Runtime.PublishTrace` current-generation rule (§61.1) — `runtime.go:463` | `TestHardGateProducer_WARPTraceGenerationMismatch` |
| `warp_trace_state_mismatch_total` | `Runtime.PublishTrace` trace-derived state vs runtime state (§63.2) — `runtime.go:471` | `TestHardGateProducer_WARPTraceStateMismatch` |

Trace pipeline hardening (`src/warp/trace.go`): P0/P1 required events are never evicted
in favor of other events (P2 evicted first; required event dropped only when the ring
holds only P0/P1 — counted as `warp_trace_dropped_required_event_total`).
`Runtime.Config.TraceCapacity` (default 256 = `warp_trace.memory_events`) added for the
bounded-ring fixture.

**Remaining missing (35):** masque_* (12, §73A) + nonru_* (8, §73) + warp causal/route (15:
geo x3, path proof x5, ownership/cleanup x4, connect-IP/non-RU x3 — follows as the next
FB-03 slices).

## Progress note 2 (2026-08-06, FB-03 b4x-q58 — WARP nested dependency graph, §73B/§62.4)

Nested-WARP producers landed (registry now **285 gates / 250 verified / 35 missing**,
`ApplicableHardGates() == 250`, code commit f54a7485-based → next pin):

| Gate | Producer call site | Fixture |
|---|---|---|
| `warp_nested_missing_parent_link_total` | `Runtime.NestedPromote` / `Runtime.NestedUseParentToken` — `src/warp/nested_runtime.go:41` | `TestHardGateProducer_WARPNestedMissingParentLink` (both sites) |
| `warp_nested_route_active_without_parent_health_total` | `Runtime.NestedPromote` — nested_runtime.go:45 | `TestHardGateProducer_WARPNestedRouteActiveWithoutParentHealth` |
| `warp_nested_parent_generation_mismatch_total` | `Runtime.NestedPromote` — nested_runtime.go:49 | `TestHardGateProducer_WARPNestedParentGenerationMismatch` |
| `warp_nested_stale_parent_token_total` | `Runtime.NestedUseParentToken` — nested_runtime.go:68 | `TestHardGateProducer_WARPNestedStaleParentToken` |
| `warp_nested_control_direct_leak_total` | `Runtime.NestedControl` — nested_runtime.go:84 | `TestHardGateProducer_WARPNestedControlDirectLeak` |

Mutation runs: each of the 6 `Metrics.Inc` sites removed → pinning fixture FAILs (6/6
killed), sites restored, no markers left. `mutation_test: [{kind: removed_inc, status:
executed}]` recorded in the registry.

## Progress note 3 (2026-08-06, FB-03 b4x-q58.1 — WARP geo-recognition, §73B/§62.5)

Geo-recognition producers landed (registry now **285 gates / 253 verified / 32 missing**,
`ApplicableHardGates() == 253`, code commit `e8a8c8e8`):

| Gate | Producer call site | Fixture |
|---|---|---|
| `warp_geo_attestation_without_route_counter_delta_total` | `Runtime.GeoAttestationCommit` (fresh provider result with `CounterDelta == 0`) — `src/warp/geo_runtime.go:43` | `TestHardGateProducer_WARPGeoAttestationWithoutRouteCounterDelta` |
| `warp_geo_quorum_without_provider_events_total` | `Runtime.GeoQuorumDecision` (quorum decision event with zero successful provider events — no route counter delta / no DNS path proof) — geo_runtime.go:71 | `TestHardGateProducer_WARPGeoQuorumWithoutProviderEvents` |
| `warp_geo_route_gate_state_mismatch_total` | `Runtime.GeoRouteGateApply` (§62.5 `RouteGateBefore`/`RouteGateAfter`) — geo_runtime.go:93+99 | `TestHardGateProducer_WARPGeoRouteGateStateMismatch` (both sites) |

§62.5 semantics wired into the production layer (`src/warp/geo_runtime.go`): each provider
result is an independent event that must carry a route counter delta (and DNS path proof);
quorum is a separate decision event; a summary/quorum event without provider events and
path proof is invalid; the route-gate after-state must match the decision (open under a
valid non-RU attestation, closed after a revoked/expired/disagreement attestation).

Mutation runs: each of the 4 `Metrics.Inc` sites removed → pinning fixture FAILs (4/4
killed, `warp_geo_route_gate_state_mismatch_total` covered on both production sites),
sites restored, no `MUTATION-RUN` markers left. `mutation_test: [{kind: removed_inc,
status: executed}]` recorded in the registry.

**Remaining missing (32):** masque_* (12, §73A) + nonru_* (8, §73) + warp causal/route
(12: path proof x5, ownership/cleanup x4, connect-IP/non-RU x3 — follow as the next
FB-03 slices b4x-q58.2/3/4/5).

## Progress note 4 (2026-08-06, FB-03 b4x-q58.2 — WARP path-proof, §73B/§62.2/§62.3/§62.6)

Path-proof producers landed (registry now **285 gates / 258 verified / 27 missing**,
`ApplicableHardGates() == 258`, code commit `c380b24e`):

| Gate | Producer call site | Fixture |
|---|---|---|
| `warp_route_promoted_without_path_proof_event_total` | `Runtime.PathProofPromote` (promotion without a path-proof event — route/rule existence is not path proof, §62.2) — `src/warp/path_runtime.go:44` | `TestHardGateProducer_WARPRoutePromotedWithoutPathProofEvent` |
| `warp_forwarded_success_without_binding_trace_total` | `Runtime.ForwardedSuccess` (success without the binding trace causal chain BindingID→RouteTokenID→PathProofID; router-origin cannot satisfy forwarded proof, §62.3) — path_runtime.go:60 | `TestHardGateProducer_WARPForwardedSuccessWithoutBindingTrace` |
| `warp_direct_fallback_without_trace_total` | `Runtime.DirectFallback` (fallback with no path-probe event in the session trace pipeline) — path_runtime.go:83 | `TestHardGateProducer_WARPDirectFallbackWithoutTrace` |
| `warp_dns_path_unproven_total` | `Runtime.DNSPathProof` (observed resolver path ≠ expected path, probe not passed or direct WAN; strict non-RU requires current DNS path proof, §62.6) — path_runtime.go:96 | `TestHardGateProducer_WARPDNSPathUnproven` |
| `warp_ipv6_path_unproven_total` | `Runtime.IPv6PathProof` (stale/absent independent IPv6 path claim, §62.6) — path_runtime.go:113 | `TestHardGateProducer_WARPIPv6PathUnproven` |

§62.2/§62.3/§62.6 semantics wired into the production layer (`src/warp/path.go` +
`src/warp/path_runtime.go`): promotion proof must carry a positive counter delta,
matching expected session/route generation and no direct WAN / recursion; forwarded
success must form the exact binding correlation chain; a direct fallback must be
traceable via the session trace pipeline; strict non-RU requires current DNS path
proof and (unless IPv6 is disabled for the exact scope) a current independent IPv6
path proof.

Mutation runs: each of the 5 `Metrics.Inc` sites removed → pinning fixture FAILs (5/5
killed), sites restored, no `MUTATION-RUN` markers left. `mutation_test: [{kind:
removed_inc, status: executed}]` recorded in the registry.

**Remaining missing (27):** masque_* (12, §73A) + nonru_* (8, §73) + ownership/cleanup
(4) + connect-IP/non-RU (3) — follow as the next FB-03 slices b4x-q58.3/4/5.

## Progress note 5 (2026-08-06, FB-03 b4x-q58.3 — WARP ownership/cleanup + connect-IP/non-RU, §73B/§62.5/§62.7/§62.8)

Ownership/cleanup + connect-IP/non-RU producers landed (registry now **285 gates /
265 verified / 20 missing**, `ApplicableHardGates() == 265`, code commit `8fef3a5c`):

| Gate | Producer call site | Fixture |
|---|---|---|
| `warp_nonru_revocation_exceeded_deadline_total` | `Runtime.NonRURevocationDeadline` (revocation started after its deadline; prompt revocation §62.5) — `src/warp/ownership_runtime.go:47` | `TestHardGateProducer_WARPNonRURevocationExceededDeadline` |
| `warp_nonru_public_ip_change_without_refresh_total` | `Runtime.NonRUPublicIPChange` (public-IP change with no fresh attestation refresh; §62.5 `warp_geo_public_ip_changed`) — ownership_runtime.go:63 | `TestHardGateProducer_WARPNonRUPublicIPChangeWithoutRefresh` |
| `warp_connect_ip_event_wrong_generation_total` | `Runtime.ConnectIPEvent` (CONNECT-IP event claiming a wrong process/config generation) — ownership_runtime.go:79 | `TestHardGateProducer_WARPConnectIPEventWrongGeneration` |
| `warp_post_cutoff_mutation_total` | `Runtime.PostCutoffMutation` (payload mutation after established bypass; §62.7 invariant CONNECT-IP → cutoff → bypass → post_cutoff_mutations == 0) — ownership_runtime.go:95 | `TestHardGateProducer_WARPPostCutoffMutation` |
| `warp_cleanup_incomplete_total` | `Runtime.CleanupComplete` (completion claim over owned resource without terminal removal/already-absent record; §62.8) — ownership_runtime.go:113 | `TestHardGateProducer_WARPCleanupIncomplete` |
| `warp_owned_resource_leak_total` | `Runtime.OwnedResourceLeak` (generation-owned resource without terminal record at finalize; §62.8) — ownership_runtime.go:130 | `TestHardGateProducer_WARPOwnedResourceLeak` |
| `warp_foreign_resource_removed_total` | `Runtime.ForeignResourceRemoved` (foreign resource received successful `removed-by-b4`; §62.8) — ownership_runtime.go:145 | `TestHardGateProducer_WARPForeignResourceRemoved` |

§62.5/§62.7/§62.8 semantics wired into the production layer (`src/warp/ownership.go` +
`src/warp/ownership_runtime.go`): strict non-RU revocation must start by its deadline;
a public-IP change requires a fresh attestation refresh; CONNECT-IP events must claim
the expected process/config generation; the §62.7 hard invariant holds
(post_cutoff_mutations == 0 after an established bypass); cleanup is complete only
when every generation-owned resource has a terminal removal record or a verified
already-absent record; a foreign resource must never receive a successful
removed-by-b4 event. `terminalRemoveResult` covers `removed-by-b4` / `remove-failed` /
`already-absent`.

Mutation runs: each of the 7 `Metrics.Inc` sites removed → pinning fixture FAILs (7/7
killed; CleanupComplete restored after a mid-mutation structural edit), sites
restored, no `MUTATION-RUN` markers left. `mutation_test: [{kind: removed_inc, status:
executed}]` recorded in the registry.

**Remaining missing (20):** masque_* (12, §73A) + nonru_* (8, §73) — follow as the
next FB-03 slices b4x-q58.4 (nonru) / b4x-q58.5 (masque).

## Progress note 6 (2026-08-06, FB-03 b4x-q58.4 - WARP strict non-RU route-gate, SECT 73)

Strict non-RU route-gate producers landed (registry now **285 gates / 273 verified /
12 missing**, `ApplicableHardGates() == 273`, code commit `68865d8c`):

| Gate | Producer call site | Fixture |
|---|---|---|
| `nonru_route_active_without_fresh_attestation` | `Runtime.NonRUActiveWithoutFreshAttestation` (active route without a current eligible non-RU attestation; SECT 62.5) - `src/warp/nonru_runtime.go:37` | `TestHardGateProducer_WARPNonRUActiveWithoutFreshAttestation` |
| `nonru_route_active_while_any_provider_ru` | `Runtime.NonRUActiveWhileAnyProviderRU` (active while any provider classifies the public IP as RU; SECT 62.5 provider-ru) - nonru_runtime.go:51 | `TestHardGateProducer_WARPNonRUActiveWhileAnyProviderRU` |
| `nonru_route_active_with_provider_disagreement` | `Runtime.NonRUActiveWithProviderDisagreement` (active under provider disagreement; SECT 62.5 provider-disagreement) - nonru_runtime.go:65 | `TestHardGateProducer_WARPNonRUActiveWithProviderDisagreement` |
| `nonru_route_active_with_direct_dns` | `Runtime.NonRUActiveWithDirectDNS` (active while DNS goes directly through the WAN path; SECT 62.6 dns-path) - nonru_runtime.go:79 | `TestHardGateProducer_WARPNonRUActiveWithDirectDNS` |
| `nonru_route_active_with_unvalidated_ipv6` | `Runtime.NonRUActiveWithUnvalidatedIPv6` (active with unvalidated IPv6 path while IPv6 enabled; SECT 62.6 ipv6-path) - nonru_runtime.go:94 | `TestHardGateProducer_WARPNonRUActiveWithUnvalidatedIPv6` |
| `nonru_route_active_after_attestation_expiry` | `Runtime.NonRUActiveAfterAttestationExpiry` (still active after attestation window passed; SECT 62.5 attestation-stale) - nonru_runtime.go:109 | `TestHardGateProducer_WARPNonRUActiveAfterAttestationExpiry` |
| `nonru_strict_direct_fallback_total` | `Runtime.StrictDirectFallback` (strict non-RU silent fallback to the direct base path; manifest no-silent-fallback) - nonru_runtime.go:123 | `TestHardGateProducer_WARPStrictDirectFallback` |
| `nonru_identity_creation_budget_exceeded` | `Runtime.IdentityCreationBudget` (identity creation above the per-generation budget) - nonru_runtime.go:137 | `TestHardGateProducer_WARPIdentityCreationBudgetExceeded` |

SECT 73 + SECT 62.5/62.6 semantics wired into the production layer
(`src/warp/nonru.go` + `src/warp/nonru_runtime.go`, reusing `GeoObservation` /
`GeoAttestation` from `geo.go`): a strict non-RU route must never be active
without a fresh non-RU attestation, with any RU-classified provider, under
provider disagreement, with direct WAN DNS, with an unvalidated IPv6 path while
IPv6 is enabled, or after attestation expiry; a strict non-RU route must never
silently fall back to the direct base path, and identity creation stays within
its budget. Gate-close reasons provider-ru / attestation-stale /
public-ip-changed / dns-path-failed / ipv6-path-failed (SECT 62.5) are covered.

Mutation runs: each of the 8 `Metrics.Inc` sites removed -> pinning fixture FAILs
(8/8 killed), sites restored, no `MUTATION-RUN` markers left. `mutation_test:
[{kind: removed_inc, status: executed}]` recorded in the registry.

**Remaining missing (12):** masque_* (12, SECT 73A) - follow as the next FB-03
slice b4x-q58.5 (masque, 273 -> 285, then missing 0).
