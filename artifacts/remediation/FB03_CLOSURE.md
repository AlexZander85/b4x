# FB-03 Closure Summary — canonical hard-gate registry, producers/consumers, meta-suite

Дата: 2026-08-01. Статус: **COMPLETE** — все 6 критериев §FB-03 **PASS** (фаза E2 после owner review;
классификация kinds APPROVED владельцем; единственные оставшиеся пункты — осознанные DEFERRED dependencies, не блокирующие).
Источник задачи: `B4X_AUDIT_FIX_TASKS v2.md:290–384` (§FB-03). Ветка: `agent/classifier-v2.3-capture-envelope`.

## 1. Что сделано

1. **Canonical registry** `specs/registries/hard_gates.yaml` (282 gates / 9 families, `total_is_not_final`),
   генерируемая Go-копия `src/validation/hard_gates_registry.gen.go` (24 applicable),
   генератор-валидатор `tools/gen_hard_gates_registry.py` (schema/orphans/duplicates/producer/consumer/test/evidence checks).
2. **Семантическая переработка (schema v1.1, kinds APPROVED владельцем 2026-08-01):** kinds разделены —
   `telemetry_counter` (**17**, никогда не блокируют; включая обязательные из требования пользователя:
   `classifier_reassembled_sni_total`, `nfqueue_gso_packets/bytes/decision/normalized/transition_total`,
   `passive_rst_observed/decision_total`, `b4_ppe_rule_reapply/self_test_total`, а также по owner-решению
   безопасная деградация `passive_rst_fail_open_total` и safety-guard `b4_hold_disabled_visibility_total`),
   `zero_tolerance_violation_counter` (**3**: `unrelated_control_action_total`,
   `classifier_layout_parity_fail_total`, `passive_rst_reconnect_regression_total`) и kind
   `current_generation_readiness_input` (**4**: `nfqueue_gso_truncated/csum_not_ready/token_miss_total`,
   `b4_capture_visibility_degrade_total` — инвалидируют current-generation readiness только вместе с owner state,
   напрямую не блокируют). `promotion_blocker: false` = 21, `true` = 3.
3. **Machine-readable producer/consumer/test/evidence chain** для всех 24 verified записей:
   `runtime_producer {symbol,file,line,mechanism,production_root}` (запрет assumed-файлов; producer_verified_commit `bd9db5d5`),
   `verdict_consumer {promotion_blocker|aggregation_blocker|readiness_observer|aggregation_observer|http_report}`,
   `test_producer`, `mutation_test {status: executed}`, `evidence_artifact`. `EXPECTED_PRODUCER_LOCATION` пуст (нет missing в scope).
4. **Аудит producers исправлен (важно):** прежний вывод «1/282 verified, 266 missing» был ложным —
   producers инкрементят через константы `observability.Metric*`, grep по литералам их не находил, а PowerShell `**`
   не раскрывал подкаталоги. Рекурсивный обход: **24/24 producers реализованы** (29 Inc-сайтов;
   полный список в `artifacts/audit/hard_gates_audit.md` §6.1), включая `nfqueue_gso_transition_total`
   (`src/http/handler/runtime_topology.go:38`), ранее считавшийся отсутствующим.
5. **10 новых executed fixtures** (3 файла): `src/nfq/hard_gate_producers_test.go` (6 тестов: GSO offload 4 метрики,
   fast-path 3, token miss, passive-RST 6, rollback 2, classifier parity 2), `src/capture/ppe/hard_gate_producers_test.go`
   (3: visibility degrade/hold, self-test, rule reapply), `src/http/handler/hard_gate_producers_test.go` (1: GSO transition).
6. **Мутационное покрытие kind-aware (owner review п.6):** 9 executed `removed_inc` mutation runs (удаление Inc →
   целевой fixture FAIL → восстановление; маркеров MUTATION-RUN = 0; production-файлы не изменены) +
   **10 executed `removed_delta` агрегационных guard-тестов** (window-delta/scope): только **zero-tolerance
   непосредственно блокируют promotion** (`removed_inc` + `removed_delta`), **readiness инвалидируют owner verdict**
   (`TestEvaluateReadinessOwnerStateEffect`: unsafe → BLOCKED, unknown → DEGRADED, revalidation новой generation → READY),
   **telemetry проверяются на producer/export/report consistency**
   (`TestProductionValidationIntegrationSnapshotPrometheusAPIFieldTest`: snapshot ↔ `/metrics` ↔ validation API ↔ report).
7. **Evaluator kind-aware + window-delta** (`src/validation/gates.go`): telemetry → `Telemetry` (не блокирует);
   readiness → `ReadinessInputs` (не блокирует напрямую); zero-tolerance: produced, delta окна == 0 → OK,
   delta != 0 → FAIL, missing producer → BLOCKED, **counter reset внутри окна (current < baseline) →
   BLOCKED_COUNTER_RESET** (новый baseline допускается только для нового process/run/generation; owner review п.3).
8. **Production window (owner review п.2):** `validation.BaselineForRun` — generation-keyed baseline store;
   Validation API, Field Test/report (`fieldtest.EvaluateHardGatesWindow`), canary и PromotePending
   (`checkHardGates`) используют **одну evaluation текущей TestSession/ValidationRun**
   (`handler.evaluateProductionGates`); process-lifetime wrapper для session promotion **не используется**.
   `hardGateScope` включает WARPBase + CSI + RSTGSO + PPE (classifier v2 pipeline).
9. **Readiness owner-state effect (owner review п.4):** `validation.EvaluateReadiness(inputs, owner)`;
   capture visibility подключён к production (PPE visibility gate: complete → safe, incomplete → unsafe);
   GSO mode / complete-representation / token-state consumers — **DEFERRED dependency (FB-27/PPE)**, wired как
   Unknown (non-zero input → DEGRADED, никогда молчаливый READY); proof в `TestEvaluateReadinessOwnerStateEffect`.
10. **Criterion 4 завершён:** новый Prometheus text-export `/metrics` (`handler/prometheus.go`), production-root
    integration test на одинаковые values/labels/kinds/produced state/window baseline/delta/generation
    (внутренний snapshot ↔ `/metrics` ↔ Validation API ↔ Field Test/release report).
11. **Meta-suite подключён и обновлён:** `src/validation/meta.go` (Reproducible = 282 gates / 24 applicable),
    `src/validation/gates_test.go` (ApplicableHardGates = 24), chain-тесты
    (`src/fieldtest/hard_gates_chain_test.go`, `src/runtimecontrol/rollout_hardgate_test.go`,
    `src/http/handler/validation_gates_test.go` — обновлён на window-семантику: первый вызов = baseline, delta → FAIL).
12. **Матрица evidence** `artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md` — 24/24 verified,
    методология (6 методов), честный статус, фиксация ложного negative прошлой версии.
13. **Коммиты (owner review п.7):**
    - producer_verified_commit = **`bd9db5d5`** (все 24 producers verified + fixtures + mutation runs);
    - classification_implementation_commit = **`7c99ec8b`** (фаза E: kinds 17/3/4 + window-delta evaluator);
    - closure_commit = **`df145b8a`** (фаза E2: reset semantics, production window, readiness owner-state,
      `/metrics` export, kind-aware mutation, criterion 2 labels).

## 2. Вердикты по критериям §FB-03 (v2:290–384)

| Критерий | Вердикт | Evidence |
|---|---|---|
| п.1 Registry schema/orphans/duplicates | **PASS** | `gen_hard_gates_registry.py --check`: 282 gates, 9 families, 0 duplicates; registry_test.go |
| п.2 Каждый gate имеет producer + consumer или not_applicable | **PASS_CURRENT_PRODUCTION_SCOPE (24/24)** + **DEFERRED_DEPENDENCY (258)** — 24/24 verified в текущем production scope (WARPBase/CSI/RSTGSO/PPE: 3 zero-tol + 17 telemetry + 4 readiness inputs, полные machine-readable цепочки); остальные 258 — вне production-графа, **без explicit not_applicable/normative basis global PASS не заявляется** (fail-closed BLOCKED при applicability; покрываются FB-02/FB-14 и др.) | реестр v1.1; ApplicableHardGates() = 24 |
| п.3 Mutation suite: каждый gate нарушается и блокирует promotion | **PASS (kind-aware)** — zero-tolerance: 9 executed removed_inc + 10 executed removed_delta (window-delta/scope, BLOCKED → apply rejected → rollback/cleanup); readiness: инвалидация owner verdict (BLOCKED/DEGRADED + восстановление revalidation новой generation); telemetry: producer/export/report consistency (integration test) | hard_gate_producers_test.go (3 файла), gates_test.go, hard_gates_chain_test.go, rollout_hardgate_test.go, production_validation_integration_test.go |
| п.4 `/metrics`, API и report консистентны | **PASS** — Prometheus `/metrics` text export (одинаковые names/labels/values с internal snapshot); production-root integration test: snapshot ↔ `/metrics` ↔ Validation API ↔ Field Test/report с идентичными window baseline/delta/generation | production_validation_integration_test.go, prometheus.go |
| п.5 Missing/skipped/stale evidence ≠ PASS | **PASS** — forced-zero → BLOCKED; missing evidence → EvidenceIntegrity=false; STALE поддерживается; **counter reset в окне → BLOCKED_COUNTER_RESET** (baseline=5,current=0 → BLOCKED) | meta_test.go, gates_test.go, TestBaselineForRunWindowSemantics |
| п.6 Evidence artifact FB03_GATE_PRODUCER_CONSUMER_MATRIX | **PASS** — обновлён (24/24, kinds 17/3/4, criterion 2 labels) | файл + executed команды |

## 3. Как проверить

```powershell
# 1. Registry validation (Python)
python tools/gen_hard_gates_registry.py --check
#   -> OK: 282 gates, 9 families, FT view 82 gates, IV view 78 gates, all mapped

# 2. Полный Go-прогон (Docker, воспроизводимо)
docker run --rm -v D:\b4x:/src -w /src/src -e GOMODCACHE=/gomod `
  -v C:\Users\AlexZander\go\pkg\mod:/gomod golang:1.25-alpine `
  sh -ceu "gofmt -w validation/hard_gates_registry.gen.go && go build ./... && go vet ./... && go test ./... -count=1"
#   -> все пакеты ok (зелёный)

# 3. Точечные проверки
go test ./validation/ -run 'TestEvaluateHardGates|TestEvaluateReadiness|TestBaselineForRun' -count=1
go test ./http/handler/ -run 'TestProductionValidationIntegration|TestValidationGates' -count=1
go test ./nfq/ -run 'TestHardGateProducer' -count=1
go test ./capture/ppe/ -run 'TestHardGateProducer' -count=1
go test ./http/handler/ -run 'TestHardGateProducer' -count=1
```

## 4. Открытые пункты (осознанные DEFERRED dependencies, не блокируют COMPLETE)

1. **GSO owner-state consumers** (`nfqueue_gso_truncated/csum_not_ready/token_miss_total`): GSO mode,
   complete-representation и token-state читаются из live capture state — реализуется в **FB-27/PPE**;
   в production wired как `Unknown` (non-zero input → readiness DEGRADED, никогда молчаливый READY).
2. **Опциональные follow-ups по требованиям владельца** (фаза E):
   - отдельный GateID «hold остался активным при incomplete visibility» — не создан (в нормативных документах отдельного требования нет; зафиксировано в binding consumer'а);
   - labelled-агрегация `b4_ppe_self_test_total{verdict}` / `b4_ppe_rule_reapply_total{result}` (readiness из current verdict/state) — вне scope evaluator'а;
   - derived-state gating для повторного active claim при `passive_rst_fail_open_total`/`passive_rst_rollback_total` — kind `derived_blocker` зарезервирован, не реализован.
3. WARP/SPF/FT §26/IV счётчики (258 записей) — **DEFERRED_DEPENDENCY**: пакеты не в production-графе;
   в реестре зафиксированы как zero-tolerance по умолчанию, fail-closed при applicability; global PASS не заявляется.

## 5. Файлы

- `specs/registries/hard_gates.yaml` — canonical registry (282 gates; 24 verified)
- `src/validation/hard_gates_registry.gen.go` — generated (24 applicable)
- `src/validation/gates.go`, `gates_window.go`, `gates_readiness.go`, `meta.go`, `gates_test.go`, `meta_test.go` — evaluator + window store + readiness + meta-suite
- `src/fieldtest/hard_gates.go` — EvaluateHardGatesWindow (report/canary path)
- `src/http/handler/production_gates.go` — единая production evaluation + owner states
- `src/http/handler/prometheus.go` — Prometheus text export (`/metrics`)
- `src/http/handler/production_validation_integration_test.go` — criterion 4 integration test
- `src/http/handler/validation_gates.go`, `runtime_control.go` — API / canary / PromotePending на единой evaluation
- `src/nfq/hard_gate_producers_test.go`, `src/capture/ppe/hard_gate_producers_test.go`,
  `src/http/handler/hard_gate_producers_test.go` — fixtures
- `src/fieldtest/hard_gates_chain_test.go`, `src/runtimecontrol/rollout_hardgate_test.go`,
  `src/http/handler/validation_gates_test.go` — chain-тесты
- `tools/gen_hard_gates_registry.py` — генератор/валидатор (RUNTIME_PRODUCERS_VERIFIED=24, REGISTER_VERIFIED_COMMIT=bd9db5d5)
- `artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md` — evidence матрица (24/24)
- `artifacts/audit/hard_gates_audit.md` (§6 актуализация), `artifacts/audit/B4X_FB03_OWNER_DECISION.md` (фаза D + фаза E2)
