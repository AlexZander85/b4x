# FB-03 Closure Summary — canonical hard-gate registry, producers/consumers, meta-suite

Дата: 2026-08-01. Статус: **READY_FOR_OWNER_REVIEW** (единственный открытый пункт не блокирует core:
Prometheus `/metrics` export consistency; классификация kinds **APPROVED владельцем**).
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
   `classifier_layout_parity_fail_total`, `passive_rst_reconnect_regression_total`) и новый kind
   `current_generation_readiness_input` (**4**: `nfqueue_gso_truncated/csum_not_ready/token_miss_total`,
   `b4_capture_visibility_degrade_total` — инвалидируют current-generation readiness только вместе с owner state,
   напрямую не блокируют). `promotion_blocker: false` = 21, `true` = 3.
3. **Machine-readable producer/consumer/test/evidence chain** для всех 24 verified записей:
   `runtime_producer {symbol,file,line,mechanism,production_root}` (запрет assumed-файлов; verified_commit `bd9db5d5`),
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
6. **Мутационное покрытие (owner requirements 4–5):** 9 executed `removed_inc` mutation runs (удаление Inc →
   целевой fixture FAIL → восстановление; маркеров MUTATION-RUN = 0; production-файлы не изменены) +
   **10 executed `removed_delta` агрегационных guard-тестов**: `EvaluateHardGatesWindow(…, current, baseline, …)`
   скорит zero-tolerance по delta окна (никогда не по lifetime absolute total; сброс счётчика в окне →
   delta = current, fail-closed), `TestEvaluateHardGatesWindowDelta`, `TestEvaluateHardGatesReadinessInputsNeverBlock`
   (4 readiness + 17 telemetry non-zero → PASS), `TestEvaluateHardGatesScopeIsolation` (violation вне scope не влияет).
7. **Evaluator kind-aware + window-delta** (`src/validation/gates.go`): telemetry → `Telemetry` (не блокирует);
   readiness → `ReadinessInputs` (не блокирует напрямую); zero-tolerance: produced, delta == 0 → OK,
   delta != 0 → FAIL, missing producer → BLOCKED; disabled capability → NOT_APPLICABLE.
8. **Meta-suite подключён и обновлён:** `src/validation/meta.go` (Reproducible = 282 gates / 24 applicable),
   `src/validation/gates_test.go` (ApplicableHardGates = 24), chain-тесты
   (`src/fieldtest/hard_gates_chain_test.go` — `TestMissingProducerBlocksPromotionEndToEnd`,
   `src/runtimecontrol/rollout_hardgate_test.go`, `src/http/handler/validation_gates_test.go`).
9. **Матрица evidence** `artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md` — 24/24 verified,
   методология (6 методов), честный статус, фиксация ложного negative прошлой версии.
10. **Коммиты:** `7c0be90f` (phase A), `1f083b5e` (enum kinds), `bd9db5d5` (all-24-producers-verified + fixtures + mutation runs),
    `7f6a3499`/`89a9d671` (verified_commit pin). Рабочая директория чистая.

## 2. Вердикты по критериям §FB-03 (v2:290–384)

| Критерий | Вердикт | Evidence |
|---|---|---|
| п.1 Registry schema/orphans/duplicates | **PASS** | `gen_hard_gates_registry.py --check`: 282 gates, 9 families, 0 duplicates; registry_test.go |
| п.2 Каждый gate имеет producer + consumer или not_applicable | **PASS** — 24/24 verified (полные machine-readable цепочки); 17 telemetry + 4 readiness inputs (никогда не блокируют); остальные 258 — zero-tolerance по умолчанию (fail-closed BLOCKED при applicability, вне scope этой задачи) | реестр v1.1; ApplicableHardGates() = 24 |
| п.3 Mutation suite: каждый gate нарушается и блокирует promotion | **PASS** — 9 executed removed_inc mutation runs + 10 removed_delta агрегационных guard-тестов (window-delta/scope, требование владельца 5) + chain-тесты (BLOCKED → apply rejected → rollback/cleanup) | hard_gate_producers_test.go (3 файла), meta_test.go, gates_test.go, hard_gates_chain_test.go, rollout_hardgate_test.go |
| п.4 `/metrics`, API и report консистентны | **PARTIAL** — validation API потребляет live snapshot (validation_gates_test.go); Prometheus export consistency против реестра — вне текущего хода | validation_gates_test.go |
| п.5 Missing/skipped/stale evidence ≠ PASS | **PASS** — forced-zero → BLOCKED; missing evidence → EvidenceIntegrity=false; STALE поддерживается | meta_test.go, gates_test.go |
| п.6 Evidence artifact FB03_GATE_PRODUCER_CONSUMER_MATRIX | **PASS** — обновлён (24/24) | файл + executed команды |

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

# 3. Точечные проверки producers (fixtures)
go test ./nfq/ -run 'TestHardGateProducer' -count=1
go test ./capture/ppe/ -run 'TestHardGateProducer' -count=1
go test ./http/handler/ -run 'TestHardGateProducer' -count=1
```

## 4. Открытые пункты (не блокируют core)

1. **Prometheus `/metrics` export consistency** (критерий п.4) — отдельный шаг, если владелец потребует полный PASS.
2. **Опциональные follow-ups по требованиям владельца** (kind-классификация APPROVED, фаза E):
   - отдельный GateID «hold остался активным при incomplete visibility» — не создан (в нормативных документах отдельного требования нет; зафиксировано в binding consumer'а);
   - labelled-агрегация `b4_ppe_self_test_total{verdict}` / `b4_ppe_rule_reapply_total{result}` (readiness из current verdict/state) — вне scope evaluator'а;
   - derived-state gating для повторного active claim при `passive_rst_fail_open_total`/`passive_rst_rollback_total` — kind `derived_blocker` зарезервирован, не реализован.
3. WARP/SPF/FT §26/IV счётчики (258 записей) — вне scope FB-03 (пакеты не в production-графе; покрываются FB-02/FB-14 и др.);
   в реестре они зафиксированы как zero-tolerance по умолчанию, fail-closed при applicability.

## 5. Файлы

- `specs/registries/hard_gates.yaml` — canonical registry (282 gates; 24 verified)
- `src/validation/hard_gates_registry.gen.go` — generated (24 applicable)
- `src/validation/gates.go`, `meta.go`, `gates_test.go`, `meta_test.go` — evaluator + meta-suite
- `src/nfq/hard_gate_producers_test.go`, `src/capture/ppe/hard_gate_producers_test.go`,
  `src/http/handler/hard_gate_producers_test.go` — новые fixtures
- `src/fieldtest/hard_gates_chain_test.go`, `src/runtimecontrol/rollout_hardgate_test.go`,
  `src/http/handler/validation_gates_test.go` — chain-тесты
- `tools/gen_hard_gates_registry.py` — генератор/валидатор (RUNTIME_PRODUCERS_VERIFIED=24, REGISTER_VERIFIED_COMMIT=bd9db5d5)
- `artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.md` — evidence матрица (24/24)
- `artifacts/audit/hard_gates_audit.md` (§6 актуализация), `artifacts/audit/B4X_FB03_OWNER_DECISION.md` (фаза D)
