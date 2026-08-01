# FB-03 Closure Summary — canonical hard-gate registry, producers/consumers, meta-suite

Дата: 2026-08-01. Статус: **READY_FOR_OWNER_REVIEW** (единственные открытые пункты не блокируют core:
owner-подтверждение классификации kinds и Prometheus `/metrics` export consistency).
Источник задачи: `B4X_AUDIT_FIX_TASKS v2.md:290–384` (§FB-03). Ветка: `agent/classifier-v2.3-capture-envelope`.

## 1. Что сделано

1. **Canonical registry** `specs/registries/hard_gates.yaml` (282 gates / 9 families, `total_is_not_final`),
   генерируемая Go-копия `src/validation/hard_gates_registry.gen.go` (24 applicable),
   генератор-валидатор `tools/gen_hard_gates_registry.py` (schema/orphans/duplicates/producer/consumer/test/evidence checks).
2. **Семантическая переработка (schema v1.1):** kinds разделены — `telemetry_counter` (15, никогда не блокируют,
   включая обязательные из требования пользователя: `classifier_reassembled_sni_total`,
   `nfqueue_gso_packets/bytes/decision/normalized/transition_total`, `passive_rst_observed/decision_total`,
   `b4_ppe_rule_reapply/self_test_total`) и `zero_tolerance_violation_counter` (9 из 24);
   `promotion_blocker: false` = 15 в YAML. Классификация — ASSUMPTION (fail-closed дефолт), ждёт подтверждения владельца.
3. **Machine-readable producer/consumer/test/evidence chain** для всех 24 verified записей:
   `runtime_producer {symbol,file,line,mechanism,production_root}` (запрет assumed-файлов; verified_commit `bd9db5d5`),
   `verdict_consumer {promotion_blocker|aggregation_blocker|aggregation_observer|http_report}`,
   `test_producer`, `mutation_test {status: executed}`, `evidence_artifact`. `EXPECTED_PRODUCER_LOCATION` пуст (нет missing в scope).
4. **Аудит producers исправлен (важно):** прежний вывод «1/282 verified, 266 missing» был ложным —
   producers инкрементят через константы `observability.Metric*`, grep по литералам их не находил, а PowerShell `**`
   не раскрывал подкаталоги. Рекурсивный обход: **24/24 producers реализованы** (29 Inc-сайтов;
   полный список в `artifacts/audit/hard_gates_audit.md` §6.1), включая `nfqueue_gso_transition_total`
   (`src/http/handler/runtime_topology.go:38`), ранее считавшийся отсутствующим.
5. **10 новых executed fixtures** (3 файла): `src/nfq/hard_gate_producers_test.go` (6 тестов: GSO offload 4 метрики,
   fast-path 3, token miss, passive-RST 6, rollback 2, classifier parity 2), `src/capture/ppe/hard_gate_producers_test.go`
   (3: visibility degrade/hold, self-test, rule reapply), `src/http/handler/hard_gate_producers_test.go` (1: GSO transition).
6. **9 executed mutation runs** (по одному на каждый zero-tolerance gate): удаление Inc → целевой negative fixture FAIL →
   восстановление; маркеров MUTATION-RUN = 0; production-файлы не изменены
   (validation.go:265, offload.go:109, offload.go:112, gso_normalizer.go:61, classifier_decision.go:214,
   passive_rst_observe.go:116, passive_rst_rollback.go:136, product_service.go:110, product_service.go:111).
7. **Evaluator kind-aware** (`src/validation/gates.go`): telemetry → информационный список (не блокирует);
   zero-tolerance: produced zero → OK, produced non-zero → FAIL, missing producer → BLOCKED; disabled capability → NOT_APPLICABLE.
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
| п.2 Каждый gate имеет producer + consumer или not_applicable | **PASS** — 24/24 verified (полные machine-readable цепочки); 15 telemetry (никогда не блокируют); остальные 258 — zero-tolerance по умолчанию (fail-closed BLOCKED при applicability, вне scope этой задачи) | реестр v1.1; ApplicableHardGates() = 24 |
| п.3 Mutation suite: каждый gate нарушается и блокирует promotion | **PASS** — 9 executed mutation runs + evaluator mutation checks + chain-тесты (BLOCKED → apply rejected → rollback/cleanup) | hard_gate_producers_test.go (3 файла), meta_test.go, gates_test.go, hard_gates_chain_test.go, rollout_hardgate_test.go |
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

1. **Owner-подтверждение классификации kinds** (15 telemetry / 9 zero-tolerance) — ASSUMPTION, fail-closed дефолт
   (`artifacts/audit/B4X_FB03_OWNER_DECISION.md` фаза C п.1, фаза D п.6). Для закрытия достаточно подтверждения списков из пункта 2.
2. **Prometheus `/metrics` export consistency** (критерий п.4) — отдельный шаг, если владелец потребует полный PASS.
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
