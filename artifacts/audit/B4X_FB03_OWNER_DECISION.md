# B4X_FB03_OWNER_DECISION

Решение владельца по FB-03 (canonical hard-gate registry).
Дата: 2026-08-01. Статус: APPROVED. Требование-источник: `B4X_AUDIT_FIX_TASKS v2.md:1470` («сначала согласуй список имён»).

## Решение

1. **Единственный canonical source**: `specs/registries/hard_gates.yaml` (создаётся в рамках FB-03; папки `specs/` и `specs/registries/` ранее не существовали).
2. **FT §26 и IV §38A.9 НЕ являются владельцами canonical namespace**.
   - FT/IV-списки — generated validation views над canonical registry.
   - `RequiredHardGates` (`src/fieldtest/hard_gates.go`) — generated applicable subset, ручной список удаляется.
3. **Приоритет при конфликте имён**: subsystem-owner addendum → ARCH §143 → FT/IV views → runtime code (только generated references).
4. **Импорт без переименования** (CanonicalMetricName = имя из addendum):
   - WARP — 56 gates (WARP v1.2 §§72–73B), owner: WARP.
   - SPF — 22 gates (SPF §45), owner: SPF.
   - FT non-WARP — 26 gates, импорт после owner/source mapping (детектор/blocking/guided/discovery/mtproto → владельцы ABD/DDI/TGB).
   - MON — все gates §§84–93, owner: MON.
   - Остальные subsystem gates отдельными families: CSI, RST/GSO, PPE, ABD, DDI/TGB, SP (+ patch plan и новые IV/FT contracts при появлении).
5. **Total=104 НЕ фиксировать** (итоговое число не является окончательным; вычисляется автоматически, а не заявляется вручную).
6. `HardGatesPass` (`src/fieldtest/hard_gates.go`) и `MetaResult.Ready()` (`src/validation/meta.go`) подключаются к production по v2:341; `BLOCKED_TARGET_VALIDATION`, `WARPTraceReady` и аналогичные константы-verdicts заменяются активными gates.

## Согласованные семейства (источники)

| Family | Owner | Кол-во | Источник |
|---|---|---|---|
| WARP | WARP v1.2 §§72–73B | 56 | `B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md:3590–3683` |
| SPF | SPF §45 | 22 | `B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md:1467–1495` |
| MON | MON §§84–93 | 57 + 9 verdicts | `B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md:2064–2184` |
| FT non-WARP | ABD/DDI/TGB (после mapping) | 26 | `B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md:3154–3241` (детектор/blocking/guided/discovery/mtproto) |
| ABD | ABD v1.2 | ~110 `== 0` gates | `B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md:3531–3642` |
| DDI/TGB | DDI/TGB v1.0 | 13 discovery + 10 mtproto | `B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md:1588–1616` |
| SP | SP v1.6 | 14 profile_warp `== 0` | `B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md:3512–3525` |
| CSI | CSI | 1 (unrelated_control_action_total) | `B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md:1220` |
| RST/GSO | RST/GSO | 19 metrics (статус hard gate — проверяется) | `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md:834–854` |
| PPE | PPE | 4 metrics (статус hard gate — проверяется) | `B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md:795–801` |

## Открытые пункты (следующие шаги FB-03)

- Определить hard-gate статус RST/GSO (19) и PPE (4) metrics по тексту addenda.
- Полный owner/source mapping для 26 FT non-WARP gates.
- Схема registry (GateID, CanonicalMetricName, GlobalGateClass, OwnerStage, RuntimeProducer, VerdictConsumer, PromotionBlocker, ResetSemantics, Expiry/GenerationBinding, Applicability, TestProducer, MutationTest, EvidenceArtifact).
- Валидатор: schema, orphans, duplicates (v2:379–384).
- Negative fixture → violation branch → gate non-zero → verdict FAIL/BLOCKED → apply rejected → cleanup/rollback (по каждой family).

## Дополнение (2026-08-01, статус: APPROVED, фаза B)

Решение владельца по реализации evaluator (заменило черновое в v2):

1. **`RequiredHardGates` — application-aware selection, НЕ статический список.**
   Сигнатура: `RequiredHardGates(scope ReleaseScope, capabilities CapabilitySet, claim VerdictID, generation GenerationSet) ([]GateID, error)`.
   Пример: WARP base enabled + camouflage disabled + non-RU disabled → base gates + causal base/path/trace gates + Android gates для production claim, БЕЗ camouflage/non-RU gates.
   Старый `var RequiredHardGates = []string{...}` удалён как source of truth (DEAD_CODE/INCOMPLETE/NON_CANONICAL/NOT_PRODUCTION_REACHABLE).
2. **`HardGatesPass` — structured evaluator.** Возвращает `GateEvaluation{Verdict GateVerdict, Violations []GateViolation, Missing []GateID, Stale []GateID, NotRun []GateID}`; boolean-формат сохранён только как обёртка.
3. **Production consumers (реализовано)**: Field Test Controller (`Controller.RecordGateEvaluation`), Validation API/CLI (`ValidationEvent.HardGateVerdict`, `APIResponse.HardGates`), canary eligibility (`CanaryEligible`), promotion (`PromotionInput.GateEvaluation` → FAIL/BLOCKED), config/apply readiness (`runtimecontrol.Options.HardGateCheck` в `Apply`/`PromotePending`, StagePromote), runtime reconfiguration (тот же promote-путь), release report aggregation (`StageReport.GateVerdict`), Service Profile capability projection (`RequiredHardGates` требует capability `service_profiles` для family SP).
4. **Семантика verdicts**: disabled capability → NOT_APPLICABLE (не PASS); missing producer → BLOCKED (не PASS); stale generation → STALE (не PASS); alias НЕ создаёт второй counter (canonical metric — единственный ключ).
5. **Chain-тесты (реализовано)**: negative fixture → violation → producer фиксирует gate → evaluator FAIL/BLOCKED → promotion rejected (StagePromote) → cleanup/rollback; плюс meta: удаление gate из registry ловится `gen_hard_gates_registry.py --check` (mutation-проверка 2026-08-01), forced zero ловится тем же валидатором.
6. **Миграция 17 legacy-имён**: exact alias → canonical (8), renamed → canonical metric (6), retired/split (3: `route_counter_missing_total`, `forwarded_binding_missing_total`, `stale_generation_event_total`). Маппинг в `validation.LegacyGateAliases`.

## Статус исполнения (2026-08-01, фаза B завершена)

- Реестр: 282 gates / 9 families; `total_is_not_final: true`; runtime producers у 24 gates.
- `src/validation/gates.go` + `hard_gates_registry.gen.go` (generated) + unit/chain/meta-тесты.
- Docker `go build ./... && go vet ./... && go test ./...` — зелёный (все пакеты).
- Изменённые файлы: см. state packet / git status (ветка agent/classifier-v2.3-capture-envelope).

## Дополнение фаза C (2026-08-01, schema v1.1 — семантическая переработка)

Корректировка по итогам ревью: «обычная телеметрия смешана с zero-tolerance hard gates; producer entries не имеют machine-readable consumers/tests/evidence».

1. **Классификация kinds (ASSUMPTION, требует owner-подтверждения).**
   Норматив (`B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md:829–855`, `B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md:790–802`) перечисляет метрики БЕЗ классификации hard gate / telemetry. Применена fail-closed по умолчанию:
   - `telemetry_counter` (15): `classifier_reassembled_sni_total`, `nfqueue_gso_packets_total`, `nfqueue_gso_bytes_total`, `nfqueue_gso_decision_total`, `nfqueue_gso_normalized_total`, `nfqueue_gso_transition_total`, `nfqueue_gso_action_suppressed_total`, `passive_rst_observed_total`, `passive_rst_decision_total`, `passive_rst_suppressed_total`, `passive_rst_rollback_total`, `passive_rst_baseline_quality_total`, `passive_rst_budget_exhausted_total`, `b4_ppe_rule_reapply_total`, `b4_ppe_self_test_total` — НЕ блокируют promotion.
   - `zero_tolerance_violation_counter` (9 из 24): `unrelated_control_action_total`, `classifier_layout_parity_fail_total`, `nfqueue_gso_truncated_total`, `nfqueue_gso_csum_not_ready_total`, `nfqueue_gso_token_miss_total`, `passive_rst_fail_open_total`, `passive_rst_reconnect_regression_total`, `b4_capture_visibility_degrade_total`, `b4_hold_disabled_visibility_total` — блокируют при verified != 0 и при missing producer (BLOCKED_MISSING_PRODUCER).
   - Остальные 258 записей реестра — `zero_tolerance_violation_counter` по умолчанию (owner-документы объявляют их как hard gates `== 0`).
2. **Честные producer-поля (запрет assumed-файлов).** `runtime_producer` — machine-readable дескриптор `{symbol, file, line, mechanism, production_root}` и НЕ null только при `producer_status: verified`. Проверка producer НЕ ограничивается `Metrics.Inc`-grep: для каждой записи применяются direct metric / owner-state / typed wrapper / production callers / executed negative fixture / mutation run. `producer_status: missing` + `expected_producer_location: {file}` для нормативных целей (FB-27, PPE wiring).
3. **Machine-readable consumer chain.** `verdict_consumer` — список `{kind: promotion_blocker|aggregation_blocker|http_report, symbol, file, line, binding}`; `test_producer` — фикстуры; `mutation_test` — выполненные прогоны; `evidence_artifact` — пути. Для verified-записи (`unrelated_control_action_total`) цепочка заполнена полностью; для missing-записей — null (цепочка невозможна без producer).
4. **Evaluator kind-aware.** Telemetry → информационный список `Telemetry`, никогда не блокирует; zero-tolerance: produced zero → OK, produced non-zero → FAIL, missing producer → BLOCKED. Валидатор `--check` требует: verified ⇒ consumers/tests/evidence непустые; telemetry ⇒ не блокирует.
5. **Интеграционный тест** `TestMissingProducerBlocksPromotionEndToEnd` (fieldtest): RSTGSO scope + missing zero-tolerance producer → BLOCKED → promotion rejected → нет committed side effect → clean stop/cleanup.
6. **Mutation-прогон (executed):** удаление `report.UnrelatedControlActionTotal++` (validation.go:265) → `TestValidateRejectsYouTubeStateOnGmailSharedIPFlow` FAIL (`UnrelatedControlActionTotal:0` вместо 1) → восстановлено → suite зелёный. Зафиксировано в реестре как `mutation_test` у verified-записи.
7. **FB-03 статус: IN_PROGRESS (НЕ COMPLETE).** REGISTRY_SCHEMA: PARTIAL/PASS; PRODUCER_AUDIT: PASS_WITH_FINDINGS (1/282 verified, 15 telemetry, 266 missing); RUNTIME_PRODUCERS: FAIL/IN_PROGRESS (блокирован FB-27, PPE wiring); VERDICT_CONSUMERS: INCOMPLETE (цепочка только у verified); MUTATION_COVERAGE: INCOMPLETE. Промежуточный коммит «FB-03 phase A» допустим.

## Дополнение фаза D (2026-08-01, producers verified — аудит исправлен)

**Важная корректировка фазы C:** вывод «266 missing, FAIL/IN_PROGRESS» был **ложным**. Producers инкрементят счётчики через константы `observability.Metric*` (а не строковые литералы), и PowerShell `**` не раскрывал подкаталоги. Полный рекурсивный обход Inc-сайтов: **все 24 записи FB-03 scope реализованы** (9 zero-tolerance + 15 telemetry), включая `nfqueue_gso_transition_total` (http\handler\runtime_topology.go:38), ранее считавшийся отсутствующим.

1. **PRODUCER_AUDIT: PASS** — 24/24 verified (29 Inc-сайтов, список в hard_gates_audit.md §6.1); production callers подтверждены (handlePacket/observeOffloadMetadata, traceGSOFastPath, RecordHealth, ApplyRuntimeControlTopology, NewProductService).
2. **RUNTIME_PRODUCERS: PASS** — все 19 RST/GSO + 4 PPE + 1 CSI producers существуют и подключены; реализационной работы по этим метрикам не осталось.
3. **VERDICT_CONSUMERS: PASS** — machine-readable цепочки (runtime_producer + verdict_consumer {promotion_blocker|aggregation_blocker|aggregation_observer|http_report} + test_producer + mutation_test + evidence_artifact) для всех 24 verified записей; `EXPECTED_PRODUCER_LOCATION` пуст (нет missing в scope).
4. **MUTATION_COVERAGE: PASS** — 9 executed mutation runs (1 CSI + 8 RST/GSO/PPE): удаление Inc → целевой negative fixture FAIL → восстановление; маркеров нет, suite зелёный.
5. **10 новых executed fixtures** (src\nfq\, src\capture\ppe\, src\http\handler\hard_gate_producers_test.go); meta.go Reproducible = 282/24; ApplicableHardGates = 24.
6. **Классификация kinds остаётся ASSUMPTION** (15 telemetry / 9 zero-tolerance) — требуется подтверждение владельца (норматив перечисляет метрики без классификации; применён fail-closed дефолт).
7. **Открытым остаётся только критерий 4** («/metrics, API и report консистентны») — Prometheus export consistency против реестра (PARTIAL; validation API уже потребляет live snapshot).
8. **FB-03 статус: IN_PROGRESS (готов к закрытию)** — все пункты, кроме criteria 4 (PARTIAL) и owner-подтверждения kinds. Коммиты: `7c0be90f` (phase A), `1f083b5e` (enum kinds), `bd9db5d5` (all-24-producers-verified + fixtures + mutation runs), `7f6a3499`/`89a9d671` (verified_commit pin). Полный Docker build/vet/test зелёный; `gen_hard_gates_registry.py --check` OK (282 gates, 9 families).

## Дополнение фаза E (2026-08-01, kinds APPROVED владельцем)

Решение владельца: предложенная классификация 15/9 исправляется на **17 telemetry / 3 zero-tolerance / 4 current_generation_readiness_input** (новый kind; 17+3+4 = 24). Реализовано:

1. **Классификация зафиксирована в реестре и evaluator:**
   - `telemetry_counter` (17): все 15 прежних + `passive_rst_fail_open_total` (безопасная деградация) + `b4_hold_disabled_visibility_total` (срабатывание safety guard, не нарушение). Не блокируют promotion по non-zero; могут участвовать в derived/threshold/current-state verdicts.
   - `zero_tolerance_violation_counter` (3): `unrelated_control_action_total`, `classifier_layout_parity_fail_total`, `passive_rst_reconnect_regression_total`.
   - `current_generation_readiness_input` (4, новый kind): `nfqueue_gso_truncated_total`, `nfqueue_gso_csum_not_ready_total`, `nfqueue_gso_token_miss_total`, `b4_capture_visibility_degrade_total`. Инвалидируют/ограничивают current-generation readiness только вместе с owner state и applicability (GSO observe/classify/action mode, complete representation, normalizer/token state, current capture visibility, revalidation result); напрямую не блокируют.
2. **Evaluation по delta окна** (не lifetime absolute total): `EvaluateHardGatesWindow(scope, caps, claim, generation, current, baseline, produced)` — zero-tolerance скорятся по `current - baseline`; при сбросе счётчика в окне (current < baseline) delta = current (сброс не скрывает нарушения — fail-closed). `EvaluateHardGates` — обёртка с окном = lifetime процесса (in-process counters; lifetime total == delta от старта процесса). `WindowBaseline` в GateEvaluation.
3. **Schema support**: kind `current_generation_readiness_input` добавлен в валидатор (`--check`: readiness/telemetry ⇒ promotion_blocker == false), YAML и `hard_gates_registry.gen.go` (GateKindReadinessInput). Consumer chain: readiness — `readiness_observer` + `http_report`; fail_open/hold_disabled — `aggregation_observer` + `http_report`. `promotion_blocker: false` = 21, `true` = 3 (261 zero-tol всего, из них verified 3).
4. **Mutation tests на агрегацию (требование 5)**: `TestEvaluateHardGatesWindowDelta` (clean window PASS при lifetime>0; delta=2 → FAIL; reset → delta=current; guard: удаление baseline-вычитания ломает PASS), `TestEvaluateHardGatesReadinessInputsNeverBlock` (4 readiness + 17 telemetry non-zero → PASS; guard: превращение readiness в блокер ломает тест), `TestEvaluateHardGatesScopeIsolation` (violation вне scope не влияет). Записаны в реестр как `mutation_test: [{kind: removed_delta, status: executed}]` у всех 7 переклассифицированных + 3 оставшихся zero-tol записей.
5. **Открытые пункты владельца:**
   - `b4_hold_disabled_visibility_total` = safety guard trigger; нарушение «hold остался активным при incomplete visibility» при необходимости получает отдельный GateID/counter (не создан — в нормативных документах отдельного требования нет; зафиксировано в binding consumer'а).
   - `b4_ppe_self_test_total{verdict}` и `b4_ppe_rule_reapply_total{result}` — labelled telemetry; readiness из current verdict/state, не из total (labelled-агрегация — вне scope evaluator'а, который работает с суммой серий).
   - `passive_rst_fail_open_total`/`passive_rst_rollback_total` могут блокировать повторный active claim через derived state — механизм derived verdict'ов зарезервирован (GateKindDerived), не реализован.
   - Criteria 4 (`/metrics` Prometheus export consistency) — PARTIAL.
6. **FB-03 статус: IN_PROGRESS → READY_FOR_OWNER_REVIEW.** REGISTRY_SCHEMA: PASS (v1.1 + readiness kind); PRODUCER_AUDIT: PASS (24/24); RUNTIME_PRODUCERS: PASS; VERDICT_CONSUMERS: PASS (kind-aware chains); MUTATION_COVERAGE: PASS (9 removed_inc + 10 removed_delta executed).

## Дополнение фаза E2 (2026-08-01, closure — все 6 критериев PASS)

Owner review 2026-08-01 (п.1–7) и фаза E2: критерии §FB-03 закрыты полностью. Реализовано:

1. **П.1 «Production window» (НЕ process-lifetime wrapper):** единая evaluation текущей TestSession/ValidationRun
   — `handler.evaluateProductionGates` (production_gates.go) используется Validation API, Field Test/report
   (`fieldtest.EvaluateHardGatesWindow`), canary и PromotePending (`checkHardGates`); process-lifetime wrapper
   для session promotion **не используется**.
2. **П.2 «Production scope»:** `hardGateScope` расширен до WARPBase + CSI + RSTGSO + PPE (classifier v2 pipeline);
   критерий 2 статусы: **PASS_CURRENT_PRODUCTION_SCOPE (24/24)** + **DEFERRED_DEPENDENCY (258)** — глобальный PASS
   не заявляется (258 вне production-графа, без explicit not_applicable/normative basis; fail-closed BLOCKED).
3. **П.3 «Counter reset»:** `BaselineForRun` (generation-keyed baseline store) + **BLOCKED_COUNTER_RESET**
   (current < baseline в окне → BLOCKED; baseline для нового process/run/generation только явный reset).
4. **П.4 «Readiness owner-state»:** `validation.EvaluateReadiness(inputs, owner)`; capture visibility подключён
   к production (PPE visibility gate: complete → safe, incomplete → unsafe); GSO mode/complete-representation/
   token-state consumers — **DEFERRED dependency (FB-27/PPE)**, wired как Unknown (non-zero input → DEGRADED,
   никогда молчаливый READY); proof: `TestEvaluateReadinessOwnerStateEffect` (unsafe → BLOCKED, unknown → DEGRADED,
   revalidation новой generation → READY).
5. **П.6 «Мутации kind-aware»:** zero-tolerance — removed_inc (9) + removed_delta (10, window-delta/scope);
   readiness — owner-verdict инвалидация (см. п.4); telemetry — producer/export/report consistency.
6. **П.5 «Критерий 4»:** Prometheus text-export `/metrics` (`handler/prometheus.go`) + production-root integration
   test `TestProductionValidationIntegrationSnapshotPrometheusAPIFieldTest` (snapshot ↔ `/metrics` ↔ Validation API
   ↔ Field Test/report: одинаковые names/labels/values/kinds/produced state/window baseline/delta/generation) —
   критерий 4 **PARTIAL → PASS**.
7. **П.7 Коммиты:** producer_verified_commit = `bd9db5d5`; classification_implementation_commit = `7c99ec8b`;
   closure_commit = `<SHA closure>` (фаза E2). Полный Docker build/vet/test зелёный.

**FB-03 статус: READY_FOR_OWNER_REVIEW → COMPLETE.** Все 6 критериев §FB-03 — **PASS** (п.2: PASS_CURRENT_PRODUCTION_SCOPE
+ DEFERRED_DEPENDENCY). Оставшиеся пункты — осознанные DEFERRED dependencies: GSO owner-state consumers (FB-27/PPE),
labelled-агрегация self_test/reapply, derived-state gating fail_open/rollback, hold-нарушение как отдельный GateID.
