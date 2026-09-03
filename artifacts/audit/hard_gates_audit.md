# Hard Gates Audit — реализация защитных проверок в коде

Дата: 2026-07-31. Read-only аудит. Источники: нормативные документы в корне D:\b4x + код src\.
Метод: req_index_part1..3.md → точные блоки hard gates в документах (grep строк) → поиск идентификаторов и вызовов в src\ (*.go, без учёта *_test.go для production-графа).

## 1. Hard gates по документам (точные списки из текстов документов)

| Документ | Раздел | Счётчиков | Ключевые идентификаторы (примеры) |
|---|---|---|---|
| WARP v1.2 | §72 Base | 10 | warp_secret_leak_total, warp_foreign_interface_modified_total, warp_recursive_control_route_total, warp_mark_collision_total, warp_route_without_liveness_total, warp_destination_set_partial_apply_total, warp_unbounded_restart_total, warp_unbounded_registration_total, warp_unrelated_control_action_total, warp_rollback_failure_total |
| WARP v1.2 | §73 Non-RU | 8 | nonru_route_active_without_fresh_attestation, nonru_route_active_while_any_provider_ru, nonru_route_active_with_provider_disagreement, nonru_route_active_with_direct_dns, nonru_route_active_with_unvalidated_ipv6, nonru_route_active_after_attestation_expiry, nonru_strict_direct_fallback_total, nonru_identity_creation_budget_exceeded |
| WARP v1.2 | §73A Camouflage | 12 | masque_camouflage_without_control_authorization_total, masque_camouflage_destination_only_authorization_total, masque_established_payload_mutation_total, masque_camouflage_cutoff_failure_total, masque_control_route_recursion_total, masque_camouflage_cross_instance_total, masque_strategy_promoted_without_forwarded_probe_total, masque_strategy_promoted_without_stability_window_total, masque_insecure_tls_total, masque_endpoint_pin_failure_accepted_total, masque_unbounded_candidate_retry_total, masque_rst_suppression_without_exact_authorization_total |
| WARP v1.2 | §73B Causal trace | 26 | warp_route_promoted_without_path_proof_event_total, warp_forwarded_success_without_binding_trace_total, warp_direct_fallback_without_trace_total, warp_nested_missing_parent_link_total, warp_nested_parent_generation_mismatch_total, warp_nested_control_direct_leak_total, warp_nested_route_active_without_parent_health_total, warp_nested_stale_parent_token_total, warp_geo_attestation_without_route_counter_delta_total, warp_geo_quorum_without_provider_events_total, warp_geo_route_gate_state_mismatch_total, warp_nonru_revocation_exceeded_deadline_total, warp_nonru_public_ip_change_without_refresh_total, warp_dns_path_unproven_total, warp_ipv6_path_unproven_total, warp_connect_ip_event_wrong_generation_total, warp_post_cutoff_mutation_total, warp_cleanup_incomplete_total, warp_owned_resource_leak_total, warp_foreign_resource_removed_total, warp_trace_secret_leak_total, warp_trace_required_event_missing_total, warp_trace_dropped_required_event_total, warp_trace_event_order_violation_total, warp_trace_generation_mismatch_total, warp_trace_state_mismatch_total |
| WARP v1.2 | §73B/§74 verdict | — | WARP_CAUSAL_TRACE_READY (все счётчики = 0 + trace schema compat + mutant-тесты + реальный router counter proof + Android correlation + nested/geo causal chain + cleanup ownership proof) |
| SPF v1.0 | §45 Mandatory hard gates | 22 | silent_failure_action_without_authorization_total, silent_failure_action_with_incomplete_visibility_total, silent_failure_destination_only_state_total, silent_failure_cross_client_action_total, silent_failure_cross_service_action_total, silent_failure_cross_component_action_total, silent_failure_cross_generation_action_total, **silent_failure_single_signal_auto_fallback_total**, silent_failure_non_independent_evidence_auto_fallback_total, silent_failure_suppressor_ignored_total, silent_failure_fast_parallel_false_positive_total, silent_failure_recent_success_false_positive_total, silent_failure_explicit_server_error_misclassified_total, silent_failure_gso_mss_progress_mismatch_total, silent_failure_ppe_visibility_violation_total, silent_failure_unbounded_probe_total, silent_failure_unbounded_rotation_total, silent_failure_recursive_transport_fallback_total, silent_failure_recovery_without_rollback_target_total, silent_failure_control_regression_promoted_total, silent_failure_false_positive_budget_ignored_total, silent_failure_user_revert_not_rolled_back_total |
| SPF v1.0 | §30 инвариант | — | single_signal_auto_fallback == forbidden |
| PPE addendum | §7.4 Verdicts | — | INCONCLUSIVE нельзя преобразовывать в PASS |
| PPE addendum | §7.1/§7.2 Level 2 | — | Controlled A/B — нормативный production gate (выделенный flow, разделение фрагментов ClientHello, изоляция device/ipset/port/ns) |
| PPE addendum | §8 Runtime safety gate | — | Safety gate wiring в hold/reassembly/ActionToken/Discovery/canary (PPE-46) |
| CSI addendum | ADR-CSI-1 | — | CaptureCandidate ≠ ActionAuthorization |
| CSI addendum | CSI-18 | 1 | unrelated_control_action_total == 0 (same-client negative controls Gmail/Google) |
| FT v1.5 | §26 Field hard gates | 82 | detector_* (10), blocking_profile_* (2), guided_search_* (4), discovery_* (2), mtproto_bridge_* (8), + все 56 WARP v1.2; missing/unread gate ≠ zero |
| IV v1.5 | §38.1 Registry meta-suite | — | blocking_requirements_without_tests == 0, duplicate ids == 0 и др. |
| IV v1.5 | §38A.9 WARP v1.2 gates | 56 | полный список WARP v1.2 (10+8+12+26); not-run/skipped ≠ zero |
| IV v1.5 | §23.2 verdicts | — | BLOCKED_TARGET_VALIDATION blocks release; BLOCKED... никогда не PASS |

Примечание к числам: в req_index_part1 §73B указано «28 gate», фактически в тексте WARP v1.2 — 26 счётчиков; в req_index_part3 и заголовке IV §38A.9 указано «52», фактически список содержит 56 (10+8+12+26); в req_index_part2 и задании — «21» SPF-гейт, фактически в §45 — 22 счётчика.

## 2. Реализация в коде (src\)

### 2.1 WARP (src\warp\) — 0 импортеров, только data-model

| Hard gate (документ) | Реализация в коде | Файл:строка | Вызов из production | Тест |
|---|---|---|---|---|
| §72 Base: 10 счётчиков | НЕТ (счётчиков нет нигде в src) | — | нет | нет |
| §73 Non-RU: 8 счётчиков | НЕТ | — | нет | нет |
| §73A Camouflage: 12 счётчиков | НЕТ | — | нет | нет |
| §73B Causal trace: 26 счётчиков (вкл. warp_trace_secret_leak_total, dropped-счётчик P0) | НЕТ | — | нет | нет |
| WARP_CAUSAL_TRACE_READY verdict | Константа + структуры: CausalTraceRelease.Verdict() (AC+AD+AE Ready + WARPHardGatesZero + KeeneticCounters + AndroidForwarded + SafetyHash); WARPGate.Verdict()/SeparateVerdicts() | src\fieldtest\cleanup.go:36–42; src\fieldtest\warp_gate.go:12–24 | нет (fieldtest: 0 импортеров) | нет |
| Geo attestation gate (TTL, quorum ≥2, revocation) | GeoAttestation/Valid(), BuildGeoAttestation (quorum=2, revoked при RU/disagreement, TTL 5 min) | src\warp\geo.go:32–63 | нет (warp: 0 импортеров) | да, src\warp\geo_test.go |
| Cutoff machine (CONNECT-IP gen, HardFallback) | CutoffMachine.Apply/HardFallback | src\warp\cutoff.go:24–37 | нет | да, cutoff_test.go |
| Authorization scoped/revocable | TransportAuthorization/RouteGeneration, RevokeOnNegativeEvidence | src\warp\authorization.go:15–36 | нет | да |
| Trace envelope (P0/P1/P2, seal, monotonic sequence) | TransportTraceEnvelope, TracePipeline.Publish (P0 не сэмплируется: capacity-evict только P1+) | src\warp\trace.go:11–68 | нет | да, trace_test.go |
| Enrollment/секреты, camouflage auth, cover SNI pin, nested, isolation, RST observe | Secrets, EnrollmentPolicy, TransportControlAuthorization, CoverSNIConfig.Insecure(), NestedBackend, IsolationReport, RSTDefense | src\warp\secrets.go, enrollment.go, camouflage_auth.go, cover_sni.go, nested.go, isolation.go, rst.go | нет (весь пакет 0 импортеров; в main.go/http\handler warp не упоминается) | да, по одному _test.go на модель |

### 2.2 SPF (src\silentpath\) — 0 импортеров

| Hard gate | Реализация в коде | Файл:строка | Вызов из production | Тест |
|---|---|---|---|---|
| 22 счётчика §45 (вкл. silent_failure_single_signal_auto_fallback_total) | НЕТ (grep 'hard|gate|single_signal|auto_fallback|forbidden' по пакету — 0 совпадений) | — | нет | нет |
| Release verdicts | silent-observe-ready / silent-recommend-ready / silent-auto-canary-ready / implemented-not-target-validated | src\silentpath\release.go:6–12 | нет | да, release_test.go |
| Leases (scope, rollback target, ConfigGen) | LeaseStore.Put (rollback required, From≠To) | src\silentpath\leases.go:23–31 | нет | да |
| Unique progress / suppressors / visibility | ProgressStore, VisibilityGate, Suppressors | src\silentpath\progress.go, visibility.go, suppressors.go | нет | да |

### 2.3 FT (src\fieldtest\) — 0 импортеров

| Hard gate | Реализация в коде | Файл:строка | Вызов из production | Тест |
|---|---|---|---|---|
| §26: 82 счётчика == 0; missing/unread ≠ zero | RequiredHardGates — только 17 имён (из них точных совпадений с §26 — 7; остальные переименованы/свои); HardGatesPass(counters, produced): !produced → false | src\fieldtest\hard_gates.go:3–12 | нет | нет |
| WARP-aware promotion gate FT-Q | WARPGate.Verdict() → PromotionBlocked/PromotionPass; PromotionBlocked = "BLOCKED_TARGET_VALIDATION" | src\fieldtest\warp_gate.go:12–16; promotion.go:7 | нет | нет |
| Same-client control (FT §17.1) | ControlScenario/ControlRun.Valid() | src\fieldtest\controls.go:11–35 | нет | нет |
| Field Test Controller (fails claim) | Controller.Start/Stop/Get | src\fieldtest\controller.go:21–64 | нет | да, session_test.go (внутрипакетный) |

### 2.4 PPE (src\capture\ppe\) — ПОДКЛЮЧЁН (http\server.go, http\handler\capture_offload*.go, action\token_lifecycle.go, nfq\, discovery\, runtimecontrol\)

| Hard gate | Реализация | Файл:строка | Вызов из production | Тест |
|---|---|---|---|---|
| Self-test (PPE-06/PPE-24, functional, не по наличию правила) | SelftestController: validate→deps→capability→endpoint_health→phase_a (isolation+probe+cleanup)→phase_b→generation_verify; результат кэшируется (SelfTestResult) | src\capture\ppe\selftest_controller_core.go:40–97; product_service.go:327–356 | да (HTTP RunSelfTest; apply требует: DefaultVisibilityGate().EnsureRequired, product_service.go:301) | да (selftest_*_test.go, product_bundle_test.go) |
| INCONCLUSIVE ≠ PASS (PPE-31) | functionalVerdictFor: INCONCLUSIVE/PASSWithLimitations → FunctionalInconclusive; record(..., result.Verdict == VerdictPASS, ...) | src\capture\ppe\product_service.go:480–493, 354 | да | да (visibility_gate_test.go:36) |
| Safety gate wiring (PPE-46) | ppe.DefaultVisibilityGate().Decision(...).Allowed — блокирует hold/replay/reassembly/ACK-replay/Discovery; visibilityCancel subscription | src\action\token_lifecycle.go:13; src\nfq\tcp_hold_store.go:16; tcp_hold_worker.go:74; tcp_hold_config.go:104; tcp_reassembly_metadata.go:26; tcp_reassembly_observe.go:23; discovery\runtime.go:152; runtimecontrol\visibility_runtime.go:20,70; nfq\passive_rst_observe.go:21 | да | да (nfq\tcp_hold_visibility_test.go, tcp_reassembly_visibility_test.go, discovery\visibility_gate_test.go, runtimecontrol\visibility_runtime_test.go, action\token_visibility_test.go) |
| UI/API не показывает PASS без self-test (PPE-10) | ProductStatus.LastSelfTest + verdict mapping; apply невозможен без self-test requirement | product_service.go:32, 301 | да | да |

### 2.5 CSI (src\crossservice\) — ПОДКЛЮЧЁН (http\handler\classifier_isolation*.go, runtime_control.go)

| Hard gate | Реализация | Файл:строка | Вызов из production | Тест |
|---|---|---|---|---|
| same-client control: unrelated_control_action_total == 0 (CSI-18) | Validate(): UnrelatedControlActionTotal++, HardGateViolation{Code:"unrelated_control_action"}; Passed = no failures && ==0; метрика observability.MetricUnrelatedControlAction | src\crossservice\validation.go:265–272, 299–312, 392; observability\observability.go:58 | да (classifier_isolation_validation.go:23 ValidateAndStore; эндпоинт handleClassifierIsolation, classifier_isolation.go:52–58; статус в runtime_control.go) | да (crossservice\validation_test.go; classifier_isolation_test.go) |
| CaptureCandidate ≠ ActionAuthorization (ADR-CSI-1) | реализуется через разделение candidate/authorization в crossservice-моделях и nfq; явного счётчика нет (в §72 WARP он называется warp_unrelated_control_action_total — отсутствует) | nfq\classifier_decision.go и др. | да | да |

### 2.6 Observability / HTTP / metrics

- Счётчиков для WARP/SPF/FT gates в observability НЕТ: весь реестр метрик — capture/classifier/crossservice/PPE/NFQ-GSO/PassiveRST/route/hold/fallback (src\observability\observability.go:40–77, ppe.go:3–13). Имен warp_*, masque_*, nonru_*, silent_failure_*, detector_* в production-реестре нет.
- HTTP-эндпоинтов статуса WARP/silent/fieldtest НЕТ (grep 'warp|silent|recovery|fieldtest' по http\handler — 0 совпадений). Есть PPE (capture_offload_product.go) и CSI (classifier_isolation.go).
- Триггер счётчика hold-видимости: observability.go:47 (b4_hold_disabled_visibility_total), fallback: routing\fallback.go:357 — единственные близкие к silent-path метрики, но к SPF §45 не привязаны.

### 2.7 Validation (src\validation\) — IV meta-suite — 0 импортеров

| Hard gate | Реализация | Файл:строка | Вызов из production | Тест |
|---|---|---|---|---|
| §38.1 meta-suite (blocking_requirements_without_tests==0 и т.п.) | MetaResult.Ready(): RegistryComplete, APIParity, VerdictMutationDetected, EvidenceIntegrity, Reproducible, InfrastructureSafe, FalseNegativeDetected + ArtifactValid | src\validation\meta.go:15–30 | нет (пакет validation: 0 импортеров) | нет |
| IV-17 WARP causal tracing | WARPTraceValidation.Ready()/Verdict(): Requirements==23 (WARP-1..10, C1..C10, FT-AC..AE), Envelope.Ready, MutantsDetected≥1, KeeneticCounters, AndroidEvidence… | src\validation\warp_trace.go:14–33 | нет | нет |
| BLOCKED_TARGET_VALIDATION | Константы: validation\verdict.go:9, fieldtest\promotion.go:7 | — | нет | нет |
| Registry (IV-1) | registry.go (не прочитан детально — вне скоупа) | src\validation\registry.go | нет | registry_test.go |

## 3. Вывод

- Счётчиков-гейтов по документам: WARP 56 + SPF 22 + FT §26 82 = **160** (плюс IV §38A.9 дублирует те же 56 WARP; meta-suite IV — отдельный набор инвариантов).
- Реально исполняемых в бинаре: **1 из 160** — `unrelated_control_action_total` (CSI; src\crossservice\validation.go:265, 392; эндпоинт + метрика + тесты). Дополнительно активен **1 механизм-гейт без счётчика** — PPE visibility safety gate (блокирует hold/reassembly/ActionToken/Discovery, включая правило INCONCLUSIVE≠PASS). Все остальные 159 счётчиков и оба вердиктных механизма (WARP_CAUSAL_TRACE_READY, BLOCKED_TARGET_VALIDATION) в бинаре отсутствуют: пакеты warp, silentpath, fieldtest, validation имеют 0 импортеров (в main.go и http\server.go их нет), счётчики не объявлены даже как метрики.
- Кодовая реализация fieldtest\hard_gates.go (17 имён + HardGatesPass, семантика «missing/unread ≠ zero») и validation\meta.go (meta-suite) существует, но не вызывается и не покрыта тестами.

## 4. Несоответствия кода документам

1. **0 счётчиков WARP/SPF в коде** при полной спецификации имён в документах (§72/73/73A/73B, §45 SPF, §38A.9 IV).
2. **Имена в RequiredHardGates не совпадают с документом**: из 82 счётчиков FT §26 в коде 17 имён, точных совпадений — 7; код использует собственные имена (route_counter_missing_total, forwarded_binding_missing_total, stale_generation_event_total, parent_generation_mismatch_total, dns_direct_leak_total, ipv6_unvalidated_egress_total, cleanup_foreign_resource_removed_total, trace_required_event_drop_total, unrelated_control_action_total без префикса warp_*), т.е. даже при подключении проверка по документам не прошла бы.
3. **Расхождения WARP_CAUSAL_TRACE_READY между документами**:
   - WARP v1.2 §73B (3678–3686): все счётчики = 0 + trace schema compat + mutant-тесты + реальный router counter proof + Android forwarded-flow correlation + nested/geo causal chain + cleanup ownership proof (после crash/restart/rollback).
   - FT v1.5 (3146–3152): FT-AC+FT-AD+FT-AE PASS + WARP v1.2 hard gates zero + Keenetic path-counter + Android correlation (mutant/cleanup не упомянуты — поглощаются суитами FT-A*).
   - IV v1.5 §38A.9 (2481–2493): FT-AC+AD+AE PASS + trace schema compatibility + **trace-derived/runtime state parity** (нет в WARP v1.2) + router counter proof + Android correlation + nested/geo proof + **cleanup ownership closure**.
   - IV v1.5 §52 (3871–3918): + DNS/IPv6 evidence, verdict'ы не транзитивны.
   - ARCH v2.4 §136: добавляет отдельный verdict WARP_BASE_READY (отсутствует в остальных).
   - Итог: IV v1.5 строже WARP v1.2 (добавляет state parity и cleanup closure как отдельные требования); FT v1.5 — лояльнее (без явных mutant/parity). Код fieldtest\cleanup.go:38–42 ближе к FT v1.5 + SafetyHash, но не включает state parity и не вызывается.
4. **Числа в индексах**: req_index_part1 — «28» §73B (факт 26); req_index_part3 и IV §38A.9 — «52» (факт 56); SPF — «21» (факт 22).
5. **PPE-10/PPE-31/PPE-46 и CSI-18** — соответствуют документам (реализованы, подключены, покрыты тестами). Единственные hard gates, прошедшие полный цикл.

## 5. Статус-сводка по пакетам

| Пакет | В production-графе | Счётчики hard gates | Verdict-механизмы | Тесты |
|---|---|---|---|---|
| src\warp | нет (0 импортеров) | 0 из 56 | нет (модели Valid() есть) | да (юнит, внутри пакета) |
| src\silentpath | нет | 0 из 22 | release.go (не вызывается) | да (юнит) |
| src\fieldtest | нет | 17 имён в списке, 0 вызовов, 0 тестов | WARP_gate/CausalTraceRelease (не вызываются) | частично (session_test.go) |
| src\validation | нет | meta-suite Ready() (не вызывается) | BLOCKED_TARGET_VALIDATION const | нет |
| src\capture\ppe | да | механизм (safety gate, self-test), 0 счётчиков | VerdictPASS/INCONCLUSIVE mapping | да, широко |
| src\crossservice | да | 1 (unrelated_control_action_total) | PromotionAllowed | да |

## 6. Актуализация 2026-08-01 (FB-03 фаза D: аудит producers исправлен)

Первоначальный аудит (разделы 2–5, 2026-07-31) использовал поиск по строковым литералам имён метрик. Это дало **ложный результат** для RST/GSO/PPE: producers инкрементят счётчики через **константы** `observability.Metric*` (`Metrics.Inc(observability.MetricX, ...)`), а не через строковые имена, и PowerShell `**` в `Select-String -Path` не раскрывает подкаталоги (`src/http/handler/runtime_topology.go` не попадал в поиск). Полный рекурсивный обход Inc-сайтов (2026-08-01) показал: **все 24 producer записи FB-03 scope реализованы** (17 telemetry + 3 zero-tolerance + 4 current_generation_readiness_input; kinds APPROVED владельцем, фаза E).

### 6.1 Verified Inc-сайты (29 sites, все 24 метрики)

| Метрика | Файл:строка |
|---|---|
| b4_capture_visibility_degrade_total, b4_hold_disabled_visibility_total | src\capture\ppe\product_service.go:110,111 |
| b4_ppe_self_test_total | src\capture\ppe\product_service.go:348 |
| b4_ppe_rule_reapply_total | src\capture\ppe\product_service.go:513 |
| nfqueue_gso_transition_total | src\http\handler\runtime_topology.go:38 |
| classifier_layout_parity_fail_total | src\nfq\classifier_decision.go:205,212,214,219,229 |
| nfqueue_gso_packets/bytes/decision_total | src\nfq\gso_fastpath.go:209,211,214 |
| nfqueue_gso_token_miss_total | src\nfq\gso_normalizer.go:61 |
| nfqueue_gso_truncated/csum_not_ready_total | src\nfq\offload.go:106,107,109,112 |
| passive_rst_observed/decision/suppressed/rollback/baseline_quality/budget_exhausted_total | src\nfq\passive_rst_observe.go:106,108,109,113,116,118 |
| passive_rst_fail_open/reconnect_regression_total | src\nfq\passive_rst_rollback.go:134,136 |
| unrelated_control_action_total | src\crossservice\validation.go:392 |

Производственные вызовы подтверждены: `handlePacket` → `DecodeOffloadMetadata`/`observeOffloadMetadata` (http\handler\handler.go:54–55), `traceGSOFastPath` (gso_fastpath.go:69), `recordObservabilityDecision`, `pool.go:468` → `RecordHealth`, `ApplyRuntimeControlTopology` (defer, runtime_topology.go:38), `NewProductService` (PPE). 24-я метрика `nfqueue_gso_transition_total` (ранее «не найдена») реализована в runtime_topology.go:38.

### 6.2 Исполненные проверки (фаза D)

- **10 executed fixtures** (3 новых файла): src\nfq\hard_gate_producers_test.go (6 тестов), src\capture\ppe\hard_gate_producers_test.go (3), src\http\handler\hard_gate_producers_test.go (1) — все зелёные в Docker.
- **9 executed mutation runs** (по одному на zero-tolerance gate): удаление Inc → целевой negative fixture FAIL → восстановление; маркеров MUTATION-RUN = 0; production-файлы не изменены. Удалялись: validation.go:265 (CSI, ранее), offload.go:109, offload.go:112, gso_normalizer.go:61, classifier_decision.go:214, passive_rst_observe.go:116, passive_rst_rollback.go:136, product_service.go:110, product_service.go:111.
- Реестр: 24/282 verified с полными machine-readable цепочками (runtime_producer + verdict_consumer/aggregation_observer + test_producer + mutation_test + evidence_artifact); `gen_hard_gates_registry.py --check` OK.
- Полный Docker `go build/vet/test -count=1` — зелёный.

### 6.3 Корректировка выводов разделов 3–5 (не удалены — история)

- «Реально исполняемых в бинаре: 1 из 160» → **неверно для RST/GSO/PPE/CSI scope**: исполняемы **24 из 24** метрик FB-03 scope (17 telemetry + 3 zero-tolerance + 4 readiness inputs) с verified producers; классификация kinds APPROVED владельцем 2026-08-01 (17/3/4).
- «nfqueue_gso_transition_total не найден» → **неверно**: реализован (runtime_topology.go:38).
- Выводы по WARP (56), SPF (22), FT §26 (82) и IV meta-suite остаются в силе: эти пакеты не в production-графе (0 импортеров), их счётчики вне FB-03 scope и покрываются другими задачами (FB-02, FB-14 и т.д.). Реестр фиксирует их как zero-tolerance по умолчанию (fail-closed BLOCKED при applicability).

### 6.4 Фаза E2 (2026-08-01, closure — FB-03 COMPLETE)

- **Production window** (`validation.BaselineForRun`, generation-keyed store): Validation API / Field Test / canary / PromotePending используют единую evaluation текущей TestSession/ValidationRun (`handler.evaluateProductionGates`); **BLOCKED_COUNTER_RESET** при current < baseline в окне (fail-closed; сброс только для нового process/run/generation).
- **Readiness owner-state** (`validation.EvaluateReadiness(inputs, owner)`): PPE capture visibility подключён к production; GSO mode/complete-representation/token-state — DEFERRED (FB-27/PPE), wired как Unknown (non-zero → DEGRADED, никогда молчаливый READY); proof — `TestEvaluateReadinessOwnerStateEffect`.
- **Критерий 4 (PASS):** Prometheus text-export `/metrics` (`http/handler/prometheus.go`) + `TestProductionValidationIntegrationSnapshotPrometheusAPIFieldTest` (snapshot ↔ `/metrics` ↔ Validation API ↔ Field Test/report: одинаковые names/labels/values/kinds/produced state/window baseline/delta/generation).
- **Мутации kind-aware:** zero-tolerance — removed_inc (9) + removed_delta (10); readiness — owner-verdict инвалидация; telemetry — producer/export/report consistency.
- **Статусы критериев §FB-03:** п.1 PASS; п.2 PASS_CURRENT_PRODUCTION_SCOPE (24/24) + DEFERRED_DEPENDENCY (258, global PASS не заявляется); п.3 PASS (kind-aware); п.4 PASS; п.5 PASS (включая BLOCKED_COUNTER_RESET); п.6 PASS. Коммиты: `bd9db5d5` (producers), `7c99ec8b` (kinds E), `df145b8a` (фаза E2).
