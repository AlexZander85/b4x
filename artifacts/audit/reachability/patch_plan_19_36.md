
# Reachability: PATCH_PLAN stages 19-36 (аудит 31.07.2026)

Место: D:\b4x. Read-only аудит. Источник требований: B4_FORK_PATCH_PLAN.md, B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md (порядок стадий взят из artifacts/audit/patch_plan_audit.md и секций плана).

## Stage 19. Executor / packet builder fail-safe — STATUS: FAIL (severity HIGH)

- Механизмы: src/action/executor.go (NewExecutor :45, ExecuteContext :66), src/action/budgets.go, src/action/packet_builder.go.
- Production root: ОТСУТСТВУЕТ. Вызовы NewExecutor/ExecuteContext найдены только в src/action/executor_test.go (строки 39, 54, 66, 77, 89, 104).
- Фактический runtime path: nfq продолжает отправлять пакеты через sock.NewSenderWithMark (src/nfq/nfq.go:66, nfq/verdict.go:69, nfq/candidate_worker.go:23), tun — src/tun/tun.go:102. Пакет action импортируется nfq ТОЛЬКО как ActionTokenStore (src/nfq/connstate.go:381, nfq/pool.go:31, nfq/gso_token.go:302 — Claim токена), без централизованного билдера, бюджета и проверок чексумм/длины через Executor.
- Build tags/platform: нет ограничений.
- Config/API: нет.
- Side effect: не существует (в production).
- Failure path: не существует.
- Cleanup: не существует.
- Integration test через root: ОТСУТСТВУЕТ (только unit).
- Комментарий: требование DoD «централизованный packet builder + fail-open при невалидном плане» не достигнуто в runtime. Stage 17 (planner) — та же история: планировщик не вызывается из nfq.

## Stage 20. Metrics / Trace / Issue Bundle v2 — STATUS: REACHABLE

- Механизмы: src/observability/ (Recorder, TraceRecorder, IssueBundle), src/metrics/.
- Production root: main.go:228 handler.GetMetricsCollector; HTTP API регистрируются в handler/observability.go:15-16 через RegisterObservabilityAPI, вызываемую из RegisterEndpoints (src/http/handler/common.go:192), которая вызывается из registerAPIEndpoints (src/http/server.go:143-144) внутри StartServer (main.go:369).
- Регистрация/wiring (цепочка): main.go:369 StartServer → server.go:54 registerAPIEndpoints → common.go:163 RegisterEndpoints → common.go:192 RegisterObservabilityAPI → observability.go:15-16 (/api/diagnostics/issue-bundle, /api/observability/metrics).
- Точки записи в runtime: nfq/classifier_decision.go:197-250 recordObservabilityDecision (вызывается из :194 — решение по каждому кандидату), nfq/handler.go:301, 741-749, nfq/gso_normalizer.go:61, nfq/passive_rst_observe.go:90-120, nfq/tcp_reassembly_observe.go:36-88, nfq/offload.go:106-114, nfq/quic_authorization.go:41-49, nfq/candidate_lifecycle.go:20-29, nfq/route_binding.go:46-60.
- Config: нет (всегда включено).
- Side effect: счётчики метрик + trace-записи + issue bundle по запросу.
- Cleanup: нет (ротация ограничена).
- Integration test через root: ДА — src/http/handler/observability_test.go: TestHandleIssueBundleIsRedactedAndIncludesCaptureStatus (httptest на зарегистрированном handler), TestHandleObservabilityMetricsMethod, TestHandleFailureCandidatesReturnsBoundedPassiveInbox.
- Комментарий: полное покрытие: NFQ-решения, GSO-нормализация, RST-наблюдение, reassembly, offload, quic auth, кандидаты, route binding — все пишут через diagnostics.Default()/observability.

## Stage 21. Изолированный Experiment Sandbox — STATUS: REACHABLE

- Механизмы: src/discovery/sandbox.go, src/discovery/runtime.go (Start :68-140, StartSuite :150-180, Stop :203-238), src/discovery/runtime_backend.go (Queue.IsDiscovery=true :42), src/nfq/pool.go:112, 486 (sandbox-пул), src/config (DiscoveryRuntimeConfig).
- Production root: HTTP /api/discovery/start — src/http/handler/discovery.go:102-180 → discoveryRT.StartSuite (runtime.go:150) → m.Start (runtime.go:68) → sandboxManager.Acquire (runtime.go:118) → suite.RunDiscovery (runtime.go:179, goroutine :196). discoveryRT создан в main.go:140, передан в handler.SetDiscoveryRuntime (main.go:197). Второй root: src/watchdog/watchdog_heal.go:29 StartSuite(Automatic:true).
- Регистрация: common.go:183 RegisterDiscoveryApi → handler/discovery.go:144 StartSuite (POST /api/discovery/start).
- Config: discovery runtime config; queue.IsDiscovery=true; visibility-гейт для automatic-запуска (runtime.go:152).
- Side effect: отдельная NFQUEUE-очередь sandbox с отдельными marks; production nfq пропускает discovery-потоки (nfq/handler.go:444 и др. IsDiscovery-проверки).
- Cleanup: Runtime.Stop (runtime.go:203-238, sandbox.Close); main.go:526 discoveryRT.Stop при shutdown.
- Integration test через root: ОТСУТСТВУЕТ (только unit: sandbox_test.go, runtime_join_test.go; нет httptest на /api/discovery/start).
- Комментарий: reachable через REST и watchdog; отсутствует e2e-тест через тот же root.

## Stage 22. ProbeOutcome / structured verdict — STATUS: REACHABLE

- Механизмы: src/discovery/probe_outcome.go (ProbeTracker :130-289, RunHTTPProbe :415).
- Production root: /api/discovery/start (см. Stage 21) → RunDiscovery (discovery.go:123) → fetchUsingIPForDomain (discovery.go:1166-1179) → NewProbeTracker (discovery.go:1172); ProbeOutcome в CheckResult; RecordProbeOutcome (probe_outcome.go:280) пишет в observability.
- Config: нет.
- Side effect: ProbeOutcome/verdict в результате проверки домена, доступен через API discovery.
- Cleanup: нет.
- Integration test через root: ОТСУТСТВУЕТ (только unit: probe_outcome_test.go).
- Комментарий: RunHTTPProbe вызывается только из тестов, но tracker — из production-цепочки discovery suite. Reachable, но probe-движок без e2e.

## Stage 23. Адаптивная матрица + shadow probes — STATUS: FAIL (severity HIGH)

- Механизмы: src/discovery/adaptive.go (RunAdaptiveMatrix :232, ShadowSample :215, ScoreOutcome :168).
- Production root: ОТСУТСТВУЕТ. RunAdaptiveMatrix вызывается ТОЛЬКО из src/discovery/adaptive_test.go. Discovery suite (discovery.go) и runtime (runtime.go) его не вызывают; shadow-пробы нигде не активируются (config MaxShadowProbes не потребляется ни одним вызовом).
- Build tags/platform: нет.
- Config: MaxShadowProbes (config/classifier_v23.go) — определён, не потребляется.
- Side effect: не существует (в production).
- Failure path/Cleanup: не существует.
- Integration test: ОТСУТСТВУЕТ.
- Комментарий: «адаптивная матрица и shadow probes» реализованы как библиотека, в runtime не подключены.

## Stage 24. Passive Failure Candidate Inbox — STATUS: REACHABLE

- Механизмы: src/diagnostics/failure_inbox.go (FailureInbox :156, defaultInbox :206), src/metrics failure_candidate_*.
- Production root: NFQ packet path — nfq/handler.go:296, 364, 751; nfq/candidate_lifecycle.go:46; nfq/classifier_decision.go:301; nfq/quic_authorization.go:43; nfq/route_binding.go:71; nfq/tcp_reassembly_observe.go:79; nfq/passive_rst_observe.go:167, 189; nfq/quic_handoff.go:56; nfq/dns_hints.go:63 — все через diagnostics.Default().Observe(...).
- API: GET /api/diagnostics/failures — handler/failure_inbox.go:26-27 RegisterFailureInboxAPI, регистрация через observability.go:17 → common.go:192 → server.go:143.
- Config: нет (bounded inbox, порядок по severity).
- Side effect: список кандидатов + UpdateEvidence + метрики; отдаётся через REST.
- Cleanup: автоматическая ротация (bounded).
- Integration test через root: ДА — http/handler/observability_test.go:68 TestHandleFailureCandidatesReturnsBoundedPassiveInbox (httptest на зарегистрированный handler; в тесте инжектированный inbox, production inbox — diagnostics.Default()).
- Комментарий: самый широко подключённый диагностический механизм — 11 точек записи в NFQ.

## Stage 25. Real ClientHello Laboratory capture — STATUS: FAIL (severity HIGH)

- Механизмы: src/lab/clienthello_capture.go (CaptureRequest :156, CaptureClientHellos :386, makeProfile :513), src/nfq/types.go:88 SetClientHelloSink, nfq/handler.go:261, 811-831 submitClientHelloSegment.
- Production root: ОТСУТСТВУЕТ для capture. Вызов Pool.SetClientHelloSink не найден нигде, кроме определения (nfq/types.go:85-115) — sink в production-пуле остаётся nil, submitClientHelloSegment (handler.go:261) — no-op. CaptureClientHellos вызывается только из lab/*_test.go. Каталог профилей (handler/clienthello_lab.go:26, GET /api/lab/clienthello) доступен, но наполняется только через SetClientHelloCatalog (тесты); дефолт — пустой lab.NewMemoryRetention(64) (clienthello_lab.go:17).
- Side effect: hook на packet path есть, результата нет (nil sink). Endpoint возвращает пустой список.
- Cleanup: не требуется (ничего не запускается).
- Integration test через root: ОТСУТСТВУЕТ (unit: clienthello_capture_test.go; handler-тест только на read-only список).
- Комментарий: требование «захват реальных ClientHello с фильтром/длительностью» не активируемо из runtime.

## Stage 26. Fake Profile Compiler — STATUS: FAIL (severity HIGH)

- Механизмы: src/lab/fake_profile_compiler.go (CompileFakeProfile :202).
- Production root: ОТСУТСТВУЕТ. Вызовы — только тесты (fake_profile_compiler_test.go, hostfakesplit_test.go, profile_catalog_test.go). Каталог скомпилированных профилей (discovery/profile_catalog.go) никуда не подключён.
- Side effect: не существует.
- Integration test: ОТСУТСТВУЕТ.
- Комментарий: компилятор профилей не может попасть в runtime: нет ни одного production-вызова.

## Stage 27. Transactional apply / canary / cooldown / rollback — STATUS: REACHABLE

- Механизмы: src/runtimecontrol/ (rollout_manager_apply.go, rollout_store.go, live_runtime.go NewLiveBuilder :42, rollout_manager_state.go NewManager :67, WrapBuilderWithDefaultVisibility :71, InstallInitial :109-129), src/http/handler/runtime_control.go (InitializeRuntimeControl :52, RegisterRuntimeControlAPI :109-115: /api/v2/runtime-control/status|prepare|canary|promote|abort|rollback, ApplyRuntimeControlConfig :307, ApplyRuntimeControlTopology :25).
- Production root: http/server.go:56 InitializeRuntimeControl (внутри StartServer, main.go:369); guard middleware server.go:185 runtimeControlMutationGuard; cleanup server.go:111 CloseRuntimeControl при shutdown.
- Config: system.classifier.flags.transactional_apply_enabled (src/config/types.go:114).
- Side effect: атомарная замена конфига NFQ-пула (pool.UpdateConfig), canary-фаза, promote с гейтом crossservice.Default().RequirePromotion (runtime_control.go:91-93), rollback (rollback func ApplyRuntimeControlConfig :337).
- Failure path: валидация конфига до apply; rollback при ошибке применения.
- Cleanup: CloseRuntimeControl на shutdown; откат при неуспехе.
- Integration test через root: ОТСУТСТВУЕТ (unit: runtime_control_test.go diff-тесты, rollout unit-тесты; нет httptest на /api/v2/runtime-control/*).
- Комментарий: механизм полностью wired (включая visibility-обёртку менеджера), но нет e2e через API-корень.

## Stage 28. Multisplit — STATUS: FAIL (severity HIGH)

- Механизмы: src/action/strategy.go (каталог стратегий :303-306).
- Production root: ОТСУТСТВУЕТ. nfq использует только ActionTokenStore; мультисплит-стратегии не вызываются ни одним production пакетом.
- Integration test: ОТСУТСТВУЕТ (unit: strategy_test.go).
- Комментарий: stage Level C по плану (после Core Fix), но по критериям аудита — механизм существует, runtime использует старый path → FAIL/HIGH.

## Stage 29. HostFakeSplit — STATUS: FAIL (severity HIGH)

- Механизмы: src/action/hostfakesplit.go (PlanHostFakeSplit :81).
- Production root: ОТСУТСТВУЕТ (только тесты: hostfakesplit_test.go).
- Integration test: ОТСУТСТВУЕТ.

## Stage 30. Fake Payload Catalog (профили, shadow, MixSplit) — STATUS: FAIL (severity HIGH)

- Механизмы: src/discovery/profile_catalog.go (NewFakeProfileCatalog :118, AddCompiled :128, Select :240).
- Production root: ОТСУТСТВУЕТ (только profile_catalog_test.go). lab.CompileFakeProfile также unwired (см. Stage 26).
- Integration test: ОТСУТСТВУЕТ.

## Stage 31. FakeMix / TLSRecordSplit — STATUS: FAIL (severity HIGH)

- Механизмы: src/action/fakemix.go (PlanFakeMix :82), src/action/tlsrecordsplit.go (PlanTLSRecordSplit :64).
- Production root: ОТСУТСТВУЕТ (только fakemix_test.go, tlsrecordsplit_test.go).
- Integration test: ОТСУТСТВУЕТ.

## Stage 32. Controlled RST + RST-path diagnostics — STATUS: PARTIAL

- Пассивная часть REACHABLE: nfq/passive_rst_observe.go (observe :31/:51, Enforce :66), nfq/passive_rst_enforce.go (:95-130 suppression → vc.drop в handler.go:232-235, rollback RecordHealth :81); точки входа nfq/handler.go:230 (observePassiveRSTIncoming), :245 (observePassiveRSTOutgoing); store connstate.go:401 NewPassiveRSTStore; Config: system.classifier.runtime.passive_rst.mode (config/classifier_v23.go:35-39, default observe :336, conservative требует подтверждение токеном); health-rollback через runtimecontrol/live_runtime.go:280 (RecordPassiveRSTHealth, вызывается при promote); API /api/v2/classifier/hardening (handler/classifier_hardening.go, регистрация classifier_v23.go:63).
- Активная часть НЕ reachable: diagnostics/rst_path.go (PlanControlledRST, CompareRSTPaths :432, AnalyzeRSTPath :478) — вызовы только в rst_path_test.go; SYN-трассировка fieldtest/rst.go — пакет fieldtest не импортируется (см. Stage 36).
- Integration test: ОТСУТСТВУЕТ (unit: passive_rst_test.go, enforce, rollback; rst_path_test.go).
- Комментарий: suppression/injection в packet path активен; активный RST и path-diagnostics — нет.

## Stage 33. TUN/SOCKS fallback (FallbackManager) — STATUS: FAIL (severity HIGH)

- Механизмы: src/routing/fallback.go (NewFallbackManager :234, Run :223-239, перехват ошибок Write).
- Production root: ОТСУТСТВУЕТ. Вызовы — только fallback_test.go. routing импортируется nfq только для BindingStore (nfq/connstate.go:379, 398; nfq/route_binding.go:37). tun, socks5, tproxy не импортируют routing.
- Integration test: ОТСУТСТВУЕТ.
- Комментарий: требование «fallback при отказе TUN/SOCKS» не подключено ни к одному транспорту.

## Stage 34. Backend config/API v2 (классификатор, schema, import/export) — STATUS: REACHABLE

- Механизмы: src/config/classifier_v23.go (Runtime config, PassiveRST, OffloadPolicy, hardening), config/migration.go (LoadWithMigration), config/ppe_validation.go, config/transactional.go; handler endpoints: /api/v2/classifier/config (GET/PUT), /api/v2/classifier/schema, /export, /import (handler/classifier_v23.go:56-63), /api/config (config.go:23), hardening :63.
- Production root: main.go:106 cfg.LoadWithMigration; main.go:369 StartServer → registerAPIEndpoints → common.go:166 RegisterConfigApi, common.go:196 RegisterClassifierV23API.
- Config: вся v2-схема конфига.
- Side effect: чтение/замена конфига классификатора, import/export, schema; применение через Stage 27 runtime-control.
- Cleanup: миграции при загрузке.
- Integration test через root: ДА — http/handler/classifier_v23_test.go (api.RegisterClassifierV23API + httptest — тот же registration root).
- Комментарий: задний слой полностью подключён; фронтенд — см. Stage 35.

## Stage 35. UI (classifier screen, connect block) — STATUS: PARTIAL

- API/WS слой REACHABLE: registerWebSocketEndpoints (server.go:135-141), REST endpoints, RegisterSpa (server.go:61, spa.go:10-18).
- Фронтенд НЕ доставляется: src/http/ui/dist ОТСУТСТВУЕТ в репо (проверено: Test-Path False). //go:embed ui/dist/* (server.go:24) — при отсутствии dist билд go не собирается; при собранном dist SPA отдаётся, иначе fallback «No UI build found» (spa.go:14-19). Makefile build не собирает UI (только go build). Исходники Vite-проекта в репо есть (package.json, vite.config, src/http/ui/), сборка требует pnpm build.
- Config: нет.
- Integration test: ОТСУТСТВУЕТ (только handler-тесты API; spa_test.go на заглушку).
- Комментарий: API+WS reachable; готовый фронтенд из репозитория не получить без внешней сборки. PPE-8 «beginner-safe UI» — заявлен, но бинарно не подтверждён.

## Stage 36. Field-test automation (14 сценариев) — STATUS: FAIL (severity HIGH)

- Механизмы: src/fieldtest/ (27 файлов: connectivity_test.go, tcp_hold_test.go, rst_test.go и т.д.), crossservice 14 requiredScenarioIDs (src/crossservice/validation.go:144).
- Production root: ОТСУТСТВУЕТ для fieldtest: пакет fieldtest не импортируется ни одним production пакетом (main.go и его транзитивный граф его не включают); автономный тест-сюит не запускается ни из CLI, ни из runtime, ни из watchdog.
- Единственный вход для crossservice-сценариев: POST /api/v2/classifier/isolation/validate (handler/classifier_isolation_validation.go:23, ValidateAndStore) — оператор-вход, не автоматизированный сюит; гейт promote через crossservice.Default().RequirePromotion (runtime_control.go:91-93).
- Integration test: ОТСУТСТВУЕТ (только unit: session_test.go).
- Комментарий: 14 сценариев существуют как пакет+юнит-тесты, но не входят ни в один production root; автоматизированный прогон на Keenetic невозможен из поставки.

## PPE_STAGE_1..8 (Keenetic PPE offload) — reachability по каждому

- PPE-1 (capability detection) — REACHABLE: ppe.ProductService → detector; API /api/v1/capture/offload/capabilities (handler/capture_offload.go:20-26 → common.go:179 RegisterCaptureOffloadAPI → server.go:143; вызывается из ensureProcessPPE server.go:43 внутри StartServer).
- PPE-2 (compiler) — REACHABLE: product_service.go:293 Compile → compiler_types.go:51; применяется при apply.
- PPE-3 (TransactionManager apply/remove/verify/rollback) — REACHABLE: product_service.go:297-300 transactions.Apply, :316 Remove, verify/rollback в transaction_*.go.
- PPE-4 (Reconciler + NDM hook) — REACHABLE (platform Keenetic): product_service.go:206-234 ensureLifecycleStarted (hook.Install, reconciler.Start, StartNDMSignalBridge); build tags: signal_bridge_unix.go/other.go — только платформенные, линукс-таргеты покрыты.
- PPE-5 (passive observability) — REACHABLE: server.go:177 pool.SetPPEPassiveObserver(service.ObservationBus()); nfq/iface.go:57 observePPEPassiveRaw → ppe_observer.go TCP/UDP; status API; функциональный verdict «not_run» (не подтверждён на реальном железе) — заявлено в отчёте честно.
- PPE-6 (self-test) — REACHABLE: product_service.go:327 RunSelfTest → controller; API /api/v1/capture/offload/self-test; полный PASS требует реального endpoint b4-ppe-self-test/v1 — отложено, заявлено.
- PPE-7 (visibility gate) — REACHABLE и АКТИВЕН в production: tcp_hold_worker.go:74, tcp_hold_store.go:16, tcp_reassembly_observe.go:23, tcp_reassembly_metadata.go:26, action/token_lifecycle.go:13, discovery/runtime.go:152, runtimecontrol/rollout_manager_state.go:71 + visibility_runtime.go:23-65, nfq/passive_rst_observe.go:21. Гейт блокирует promote/hold/reassembly/ACK-замыкание при неполном PPE.
- PPE-8 (productization) — REACHABLE: сервис стартует/останавливается с продуктом (server.go:43-55, 157-166), API-роуты, i18n-файлы UI (ppe.en.json/ppe.ru.json в src/http/ui/locales), но сам фронтенд не собран (см. Stage 35).

## Ложные readiness (по каждому отчёту PPE)

- docs/reports/ppe/PPE_STAGE_1_IMPLEMENTATION_REPORT.md — ЛОЖНОГО readiness НЕТ: capability detection заявлен, ограничения честные (нет реального Keenetic).
- PPE_STAGE_2_IMPLEMENTATION_REPORT.md — НЕТ: compiler реализован и reachable, ограничения описаны.
- PPE_STAGE_3_IMPLEMENTATION_REPORT.md — НЕТ: transactions reachable; явно указано отсутствие проверки на реальном устройстве.
- PPE_STAGE_4_IMPLEMENTATION_REPORT.md — НЕТ: Reconciler/NDM hook reachable; реальная проверка отложена.
- PPE_STAGE_5_IMPLEMENTATION_REPORT.md — НЕТ: пассивная наблюдаемость reachable (server.go:177), verdict not_run, production_ready=false — заявлено явно.
- PPE_STAGE_6_IMPLEMENTATION_REPORT.md — НЕТ: self-test reachable; deferred реальный MediaTek-прогон указан.
- PPE_STAGE_7_IMPLEMENTATION_REPORT.md — НЕТ (небольшая неточность формулировки, не ложный readiness): в отчёте сказано, что lifecycle-wrapper «available but not globally instantiated», тогда как фактически ensureProcessPPE вызывается из StartServer (server.go:43) — т.е. wrapper проинициализирован. Итоговый статус gate корректен (visibility enforced).
- PPE_STAGE_8_IMPLEMENTATION_REPORT.md — ОГОВОРКА: «beginner-safe UI controls» — UI не собран в репо (ui/dist отсутствует), бинарно не подтверждён; API-часть reachable.
- PPE_STAGE_1..8_VALIDATION_REPORT.md (все 8) — НЕТ: статусы PASS_WITH_LIMITATIONS, ограничения (Go 1.25.3 недоступен, нет реального Keenetic/MediaTek, PPE-5/6/7 не дают promotion) описаны в каждом.

## Сводка

- REACHABLE: 6 (20, 21, 22, 24, 27, 34)
- FAIL: 10 (19, 23, 25, 26, 28, 29, 30, 31, 33, 36)
- PARTIAL: 2 (32, 35)
- PPE_STAGE_1..8: все 8 механик reachable (visibility gate активен); 2 ограничения продукта: self-test требует реальный endpoint (PPE-6), UI не собран (PPE-8/Stage 35).
- Интеграционные тесты через production root есть только для: observability API (Stage 20/24), classifier v2 API (Stage 34), capture offload API (PPE). Для остальных reachable-механизмов (21, 22, 27, 32) — только unit-уровень.
- Блокеры до «production-ready»: wiring action/planner в NFQ (19), adaptive matrix (23), lab capture+compiler (25/26), все Level C стратегии (28-31), fallback (33), fieldtest-сюит (36), сборка UI (35).

