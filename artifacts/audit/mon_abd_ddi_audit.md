# Аудит соответствия: MON v1.0 / ABD v1.2 / DDI-TGB v1.0 (88 требований)

Дата: 2026-07-31 · Метод: read-only, grep-поиск символов + чтение исходников (src/). Пакеты `rg` нет — использовался Grep tool.
Источник индекса: `req_index_part1.md` (88 строк таблиц; заголовки заявляют 91 запись — расхождение индекса).

## Ключевой контекст (доказуемый факт)

Пакеты `monitor`, `detector`, `observability`, `metrics` НЕ импортируются из `src/main.go`.
`monitor` целиком — «библиотека типов»: все конструкторы (`NewObservationBus`, `NewDiagnosticScheduler`,
`NewTemporalAccumulator`, `NewDemandInbox`, `NewABDEscalationAdapter`, `NewMonitorAPIProjection`,
`NewLegacyWatchdogAdapter`, `NewCanarySummaryAdapter`, `NewSuppressorEngine`, `BuildGuidedDiscovery`)
вызываются только из `*_test.go`. То же для ABD-типов (`detector/abd_*.go`) и DDI-типов
(`discovery/guided_api.go`, `diagnostic_profile.go`, `hint_planner.go`, `revalidation.go`, `network_context.go`,
`adaptive.go`). Продовый runtime — только legacy: `tables.Monitor` (iptables), `watchdog` (прямая мутация конфига),
детектор по HTTP API `/api/detector/*`, discovery `Runtime.StartSuite`, mtproto bridge с boolean fail-open.

Статусы: **IMPLEMENTED** = поведение есть в runtime и соответствует; **PARTIAL** = типы/контракты/валидации есть в коде, но не подключены к runtime и/или неполны; **ABSENT** = в коде отсутствует (в т.ч. deliverable-документы).

## MON v1.0 (строки 19–2372) — 32 требования

| Требование | Статус | Evidence | Заметки |
|---|---|---|---|
| §0.1 Strangler-решение (19–40) | ABSENT | watchdog_heal.go:10,29 → applier.go:18 → saveFunc; монитор — только types | Нет shadow/cutover; legacy direct apply жив |
| Migration-инвариант (10) | ABSENT | main.go:423 handler.SetWatchdog(wd) — оригинальный watchdog | Старый API — не compatibility adapter |
| Safety-инвариант (11) | PARTIAL | monitor/types.go:91 MonitorObservation; nfq/classifier_decision.go (ActionAuthorization) | Пересечения типов нет, но оно вакуумно: наблюдений в runtime нет; запрещённый путь observation→config mutation существует через watchdog |
| §13 Goals (384–403) | ABSENT | — | Нет наблюдения на клиентском трафике в runtime |
| §14 Non-goals (405–420) | PARTIAL | tables/monitor.go:14,56 (не заменён ✓); нет compile BlockingProfile в runtime ✓ | «Production config change» запрещено — нарушено watchdog/applier |
| §15 Core invariants (422–441) | PARTIAL | monitor/types.go:91 (observation≠profile), temporal.go (recurrence≠independence) | Инварианты соблюдены только на уровне типов |
| §57 Compatibility (1443–1466) | ABSENT | http/handler/watchdog.go:21-26 — globalWatchdog напрямую; monitor/compat.go:64 — только compat_test.go | /api/watchdog/* не транслируется в MON |
| §58 Status projection (1467–1485) | ABSENT | — | Нет compatibility_projection, нет projection |
| §59 Direct apply removal (1487–1503) | ABSENT | watchdog/applier.go:18 applyBatchResults (активен); config: нет legacy_watchdog_* ключей | Прямое применение конфига работает в проде |
| §60 Cutover stages (1505–1532) | ABSENT | monitor/compat.go: MonitorCheckpoint/CutoverVersion — только тесты | Фаз A–F нет |
| §61–63 Persistence/restart (1538–1570) | ABSENT | — | 5 store отсутствуют; монитор только in-memory |
| §80 Migration parity (1933–1944) | ABSENT | — | Нет shadow-сравнения legacy vs MON |
| §81 Fault injection (1946–1961) | ABSENT | — | Нет harness |
| §82 Real router (1963–1976) | ABSENT | — | Нет gate-инфраструктуры |
| §83 Real Android (1978–1990) | ABSENT | — | — |
| §84 Observation/authority gates (1996–2005) | ABSENT | observability: нет monitor-метрик (grep 0) | 6 gate==0 не существуют |
| §85 Scope gates (2007–2017) | ABSENT | — | — |
| §86 Temporal gates (2019–2024) | ABSENT | — | — |
| §91 Legacy migration gates (2076–2083) | ABSENT | — | Release gate невозможен |
| MON-1 (2136–2153) | ABSENT | — | Нет baseline audit-артефактов/fixtures |
| MON-2 (2155–2172) | PARTIAL | monitor/types.go (MonitorScopeKey, MonitorObservation, authority 76–79), observation_bus.go | Типы+тесты; packet path не подключён (не блокирует — вакуумно) |
| MON-3 (2174–2191) | PARTIAL | monitor/subjects.go (MonitorSubject, DemandInbox, ClientResolutionSnapshot) | Pinned adapter отсутствует |
| MON-4 (2193–2208) | PARTIAL | monitor/correlation.go; ObservationSource-таксономия | SPF adapter нет; runtime-корреляции нет |
| MON-5 (2210–2226) | PARTIAL | monitor/temporal.go: TemporalAccumulator, DefaultTemporalConfig | Buckets/decay/recovery FSM — типы |
| MON-6 (2228–2243) | PARTIAL | monitor/visibility.go: NewSuppressorEngine | Heartbeat/PPE-видимости нет |
| MON-7 (2245–2261) | PARTIAL | monitor/scheduler.go: DiagnosticScheduler | Быстрый lane не компилирует profile — верно в типах |
| MON-8 (2263–2279) | PARTIAL | monitor/abd_adapter.go:73 NewABDEscalationAdapter (MonitorDiagnosticRequest, TargetPlanOverlay, ABDRun) | Runtime-цепочки нет; отдельного типа MonitorAssessment нет (только MonitorAssessmentRef) |
| MON-9 (2281–2296) | PARTIAL | monitor/ddi.go: BuildGuidedDiscovery | Нет интеграции Discovery/WARP |
| MON-10 (2298–2313) | PARTIAL | monitor/canary.go: CanarySummaryAdapter | Milestone-корреляция — типы |
| MON-11 (2315–2332) | ABSENT | нет /api/monitor/v1; applier не отключён; store нет | Single source of truth отсутствует: два параллельных мира |
| MON-12 (2334–2354) | ABSENT | — | Field validation отсутствует |
| §95 ABD alignment (2360–2372) | PARTIAL | monitor/* не пересекается с detector/abd_* | Соблюдено тривиально (нет runtime) |

## ABD v1.2 (строки 135–4053) — 26 требований

| Требование | Статус | Evidence | Заметки |
|---|---|---|---|
| §0.3.1 MON↔ABD boundary (135–183) | PARTIAL | 7 объектов как отдельные типы (MonitorObservation, MonitorDiagnosticRequest, TargetPlanOverlay, ABDRun, ABDResult, MonitorDiagnosticResult abd_profile.go:53) | Цепочка не исполняется; типы не взаимозаменяемы ✓ |
| §0.4 Общие запреты, 40 (185–229) | PARTIAL | DimensionByte/DimensionPacket (abd_l4.go), ProbeFailureCode≠FailureAttribution (abd_dns.go), CompileBlockingProfile требует authoritative+complete (abd_profile.go) | Часть MUST NOT валидируется в библиотеке; runtime нет |
| §3.9 History ≠ BlockingProfile (655–670) | IMPLEMENTED | detector/history.go (HistoryEntry) — отдельно от BlockingProfile; переиспользования нет | — |
| §3.10 Self-interference (672–681) | PARTIAL | abd_path.go: ProbeContext.SelfInterference + Valid() | Проверка на уровне типа |
| §9.7 EvidenceAuthority (1491–1511) | IMPLEMENTED | monitor/types.go:76-79 (4 уровня); Confidence()/CompileBlockingProfile gate на authoritative | Только библиотека, но контракт полный |
| §9.8 ClientResolutionSnapshot (1513–1539) | PARTIAL | monitor/subjects.go: ClientResolutionSnapshot (SchemaVersion, query/CNAME/answers/TTL) | AttemptResolutionBinding как отдельного типа нет (DNSAddressOutcome связывает snapshot+IP+outcome) |
| §19 BlockingProfile (2282–2348) | PARTIAL | abd_profile.go: ProfileID/Status/Scope/Assessment/Hypothesis/Confidence/EvidenceRefs/ContentHash/CompiledAt | Нет SchemaVersion/SourceSuiteID/TargetPlanID/Components/DNS/Infrastructure/Exclusions/Controls/SearchPrior/CaptureVisibility; envelope SchemaVersion=1 (не 2) |
| §24.1 Atomicity (2821–2828) | PARTIAL | discovery/profile_store.go: ProfileStore (bounded, in-memory, ContentHash) | Нет temp+fsync+rename; идемпотентной миграции нет |
| §24.2 Schema versions (2830–2845) | ABSENT | SchemaVersion есть только в monitor(1)/warp(2)/observability("b4-observability-v2") | У DiagnosticTargetPlan/DiagnosticAttemptEvidence/BlockingProfile/DiscoverySearchPrior/DetectorCapacityProfile schema-полей нет |
| §24.3 Resume conditions (2847–2868) | PARTIAL | abd_release.go: DeepCheckpoint.Compatible (runID/scope/configGen/networkContext/30 мин) | Нет target-plan hash и build version; revalidation в runtime нет |
| §24.4 DetectorCapacityProfile (2870–2899) | PARTIAL | abd_release.go: DetectorCapacityProfile, SafeStaticCapacity (MaxConcurrent/MaxPackets/MaxUniqueBytes=4<<20), CalibrateCapacity | Нет NFQUEUE/RAM/CPU-калибровки; нет PlatformID/CPUClass/AvailableRAMBytes; schema нет |
| §24.6 Monitoring persistence (2915–2930) | PARTIAL | abd_release.go: HandoffGuard (bounded linkage) | MonitoringEpoch в resume отсутствует |
| §42 Hard gates (3581–3643) | ABSENT | observability/observability.go — нет blocking_profile_*/guided_search_*/detector_monitor_* (grep 0) | 48 gate==0 не существуют |
| §43 Release verdicts (3645–3655) | PARTIAL | abd_release.go: ABDReleaseGate.Verdict (только ABD_PRODUCTION_READY при DirectApplyDisabled, ABD_FIELD_VALIDATION_PENDING) | Урезанная лестница; DirectApplyDisabled=false в проде |
| ABD-1 (3736–3752) | ABSENT | — | Baseline audit отсутствует; pinned refs rcd27/blockcheckw/ladon в репо нет |
| ABD-2 (3754–3781) | PARTIAL | abd_plan.go: CompileDiagnosticTargetPlan + валидация (duration/cooldown/budget) | Нет Service Profile merge, persistence, schema |
| ABD-3 (3783–3814) | PARTIAL | abd_path.go: ObserverCapability, ObserverHealthLease, ProbeContext, DeepCheckpoint; budget token | Нет MultiVantageComparison, path proof runtime |
| ABD-4 (3816–3841) | PARTIAL | abd_dns.go: BuildDNSDifferential (exact/independent), DNSAddressOutcome, stale-детекция | AttemptResolutionBinding нет |
| ABD-5 (3843–3874) | PARTIAL | abd_http.go: TLSHTTPEvidence, BodyProgressEvidence (UniqueBytes, Chunks), DeadlineStages, ProbeFailureCode | — |
| ABD-6 (3876–3891) | PARTIAL | abd_quic.go: QUICEvidence (стадии Q0–Q7, ImpliesGlobalUDPBlock) | Resource bounds на run нет |
| ABD-7 (3893–3909) | PARTIAL | abd_l4.go: L4Experiment (packet/byte, UniqueBytes) | Confidence фикс. 0.25 — «один origin не даёт high confidence» выполнено тривиально |
| ABD-8 (3911–3927) | PARTIAL | abd_dynamic.go: DynamicControlTargetProvider (bounded, seed, TTL), StaticTargetSource | — |
| ABD-9 (3929–3953) | PARTIAL | abd_graph.go:22 EvidenceGraph, ConfidenceSummary, Authority monitor.EvidenceAuthority | Recurrence как metadata, provenance edges — типы |
| ABD-10 (3955–3981) | PARTIAL | abd_profile.go: CompileBlockingProfile (authoritative+complete, MonitorAssessmentRef), profile не авторизует | Runtime не используется |
| ABD-11 (3983–4017) | PARTIAL | abd_ddi.go: DiscoverySearchPrior, BuildDiscoverySearchPrior; discovery/hint_planner.go:56 `_ = prior` | **prior игнорируется**; freshness-интеграции нет |
| ABD-12 (4019–4053) | ABSENT | DirectApplyDisabled=false в проде; shadow/cutover vs Watchdog нет | UX/field/release отсутствуют |

## DDI/TGB v1.0 (строки 71–1883) — 30 требований

| Требование | Статус | Evidence | Заметки |
|---|---|---|---|
| §0.3 Общие запреты, 12 (71–87) | ABSENT | transparent.go:97 (5s deadline), :104 (zero-byte → true,nil) | zero-byte drop за 5s и handled=true — ЖИВЫ; unbounded idle sockets; prefix теряется при drop |
| §1 Issue #278 (92–182) | ABSENT | http/handler/discovery_types.go: DiscoveryRequest без profile ID; discovery/guided_api.go не подключён; detector/history.go без context envelope | Gap подтверждён кодом |
| §2 Issue #277 (184–251) | ABSENT | transparent.go:97,104,157 (dial-fail → true,nil) | Дефект жив: silent destructive drop, оба fallback заблокированы |
| §15 Disposition rules (902–910) | PARTIAL | bridge_outcome.go: BridgeDisposition handled/fail-open/drop/pending | Контракт называется иначе (нет claimed/parked/rejected/terminal_error); prod не использует (только bridge_outcome_test.go) |
| §16.1 Soft/hard deadlines (930–949) | PARTIAL | handshake_state.go: DefaultFirstDataPolicy 5s/30s/5s; bridge_config.go: 5000/30000 ms | Дефолты ≠ 15s/45s/10s из дока; prod не использует FirstDataMachine |
| §16.2 Zero-byte policy (951–971) | PARTIAL | handshake_state.go: zero-byte → park (библиотека) | Prod — обратное поведение (transparent.go:104) |
| §32 DDI hard gates (1562–1579) | ABSENT | — | 14 gate==0 не существуют |
| §33 TGB hard gates (1581–1598) | ABSENT | — | 15 gate==0 не существуют; zero-byte handled drop жив |
| §34 Release verdicts (1600–1631) | ABSENT | — | Нет ISSUE_277/278_RESOLVED и лестницы |
| DDI-1 (1637–1645) | ABSENT | — | Baseline audit отсутствует |
| DDI-2 (1647–1656) | PARTIAL | discovery/diagnostic_profile.go: NetworkDiagnosticProfileEnvelope (SchemaVersion=1, ContentHash, Redacted) | Версия envelope 1 ≠ 2 по ABD §19; миграционный контракт — MigrationVersion |
| DDI-3 (1658–1666) | PARTIAL | discovery/network_context.go: NetworkContext, CompareContext, InvalidateOnContextChange | TTL-state machine нет |
| DDI-4 (1668–1676) | PARTIAL | discovery/profile_store.go: CompileNetworkDiagnosticProfile, ProfileStore | Store in-memory; атомарного файлового store нет; legacy history отдельный (history.go) |
| DDI-5 (1678–1686) | PARTIAL | discovery/revalidation.go: BuildRevalidationPlan, ResolveRevalidation | Библиотека; runtime нет |
| DDI-6 (1688–1696) | PARTIAL | discovery/guided_api.go: DiscoveryRequest, GuidedDiscoveryOptions, BuildDiscoverySnapshot | /api/discovery/start (handler/discovery.go) НЕ расширен |
| DDI-7 (1698–1707) | PARTIAL | discovery/hint_planner.go: CompileHintPlan (boost/penalty/defer, exhaustive fallback) | **hint_planner.go:56 `_ = prior` — prior игнорируется**; allowed-SNI интеграции нет |
| DDI-8 (1709–1717) | ABSENT | — | UI отсутствует |
| DDI-9 (1719–1727) | ABSENT | — | Integration/validation отсутствуют (только unit-тесты библиотек) |
| DDI-10 (1729–1737) | ABSENT | — | — |
| TGB-1 (1739–1747) | ABSENT | handshake_state_test.go: FirstDataZeroByteDoesNotDrop… | Тест библиотеки есть, но это не repro продового дефекта и не audit |
| TGB-2 (1749–1756) | PARTIAL | bridge_outcome.go: BridgeOutcome, LegacyBridgeOutcome | Prod-код — boolean (transparent.go:104,157,169) |
| TGB-3 (1758–1766) | PARTIAL | handshake_state.go: FirstDataMachine (soft/hard, progress) | Soft=5s не 15s; prod не использует |
| TGB-4 (1768–1776) | PARTIAL | pending_manager.go: PendingHandshakeManager (maxGlobal 128/maxClient 8, ErrPendingOverflow) | Не в проде |
| TGB-5 (1778–1785) | PARTIAL | prefix_handoff.go: PrefixHandoff; transparent.go:107,112,118,124,138 (prefixConn) | В проде prefix сохраняется только при partial-чтении; при zero-byte drop теряется |
| TGB-6 (1787–1795) | PARTIAL | bridge_config.go (RouteLadder); tproxy/listener.go:220-231 (FailOpenViaWorker → failOpenDirect) | Лестница есть, но handled=true (transparent.go:104) блокирует её запуск |
| TGB-7 (1797–1805) | ABSENT | config/types.go:341 MTProtoConfig — нет transparent subtree | BridgeConfig — только библиотека |
| TGB-8 (1807–1815) | ABSENT | handler/mtproto.go — только legacy sessions/active-clients | UI/diagnostics bridge отсутствует |
| TGB-9 (1817–1825) | ABSENT | — | Нет stress-харнеса/bench |
| TGB-10 (1827–1836) | ABSENT | — | — |
| DoD (1866–1883) | ABSENT | — | Gate≠0: zero-byte silently claimed жив, prefix теряется |

## Сводка

| Документ | Заявлено | Проверено строк | IMPLEMENTED | PARTIAL | ABSENT |
|---|---|---|---|---|---|
| MON v1.0 | 33 | 32 | 0 | 13 | 19 |
| ABD v1.2 | 27 | 26 | 2 | 20 | 4 |
| DDI/TGB v1.0 | 31 | 30 | 0 | 14 | 16 |
| **Итого** | **91** | **88** | **2** | **47** | **39** |

## 5 самых серьёзных расхождений

1. **Issue #277 жив в проде** (`mtproto/transparent.go:97,104,157`): дедлайн 5s → zero-byte → `return true, nil`; dial-fail → `return true, nil`. Соединения Telegram молча уничтожаются, оба fallback заблокированы, prefix теряется — прямая инверсия TGB-1/§16.2/§0.3.
2. **MON-strangler не начат** (`watchdog/applier.go:18`, `watchdog_heal.go:29`): applyBatchResults и прямое применение конфига активны; нет фаз cutover, нет ключей `legacy_watchdog_*`, нет /api/monitor/v1, нет durable store — single source of truth отсутствует (MON-11/§59/§60 ABSENT).
3. **Вся платформа MON/ABD/DDI — библиотека типов**: 0 вызовов конструкторов из production (main.go не импортирует monitor/detector/observability); runtime-монитор — только `tables.Monitor` (iptables); метрики hard gates (ABD §42, MON §84–86, DDI §32, TGB §33) отсутствуют в `observability` (grep — 0 совпадений).
4. **Модель BlockingProfile и schema-версии не соответствуют** ABD §19/§24.2: нет SchemaVersion/Components/DNS/Infrastructure/Exclusions/Controls/SearchPrior; envelope SchemaVersion=1 вместо 2; schema-полей нет у DiagnosticTargetPlan/DiscoverySearchPrior/DetectorCapacityProfile.
5. **DDI-7/ABD-11: prior игнорируется** (`discovery/hint_planner.go:56` `_ = prior`) — DiscoverySearchPrior формально строится, но не влияет на hint-plan; API (DDI-6) не расширен — issue #278 жив.

## Оценка исполняемости в бинаре

В бинаре (main.go) исполняются только legacy-пути: iptables-монитор `tables.Monitor` (config MonitorInterval, bind.go:13), watchdog с прямым применением конфига, детектор по ручному HTTP API, legacy discovery (StartSuite), mtproto bridge с boolean fail-open. Реального исполнения требований: MON ≈ 0%, DDI/TGB ≈ 0%, ABD ≈ 7% (2 из 26 — только библиотечные контракты §3.9/§9.7, не задействованные в runtime). Код аддитивен: библиотеки MON/ABD/DDI могут быть подключены позже без рефакторинга legacy, но сам факт «strangler» и отключение direct apply не реализованы.
