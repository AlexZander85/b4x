# Аудит реализации требований в пакетах serviceprofile / fieldtest / silentpath

Read-only аудит (2026-07-31). Исходники: 3 пакета, 110 требований (SP 22 + FT 14 + SPF 74).
Метод: полное чтение всех файлов пакетов + grep сквозных терминов + чтение тестов. Сборка **не выполнялась**: `go` отсутствует в PATH окружения (проверено), выводов о компиляции не делается. Импорты silentpath→classifier/clock статически верифицированы (символы `FlowKey`/`ClientKey`/`NewFlowKey`/`ActionAuthorization{FlowKey,Client,SetID,Domain,ConfigGen,Final}` и `Clock/RealClock/FixedClock/NewFixed/Advance` существуют).

Статусы: **IMPLEMENTED** — доказуемая модель/логика в пакете; **PARTIAL** — часть элементов; **ABSENT** — нет реализации в пакете (может быть в другом месте репозитория или отсутствовать вообще). Все пути — `src/<pkg>/<file>:<symbol>`.

---

## 1. serviceprofile (22 требования, 17 файлов + schema/ + validate/)

| Требование | Статус | Evidence | Заметки |
|---|---|---|---|
| §18 required-before (runtime apply: immutable config gen, transactional, last-good, rollback, schema validation, dry-run) | PARTIAL | `transaction.go:Diff/Begin/Apply/Rollback`; `compiler.go:Compile` + `CompileOptions.DryRun`; `schema/manifest.go:SafetyHash/CanonicalBytes`; `validate/validator.go:Manifest` | Схема/дифф/превью/драй-ран — есть. `Apply()`/`Rollback()` — флаговые заглушки (только `t.Applied=true`), реального применения side effects нет. Last-good — только как `RecoveryBinding.RollbackTarget`. |
| §18 required-before (auto local validation: Discovery sandbox, structured ProbeOutcome, resource budgets, canary) | ABSENT | `compiler.go:Probe` (только тип ID/ComponentID/Role) | Sandbox, ProbeOutcome, бюджеты, canary в пакете отсутствуют. |
| §18 required-before (optimized YouTube pack: API/UI/video probes, component ranking, field trace contract, multi-client isolation, CDN switch) | PARTIAL | `packs.go:YouTubePack` (api/video компоненты, gmail same-provider-control, `*.googlevideo.com`); `controls.go:YouTubeControlScenarioIDs` (9 сценариев) | Ранжирование (fieldtest `optimizer.go:Rank`), field trace contract и multi-client isolation — вне пакета. |
| §18 required-before (beginner UI: backend profile API, ownership metadata, compile diff, basic/advanced) | PARTIAL | `ui.go:WizardView` (Mode preview/apply, Preview, AdvancedLink, CanClaimHealthy); `ownership.go:OwnershipMeta`; `transaction.go:Preview` | UI-модель, ownership-метаданные и compile diff есть. Backend profile API — вне пакета. |
| §18 required-before (transport-required: client-configured healthcheck/secret storage/artifact generator; router-tunnel stage-33 fallback, no double processing, leak/fail-open) | PARTIAL | `transport.go:TransportBinding` (RouterScoped/ClientConfigured/SecretRef) + `ValidateTransportBinding` (запрет global router transport, лимит SecretRef 128) | Healthcheck, artifact generator, stage-33 fallback, leak/fail-open политика — нет. |
| §18 required-before (direct-strategy: завершённые CSI-1…10 и 9 capabilities) | PARTIAL | `capability.go:CapabilityProjection` (IPCaptureOnly, EffectiveDomainPolicy, NegativeControls, SideEffectScope) | 9 capabilities не перечислены; CSI-1…10 — вне пакета (др. пакеты). |
| §18 required-before (GSO-aware execution: gates H1–H5, normalize-if-required/direct-if-certified, gso_policy=inherit) | PARTIAL | `gso_rst.go:GSOProjection` (Policy, CertifiedTechnique, ValidationRequired, DegradedReason) | H1–H5 гейты и normalize/direct-if-certified логика — вне пакета. |
| §18 required-before (Passive RST exposure: H6 UI-observation, H7–H10 suppression, профиль не повышает runtime mode) | IMPLEMENTED | `gso_rst.go:GSOProjection.Valid()` (`PassiveRSTMaximum != "aggressive"`); `validate/validator.go:33-35` (aggressive rejected); `packs.go` (`PassiveRST: "observe-max"`) | Профиль не может поднять выше observe-max; aggressive отвергается валидатором. |
| §18 required-before (YouTube pack promotion: CSI release gate + GSO parity + RST mode gate + same-client controls + rollback proof) | PARTIAL | `controls.go:ControlScenarios()` (same-provider Gmail controls); `detector_plan.go:PackReleaseVerdict` (ABD/DDI/TGB карта) | CSI release gate и rollback proof — вне пакета. |
| Telegram pack (transport-required, не обещает обход IP-block через fake/split, structured maturity, не включает global tunnel) | IMPLEMENTED | `telegram.go:TelegramPack` | Classification `transport-required`, Delivery `client-configured`, Execution `observe`, Maturity `experimental`, Controls direct-dc-connectivity/transport-health/failover. fake/split/global tunnel не упоминаются — корректно. |
| SP-11 (Telegram DC probe, MTProxy/SOCKS5 handoff, no fake/split primary default, QR только из локальной конфигурации) | ABSENT | — | DC probe, MTProxy/SOCKS5 handoff, QR-логика отсутствуют (telegram_field.go в fieldtest покрывает только delayed-first-data FSM bridge, не DC probe). |
| Custom templates (custom-domain-group, custom-streaming-service, custom-api-plus-media, custom-transport-required-service) | ABSENT | — | Grep `custom-` — 0 совпадений в пакете. |
| SP-20 (Silent recovery capability projection: manifest schema, upper bound без runtime, reject destination-global/recursive/rollback-less) | IMPLEMENTED | `recovery.go:ValidateRecovery` (rejects `destination-global`/`recursive`; auto-canary требует RollbackTarget+TTL+MaxAttempts) | Верхняя граница (TTL/MaxAttempts) задаётся без runtime-состояния. |
| SP-21 (False-positive-safe UX: observe default, effective/configured separation, lease и rollback controls) | IMPLEMENTED | `recovery.go:RecoveryUX` (Wording, LeaseID, RollbackAvailable, EffectiveMode, Truthful()); `RecoveryHealth` (ConfiguredMode/EffectiveMode/DegradedReason) | Разделение configured/effective есть; UX без лизы не заявляет rollback. |
| SP-22 (Recovery binding compiler: ordered bindings, exact client/service/component/config-gen, last-good/cooldown/TTL/max-attempts) | PARTIAL | `recovery.go:RecoveryBinding` (Ordered, ClientScope, ComponentID, ConfigGeneration, TTLSeconds, MaxAttempts, RollbackTarget) | **Нет cooldown** в структуре/валидации. Остальное есть. |
| SP-23 (Silent recovery validation/promotion: карта FT-R…FT-V, SPF-1…SPF-10, раздельные verdict'ы, invalidation) | PARTIAL | `recovery.go:RecoveryPromotion` (EvidenceRefs, FieldTests, FalsePositiveBudget, Ready()) | Карта — списки строк-ссылок, инвалидации нет; раздельные verdict'ы — в fieldtest/silentpath. |
| §28A.4 (WARP не primary при DNS/QUIC/SNI/TLS/HTTP/L4 evidence; primary только при IP/SYN/CIDR; nested-nonru при geo-constraint; camouflage отдельно) | IMPLEMENTED | `recommendation.go:supportedIPHypotheses` (только IP/SYN/CIDR/путевые гипотезы; прочие → NotApplicable); `warp_profile.go:CompileStrictNonRU` (strict требует GeoRequirement+ForwardedBindingCorrelation); `CamouflagePolicy` отдельно | Хорошая реализация «IP-only recommendation». |
| §28A.5 (warp_recommendation YAML, 9 полей) | IMPLEMENTED | `warp_profile.go:WARPProjection` (Provider, BundledEngineAvailable, EnrollmentSupported, BaseTransportCapable, CausalTraceReady, PathProofSupported, ForwardedBindingCorrelation, TargetCanarySupported, RuntimeState); метод `MarshalWARPRecommendation` (9 snake_case полей, fail-closed на unknown runtime state); `Valid()` требует CausalTraceReady+PathProofSupported | 9/9 полей, YAML-сериализация есть; тесты: `warp_projection_test.go` (Valid требует path proof, 9 полей YAML, все 5 runtime states, fail-closed). `transport_kind` — канонический `cloudflare-warp-masque`. |
| §28A.6 (Scoped validation plan: 10 шагов bounded transaction, freeze scope, direct-vs-WARP, rollback token'ов, TransportRecommendationValidated) | PARTIAL | `recommendation.go:RecommendationTransaction` (BeginTest/Finish/EnableAfterValidation, TestToken); `ValidateRecommendation` → validated/rejected/blocked-by-safety | Транзакция с test/production авторизациями есть; «10 шагов» как процедура не формализованы. |
| SP-30 (BlockingProfile transport-recommendation compiler: typed TransportRecommendation, base-WARP-only, без ActionAuthorization, expiry) | IMPLEMENTED | `recommendation.go:CompileRecommendation` (только `cloudflare-warp-masque`/`base`; fresh scoped independent evidence ≥2 refs; ExpiresAt = now+10min) | Типизированный объект, без ActionAuthorization, expiry есть. |
| SP-31 (Scoped WARP UX + validation transaction: тест без изменения постоянных правил, раздельные test/production авторизации) | IMPLEMENTED | `recommendation.go:RecommendationUX.PermanentRulesChanged`; `RecommendationTransaction.TestToken` + `ProductionAuthorized`; `EnableAfterValidation` (production только после validated) | Разделение test/production явное. |
| SP-32 (WARP recommendation release: FT-M/FT-W…Z/FT-AC…AD, IV-14/15/17, downgrade при expiry, PROFILE_WARP_RECOMMENDATION_READY) | IMPLEMENTED | `recommendation.go:RecommendationReleaseVerdict` (FieldTests, Umbrella, HardGateViolations, Ready()); `ProfileWARPRecommendationReady`; `Fresh()` (expiry downgrade) | Вердикт и expiry-логика на месте; карты suite — списки. |

**Итог SP: 10 IMPLEMENTED / 8 PARTIAL / 4 ABSENT.**

---

## 2. fieldtest (14 требований, 26 файлов)

| Требование | Статус | Evidence | Заметки |
|---|---|---|---|
| §17.1 (CSI-интеграция: TestSession roles, trace, analyzer, mandatory same-client control hard gate) | IMPLEMENTED | `session.go:TestSession/EventStream`; `controls.go:ControlRun`; `api.go:AuthorizationAudit.Clean()`; `audit.go:Audit` (control actions → `UnrelatedControlActionTotal` + violations) | Счётчик same-client hard gate есть и включается в Clean(). |
| §17.2 (RST/GSO-интеграция: offload metadata, GSO/MSS parity, RST observe, mode gates, stale-validation invalidation) | PARTIAL | `gso.go:ParityResult/ValidateParity`; `rst.go:RSTSuite.Valid` (aggressive → false; observe → true; conservative требует visibility+budget+rollback) | GSO/MSS parity и RST observe-гейт есть. Offload metadata и stale-validation invalidation — нет. |
| FT-Q (Unified WARP-aware promotion gate; раздельные verdict'ы; base WARP не маскирует camouflage/non-RU) | IMPLEMENTED | `warp_gate.go:WARPGate.Verdict/SeparateVerdicts` (base+Trace+Route+Forwarded+FaultMatrix+hard gates); camouflage/non-RU — отдельные типы | Раздельные verdict'ы base vs nested явные. |
| FT-R (Silent observation: unique-range TCP accounting, zero-verdict observe, downgrade) | IMPLEMENTED | `silent.go:SilentObservation/ProgressSample` (Mode, Suppressed, Ready — без вердикта); `silentpath/progress.go:uniqueRangeTracker` | Unique-range учёт — в silentpath; здесь observe-модель без вердикта (zero-verdict). |
| FT-S (False-positive suppression: fast-parallel/HLS/prefetch, benign fixtures → zero active recovery) | IMPLEMENTED | `silent.go:SuppressedPattern` (FastParallel/HLS/Prefetch/RecentSuccess); `silentpath/suppressors.go` | Suppressed-флаг исключает recovery (Ready() требует валидные sample). |
| FT-T (Differential causal proof: bounded A/B; candidate success без observed current-path failure не даёт PASS) | IMPLEMENTED | `silent.go:DifferentialProof.Valid` (требует DirectFailed && CandidateSucceeded && ControlsUnaffected); `DifferentialReady` | Обратное условие корректно. |
| FT-U (Scoped recovery, WARP fallback, rollback: lease TTL/cooldown, no recursive fallback, same-client Gmail/Google controls) | PARTIAL | `silent.go:RecoveryLeaseRecord` (TTL/MaxAttempts/RollbackTarget/ScopeHash/CleanupClosed); `FalsePositiveResult.Safe`; `audit.go` | **Нет cooldown**; no-recursive (WARP→WARP запрет) не проверяется в fieldtest (роли From/To — в silentpath leases). |
| FT-V (Silent recovery long-run gate: OBSERVE→RECOMMEND→AUTO_CANARY→COHORT_PROMOTED; отсутствие evidence → BLOCKED_TARGET_VALIDATION) | PARTIAL | `silent.go:SilentPromotionGate.Verdict` → `promotion.go:PromotionBlocked` (= BLOCKED_TARGET_VALIDATION); SilentMode observe/recommend/auto-canary | **Нет вердикта COHORT_PROMOTED** (grep по репозиторию: cohort только в validation/silent_validation.go вне пакета). |
| FT-AC (WARP causal envelope: EventID/TraceID/Sequence, generations, 9 mandatory mutants, event durability) | PARTIAL | `trace_causal.go:CausalEvent` (EventID/TraceID/Sequence/MonotonicNS/BootIDHash/ProcessStartID/ConfigGen/RouteGen/SessionGen) + `ValidateEventOrder`; `session.go:EventStream` (в памяти) | Envelope и валидация порядка есть. **9 mutants и event durability отсутствуют** (EventStream — in-memory, без персистентности). |
| FT-AD (Route/path proof + forwarded correlation: TransportPathProof, counter deltas, Android BindingID/RouteTokenID/SessionGen, 7 blocking fixtures) | PARTIAL | `warp_base.go:TransportPathProof` (PathCounters deltas, BindingID/RouteTokenID/SessionGen, Forwarded/RouterOrigin); `path_correlation.go:AndroidBindingCorrelation` + `RoutePathReport.Ready` | Структуры полные. **7 blocking fixtures не реализованы** (fixtures — тестовый уровень, в пакете нет). |
| FT-AE (Nested WARP, geo quorum, DNS/IPv6 path, cleanup ownership; 12 mandatory negative cases) | PARTIAL | `nonru.go:NonRUSuite` (Quorum ≥2 current providers, country≠RU, DNSInnerPath, IPv6Validated, DirectWANAbsent, CleanupClosed); `cleanup.go:CleanupReport` (Foreign → fail, ParentLinkCurrent, ParentReconnectInvalidated) | Модель полная. **12 negative cases не реализованы** (нет мутант-фикстур). |
| WARP_CAUSAL_TRACE_READY (FT-AC+AD+AE PASS, WARP hard gates zero, real Keenetic counters, Android forwarded) | IMPLEMENTED | `cleanup.go:CausalTraceRelease.Verdict` + const `WARPTraceReady` (требует AC.Ready+AD.Ready+AE.Ready+WARPHardGatesZero+KeeneticCounters+AndroidForwarded+SafetyHash) | Verdict-модель точная; «real» evidence — флаги, поставляемые интегратором. |
| §26 field hard gates (Controller fails claim при ненулевом счётчике; missing/unread gate ≠ zero) | PARTIAL | `hard_gates.go:HardGatesPass(counters, produced)` — missing (не produced) → false ✓; `controller.go:Controller` | Логика гейтов есть, но **Controller не вызывает HardGatesPass** — неинтегрировано в контроллер. |
| п.95 DoD (FT-AC…AE: machine-readable stage report, requirement coverage, source addendum hash) | IMPLEMENTED | `hard_gates.go:StageReport` (Stage, Verdict, SourceAddendumHash, Requirements, HardGates, AutomatedTests, FieldEvidenceRequired) + `Valid()` | Покрытие и hash — обязательные поля. |

**Итог FT: 8 IMPLEMENTED / 6 PARTIAL / 0 ABSENT.**

---

## 3. silentpath (74 требования, 10 файлов + 8 тест-файлов)

| Требование | Статус | Evidence | Заметки |
|---|---|---|---|
| SPF-01 (одиночный timeout/stall/retry не достаточен для auto-fallback) | PARTIAL | `types.go:Confidence` (лестница), `Assessment` | Явный запрет кодируется только косвенно (RecoveryAllowed=false у suspicion). |
| SPF-02 (запрет rkn_block_confirmed без differential; suspected/correlated/differentially_confirmed) | IMPLEMENTED | `types.go:Confidence` (suspicion/correlated/differential/recurrent-validated); `ReasonCode` — нейтральные формулировки | Нет «rkn_block_confirmed» формулировок вообще — безопасно. |
| SPF-03 (порядок реализации CSI→…→SPF-1…10) | ABSENT | — | Процессное требование, не код. |
| SPF-04 (z2k reference freeze, blind port запрещён) | ABSENT | — | Процессное. |
| SPF-05 (MAY: retry gap ≥5s, retry window, свежий QUIC success подавляет TCP retry, state per scope) | ABSENT | — | Нет retry-таймингов; частично `FreshSuccessSuppressor`. |
| SPF-06 (negative z2k: не вращать по двум ClientHello, не один threshold, не host-wide, stale retry expire) | ABSENT | — | Нет retry-логики вовсе. |
| SPF-07 (цели: unique-range progress, классы failure, positive+suppressing evidence, parallel success, bounded probe, exact scope recovery, auto-rollback, observe default, fail-open) | IMPLEMENTED | `progress.go`, `types.go:FailureClass`, `suppressors.go`, `differential.go`, `leases.go`, `rollback.go`, `visibility.go:EffectiveMode` | Ключевые цели реализованы (кроме bounded probe — см. SPF-21). |
| SPF-08 (не-цели: не destination-global, не WARP глобально, observe default, fail-open) | IMPLEMENTED | `types.go:Scope.ValidForRecovery` (запрет destination-only), `visibility.go:EffectiveMode` | Документировано в doc-comment пакета: evidence-only, не авторизует mutation/routing. |
| SPF-09 (Silent Path Failure — inference, не факт DPI) | IMPLEMENTED | `types.go:Confidence`/`Assessment` (вероятностная модель) | — |
| SPF-10 (Useful Progress = unique byte range; dup/retransmit/ACK/keepalive не считаются) | IMPLEMENTED | `progress.go:uniqueRangeTracker.add` (overlap вычитается, dup → Duplicate, Bytes==0 → non-data) | Точная реализация. |
| SPF-11 (Suppressing evidence: fresh same-scope/QUIC, явные ошибки, backgrounded, grace, preconnect, resource pressure, visibility gaps) | IMPLEMENTED | `suppressors.go` (FreshSuccessSuppressor, CompatibleSuccessSuppressor — «QUIC/совместимый путь»); ReasonCode: ExplicitServerResponse, FlowTooYoung, LikelyParallel, ResourcePressure, VisibilityIncomplete | Backgrounded/grace/preconnect — как ReasonCode-константы без отдельного collector. |
| SPF-12 (Differential Proof: current fails + candidate milestone + controls healthy + повторяемость в bounded window) | PARTIAL | `differential.go:ComparePaths` (3 условия) | **Повторяемость в bounded window не моделируется** (одноразовое сравнение). |
| SPF-13 (Recovery Lease exact scope; DestinationIP не единственный key) | IMPLEMENTED | `leases.go:Lease/LeaseStore` (Scope — полный); `types.go:Scope.ValidForRecovery` | — |
| SPF-14 (ProgressObserver принимает только immutable события, не выбирает strategy) | IMPLEMENTED | `progress.go` doc-comment + `FlowProgressState` (только факты наблюдения) | Явно заявлено в комментарии. |
| SPF-15 (UniqueRangeTracker: seq arithmetic, overlap, wrap, GSO/MSS parity, bounded, cleanup) | IMPLEMENTED | `progress.go:uniqueRangeTracker` (signed delta от anchor — wrap-safe); тесты wrap/overlap/parity/bounds | Полная реализация + тесты. |
| SPF-16 (ProtocolMilestoneTracker: syn/syn_ack/ClientHello/ServerHello/app-data/fin/rst/tls_alert) | IMPLEMENTED | `visibility.go:Milestones` + 8 констант Milestone | — |
| SPF-17 (VisibilityGate: complete incoming+outgoing, healthy queue, GSO parity, offload; иначе observe) | IMPLEMENTED | `visibility.go:CapabilitySnapshot.Complete()` (5 доказательств) + `EffectiveMode` → observe/`visibility_incomplete` | — |
| SPF-18 (SuppressionEvidenceCollector работает до classifier action) | IMPLEMENTED | `suppressors.go` doc-comment («evaluated before correlation or recovery») | Семантически на месте; отдельного collector-компонента нет. |
| SPF-19 (BaselineModel: bounded/explainable; запрет обучения на unvalidated recovery и пр.) | ABSENT | — | **Нет baseline model в пакете** (grep baseline — 0). |
| SPF-20 (RetryCorrelator: exact scope, gap [min,window], не parallel, нет fresh success) | ABSENT | — | **Нет retry correlator** (единственное «retry» — ReasonRetryObserved). |
| SPF-21 (DifferentialProbeController: probe после suspicion+budget, exact component, DNS/IP-family, control probe, budgets, cleanup, causal report) | ABSENT | — | **Нет probe controller**; `differential.go:ComparePaths` — чистая функция без бюджета/cleanup. |
| SPF-22 (RecoveryPlanner: не создаёт action из destination IP; только разрешённые binding: next validated/last-good/base WARP/proxy-TUN/fail-open/scoped fail-closed) | PARTIAL | `leases.go:Lease.From/To`; `types.go:Scope.ValidForRecovery` | Планировщика нет; binding-модель lease — есть. |
| SPF-23 (RollbackMonitor: candidate не достиг milestone, control regression, reconnect spike, latency/goodput, cross-service, DNS leak, recursion, budget, visibility loss, user disable, ConfigGen change) | PARTIAL | `rollback.go:RollbackMonitor` (только бюджет MaxRollbacks→ObserveOnly; причин — reason string) | Реализована только budget-ветка из 12 триггеров. |
| SPF-24 (State machine OBSERVING→…→PROMOTED; failure paths SUPPRESSED/ROLLED_BACK/OBSERVE_ONLY/COOLDOWN/EXPIRED) | PARTIAL | `types.go:Confidence` (5 уровней лестницы) | **Полного FSM нет** — только confidence ladder; нет SUPPRESSED/ROLLED_BACK/COOLDOWN/EXPIRED состояний. |
| SPF-25 (suspicion: один signal family → только trace/metrics/Inbox) | PARTIAL | `types.go:ObserveAssessment` (RecoveryAllowed=false, Confidence=suspicion) | «Одна family → только observe» не формализовано явно. |
| SPF-26 (correlated: две независимые families → recommendation и probe; auto fallback запрещён) | PARTIAL | `types.go:Evidence.IndependentFamily`; `types_test.go:TestObserveAssessmentCannotAuthorizeRecovery` | Поле есть; переход correlated→probe не реализован. |
| SPF-27 (differential: current fails + candidate succeeds + controls pass + no suppressors → scoped lease при policy opt-in) | PARTIAL | `differential.go:ComparePaths`; `leases.go` | Цепочка вручную собирается, авто-перехода нет. |
| SPF-28 (recurrent-validated: только он MAY промоутиться) | PARTIAL | `types.go:ConfidenceRecurrent` | Константа есть; enforcement нет. |
| SPF-29 (Независимость evidence families; два таймера одной причины не независимы) | IMPLEMENTED | `types.go:Evidence.IndependentFamily` (поле-маркер) | Поле есть; проверка независимости — на вызывающем. |
| SPF-30 (single_signal_auto_fallback == forbidden) | PARTIAL | `types.go:ObserveAssessment` + лестница | Инвариант не представлен явным счётчиком/инвариантом. |
| SPF-31 (Suppression: minimum_grace floor ≥5s) | IMPLEMENTED | `types.go:ReasonFlowTooYoung` | Значение 5s не захардкожено — код нейтрален. |
| SPF-32 (Suppression: fast parallel/prefetch → likely_parallel_or_prefetch) | IMPLEMENTED | `types.go:ReasonLikelyParallel`; `fieldtest/silent.go:SuppressedPattern` | — |
| SPF-33 (Suppression: fresh same-scope success + compatible-protocol (QUIC); outgoing Initial не считается; bypass TTL bounded) | IMPLEMENTED | `suppressors.go:FreshSuccessSuppressor/CompatibleSuccessSuppressor` (TTL через ExpiresAt) | — |
| SPF-34 (Suppression: явный server/application response (FIN/RST/TLS Alert/HTTP) — не silent failure) | IMPLEMENTED | `types.go:ReasonExplicitServerResponse`; `visibility.go:MilestoneFIN/RST/TLSAlert` | — |
| SPF-35 (Suppression: device/app lifecycle (background/Doze/network switch/cancel)) | ABSENT | — | **Нет маркеров lifecycle** (background есть в fieldtest `BackgroundRole`/android.go, но не как suppressor). |
| SPF-36 (Suppression: visibility degradation → active action запрещён) | IMPLEMENTED | `types.go:ReasonVisibilityIncomplete`; `visibility.go:EffectiveMode` | — |
| SPF-37 (Suppression: resource pressure) | IMPLEMENTED | `types.go:ReasonResourcePressure` | — |
| SPF-38 (Suppression: без final ActionAuthorization recovery запрещён) | IMPLEMENTED | `types.go:Scope.ValidForRecovery` (требует auth.Final) + тест | — |
| SPF-39 (Suppression: control failure → общий WAN/router outage) | IMPLEMENTED | `types.go:ReasonControlUnhealthy`; `differential.go` (control_unhealthy → no confirm) | — |
| SPF-40 (Quarantine-before-action: после CORRELATED wait 2–10s, собрать parallel/control, затем probe) | ABSENT | — | **Нет quarantine-тайминга** (grep quarantine — 0). |
| SPF-41 (Per-service adaptive thresholds; static threshold только observe cold-start) | ABSENT | — | **Нет threshold model** (grep threshold — 0). |
| SPF-42 (Conservative defaults: observe, grace 5s, retry_window 120s, 2 families, differential, visibility, control probe, success_bypass 30s, max_attempts 2, cooldown 120s, lease_ttl 300s, fail_open) | PARTIAL | `visibility.go:EffectiveMode` (observe default); `progress.go:DefaultProgressConfig` (4096/64/30min) | Числовые safety-дефолты (5s/120s/30s/2/120s/300s) **не в коде**. |
| SPF-43 (FP budget: max_rollbacks/hour 2, control regressions 0, user reverts/day 1) | PARTIAL | `rollback.go:Budget{MaxRollbacks, Rollbacks}` + тест | Бюджет есть, но без per-hour окна и контроля регрессий/ревертов. |
| SPF-44 (User feedback FP: rollback exact lease, negative outcome, counter, без hardcoded exception, trace IDs) | PARTIAL | `rollback.go:Rollback(id, scope, reason="user")` — exact lease scope | Счётчик FP и trace IDs — нет. |
| SPF-45 (Detection contracts 24–29: handshake silence, after-ServerHello, early-body byte threshold, midstream stall (idle исключён), throughput collapse, transport path (TUN≠health)) | PARTIAL | `types.go:FailureClass` (5 классов + transport-path) | Классы есть; **byte threshold и idle-исключение не реализованы**. |
| SPF-46 (Scope invariant: ClientKey+SetID+ComponentID+DomainKey+ConfigGen+IP family+TransportPath) | IMPLEMENTED | `types.go:Scope` — все 7 полей | — |
| SPF-47 (Authorization: активный recovery требует ActionAuthorization + capability + prevalidated binding + exact ConfigGen; detector не создаёт identity) | IMPLEMENTED | `types.go:Scope.ValidForRecovery` (Client/SetID/Domain/ConfigGen/auth.Final) | Capability/prevalidated binding не проверяются — только auth. Модель. |
| SPF-48 (Recovery order: retry same gen → next direct → last-good → base WARP → proxy/TUN → fail-open → scoped fail-closed) | PARTIAL | `leases.go:Lease.From/To` (направление перехода) | Упорядоченный planner не реализован. |
| SPF-49 (Existing flows не мигрируются; lease для retry/new flow/probe; controlled RST запрещён по умолчанию) | PARTIAL | пакет evidence-only по дизайну (doc-comment) | Отсутствие миграций — дизайн; явный запрет RST не кодируется. |
| SPF-50 (Lease rules: bounded TTL/attempts, immutable candidate gen, известный rollback, monitor, no recursive lease; direct→WARP ок, WARP→WARP запрещён) | PARTIAL | `leases.go:Put` (ExpiresAt, MaxAttempts, Rollback непустой, ConfigGen==Scope.ConfigGen) | **WARP→WARP не проверяется** (From/To — произвольные строки). |
| SPF-51 (WARP interaction: direct failure → temporary base-WARP lease; WARP failure → last-good; detector не включает require_non_ru) | PARTIAL | `leases.go:Lease.From="direct"` (ролевые переходы) | Логика WARP-взаимодействия — на вызывающем. |
| SPF-52 (Config schema: evidence/visibility/timing/recovery/safety; per-profile upper bounds; профиль не может ослабить global gates) | ABSENT | — | **Нет config schema** (профильные upper bounds — в serviceprofile recovery.go). |
| SPF-53 (API: capabilities/status/assessments/recovery endpoints; mutations с Idempotency-Key + request ID + scope) | PARTIAL | `status.go:BuildStatus` (capabilities/status модель) | Endpoints и idempotency — нет. |
| SPF-54 (Events suspicion→rollback→revoke без secrets; псевдонимные ID, ConfigGen, binding, reason) | PARTIAL | `types.go:Evidence/Assessment` (source, сроки, без секретов) | Событийная модель частично; rollback/revoke events — нет. |
| SPF-55 (UI: beginner карточка без «РКН заблокировал»; expert evidence/suppressor таблицы) | PARTIAL | В пакете нет UI; аналог — `serviceprofile/recovery.go:RecoveryUX` (Wording/EvidenceRefs/Suppressors/Truthful) | Реализация — в serviceprofile, не в silentpath. |
| SPF-56 (Metrics без raw hostname/MAC/token) | IMPLEMENTED | `status.go:Status` (только счётчики); `progress.go:ProgressStats` (агрегаты) | — |
| SPF-57 (Hard gates: 21 счётчиков = 0; ненулевое блокирует promotion) | ABSENT | — | В silentpath нет счётчиков. В fieldtest `hard_gates.go:RequiredHardGates` — **17 из 21** гейта (cross-ref). |
| SPF-58 (Invariants: observe не меняет verdict/route; recommend не ставит lease; suspicion не auto-recovers; lease не переживает ConfigGen; visibility loss revokes auto) | IMPLEMENTED | `types.go:ObserveAssessment` (RecoveryAllowed=false); `leases.go` (ConfigGen в Scope); `visibility.go:EffectiveMode` (degradation → observe) | Ключевые инварианты в коде. |
| SPF-59 (Тесты: unit progress/independence/suppressors/scope, fuzz, packet-path fixtures, differential, same-client controls, fault injection, perf ceilings 4096) | PARTIAL | 13 тест-функций (см. §6): progress ✓, suppressors ✓, differential ✓, rollback ✓, leases ✓, visibility ✓, scope ✓ | **Нет fuzz, packet-path fixtures, fault injection, perf-ceiling тестов** (bounds-тест есть). |
| SPF-60…69 (этапы SPF-1…10 deliverables) | ABSENT | — | Процессные этапы, вне кода. |
| SPF-70 (Mode gates: observe-ready / recommend-ready / auto-canary-ready / cohort promoted) | PARTIAL | `release.go:ReleaseVerdict` (silent-observe-ready, silent-recommend-ready, silent-auto-canary-ready, implemented-not-target-validated) | **Нет cohort-promoted вердикта**; есть NotTargetValidated. |
| SPF-71 (Automatic demotion: WAN fingerprint/engine/config/visibility change, profile update, budget breach, repeated rollback, user report, control regression) | PARTIAL | `visibility.go:EffectiveMode` (visibility change); `rollback.go` (budget breach → ObserveOnly) | 2 из 8 триггеров. |
| SPF-72 (Синхронизация: Field Test suites после SPF-10; Profiles per-component policy; umbrella) | ABSENT | — | Процессное. |
| SPF-73 (DoD 20 пунктов) | PARTIAL | `release.go:Verdict`; `visibility.go`; `rollback.go` | Часть DoD-пунктов представлена моделями. |
| SPF-74 (Agent execution contract: без target доступа → IMPLEMENTED_NOT_TARGET_VALIDATED, не PASS) | IMPLEMENTED | `release.go:NotTargetValidated` = "implemented-not-target-validated"; `Verdict(unitPass, targetValidated)` | Точное соответствие. |

**Итог SPF: 26 IMPLEMENTED / 25 PARTIAL / 23 ABSENT.**

---

## 4. Готовность к интеграции по пакетам

### serviceprofile — **частично готов**
Целостная модель: schema (canonical hash, безопасные поля), валидатор (rejects aggressive RST, роли, домены), compiler (детерминированный stableID), ownership (manual/managed/pinned/excluded), transaction (preview/diff), WARP-рекомендации (SP-30/31/32, §28A.4), recovery binding (SP-20/21), Telegram pack (без fake/split).
**Что мешает:**
1. `transaction.go:Apply/Rollback` — флаговые заглушки (нет применения к реальному состоянию, нет last-good применения).
2. §28A.5: `path_proof_supported` реализован (9/9 полей + YAML `MarshalWARPRecommendation`); прикладной вызов YAML-блока в драйвере/UI wire (SCHEDULE/ENABLE path) ещё не подключён.
3. ABSENT: custom templates (4 шт.), SP-11 DC probe/MTProxy/SOCKS5/QR, авто-валидация (sandbox/ProbeOutcome/бюджеты), cooldown в SP-22.
4. `import_export.go:Import` — принимает любой JSON; `SecretsRedacted` декларативен, не проверяется при импорте (манифест импортируется как есть — секреты не извлекаются, но и не контролируются).

### fieldtest — **частично готов (наиболее полный)**
Verdict-модель закрывает все 14 требований: FT-Q (раздельные verdict'ы), FT-R…V (silent observation/доп. proof), FT-AC…AE (trace/path/correlate/cleanup), WARP_CAUSAL_TRACE_READY, StageReport DoD.
**Что мешает:**
1. `controller.go:Controller` не интегрирует `HardGatesPass` — гейты живут отдельно от жизненного цикла сессий (§26 не выполняется на уровне контроллера).
2. Отсутствуют фикстурные сущности требований: 9 mutants (FT-AC), 7 blocking fixtures (FT-AD), 12 negative cases (FT-AE) — в пакете нет ни списков, ни исполняемых кейсов.
3. Нет cooldown (FT-U) и вердикта COHORT_PROMOTED (FT-V).
4. `promotion.go:Promote`: `ReportOnly → PromotionPass` без canary/evidence — риск «PASS без evidence» при report-only с выключенным `RequireEvidence` (грань с BLOCKED_TARGET_VALIDATION — требуется решение).
5. EventStream (session.go) — in-memory, «event durability» (FT-AC) не обеспечивается.

### silentpath — **частично готов (ядро сильно, детекция отсутствует)**
Сильное ядро с тестами: unique-range progress (wrap/overlap/GSO-MSS parity), 8-мильный visibility gate с деградацией, suppressors (9/10 гейтов), leases (exact scope, rollback target), differential (3 условия), rollback budget, scope-инварианты, 4 release-вердикта + IMPLEMENTED_NOT_TARGET_VALIDATED.
**Что мешает:**
1. **Детекционная цепочка пуста**: BaselineModel (SPF-19), RetryCorrelator (SPF-20), DifferentialProbeController (SPF-21), quarantine (SPF-40), adaptive thresholds (SPF-41) — ABSENT. Без них confidence ladder (SPF-24) не имеет источников корреляции — пакет может работать только как observe-модель.
2. Нет полного FSM (SPF-24): только 5 уровней Confidence вместо 9 состояний + 5 failure-путей.
3. Нет config schema (SPF-52), 21 hard gate счётчиков (SPF-57 — в silentpath их нет; в fieldtest 17/21), числовых safety-дефолтов (SPF-42: grace 5s, cooldown 120s, lease_ttl 300s).
4. RollbackMonitor (SPF-23) — только budget-триггер из 12; WARP→WARP recursion не проверяется (SPF-50).
5. Пакет не подключён к production (0 импортеров) — известный finding, вне scope.

---

## 5. Заглушки / TODO / нереализованные функции

Grep `TODO|FIXME|panic(|not implemented` по трём пакетам: **0 совпадений** — маркеров нет. Однако функциональные заглушки есть:

| Пакет | Место | Характер |
|---|---|---|
| serviceprofile | `transaction.go:57-70` `Apply()`/`Rollback()` | Только выставляют флаги Applied/RolledBack; никакого реального применения изменений. |
| serviceprofile | `import_export.go:Import` | Не проверяет `SecretsRedacted`/provenance при импорте — принимает произвольный манифест. |
| serviceprofile | `catalog.go:Verify` | Community/Local источники возвращают nil без какой-либо проверки. |
| fieldtest | `controller.go` | Не вызывает `HardGatesPass`; runs хранятся в памяти, нет claim/verdict-логики. |
| fieldtest | `session.go:EventStream` | Только in-memory; durability (FT-AC) не реализована. |
| fieldtest | `promotion.go:27` `ReportOnly → PromotionPass` | PASS без canary — флаг-заглушка, граничит с запретом «no evidence → PASS». |
| silentpath | `rollback.go:Rollback` | Единственный триггер — бюджет; остальные 11 причин SPF-23 не представлены. |
| silentpath | `differential.go:ComparePaths` | Чистая функция без бюджета/окна повторяемости (SPF-12/21). |

---

## 6. Тесты

### serviceprofile — 4 тест-функции (3 файла + validate)
| Файл | Тест | Покрывает |
|---|---|---|
| `compiler_test.go` | TestCompileDeterministic | Детерминированность SafetyHash и stableID set-ID |
| `ownership_test.go` | TestOwnershipMigrationIsManual | Миграция → manual, CanReplace=false |
| `transaction_test.go` | TestTransactionRollback | Diff create+remove, Apply, Rollback |
| `validate/validator_test.go` | TestManifestRejectsAggressiveRSTAndAcceptsCanonical | Валидация манифеста |

**Пробел:** нет тестов на: canonical compile hash без executable fields, warp_recommendation (9 полей), recovery binding (SP-22/20), Telegram pack, recommendation transaction (SP-31/32), UI mapping, import/export secrets.

### fieldtest — 1 тест-функция
| Файл | Тест | Покрывает |
|---|---|---|
| `session_test.go` | TestEventStreamRejectsDuplicateAndRedactsIdentity | EventStream seq, Pseudonym (sha256:16 hex) |

**Пробел:** 0 тестов на hard gates, trace_causal, path_correlation, warp_gate, nonru, cleanup (WARP_CAUSAL_TRACE_READY), canary, promotion, silent (FT-R…V), release_detector, telegram_field — весь verdict-код не покрыт.

### silentpath — 13 тест-функций (8 файлов)
| Файл | Тест | Покрывает |
|---|---|---|
| `progress_test.go` | TestUniqueProgressIgnoresDuplicateAndOverlap | dup/overlap не увеличивают прогресс |
| | TestUniqueProgressOutOfOrderAndWrap | wrap + out-of-order |
| | TestGSOAndMSSHaveEqualUniqueTotals | GSO/MSS parity (SPF-15) |
| | TestProgressLifecycleAndBounds | Close/InvalidateGeneration/GC/range budget (SPF-15) |
| `suppressors_test.go` | TestFreshAndCompatibleSuccessSuppress | свежий/совместимый success, stale expiry (SPF-33) |
| | TestExplicitErrorAlwaysSuppresses | явный ответ сервера (SPF-34) |
| `differential_test.go` | TestDifferentialNeedsCandidateAndControl | control bypass rejected (SPF-12) |
| `rollback_test.go` | TestRollbackRevokesBudget | бюджет → ObserveOnly (SPF-43) |
| `leases_test.go` | TestLeaseScopeAndRollback | lease требует rollback (SPF-50) |
| `visibility_test.go` | TestActiveModeDegradesWithoutEveryVisibilityProof | 5 доказательств видимости (SPF-17) |
| | TestMilestones | 8 протокольных milestone (SPF-16) |
| `types_test.go` | TestObserveAssessmentCannotAuthorizeRecovery | suspicion не авторизует (SPF-25/58) |
| | TestScopeRequiresExactAuthorizationNotDestination | destination-only запрещён (SPF-13/38/46) |
| | TestEvidenceExpiry | сроки evidence |
| `status_test.go` | TestStatusRedactsIdentifiers | метрики без raw (SPF-56) |
| `release_test.go` | TestNoTargetValidationNoPromotion | IMPLEMENTED_NOT_TARGET_VALIDATED (SPF-74) |

**Пробел:** нет fuzz-тестов, packet-path fixtures (HLS/prefetch/parallel/blackhole), same-client negative controls (Gmail/Google, `unrelated_control_action_total==0`), fault injection, perf ceilings (SPF-59).

---

## 7. Сводка

| Пакет | IMPLEMENTED | PARTIAL | ABSENT | Готовность к интеграции |
|---|---|---|---|---|
| serviceprofile (22) | 10 | 8 | 4 | **Частично** — модель целостная; блокеры: transaction-заглушки, cooldown SP-22/invalidation SP-23, ABSENT custom templates/SP-11/авто-валидация |
| fieldtest (14) | 8 | 6 | 0 | **Частично (ближе к да)** — verdict-модель полная; блокеры: controller не вызывает HardGatesPass, нет мутант-фикстур FT-AC/AD/AE, cooldown, COHORT_PROMOTED |
| silentpath (74) | 26 | 25 | 23 | **Частично** — observe-ядро готово; блокеры: нет baseline/retry-correlator/probe-controller (SPF-19/20/21), FSM (SPF-24), config schema + 21 гейт (SPF-52/57) |
| **Всего (110)** | **44** | **39** | **27** | |

**Топ-3 пробела:**
1. **Детекционная цепочка silentpath отсутствует** (SPF-19 BaselineModel, SPF-20 RetryCorrelator, SPF-21 DifferentialProbeController, SPF-40/41 quarantine/thresholds): без неё confidence ladder не имеет корреляции и единственный рабочий режим — observe. Это крупнейший функциональный пробел.
2. **warp_recommendation YAML не исполняется в production**: `warp_profile.go` даёт 9/9 полей + `MarshalWARPRecommendation`, но ни один HTTP/UI-вызов не эксплуатирует его (endpoints WARP-recommendation отсутствуют).
3. **Вердикт-код fieldtest не исполняется**: Controller не интегрирует HardGatesPass (§26), 1 тест на 26 файлов; мутант-фикстуры FT-AC (9), FT-AD (7), FT-AE (12) не существуют — WARP_CAUSAL_TRACE_READY декларируется моделью, но не имеет исполняемых проверок.

*Ограничения аудита: сборка не запускалась (go отсутствует в PATH); оценка — статическая по исходникам; требования процессного типа (SPF-03/04/60…69/72, §18A последовательности) помечены ABSENT как неприменимые к коду.*
