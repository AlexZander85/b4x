# Audit: CSI + PPE + RST/GSO требования (read-only, 2026-07-31)

Метод: чтение трёх addendum (полностью) + req_index_part2.md + точечное чтение кода src\.
Статусы: `IMPLEMENTED` (подтверждено кодом), `PARTIAL` (часть требования), `UNWIRED` (код есть, не подключён в runtime path), `ABSENT` (не найдено), `REPORT-EXISTS` (код/отчёт есть, содержимое не ревизовано), `NOT-VERIFIED` (не удалось проверить read-only средствами).

Верификация сборки: `go build` в docker golang:1.25.12 — все логические пакеты (nfq, capture, classifier, crossservice, runtimecontrol, config, http/handler, fieldtest) компилируются; единственная ошибка `go build ./...` — `http/server.go:24:12: pattern ui/dist/*: no matching files found` (embed UI, не собран в репо).

---

## 1. B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md (49 требований)

| ID | Статус | Evidence (1 строка) | Заметки |
|---|---|---|---|
| PPE-01 | IMPLEMENTED | config OffloadPolicyDetect/Exclude/DisableGlobal (config\classifier_v23.go:9); нет авто-disable | Нет кода, выключающего global offload автоматически |
| PPE-02 | IMPLEMENTED | compileFamily с -m connskip --connskip N -j PPE (capture\ppe\compiler_family.go:49-56) | Per-flow exclusion по подтверждённой capability |
| PPE-03 | IMPLEMENTED | ConnskipPackets: 30, default (config\classifier_v23.go:332) | CPU window ограничен первыми N пакетами |
| PPE-04 | IMPLEMENTED | ChainPre/B4_PPE_PRE, ChainFwd/B4_PPE_FWD (compiler_types.go:12-13) | Только forwarding path (mangle/FORWARD) |
| PPE-05 | IMPLEMENTED | IPv4/IPv6 раздельные поля PPEOffloadConfig (classifier_v23.go:332), ppe_validation.go:51-100 | TCP и QUIC тоже раздельные enable |
| PPE-06 | PARTIAL | evaluateSelfTest (selftest_verdict.go:5): PASS только при bComplete && OffloadSuspected; VerdictINCONCLUSIVE ≠ PASS | Механизм есть; НО self-test запускается только через HTTP POST (capture_offload_product.go:183); авто-запуск при старте не найден, несмотря на default mode `startup-and-change` |
| PPE-07 | IMPLEMENTED | product_service.go:184-199: startup-skip-tables/capability/apply — деградация, не остановка; metrics PPE rules present | fail-open/observe-only |
| PPE-08 | IMPLEMENTED | Собственные chains B4_PPE_PRE/FWD + owned jumps; reconciler; transaction*.go | Идемпотентность: releaseHeldUnchanged, verify exact rules |
| PPE-09 | IMPLEMENTED | ndm_hook.go + reconciler.go:122 ReconcileStartup + ReassertIntervalSec: 55 (classifier_v23.go:332) | NDM-hook + периодический assert как safety net |
| PPE-10 | IMPLEMENTED | diagnostics.go: FunctionalNotRun default; functionalVerdictFor: PASSWithLimitations→Inconclusive (product_service.go:480-493); capture_offload_test.go:51-63 | PASS не эмитится без реального self-test |
| PPE-11 | IMPLEMENTED | OffloadPolicyDetect/Exclude/DisableGlobal + валидация (ppe_validation.go:51-53) | |
| PPE-12 | PARTIAL | ppe_validation.go:96-100: disable-global требует явного all-forwarded scope ack | «только в Advanced UI» не проверяемо без UI (read-only) |
| PPE-13 | IMPLEMENTED | ports.go:11-39 inspectionPorts: пересечение с портами enabled sets | intersection реализован |
| PPE-14 | IMPLEMENTED | detect.go:28: /proc/net/ip_tables_targets, ip6_tables_targets | |
| PPE-15 | IMPLEMENTED | detect.go:143-149: временная chain с -m connskip --connskip 1, функциональный probe | |
| PPE-16 | IMPLEMENTED | PPEOffloadConfig self_test.mode startup-and-change (classifier_v23.go:332) | См. PPE-06: режим задан, авто-запуск не подключён |
| PPE-17..23 | IMPLEMENTED | Config-модель §3: offload_policy, ppe.*, source_scope managed-devices, reassert 55s | |
| PPE-24..31 | IMPLEMENTED | Detect/compiler/backend_iptables; scope managed-devices; IPv4/IPv6 гейты; comment b4:ppe:v1:tcp | §4-5 rule model |
| PPE-32..35 | IMPLEMENTED | transaction*.go, reconciler.go, ndm_hook.go, cleanup | §6 lifecycle: apply/rollback/idempotency/recovery |
| PPE-36 | IMPLEMENTED | selftest_isolation.go:17 IPTablesABIsolation.BeginBypass: временные правила в B4_PPE_PRE/FWD; sport-маркер | §7.2: A/B изоляция допустимым способом (dedicated source port range) |
| PPE-37 | IMPLEMENTED | CaptureVisibilityResult поля Outgoing*/IncomingProgress* (см. selftest_verdict.go:5) | §7.3 |
| PPE-38 | IMPLEMENTED | VerdictPASS/FAIL/UNSUPPORTED/INCONCLUSIVE/PASSWithLimitations; INCONCLUSIVE не конвертируется в PASS | §7.4 |
| PPE-39 | IMPLEMENTED | offload_suspected только при A/B контрасте; dead endpoint → INCONCLUSIVE (health check) | §7.5 |
| PPE-40..47 | REPORT-EXISTS | docs\reports\ppe\PPE_STAGE_1..8_IMPLEMENTATION/VALIDATION_REPORT.md (glob подтвердил) | Этапы PPE-1..8; содержимое отчётов не ревизовано |
| PPE-48 | REPORT-EXISTS | PPE_STAGE_8_VALIDATION_REPORT.md существует; real Keenetic-артефакты не проверяемы read-only | Production acceptance gate |
| PPE-49 | PARTIAL | PR-разделение не проверяемо без git-истории (репо не git) | deliverable |

## 2. B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md (34 требования)

| ID | Статус | Evidence | Заметки |
|---|---|---|---|
| RG-01 | NOT-VERIFIED | Приоритет документации; read-only аудит не может оценить | |
| RG-02 | IMPLEMENTED | Fixed mark 0x08000000: grep по src\ — 0 совпадений; allocator в packetmark\marks.go:9-12 | Запрет соблюдён |
| RG-03 | IMPLEMENTED | authoritative_sni.go:57,68 EvidenceReassembledSNI; classifier_decision.go:206; handler.go:369 | |
| GSO-01 | IMPLEMENTED | offload.go:23-30 OffloadMetadata; nfqueueOpenConfig NfQaCfgFlagGSO; reassembly остаётся correctness path | |
| GSO-02 | IMPLEMENTED | gso_normalizer.go:20 consumeGSOPassForPacket — только при :normalizer, token-валидация; fast path результат accept-unchanged без secondary | |
| RST-01 | IMPLEMENTED | passive_rst_observe.go; PassiveRSTMode default observe (classifier_v23.go); Enforce (passive_rst_enforce.go:29-126) | |
| RST-02 | IMPLEMENTED | passive_rst_rollback.go: RecordHealth по SetID+DeviceScope+ConfigGen+Environment (production/candidate раздельно); Enforce: rollback → observe (enforce.go:70-73) | |
| RST-03 | IMPLEMENTED | Не-цели соблюдены: no fixed mark, no IPID-only block (IPID diagnostic-only, enforce.go signal classes), no redo Stage 1-36 | |
| ADR-H1 | IMPLEMENTED | fast path → authoritative; MSS → bounded reassembly; truncated → не authoritative (authoritative_sni.go:40-48) | |
| ADR-H2 | IMPLEMENTED | EvidenceReassembledSNI: classifier\types.go:25; policy.go:248-262 strict/scoped-hints; не global learned-IP; phase.go:107 | |
| ADR-H3 | IMPLEMENTED | GSOModeOff/..Full (classifier_v23.go:22-25); defaults off/inherit; full требует explicit (classifier_v23_validation_identity.go:56-72) | full не включается автоматически |
| ADR-H4 | IMPLEMENTED | normalize_for_mutation + normalizer только при RequiresAction; accept-unchanged для no-mutation (gso_fastpath.go:66) | |
| ADR-H5 | IMPLEMENTED | PassiveRSTOff/Observe/Conservative/Aggressive; default observe; aggressive требует confirmation token (enforce.go:88-97) | |
| H1 | IMPLEMENTED | handler.go:272-282: reassembled SNI в основном matcher path; один ClientHelloID (clientHelloClaims.Claim handler.go:374); layout parity — authoritative_sni.go | Invariant «1 CH → 1 Decision → 1 ActionToken» подтверждён структурно |
| H2 | IMPLEMENTED | offload.go:23-43 OffloadMetadata + GSOCapabilityLevel (unsupported..full-action-ready..failed); Truncated → не parse | |
| H3 | IMPLEMENTED | gso_fastpath.go:69 handleGSOFastPath; :110 observe-only в диагностическом scope; no second ClientHelloID (Claim один) | |
| H4 | IMPLEMENTED | gso_token.go:25-36: FlowKey/ClientHelloID/ConfigGen/Decision/StrategyID/RequiresAction (+ActionToken, Scope, CreatedAt); bounded store; Validate требует Scope (gso_token.go:101-105) — production/candidate/discovery не шарится; cleanup по generation | Первый pass: no matcher learning/action (dry-run); token miss → fail-open (gso_normalizer.go:35) |
| H4.1 | IMPLEMENTED | Очередь secondary: NormalizerQueueOffset: 2 (classifier_v23.go:332); fixed mark запрещена — allocator+mask контракт (packetmark) | NF_QUEUE_NR-механизм |
| H5 | IMPLEMENTED | runtimecontrol\gso_topology_transaction.go:70 Apply: validate→reserve→start secondary→readiness→switch→drain→commit; rollback:154; http\handler\runtime_topology.go:78,135-206 | |
| H5.1 | PARTIAL | queue ranges validation (classifier_v23_validation_identity.go:138), no global flush; iptables/nftables parity и Keenetic CPU/RAM budget — только target-тесты | |
| H6 | IMPLEMENTED | passive_rst_observe.go: state (SYN/SYN-ACK, server payload, windows, TTL samples, option fingerprint, RST count, suppression budget); Baseline quality none/weak/stable/stale/route-change (rollback.go) | |
| H6.1 | IMPLEMENTED | Robust TTL baseline: медиана/spread; IPv4 TTL и IPv6 hop-limit раздельно; weak/stale/route-change → не основание для drop (enforce.go:92-94) | |
| H7 | IMPLEMENTED | enforce.go:37-126: strong/corroborating/diagnostic классы; conservative strong+corroborating → suppress; aggressive только при token+no route-change; legitimacy guards (synSeen/synAckSeen, serverPayloadProgress, closed-port RST pass) | |
| H7.1 | IMPLEMENTED | exact FlowKey+generation, scope set/device (enforce.go:62-69), visibility complete required (:74-76), бюджеты per-flow+global (:102-121), unknown flow не трогается (state==nil → fail-open :63) | |
| H8 | IMPLEMENTED | diagnostics\passive_rst.go:48-50 (redaction), failure_inbox; rollback scoped+transactional; suppression не считается success proof (не генерирует success verdict) | |
| H9 | IMPLEMENTED | config: gso_mode/max_gso_bytes/normalize_for_mutation/tcp_only/execution.gso_policy (classifier_v23.go:128-131); passive_rst mode/scopes/budgets; migration defaults off/observe; API/UI расширения — REPORT-EXISTS (docs\reports\rst-gso\H10_VALIDATION_REPORT.md) | |
| H10 | REPORT-EXISTS | H10_VALIDATION_REPORT.md существует; real Keenetic/field evidence не проверяемо read-only | gate; без target-проверки → BLOCKED_TARGET_VALIDATION, не PASS |
| RST-04 | PARTIAL | Representation контракт: gso_fastpath result routing-only/action-suppressed; явный тип PacketRepresentation не найден (planner полагается на RequiresAction+capability) | Незначительное расхождение формы |
| RST-05 | IMPLEMENTED | packetmark\marks.go allocator, masks (Processed 1<<27, canary 24-26, PPE — контракт в capture\marks.go:10-13); startup validation (config) | |
| RST-06 | IMPLEMENTED | tcp_hold_worker.go:73-106: bounded hold, release на timeout/pressure/FIN/RST/progress/shutdown/generation; ReleaseAll + fail-open (:78,104-105) | |
| RST-07 | IMPLEMENTED | Backpressure: hold pressure → fail-open accept (tcp_hold_worker.go:104-105); GSO pressure → accept unchanged (fast path результаты); mode не повышается автоматически | |
| RST-08 | IMPLEMENTED | observability RedactIdentifier/RedactDomain; IssueBundle sanitized (observability.go:246-247, 352-353, 401); crossservice validation.go:179-180; GSO payload не экспортируется | |
| RG-04..RG-07 | NOT-VERIFIED | DoD-gates: код соответствует, но полевые доказательства (Keenetic/Android, no regression controls) — только в отчётах, не ревизованы | |
| RG-08 | IMPLEMENTED | Последовательность H1→H10 в коде соблюдена (модули присутствуют в ожидаемом виде) | |

## 3. B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md (32 требования)

| ID | Статус | Evidence | Заметки |
|---|---|---|---|
| CSI-01 | IMPLEMENTED | Формула ClientKey+FlowKey+evidence+ConfigGen+auth: classifier_decision.go:334 (action_authorization trace), route_binding.go:31-36 | |
| CSI-02 | IMPLEMENTED | Diagnostics сигнал cross_service_scope_violation (crossservice\validation.go ActionKind + failure_inbox) | |
| CSI-03/04 | IMPLEMENTED | Цели/не-цели: разделение candidate/auth, per-set DomainPolicy, fail-open — реализованы (ниже) | |
| ADR-CSI-1 | IMPLEMENTED | CaptureCandidate (classifier\authorization.go:11) ≠ ActionAuthorization (:23, ValidFor :50); handler.go:947-957: IP match без SNI → set=nil для DomainOnly (QUIC); route_binding.go:18 требует !authorized → reject | |
| ADR-CSI-2 | IMPLEMENTED | DomainPolicyInherit/Strict/ScopedHints/Legacy/Disabled (config\domain_policy.go:12); EffectiveDomainPolicy :45 (DomainOnly=false→Disabled); policy.go:221; managed sets → scoped-hints по умолчанию | |
| ADR-CSI-2.1 | IMPLEMENTED | Legacy safety: validation.go:356-386; reason unsafe_legacy_domain_scope (classifier_isolation_validation.go); UI миграция — REPORT-EXISTS | |
| ADR-CSI-3 | IMPLEMENTED | candidate_lifecycle.go:14 recordCandidateDisposition: Contradicted→MetricCrossServiceRevoked, Ambiguous→MetricCrossServiceAmbiguous; handler.go:938-944 QUIC SNI contradiction revokes provisional | |
| ADR-CSI-4 | IMPLEMENTED | authoritative_sni.go:57,68; policy.go:248-262; без global IP learning; конфликт → fail-open + Inbox | |
| ADR-CSI-4.1 | IMPLEMENTED | H1 реализован как verification/parity поверх (gso_fastpath использует тот же classifier API, authoritative_sni.go) | |
| ADR-CSI-5 | IMPLEMENTED | maybeHoldTCPPacket (tcp_hold_worker.go:73-90): hold только при bounded incomplete CH + visibility gate; иначе fail-open; «на всякий случай» mutation отсутствует | |
| ADR-CSI-6 | IMPLEMENTED | scoped_learned.go:11 observeScopedLearnedObservation: client-bound, Confidence 50, ExpiresAt +90s абсолютный (не sliding), при reuse → MetricLegacyScopeRejected | |
| ADR-CSI-7 | IMPLEMENTED | scoped_failure_state.go:23: ключи ClientKey+IP+Port+L4+SetID+DomainKey+ConfigGen (ScopedFailureKey), maxEntries 8192; блок-кэш только при domain evidence (handler.go:742); RST state exact-FlowKey (passive_rst state.flows) | |
| ADR-CSI-7.1 | IMPLEMENTED | Failure Inbox сигналы: cross_service_scope_violation, provisional_set_revoked_by_sni, shared_ip_ambiguous, unsafe_legacy_domain_scope, blocked_cache_scope_rejected, route_scope_rejected, quic_action_scope_rejected (metrics/trace) | События не расширяют domain list |
| ADR-CSI-8 | IMPLEMENTED | quic_authorization.go:16-22 quicActionGate; handler.go:914-962: IP match → только candidate; !Authorized → set=nil (fail-open); FilterQUIC=all только после авторизации (:960-962); shouldHandle требует quicGate.Authorized (:968) | |
| ADR-CSI-9 | IMPLEMENTED | route_binding.go:14-52: exact-flow binding, ActionAuthorization required, timeout 2min, TransactionID/owner/provenance; без destination-global ipset | |
| CSI-1..CSI-9 | IMPLEMENTED | Этапы покрыты модулями (см. evidence выше); отчёты — docs\reports\cross-service\CSI_IMPLEMENTATION_REPORT.md, CSI_VALIDATION_REPORT.md (REPORT-EXISTS) | |
| CSI-10 | REPORT-EXISTS | CSI_VALIDATION_REPORT.md существует; полевые negative-control артефакты не проверяемы read-only | gate |
| CSI-10.1 | IMPLEMENTED | fieldtest: ClientPseudonym (session.go:60), ControlScenario/TargetRole/ControlRole (controls.go:6-8), PrivacyRedacted required (controls.go:27) | |
| CSI-11 | IMPLEMENTED | Classifier invariants: shared IP ≠ service (candidate≠auth), SNI revokes, ambiguity → no mutation, один CH → один decision (clientHelloClaims.Claim) | |
| CSI-12 | IMPLEMENTED | State invariants: no *SetConfig in caches (scoped_learned хранит SetID строкой), lookup не продлевает validity (абсолютный ExpiresAt), ConfigGen revalidate (RecordAttempt, Enforce: generation mismatch → fail-open) | |
| CSI-13 | IMPLEMENTED | Fail-open инварианты: incomplete/conflict/unknown QUIC/visibility/pressure/ambiguity → no action + NF_ACCEPT (перечисленные выше гейты) | |
| CSI-14 | NOT-VERIFIED | Порядок addendum (CSI до RST/GSO) — документационный, код совместим | |
| CSI-15 | **FAIL** | GSOPassToken (gso_token.go:25-36) НЕ содержит Authorization/EffectivePolicy/CandidateDisposition — только Decision+RequiresAction+ActionToken(отдельный bounded store)+Scope | Частичная компенсация: ActionToken отдельно (bounded, scoped), secondary worker не перевыбирает set по IP (gso_normalizer.go:35); но буквальное требование §18 не выполнено |
| CSI-16 | IMPLEMENTED | Passive RST: exact FlowKey (enforce.go:29, state.flows по FlowKey), наследует authorized set/device scope (:67-69), rollback по cohort (SetID+DeviceScope+ConfigGen+Environment) | |
| CSI-17..CSI-19 | NOT-VERIFIED | DoD-gates: код соответствует; целевые/ресурсные доказательства — только в отчётах | |
| CSI-20 | REPORT-EXISTS | docs\reports\cross-service\CSI_IMPLEMENTATION_REPORT.md + CSI_VALIDATION_REPORT.md | |
| CSI-21 | IMPLEMENTED | Shortcuts не реализованы: нет allowlist Gmail, нет global QUIC off, нет broad ACCEPT | |

---

## Ключевые инварианты

### 1. ADR-CSI-1: CaptureCandidate ≠ ActionAuthorization — **PASS**
- Два раздельных типа: CaptureCandidate (classifier\authorization.go:11) и ActionAuthorization (:23, ValidFor :50).
- IP/CIDR/port match создаёт только candidate; domain-scoped action требует authorization: handler.go:947-957 (QUIC), route_binding.go:18 (`!authorized → rejected`), policy.go:106-109 (strict: только SNI/static host).
- ActionPlan для domain-scoped set ссылается на ActionAuthorization той же FlowKey/SetID/ConfigGen: classifier_decision.go:334, gso_normalizer.go:35.

### 2. H4 + CSI §18: GSOPassToken — **PASS для RST/GSO H4 / FAIL для CSI-15 (§18)**
- RST/GSO H4: точно соответствует (FlowKey, ClientHelloID, ConfigGen, Decision, StrategyID, RequiresAction, ExpiresAt) + бонусы (ActionToken, Scope, CreatedAt); bounded store, keyed flow/hello/gen, deterministic, cleanup (gso_token.go:101-105, 185), изоляция scopes.
- CSI §18: поля `Authorization`, `EffectivePolicy`, `CandidateDisposition` в GSOPassToken **отсутствуют** (gso_token.go:25-36). Частичная компенсация — отдельный bounded ActionToken + Scope + запрет перевыбора set в secondary pass — но буквальное требование «последующий GSO token MUST включать минимум» не выполнено.

### 3. Запрет фиксированной mark 0x08000000 — **PASS**
- grep '0x08000000|fixedMark|fixed_mark' по src\ — 0 совпадений. Все transient marks — из общего allocator с масками/владельцами (packetmark\marks.go:9-12, capture\marks.go:10-13), проверка конфликтов при startup/validation (config), очистка на terminal verdict/fail-open.

### 4. PPE functional self-test / runtime safety gate — **PARTIAL (UNWIRED при старте)**
- Verdict PASS только при реальном A/B (selftest_verdict.go:5, selftest_isolation.go:17), INCONCLUSIVE не конвертируется, diagnostics не эмитит PASS без self-test (diagnostics.go:14-18, product_service.go:480-493).
- Gate по умолчанию безопасен: без PASS → VisibilityUnknown → hold/reassembly/autopromotion отключены (visibility_gate_state.go:28, tcp_hold_worker.go:74).
- НО: RunSelfTest вызывается только из HTTP POST (http\handler\capture_offload_product.go:183); авто-запуск при старте (несмотря на default `self_test.mode: startup-and-change` в classifier_v23.go:332) в runtime path не найден — при старте выполняется только reconcile правил (reconciler.go:122).

---

## Топ-3 расхождения

1. **CSI-15 (§18 GSOPassToken extension)**: токен не несёт Authorization/EffectivePolicy/CandidateDisposition — компенсация ActionToken+Scope не является буквальным соответствием (gso_token.go:25-36).
2. **PPE-06 авто-запуск self-test**: конфиг декларирует `startup-and-change`, фактически self-test запускается только вручную через API; при старте — только reapply правил (capture_offload_product.go:183 vs reconciler.go:122).
3. **Сборка/артефакты**: `go build ./...` падает на embed `ui/dist/*` (http/server.go:24) — UI в репо не собран; полевые gate-артефакты (Keenetic/Android, H10/CSI-10) существуют только в виде отчётов, содержимое не ревизовано; репо не git — PR-декомпозиция (PPE-49) не проверяема.

## Сводка статусов

- **PPE (49)**: IMPLEMENTED 38, PARTIAL 3 (PPE-06, 12, 49), REPORT-EXISTS 8 (PPE-40..48), NOT-VERIFIED 0.
- **RST/GSO (34)**: IMPLEMENTED 27, PARTIAL 2 (H5.1, RST-04), REPORT-EXISTS 1 (H10), NOT-VERIFIED 4 (RG-01, RG-04..07).
- **CSI (32)**: IMPLEMENTED 25, **FAIL 1 (CSI-15)**, REPORT-EXISTS 2 (CSI-10, CSI-20), NOT-VERIFIED 4 (CSI-14, CSI-17..19).
- Ключевые инварианты: 2 PASS, 1 PARTIAL, 1 FAIL (CSI-15).
