# Атомарный индекс нормативных требований — часть 1 (4 addendum-документа)

Документы:
- **WARP** = `B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md` (4846 строк)
- **ABD** = `B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md` (4215 строк)
- **MON** = `B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md` (2452 строки)
- **DDI/TGB** = `B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md` (1884 строки)

Строки указаны по нумерации Read. Тип: MUST / SHOULD / MAY / verification gate / deliverable.

## WARP (B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md) — 44 записи

| ID | Документ | Строки | Содержание (≤15 слов) | Тип |
|---|---|---|---|---|
| ADR-WARP-1 | WARP | 398–435 | Engine поставляется как first-party bundled component: b4-warpd из pinned source, без отдельного opkg-dep и update channel; layout /usr/libexec/b4/b4-warpd, third_party/usque/ | MUST + deliverable |
| ADR-WARP-2 | WARP | 463–507 | Структурированный IPC по Unix socket вместо log parsing; лог — только secondary diagnostics | MUST |
| ADR-WARP-3 | WARP | 509–521 | Upstream hooks не policy engine: без user shell hooks, фиксированный путь, bounded timeout, роутинг только через B4 RouteManager | MUST |
| ADR-WARP-4 | WARP | 632–659 | Base transport: один native TUN b4warp0, HTTP/2/TCP/443, MTU 1280, IPv6 disabled; H3 — только capability | MUST + MAY |
| ADR-WARP-5 | WARP | 889–942 | CaptureCandidate не роутит трафик; маршрут только по TransportAuthorization + generation-owned route token; negative SNI revokes | MUST |
| ADR-WARP-6 | WARP | 1199–1242 | Non-RU — вторая изолированная WARP-сессия, зависит от base; dual-netns native TUN, same-namespace запрещён без proof | MUST |
| ADR-WARP-7 | WARP | 1379–1454 | Geo attestation — hard route gate: PASS_NON_RU только при ≥2 провайдерах, без RU и без direct WAN; TTL 120s без grace | MUST |
| §15 NDM apply order | WARP | 710–735 | Порядок: TUN→MTU 1280→адрес→NDM→проверка kernel state; exit code недостаточен, fallback iproute2 non-persistent | MUST |
| §16 MTU/MSS | WARP | 737–769 | MTU 1280 до роутинга; MSS: NDM adjust-mss иначе один generation-owned clamp, double clamp запрещён; PMTU тесты 1280/1281/1500/SYN/UDP | MUST + verification gate |
| §62.1 Required events | WARP | 2535–2620 | Таксономия обязательных lifecycle/MASQUE событий; слой-specific failure class вместо generic connect failed | MUST |
| §62.2 Path proof | WARP | 2622–2654 | Route proof = counter deltas (packets/bytes до/после); rule existence не proof; ProofKind router/forwarded/geo/dns/ipv6 | MUST |
| §72 Base hard gates | WARP | 3590–3603 | 10 gate-счётчиков == 0: secret leak, foreign interface, recursive route, mark collision, route без liveness, partial apply, restart, registration, unrelated control, rollback | verification gate |
| §73 Non-RU hard gates | WARP | 3605–3616 | 8 gate: route без свежей attestation, при RU/разногласии/direct DNS/невалидном IPv6/после expiry, direct fallback, budget identity | verification gate |
| §73A Camouflage hard gates | WARP | 3618–3633 | 12 gate: без control authorization, destination-only auth, payload mutation, cutoff failure, recursion, cross-instance, promotion без probe/window, insecure TLS, pin, retry, RST | verification gate |
| §73B Causal trace hard gates | WARP | 3635–3686 | 28 gate: path proof, forwarded binding, nested parent/generation/leak/health/token, geo quorum/revocation, DNS/IPv6, CONNECT-IP gen, cleanup, trace leak/completeness/order; verdict WARP_CAUSAL_TRACE_READY | verification gate |
| §74 Promotion verdict | WARP | 3688–3711 | Production PASS = WARP_CAUSAL_TRACE_READY + все base/camouflage gates; non-RU — PASS_EXPERIMENTAL; unsafe activation = FAIL | verification gate |
| WARP-1 | WARP | 3717–3747 | Freeze z2k/usque/usque-keenetic commits, SBOM, threat model; hash mismatch ломает build; deliverable WARP_1_REFERENCE_AUDIT.md | deliverable |
| WARP-2 | WARP | 3749–3781 | Сборка b4-warpd из pinned source, в составе B4, без runtime download; транзакционные upgrade/rollback/uninstall; WARP_2_BUNDLED_ENGINE.md | deliverable |
| WARP-3 | WARP | 3783–3813 | Secret store 0600/encrypted, consent flow, bounded registration, redaction, rollback candidate; без bundled proxy credentials; WARP_3_ENROLLMENT_AND_SECRETS.md | deliverable |
| WARP-4 | WARP | 3815–3861 | IPC supervisor, TransportTraceEnvelope, BootID/generation identity, P0/P1/P2 priority pipeline, required-event persistence, checksums; deliverable WARP_4_SUPERVISOR_IPC.md + WARP_4_TRACE_ENVELOPE.md + docs/runtime/warp-trace-schema-v2.md | deliverable |
| WARP-5 | WARP | 3863–3890 | TUN/NDM lifecycle: registry, netdev-before-NDM, MTU 1280 до route, state verification, safe stale reconciliation; WARP_5_TUN_NDM.md | deliverable |
| WARP-6 | WARP | 3893–3925 | Socket marks SO_MARK/BINDTODEVICE, endpoint pin mandatory, MarkAllocator, recursion guards, proxy env disabled; WARP_6_CONTROL_SOCKET_ROUTING.md | deliverable |
| WARP-7 | WARP | 3927–3961 | Scoped PBR: TransportAuthorization, atomic destination sets, транзакционные поколения, conditional MSS, DNS follow-binding, negative-evidence revocation; WARP_7_SCOPED_ROUTING.md | deliverable |
| WARP-8 | WARP | 3963–3998 | Liveness/self-heal: layered health, forwarded canary, retry/cooldown, fail-open vs fail-closed-scoped, restart storm prevention; WARP_8_HEALTH_SELFHEAL.md | deliverable |
| WARP-C1 | WARP | 4000–4034 | Точная control-авторизация до первого SYN: TransportControlPurpose/Authorization, поколения; destination/SNI-only отвергается; WARP_C1_CONTROL_AUTHORIZATION.md | deliverable |
| WARP-C2 | WARP | 4036–4064 | Enrollment camouflage: отдельный retry budget, redaction, запрет proxy/credentials; policy не авторизует data-plane camouflage; WARP_C2_ENROLLMENT_CAMOUFLAGE.md | deliverable |
| WARP-C3 | WARP | 4066–4094 | Cover SNI: canonical/builtin/user-explicit режимы, pinning во всех режимах, запрет insecure fallback; WARP_C3_COVER_SNI_PINNING.md | deliverable |
| WARP-C4 | WARP | 4096–4125 | Handshake-only адаптер: только approved primitives, ceilings, запрет мутации established stream; WARP_C4_HANDSHAKE_ADAPTER.md | deliverable |
| WARP-C5 | WARP | 4127–4156 | CONNECT-IP cutoff: переход по masque_connected, атомарное снятие eligibility, established bypass, fallback cutoff при отсутствии события; WARP_C5_CONNECT_IP_CUTOFF.md | deliverable |
| WARP-C6 | WARP | 4158–4188 | Auto-selection C0–C6: отдельные candidate generations, forwarded probe + stability window, expiry по WAN/endpoint/build; WARP_C6_AUTO_SELECTION.md | deliverable |
| WARP-9 | WARP | 4190–4234 | Experimental nested backend: dual-netns, inner control через base SO_MARK, TunnelDependencyLink, exact cleanup, proxy fallback с ограничениями; WARP_9_NESTED_BACKEND.md + WARP_9_DEPENDENCY_TRACE.md | deliverable |
| WARP-10 | WARP | 4236–4282 | Non-RU discovery: multi-provider quorum, attestation TTL, revocation при RU/stale, DNS через inner, IPv6 off, per-provider события, counter deltas; WARP_10_NON_RU_ATTESTATION.md + WARP_10_GEO_ROUTE_PROOF.md | deliverable |
| WARP-C7 | WARP | 4284–4321 | Outer/inner изоляция: независимые marks/policies, раздельные cutoff/bypass tokens, revoke inner при падении base/non-RU; WARP_C7_INSTANCE_ISOLATION.md | deliverable |
| WARP-C8 | WARP | 4323–4351 | Passive RST: наблюдение и классификация, enforcement off by default, canary suppression, rollback при регрессии; WARP_C8_RST_DEFENSE.md | deliverable |
| WARP-C9 | WARP | 4353–4392 | Camouflage API/UI/observability: trace schema v2, completeness/mismatch exposure, запрет claims invisibility, redaction; WARP_C9_PRODUCT_OBSERVABILITY.md + WARP_C9_CAUSAL_TRACE_VALIDATION.md | deliverable |
| WARP-C10 | WARP | 4394–4431 | Target validation: Keenetic MediaTek, candidate matrix, GSO/segmentation parity, все hard gates, rollback; иначе BLOCKED_TARGET_VALIDATION; WARP_CAMOUFLAGE_IMPLEMENTATION/VALIDATION_REPORT.md | deliverable |
| WARP-11 | WARP | 4433–4476 | Product integration: API/UI, Service Profile cloudflare-warp-masque, forbidden_countries [RU], FT/SP/IV companion deltas; WARP_11_PRODUCT_INTEGRATION.md | deliverable |
| WARP-12 | WARP | 4478–4530 | Release gate: Keenetic + Android validation, TestSession→Binding→RouteToken→PathProof, causal trace отчёт, cleanup ownership; иначе BLOCKED_TARGET_VALIDATION, no production claim; deliverable set включая warp-trace-schema-v2.md | deliverable |
| §75 Base DoD | WARP | 4536–4568 | Только B4, pin, consent, MTU до route, NDM verified, liveness перед route, path proof counters, trace completeness PASS | verification gate |
| §76 Non-RU DoD | WARP | 4570–4596 | Checkbox off by default, изоляция, two-provider quorum, revocation, no silent fallback, revocation latency измерена | verification gate |
| §76A Camouflage DoD | WARP | 4598–4622 | Отдельная авторизация, pinning, least-invasive auto, bounded budgets, cutoff, zero post-cutoff mutation, gates zero | verification gate |
| §76B Causal trace DoD | WARP | 4624–4643 | Единый versioned TransportTraceEnvelope, monotonic sequence, P0 не сэмплируются, trace I/O не блокирует packet path, trace==runtime state | verification gate |
| §77 Final invariants | WARP | 4645–4678 | 4 инварианта: authorized scoped traffic → verified WARP; camouflage только generation-owned до CONNECT-IP; trace completeness обязательна; non-RU без свежих provider evidence запрещён | MUST |
| Appendix B reports | WARP | 4762–4789 | Каждый stage report обязан содержать: stage ID, commits, requirements, tests, router status, trace schema, path-proof deltas, cleanup/rollback proof, verdict | deliverable |

## ABD (B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md) — 27 записей

| ID | Документ | Строки | Содержание (≤15 слов) | Тип |
|---|---|---|---|---|
| §0.3.1 MON↔ABD boundary | ABD | 135–183 | Нормативная цепочка MonitorAssessment→MonitorDiagnosticRequest+budget token→TargetPlanOverlay→run→BlockingProfile→MonitorDiagnosticResult; 7 объектов не взаимозаменяемы; ABD MUST NOT: listener, temporal state, subjects из DNS, stale request, trigger как разрешение | MUST |
| §0.4 Общие запреты (40) | ABD | 185–229 | 40 MUST NOT: byte≠packet threshold, один timeout не DPI, final BlockingProfile без completeness, recurrence≠independence, silent resolution replace, observer-unavailable≠target-failure, cross-generation merge и др. | MUST |
| §3.9 History ≠ BlockingProfile | ABD | 655–670 | Raw history не переиспользуется как профиль: нет plan identity, network context, packet/unique-byte counters, confidence, expiry | MUST |
| §3.10 Self-interference | ABD | 672–681 | Каждый probe mode доказывает свой path (native/production/candidate/transport); unlabeled path mixing invalidates evidence | MUST |
| §9.7 EvidenceAuthority | ABD | 1491–1511 | 4 уровня authority: passive-monitoring, provisional-fast, authoritative-abd, android-canary; финальный BlockingProfile только из AuthorityAuthoritativeABD | MUST |
| §9.8 ClientResolutionSnapshot | ABD | 1513–1539 | Immutable snapshot + AttemptResolutionBinding: query/CNAME/answers/TTL, per-address outcomes, exact endpoint привязан к snapshot | MUST |
| §19 BlockingProfile | ABD | 2282–2348 | Canonical immutable модель: components/DNS/infrastructure/hypotheses/controls/SearchPrior; NetworkDiagnosticProfile envelope версия 2; legacy v1 → только low-confidence | MUST |
| §24.1 Atomicity | ABD | 2821–2828 | temp+fsync+rename, content hash, bounded entries, идемпотентная миграция, no partial profile виден Discovery | MUST |
| §24.2 Schema versions | ABD | 2830–2845 | DiagnosticTargetPlan=1, DiagnosticAttemptEvidence=2, BlockingProfile=2, NetworkDiagnosticProfile=2, DiscoverySearchPrior=2, DetectorCapacityProfile=1 | MUST |
| §24.3 Resume conditions | ABD | 2847–2868 | Resume только при: тот же target-plan hash, совместимый build, тот же config gen/network context, evidence не expired; resumed run MUST revalidate; partial не даёт final profile | MUST |
| §24.4 DetectorCapacityProfile | ABD | 2870–2899 | Капсулирует параллельность/лимиты; calibration по NFQUEUE/RAM/CPU; concurrency = ниже всех safety thresholds, не max throughput | MUST |
| §24.6 Monitoring persistence | ABD | 2915–2930 | ABD хранит только bounded request/result linkage; не хранит temporal history; resume требует matching MonitoringEpoch | MUST |
| §42 Hard gates | ABD | 3581–3643 | 21 gate BlockingProfile/guided search (без target plan, mutation, direct authorization, cross-service, false savings) + 27 monitoring adapter gates (без overlay, expired accepted, recurrence как independence, cross-generation result) | verification gate |
| §43 Release verdicts | ABD | 3645–3655 | ABD_TARGET_PLAN_READY … ABD_MULTI_VANTAGE_READY и др.; +ABD_PRODUCTION_READY → MON_ABD_ESCALATION_READY | verification gate |
| ABD-1 | ABD | 3736–3752 | Baseline audit: карта detector/API/history, fixtures, backward-compat тесты; pinned refs rcd27/blockcheckw 0.9.2 и belotserkovtsev/ladon | deliverable |
| ABD-2 | ABD | 3754–3781 | User Target Plan: MonitorDiagnosticRequest + strict validator, TargetPlanOverlay + report, Service Profile merge, reject cross-client/expired; DiagnosticTargetPlan schema | deliverable |
| ABD-3 | ABD | 3783–3814 | Clean probe path: валидация generations/budget token, ObserverCapability + health lease, exact-endpoint и independent-resolution, MultiVantageComparison, self-interference detector, path proof | deliverable |
| ABD-4 | ABD | 3816–3841 | DNS differential: immutable ClientResolutionSnapshot, CNAME chain, per-address/family outcomes, independent-current resolution отдельным экспериментом | deliverable |
| ABD-5 | ABD | 3843–3874 | TLS/HTTP fingerprint matrix: EvidenceAuthority в каждом attempt, ProbeFailureCode ≠ FailureAttribution, staged deadlines, BodyProgressEvidence с partial unique-byte сохранением | deliverable |
| ABD-6 | ABD | 3876–3891 | QUIC ladder Q0–Q7, Version Negotiation/Retry, TCP-vs-QUIC сравнение, resource bounds; один target не implies global UDP block | deliverable |
| ABD-7 | ABD | 3893–3909 | L4 profiler: независимые packet/byte эксперименты, unique-byte accounting, validated packet layer; no drop_at_kb claim только по packet trigger, один origin не даёт high confidence | deliverable |
| ABD-8 | ABD | 3911–3927 | Dynamic infrastructure controls: bounded provider, ASN/subnet selectors, TTL/last-good, anti-abuse, deterministic sampling seed; no broad scanning | deliverable |
| ABD-9 | ABD | 3929–3953 | Evidence graph: recurrence только как metadata, provenance-only edges, passive/provisional не финальная поддержка, contradictions видимы и downgrade | deliverable |
| ABD-10 | ABD | 3955–3981 | BlockingProfile compiler: только authoritative complete evidence, MonitorAssessmentRef, profile ID запрещён при incomplete, temporal state вне профиля; profile не авторизует action | deliverable |
| ABD-11 | ABD | 3983–4017 | DDI adapter: DiscoverySearchPrior из профиля, DDI freshness обязательна, запрет Monitoring→Discovery/WARP handoff, no second optimizer, exhaustive fallback | deliverable |
| ABD-12 | ABD | 4019–4053 | UX/field/release: Monitoring adapter idempotency, authority в UX, shadow/cutover против Watchdog, capacity calibration, resume lifecycle, Keenetic+Android, verdict только от umbrella | deliverable |

## MON (B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md) — 33 записи

| ID | Документ | Строки | Содержание (≤15 слов) | Тип |
|---|---|---|---|---|
| §0.1 Strangler-решение | MON | 19–40 | Strangler-style replacement: compatibility adapters → MON core → shadow parity → controlled cutover → удаление legacy direct apply; monitor.go остаётся infrastructure-integrity | MUST |
| Migration-инвариант | MON | 10 | Нет flag-day rewrite; shadow/cutover; старый API/UI — временный compatibility adapter | MUST |
| Safety-инвариант | MON | 11 | Observation/recurrence/provisional failure ≠ BlockingProfile/ActionAuthorization/TransportAuthorization/production config change | MUST |
| §13 Goals | MON | 384–403 | MON наблюдает на реальном client traffic, temporal accumulation с decay/hysteresis, bounded ABD requests, Keenetic resource limits, deterministic rollback | MUST |
| §14 Non-goals | MON | 405–420 | Не: замена tables.Monitor, компиляция BlockingProfile, auto-WARP по timeout, production config change, router-origin ≡ Android proof | MUST |
| §15 Core invariants | MON | 422–441 | MonitorObservation ≠ BlockingProfile/Authorizations; recurrence ≠ independence; router-origin health ≠ forwarded-client health | MUST |
| §57 Compatibility | MON | 1443–1466 | Legacy /api/watchdog/* остаётся и транслируется в MON (pinned subject, bounded quick diagnostic, projection) | MUST |
| §58 Status projection | MON | 1467–1485 | Legacy поля выводятся из MON state; обязателен флаг compatibility_projection=true | MUST |
| §59 Direct apply removal | MON | 1487–1503 | applyBatchResults() disabled в production-safe; legacy_watchdog_direct_apply=true только unsafe dev, warning + hard-gate counter, не в beginner UI | MUST |
| §60 Cutover stages | MON | 1505–1532 | Фазы A shadow → B trigger shadow → C diagnostic cutover → D API cutover → E apply cutover → F cleanup; rollback документирован на каждой фазе | MUST |
| §61–63 Persistence/restart | MON | 1538–1570 | 5 отдельных store, versioned/atomic/checksum/bounded; restart: reattach или interrupted, expired leases invalidated, stale context demoted | MUST |
| §80 Migration parity | MON | 1933–1944 | Shadow-сравнение: legacy vs MON outcomes, FP/FN разницы, resource usage, no config mutations от shadow, no probe storms | verification gate |
| §81 Fault injection | MON | 1946–1961 | Сценарии: crash в checkpoint, disk full, queue overflow, clock jump, restart, ABD/DDI unavailable, WAN reconnect, legacy API spam | verification gate |
| §82 Real router | MON | 1963–1976 | Keenetic/Entware: NFQUEUE/TUN, PPE on/off, low memory, high DNS volume, router-origin vs forwarded separation, reboot persistence | verification gate |
| §83 Real Android | MON | 1978–1990 | Доказать: Android client identity, exact DNS correlation, passive observation, ABD escalation, no router-origin substitution | verification gate |
| §84 Observation/authority gates | MON | 1996–2005 | 6 gate == 0: observation→direct action, provisional profile, passive Discovery/WARP, fast lane action/promotion | verification gate |
| §85 Scope gates | MON | 2007–2017 | 7 gate == 0: destination-only deep trigger, cross-client/service/component/WAN/generation merge, router-origin как forwarded proof | verification gate |
| §86 Temporal gates | MON | 2019–2024 | duplicate evidence independence == 0, temporal persistence без time separation == 0, success suppressor ignored == 0 | verification gate |
| §91 Legacy migration gates | MON | 2076–2083 | shadow/active writer overlap == 0 и др.; release gate требует все MON-1..12, hard gates zero, ABD/DDI readiness, real router/Android proof | verification gate |
| MON-1 | MON | 2136–2153 | Audit и compatibility freeze: карта tables.Monitor/watchdog/Failure Inbox, fixtures, direct mutation path map, rollback plan | deliverable |
| MON-2 | MON | 2155–2172 | Core schemas и observation bus: MonitorScopeKey, MonitorObservation, authority taxonomy, bounded queues, no cross-merge, packet path non-blocking | deliverable |
| MON-3 | MON | 2174–2191 | Subjects/demand intake: MonitorSubject, pinned adapter, Service Profile subjects, CNAME/answer correlation, multi-IP outcome vector, intake budgets | deliverable |
| MON-4 | MON | 2193–2208 | Passive flow-health correlation: DNS/SNI/QUIC correlation, SPF adapter, router-origin/forwarded separation; SYN-ACK-only не универсальный success | deliverable |
| MON-5 | MON | 2210–2226 | Temporal accumulation: buckets, recurrence/independence scores, decay, recovery FSM; duplicates не повышают independence; cohorts не авторизуют | deliverable |
| MON-6 | MON | 2228–2243 | Source health/suppressors: heartbeat, PPE/capture visibility, suppressor engine, WAN transition; no auto-diagnose при stale visibility | deliverable |
| MON-7 | MON | 2245–2261 | Provisional fast lane и scheduler: bounded queues, resource leases, coalescing, cooldown; fast lane никогда не компилирует profile/action | deliverable |
| MON-8 | MON | 2263–2279 | ABD escalation adapter: MonitorDiagnosticRequest, overlay, resolution refs, run lifecycle; ABD — owner active probes, partial run не ready profile | deliverable |
| MON-9 | MON | 2281–2296 | DDI/Discovery интеграция: profile refs, stale handling, guided Discovery policy, WARP handoff; authoritative profile + DDI freshness обязательны | deliverable |
| MON-10 | MON | 2298–2313 | Canary/recovery/rollback observation: milestone correlation, binding recovery; router-origin proof не закрывает Android gate; rollback — action-plane решение | deliverable |
| MON-11 | MON | 2315–2332 | API/UI/persistence cutover: /api/monitor/v1, legacy adapter, durable stores, direct applier disabled, shadow/cutover reports, single source of truth | deliverable |
| MON-12 | MON | 2334–2354 | Field validation/release: lab, fault injection, Keenetic resources, real Android, privacy audit, hard-gate report; MON_PRODUCTION_READY только от umbrella | deliverable |
| §95 ABD alignment | MON | 2360–2372 | ABD v1.2 добавляет только adapter contracts; ABD MUST NOT поглощать observation/temporal state | MUST |

## DDI/TGB (B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md) — 31 запись

| ID | Документ | Строки | Содержание (≤15 слов) | Тип |
|---|---|---|---|---|
| §0.3 Общие запреты (12) | DDI/TGB | 71–87 | MUST NOT: profile как production config, skip target validation, cross-WAN profile, SNI без Discovery/canary, zero-byte drop за 5s, handled=true для zero-byte, unbounded idle sockets, потеря prefix, route recursion, скрытие saturation | MUST |
| §1 Issue #278 | DDI/TGB | 92–182 | Verified gaps: DiscoveryRequest/StartSuiteOptions без profile ID/context/freshness; HistoryEntry без context envelope → нельзя использовать как reusable Discovery input | MUST |
| §2 Issue #277 | DDI/TGB | 184–251 | Verified defect: 5s read deadline + handled=true,nil = silent destructive drop, блокирует оба fallback; DialObfuscatedDC ошибка тоже handled=true; нет bridge-specific timeouts/budgets | MUST |
| §15 Disposition rules | DDI/TGB | 902–910 | claimed/handoff/parked/rejected/terminal_error контракт; zero-byte deadline не может дать claimed или silent terminal_error | MUST |
| §16.1 Soft/hard deadlines | DDI/TGB | 930–949 | Defaults: first_byte_soft=15s, hard=45s, handshake=10s; soft MUST NOT закрывать соединение; monotonic time | MUST |
| §16.2 Zero-byte policy | DDI/TGB | 951–971 | Zero bytes → park в PendingHandshakeManager до hard deadline; close как idle_preconnect_expired с метрикой; lazy worker не дозванивается до первого байта | MUST |
| §32 DDI hard gates | DDI/TGB | 1562–1579 | 14 gate == 0: cross-WAN use, stale без revalidation, mutable pointer, hint без provenance, overrode baseline, skipped validation, disabled fallback, direct write, SNI promotion, capture bypass, false pass | verification gate |
| §33 TGB hard gates | DDI/TGB | 1581–1598 | 15 gate == 0: zero-byte handled drop, fixed 5s destructive timeout, unbounded pending, prefix loss/duplicate, route recursion, silent drop, deadline reset, secret in trace, false handshake | verification gate |
| §34 Release verdicts | DDI/TGB | 1600–1631 | DDI_SCHEMA/REVALIDATION/HINT_PLANNER/TARGET_VALIDATED/PRODUCTION_READY; TGB_STATE_MACHINE/PENDING_BUDGET/PREFIX_HANDOFF/ANDROID_VALIDATED/PRODUCTION_READY; ISSUE_278/277_RESOLVED требует proof, не только поле | verification gate |
| DDI-1 | DDI/TGB | 1637–1645 | Baseline audit: карта Detector/Discovery lifecycle, fixtures (DNS/TLS/RST/timeout/fat/SNI/IP block), negative fixtures stale/mismatch | deliverable |
| DDI-2 | DDI/TGB | 1647–1656 | Versioned profile schema: NetworkDiagnosticProfile, content hash, bounds, redacted export, migration contract | deliverable |
| DDI-3 | DDI/TGB | 1658–1666 | Network context: collector, exact/compatible/mismatch comparator, TTL state machine, invalidation на change, privacy tests | deliverable |
| DDI-4 | DDI/TGB | 1668–1676 | Profile compiler и persistence: raw suite → profile, provenance/confidence, atomic bounded store, legacy history, revoke/delete | deliverable |
| DDI-5 | DDI/TGB | 1678–1686 | Fast revalidation: bounded planner, evidence-specific probes, конфликты, no-side-effect sandbox | deliverable |
| DDI-6 | DDI/TGB | 1688–1696 | Discovery API: request/options extensions, selection modes, immutable snapshot, plan/hint-report endpoints, backward compat | deliverable |
| DDI-7 | DDI/TGB | 1698–1707 | Hint compiler: mapping rules, boost/penalty/defer, threshold seeding, allowed-SNI интеграция, baseline precedence, exhaustive fallback | deliverable |
| DDI-8 | DDI/TGB | 1709–1717 | UI/observability: profile selector, freshness badge, applied/suppressed объяснения, savings report, RU/EN | deliverable |
| DDI-9 | DDI/TGB | 1719–1727 | Integration/validation: same-seed A/B, stale/conflict tests, restart/migration, resource bounds, issue bundle | deliverable |
| DDI-10 | DDI/TGB | 1729–1737 | Router/target release: реальные Detector→Discovery прогоны, target-specific proof, measured savings, negative-control proof | deliverable |
| TGB-1 | DDI/TGB | 1739–1747 | Baseline audit: lifecycle map, репро 5s drop, fake-clock/conn fixtures, delayed-first-byte corpus | deliverable |
| TGB-2 | DDI/TGB | 1749–1756 | Структурный outcome contract вместо boolean ownership; disposition/reason; compatibility adapter при необходимости | deliverable |
| TGB-3 | DDI/TGB | 1758–1766 | First-data state machine: soft/hard deadlines, progress-aware handshake timeout, zero-byte no-drop, config snapshot | deliverable |
| TGB-4 | DDI/TGB | 1768–1776 | PendingHandshakeManager: global/per-client budgets, bounded lifecycle, overflow policy, shutdown/reload cleanup | deliverable |
| TGB-5 | DDI/TGB | 1778–1785 | Prefix-preserving handoff: immutable prefix, 0/1–3/4–63/64+ byte случаи, worker/direct replay, no duplicate/loss | deliverable |
| TGB-6 | DDI/TGB | 1787–1795 | Upstream route ladder: primary/worker/direct bounded plan, no recursion, dial failure handoff, terminal verdict | deliverable |
| TGB-7 | DDI/TGB | 1797–1805 | Config/migration/API: transparent subtree, defaults/validation, legacy behavior, live status, config generation | deliverable |
| TGB-8 | DDI/TGB | 1807–1815 | UI/diagnostics: beginner auto mode, advanced timeouts/budgets, pending status, reason trace, privacy-safe issue bundle | deliverable |
| TGB-9 | DDI/TGB | 1817–1825 | Packet-path/stress: TPROXY IPv4/IPv6, marks/original destination proof, 1000-connection stress, no leak benchmark | deliverable |
| TGB-10 | DDI/TGB | 1827–1836 | Keenetic/Android: репро #277, delayed connections > 5s, успешный bridge или bounded fallback, WAN flap/reboot | deliverable |
| DoD | DDI/TGB | 1866–1883 | Версии: profile versioned/scoped/fresh, hints не отменяют target proof и fallback, A/B measured, zero-byte никогда не silently claimed, prefix preserved, gates zero | verification gate |
