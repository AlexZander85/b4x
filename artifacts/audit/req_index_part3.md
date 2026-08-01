# Индекс нормативных требований — Part 3

Атомарный индекс требований по 5 документам репозитория D:\b4x (read-only аудит, 2026-07-31).
Метод: grep по идентификаторам (`FT-A[CDE]`, `FT-[R-V]`, `SP-2[0-9]`, `SP-3[0-9]`, `IV-[0-9]+`, `^## `, `^### `, stage) + чтение диапазонов строк.
Типы: `MUST` (императив), `gate` (hard gate), `suite` (validation suite), `verdict` (release/terminal verdict), `DoD` (definition of done), `int` (интеграция), `UX`, `schema`, `coverage`, `stage` (patch-plan этап), `inv` (инвариант), `proc` (процессный).

---

## 1. B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md (3359 строк)

| ID | Документ | Строки | Содержание | Тип |
|---|---|---|---|---|
| §17.1 | FIELD_TEST v1.5 | 2030–2046 | CSI-интеграция: TestSession roles, trace, analyzer, mandatory same-client control hard gate для Discovery/canary | int |
| §17.2 | FIELD_TEST v1.5 | 2048–2064 | RST/GSO-интеграция: offload metadata, GSO/MSS parity, RST observe, mode-specific gates, stale-validation invalidation | int |
| FT-Q | FIELD_TEST v1.5 | 2461–2511 | Unified WARP-aware promotion gate; потребляет FT-M…FT-P и FT-AC…FT-AE; раздельные verdict'ы, base WARP не маскирует camouflage/non-RU | gate |
| FT-R | FIELD_TEST v1.5 | 2512–2528 | Silent observation: unique-range TCP accounting, zero-verdict observe, downgrade behavior; артефакты FT-R_* | suite |
| FT-S | FIELD_TEST v1.5 | 2530–2548 | False-positive suppression: fast-parallel/HLS/prefetch, benign fixtures → zero active recovery | suite |
| FT-T | FIELD_TEST v1.5 | 2550–2561 | Differential causal proof: bounded A/B, candidate success без observed current-path failure не даёт PASS | suite |
| FT-U | FIELD_TEST v1.5 | 2563–2583 | Scoped recovery, WARP fallback, rollback: lease TTL/cooldown, no recursive fallback, same-client Gmail/Google controls | suite |
| FT-V | FIELD_TEST v1.5 | 2585–2606 | Silent recovery long-run gate: 4 вердикта (OBSERVE→RECOMMEND→AUTO_CANARY→COHORT_PROMOTED); отсутствие evidence → BLOCKED_TARGET_VALIDATION | gate |
| FT-AC | FIELD_TEST v1.5 | 3035–3069 | WARP causal envelope: TransportTraceEnvelope, EventID/TraceID/Sequence, generations, 9 mandatory mutants, event durability | suite |
| FT-AD | FIELD_TEST v1.5 | 3071–3102 | Route/path proof + forwarded correlation: TransportPathProof, counter deltas, Android BindingID/RouteTokenID/SessionGen, 7 blocking fixtures | suite |
| FT-AE | FIELD_TEST v1.5 | 3104–3144 | Nested WARP, geo quorum, DNS/IPv6 path, cleanup ownership; 12 mandatory negative cases | suite |
| WARP_CAUSAL_TRACE_READY | FIELD_TEST v1.5 | 3146–3152 | Требует FT-AC+FT-AD+FT-AE PASS, WARP v1.2 hard gates zero, real Keenetic path-counter, real Android forwarded-flow correlation | verdict |
| §26 field hard gates | FIELD_TEST v1.5 | 3154–3164+ | Field Test Controller fails claim при ненулевом счётчике; missing/unread gate ≠ zero | gate |
| п.95 DoD | FIELD_TEST v1.5 | 3273 | FT-AC…FT-AE имеют machine-readable stage report, requirement coverage и source addendum hash | DoD |

Итого по документу 1: 14 требований.

---

## 2. B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md (3732 строки)

| ID | Документ | Строки | Содержание | Тип |
|---|---|---|---|---|
| §18 required-before (runtime apply) | SP v1.6 | 1570–1577 | immutable config gen, transactional apply, last-good, rollback, schema validation, dry-run | MUST |
| §18 required-before (auto local validation) | SP v1.6 | 1579–1584 | Discovery sandbox, structured ProbeOutcome, resource budgets, canary | MUST |
| §18 required-before (optimized YouTube pack) | SP v1.6 | 1586–1592 | API/UI/video probes, component ranking, field trace contract, multi-client isolation, CDN switch | MUST |
| §18 required-before (beginner UI) | SP v1.6 | 1594–1599 | backend profile API, ownership metadata, compile diff, basic/advanced UI foundation | MUST |
| §18 required-before (transport-required profiles) | SP v1.6 | 1601–1619 | client-configured: healthcheck/secret storage/artifact generator; router-tunnel: stage 33 fallback, no double processing, leak/fail-open policy | MUST |
| §18 required-before (direct-strategy runtime apply) | SP v1.6 | 1624–1647 | Завершённые CSI-1…CSI-10 и 9 capabilities; отсутствие → не production candidate | MUST |
| §18 required-before (GSO-aware execution) | SP v1.6 | 1649–1661 | Gates H1–H5; normalize-if-required/direct-if-certified только после target validation; gso_policy=inherit везде | MUST |
| §18 required-before (Passive RST exposure) | SP v1.6 | 1663–1674 | UI-observation — H6; active suppression — H7–H10; profile не повышает runtime mode | MUST |
| §18 required-before (YouTube pack promotion) | SP v1.6 | 1676–1686 | CSI release gate + GSO parity + RST mode gate + same-client controls + rollback proof | MUST |
| Telegram pack | SP v1.6 | 1523–1550 | transport-required; не обещает обход IP-block через fake/split; maturity structured; не включает global tunnel автоматически | MUST |
| SP-11 | SP v1.6 | 2351–2369 | Telegram transport-required pack: DC probe, MTProxy/SOCKS5 handoff, no fake/split primary default, QR только из локальной конфигурации | suite |
| Custom templates | SP v1.6 | 1552–1561 | 4 шаблона: custom-domain-group, custom-streaming-service, custom-api-plus-media, custom-transport-required-service | schema |
| SP-20 | SP v1.6 | 2503–2508 | Silent recovery capability projection: manifest schema, upper bound без runtime, reject destination-global/recursive/rollback-less | suite |
| SP-21 | SP v1.6 | 2510–2516 | False-positive-safe UX: observe default, effective/configured separation, lease и rollback controls | UX |
| SP-22 | SP v1.6 | 2518–2524 | Recovery binding compiler: ordered bindings, exact client/service/component/config-gen, last-good/cooldown/TTL/max-attempts | suite |
| SP-23 | SP v1.6 | 2526–2532 | Silent recovery validation/promotion: карта FT-R…FT-V, SPF-1…SPF-10, раздельные verdict'ы, invalidation | coverage |
| §28A.4 | SP v1.6 | 3235–3255 | WARP не primary recommendation при DNS/QUIC/SNI/TLS/HTTP/L4 evidence; WARP primary только при IP/SYN/CIDR; nested-nonru только при geo-constraint; camouflage отдельно | MUST |
| §28A.5 | SP v1.6 | 3257–3290 | warp_recommendation YAML: transport_kind, bundled_engine_available, enrollment_supported, base_transport_capable, causal_trace_ready, path_proof_supported, forwarded_binding_correlation, target_canary_supported, current_runtime_state | schema |
| §28A.6 | SP v1.6 | 3292–3322 | Scoped validation plan: 10 шагов bounded transaction, freeze scope, direct-vs-WARP сравнение, rollback token'ов, TransportRecommendationValidated | proc |
| SP-30 | SP v1.6 | 3604–3614 | BlockingProfile transport-recommendation compiler: typed TransportRecommendation, base-WARP-only, без ActionAuthorization, expiry | suite |
| SP-31 | SP v1.6 | 3616–3628 | Scoped WARP recommendation UX + validation transaction: тест без изменения постоянных правил, раздельные test/production авторизации | UX |
| SP-32 | SP v1.6 | 3630–3639 | WARP recommendation release: FT-M/FT-W…Z/FT-AC…AD, IV-14/15/17, downgrade при expiry, verdict PROFILE_WARP_RECOMMENDATION_READY | gate |

Итого по документу 2: 22 требования.

---

## 3. B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md (4291 строка)

| ID | Документ | Строки | Содержание | Тип |
|---|---|---|---|---|
| §21 acceptance 1–12 | IV v1.5 | 1038–1051 | Автопроверка subsystem, real packet path, router отдельно, Android API+ADB, fault injection, отдельные verdict'ы, bundle, PASS невозможен при MUST-нарушении | DoD |
| §23.1 registry sources | IV v1.5 | 1100–1137 | Machine-readable registry: ARCH-v2.3, PLAN Stage 1–36, CSI-1…10, H1…10, PPE-1…8, FT-A…L, SP-1…15, IV-1…12; запрещены MUST без TestID и скрытые исключения | proc |
| §23.2 verdict model | IV v1.5 | 1139–1181 | Terminal verdicts: PASS/FAIL/BLOCKED_CAPABILITY/BLOCKED_TARGET_VALIDATION и др.; any required BLOCKED_TARGET_VALIDATION → subsystem BLOCKED → release gate не пройден | verdict |
| §35 (PPE) | IV v1.5 | 1878–1948 | Suite Keenetic PPE per-flow offload: capability detection, rule compiler/scope, bidirectional visibility self-test, lifecycle, performance | suite |
| §36.1 schema/compiler | IV v1.5 | 1958–1968 | Service-profiles suite: manifest limits/provenance, canonical compile hash, no executable fields, import/export без secrets | suite |
| §36.2 policy projection | IV v1.5 | 1970–1981 | shared IP capture-only, negative_sni_override, профиль не владеет NFQUEUE/marks/tokens, uncertified GSO rejected | suite |
| §36.3 YouTube pack | IV v1.5 | 1983–1993 | Компоненты api/ui/video; official+ReVanced, CDN switch, multi-client, same-client Gmail/Google controls | suite |
| §36.4 additional profiles | IV v1.5 | 1995–2002 | direct/hybrid без broad capture, Discord hybrid, Telegram transport-required без fake/split как primary, tunnel scope/leak/failover | suite |
| §36.5 UI | IV v1.5 | 2004–2006 | Basic/Advanced — два представления одной config generation | suite |
| §38.1 registry hard gates | IV v1.5 | 2080–2099 | Meta-suite: blocking_requirements_without_tests==0, duplicate ids==0 и др. | gate |
| §38.3 verdict aggregation | IV v1.5 | 2113–2127 | FAIL не маскируется PASS; ERROR≠PASS_WITH_LIMITATIONS; BLOCKED_TARGET_VALIDATION blocks release; mutation tests | gate |
| §38A.1 WARP requirement domains | IV v1.5 | 2197–2235 | Registry содержит WARP-1…12, WARP-C1…10, FT-M…Q, FT-AC…AE, SP-16…19, WARP_CAUSAL_TRACE_READY | coverage |
| §38A.9 WARP v1.2 hard gates | IV v1.5 | 2418–2479 | 52 счётчика (secret leak, recursion, non-RU gates, camouflage cutoff, trace events); not-run ≠ zero, WARP_CAUSAL_TRACE_READY требует FT-AC+AD+AE PASS | gate |
| §52 release verdict registry | IV v1.5 | 3871–3918 | WARP_CAUSAL_TRACE_READY требует FT-AC…AE, path proofs, Android correlation, nested/geo/DNS/IPv6, cleanup closure; verdict'ы не транзитивны | verdict |
| §52.1 blocked verdicts | IV v1.5 | 3920–3938 | BLOCKED_TARGET_VALIDATION, BLOCKED_TRACE_SCHEMA/COMPLETENESS/TARGET_VALIDATION/RUNTIME_MISMATCH и др. | verdict |
| IV-1 | IV v1.5 | 3266–3274 | Requirement and suite registry: canonical IDs, coverage mapping, orphan detection | suite |
| IV-2 | IV v1.5 | 3276–3284 | Verdict engine: terminal model, aggregation, limitation policy, false-pass mutation tests | suite |
| IV-3 | IV v1.5 | 3286–3292 | Validation API/CLI contract v1.3: list/plan/run/status/events/cancel/report, parity, dry-run | suite |
| IV-4 | IV v1.5 | 3294–3296 | Stage 1–36 suite completion; Stage 36 E2E не заменяет unit/component тесты | suite |
| IV-5 | IV v1.5 | 3298–3300 | DNS/UDP/QUIC/IP-family suites (§29–31) | suite |
| IV-6 | IV v1.5 | 3302–3304 | Transport/built-in WARP/transactional lifecycle (§33–34, 38A base), WARP-1…12, forwarded path proof | suite |
| IV-7 | IV v1.5 | 3306–3308 | PPE target suite (§35), карта PPE-1…8 | suite |
| IV-8 | IV v1.5 | 3310–3312 | CSI/GSO/RST/WARP-camouflage unified safety (§26–28, 38A), WARP-C1…C10 | suite |
| IV-9 | IV v1.5 | 3314–3316 | Service Profile conformance (§36), карта SP-1…19 | suite |
| IV-10 | IV v1.5 | 3318–3320 | Field Test contract conformance (§37), карта FT-A…FT-AE | suite |
| IV-11 | IV v1.5 | 3322–3324 | Validation infrastructure meta-suite (§38): completeness, evidence integrity, reproducibility | suite |
| IV-12 | IV v1.5 | 3326–3338 | Full WARP-aware release orchestration (§40): раздельные verdict'ы, cleanup, full-fork claim требует WARP_CAUSAL_TRACE_READY | suite |
| IV-13 | IV v1.5 | 3341–3350 | Silent Path Failure false-positive and scoped-recovery suite | suite |
| §45 criteria 13–42 | IV v1.5 | 3354–3385 | Расширенные acceptance (1.1/1.2): coverage Stage 1–36, DomainOnly semantics, SNI revocation, QUIC/NAT, RST distinguish, transactional hot apply, PPE, profile compiler, BLOCKED_TARGET_VALIDATION, reproducible bundle | DoD |
| §45 criteria 43–67 (1.2, WARP) | IV v1.5 | 3391–3417 | WARP: WARP-1…12/WARP-C1…10 coverage, SBOM/provenance, no external usque, forwarded W4 proof, camouflage cutoff, non-RU leak blocking, раздельные base/camouflage/non-RU verdict'ы, BLOCKED_TARGET_VALIDATION | DoD |
| §45 criteria 68–86 (1.3, silent) | IV v1.5 | 3420–3440 | Silent Path: SPF-1…10 coverage, observe non-mutating, unique-range progress, suppressors, exact-scope recovery, раздельные verdict'ы, meta-suite детектирует bypass | DoD |
| §56 criteria 87–114 | IV v1.5 | 4107–4136 | Detector v2/DDI/TGB: ABD/DDI/TGB coverage, clean baseline, evidence families, BlockingProfile immutable, A/B truthful, ISSUE_277/278 | DoD |
| §56 criteria 115–146 | IV v1.5 | 4139–4170 | WARP causal trace: source hash, FT-AC…AE/IV-17 mappings, event schema/generations, counter-delta proof, W4 correlation, nested parent/child, geo quorum, DNS/IPv6 observed, cleanup ledger, WARP_CAUSAL_TRACE_READY не выводится из connectivity; full-fork PASS требует его | DoD |
| IV-14 | IV v1.5 | 4050–4056 | ABD conformance: ABD-1…12, target plan, clean path, EvidenceGraph, BlockingProfile, ABD verdict'ы | suite |
| IV-15 | IV v1.5 | 4058–4065 | DDI/guided-search causal: DDI-1…10, freshness, priors, full fallback, target A/B, issue #278 | suite |
| IV-16 | IV v1.5 | 4067–4074 | Telegram bridge lifecycle: TGB-1…10, delayed-first-data FSM, pending budgets, issue #277 | suite |
| IV-17 | IV v1.5 | 4078–4105 | WARP causal tracing и validation-of-observability: trace schema, generations, counter deltas, Android chain, geo quorum, cleanup, mutants; WARP_CAUSAL_TRACE_READY только после synthetic+Keenetic+Android evidence | suite |
| §59 source binding | IV v1.5 | 4270–4291 | Цепочка: WARP addendum v1.2 (sha256 87c909…) → field contract v1.5 → umbrella IV-17 → verdict WARP_CAUSAL_TRACE_READY; final invariant из 8 компонентов | coverage |

Итого по документу 3: 39 требований (включая 5 подразделов §36, 4 группы acceptance criteria и verdict/registry блоки).

---

## 4. B4_FORK_PATCH_PLAN.md (1671 строка)

Уровни работ (этапы A/B/C): Level A — Core Fix (обязательно), Level B — Productization (обязательно до rollout), Level C — Strategy Catalog (после A и B; запрещён обход незавершённого classifier).

| ID | Документ | Строки | Содержание | Тип |
|---|---|---|---|---|
| Stage 1 | PATCH_PLAN | 88–127 | Baseline implementation audit; выход docs/audit/b4-1.73-flow-path.md | stage |
| Stage 2 | PATCH_PLAN | 130–187 | Regression fixtures: TLS/DNS/TCP/Android corpus | stage |
| Stage 3 | PATCH_PLAN | 190–215 | Config/version scaffolding: generation ID, feature flags, defaults observe/off | stage |
| Stage 4 | PATCH_PLAN | 220–271 | Capture Envelope + processed provenance mark, queue readiness, offload self-check | stage |
| Stage 5 | PATCH_PLAN | 276–320 | ClassificationPhase/Evidence/Confidence; deterministic policy | stage |
| Stage 6 | PATCH_PLAN | 323–351 | ClientKey: IP/MAC/ifindex/VLAN, late ARP, bounded cache | stage |
| Stage 7 | PATCH_PLAN | 354–393 | Clean SYN pass + TCP FSM skeleton; инвариант SYN+no payload → NF_ACCEPT | stage |
| Stage 8 | PATCH_PLAN | 398–434 | Bounded HostHintStore: HintKey(client,dst,proto), absolute expiry, generation revalidation | stage |
| Stage 9 | PATCH_PLAN | 437–463 | Structured DNS parser: A/AAAA/CNAME/HTTPS/SVCB/ECHConfig, bounds/fuzz | stage |
| Stage 10 | PATCH_PLAN | 466–499 | DNS → first-flow integration: DoH/system DNS, negative → diagnostic only | stage |
| Stage 11 | PATCH_PLAN | 502–526 | QUIC → TCP handoff: source-scoped, no global IP overwrite | stage |
| Stage 12 | PATCH_PLAN | 529–562 | NFQ decision integration + DomainOnly v2 (strict/scoped-hints/legacy/disabled) | stage |
| Stage 13 | PATCH_PLAN | 567–594 | Structured TLS metadata: SNI/ALPN/ECH/ClientHello size, no unbounded alloc | stage |
| Stage 14 | PATCH_PLAN | 597–635 | Observe-only TCP reassembly: RangeSet, overlap policy, memory budgets | stage |
| Stage 15 | PATCH_PLAN | 638–663 | ECH-aware evidence policy: no final unknown, contradiction handling | stage |
| Stage 16 | PATCH_PLAN | 666–709 | Auto hold/replay: off/observe/auto/always-debug; все abort paths release unchanged | stage |
| Stage 17 | PATCH_PLAN | 714–762 | Stream-offset/semantic-marker planner: markers ClientHello/SNI/host/SLD | stage |
| Stage 18 | PATCH_PLAN | 765–796 | First-flight-only + retransmission idempotency: ActionTokenStore | stage |
| Stage 19 | PATCH_PLAN | 799–826 | Executor fail-safe: checksums, mark verification, budgets, fail-open | stage |
| Stage 20 | PATCH_PLAN | 831–865 | Metrics, trace и issue bundle v2: redacted, no raw ClientHello by default | stage |
| Stage 21 | PATCH_PLAN | 870–907 | Isolated Experiment Sandbox: baseline-none/production/candidate, dedicated queue | stage |
| Stage 22 | PATCH_PLAN | 910–947 | Structured ProbeOutcome + layered verdict: L4/TLS/HTTP/TTFB/body/throughput | stage |
| Stage 23 | PATCH_PLAN | 950–994 | Adaptive matrix + shadow probes: vary one dimension, no Cartesian explosion | stage |
| Stage 24 | PATCH_PLAN | 997–1039 | Passive Failure Candidate Inbox: UNREPLIED/SYN_SENT inputs, no auto destructive action | stage |
| Stage 25 | PATCH_PLAN | 1044–1076 | Real Android ClientHello capture: selected client, redaction, provenance | stage |
| Stage 26 | PATCH_PLAN | 1079–1120 | Fake Profile Compiler: fingerprint-preserving, MTU-aware, не active автоматически | stage |
| Stage 27 | PATCH_PLAN | 1125–1177 | Transactional apply, last-good, canary, cooldown, rollback | stage |
| Stage 28 | PATCH_PLAN | 1184–1214 | Marker-based multisplit/multidisorder; только после Core Fix + Productization DoD | stage |
| Stage 29 | PATCH_PLAN | 1217–1241 | Hostfakesplit: confidence-gated, ECH/no-host unavailable | stage |
| Stage 30 | PATCH_PLAN | 1244–1267 | Fake payload catalog + bounded auto-selection; promotion после canary | stage |
| Stage 31 | PATCH_PLAN | 1270–1301 | Fakedsplit/fakeddisorder + TLS record split; высокий confidence, kill switch | stage |
| Stage 32 | PATCH_PLAN | 1304–1326 | Controlled RST + RST-path diagnostics; не auto-select по inferred hop | stage |
| Stage 33 | PATCH_PLAN | 1331–1361 | Confidence-based TUN/SOCKS fallback: SO_MARK isolation, healthcheck, cooldown | stage |
| Stage 34 | PATCH_PLAN | 1366–1396 | Backend config/API: schema migration, safe defaults, import/export без raw artifacts | stage |
| Stage 35 | PATCH_PLAN | 1399–1424 | UI: classifier/Discovery/Lab/Failure Inbox экраны, basic/advanced, warnings | stage |
| Stage 36 | PATCH_PLAN | 1430–1481 | Controlled router validation: 14 Android-сценариев, success metrics, acceptance по DoD | stage |
| Gate 1 | PATCH_PLAN | 1549–1556 | Hold/replay только после verified capture envelope, stable reassembly, benchmark, release paths | gate |
| Gate 2 | PATCH_PLAN | 1558–1565 | Planner mutation только после decision/evidence, clean SYN, FSM, ActionToken tests | gate |
| Gate 3 | PATCH_PLAN | 1567–1574 | Optional strategies только после Core Fix DoD, structured Discovery, canary/rollback | gate |
| Gate 4 | PATCH_PLAN | 1576–1584 | Production rollout только после field matrix, no cross-client leakage, resource budget, rollback | gate |
| PR decomposition | PATCH_PLAN | 1487–1543 | PR A1/A2/B/C/D/E/F1-F5/G1-G5/H/I; Core Fix нельзя объединять с UI/strategy PR | proc |

Итого по документу 4: 43 требования (3 уровня + 36 stages + 4 gates).

---

## 5. B4_FORK_ARCHITECTURE_v2.4.md (2998 строк)

### 5.1. Главные инварианты (§5, строки 203–345)

| ID | Строки | Содержание | Тип |
|---|---|---|---|
| §5.1 | 205–214 | Classification before action: никакой fake/split/duplicate/disorder без решения classifier | inv |
| §5.2 | 216–225 | Clean SYN + empty payload + нет SYN-техники → NF_ACCEPT | inv |
| §5.3 | 227–236 | Fail-open: release unchanged, clear state, record reason, continue direct | inv |
| §5.4 | 238–240 | Source scope: DNS/QUIC evidence по умолчанию включает identity клиента | inv |
| §5.5 | 242–244 | Logical first-flight idempotency: один ClientHello — один ActionToken | inv |
| §5.6 | 246–248 | Config generation safety: no mutable config pointers в flow/hint state | inv |
| §5.7 | 250–260 | Bounded resources: memory/per-client/per-flow limits, TTL, eviction, fail-open | inv |
| §5.8 | 262–264 | Provenance mark для каждого injected/replayed packet | inv |
| §5.9 | 267–280 | CaptureCandidate ≠ ActionAuthorization; IP/CIDR/port match не разрешает destructive action | inv |
| §5.10 | 282–293 | Полный service scope: ClientKey+SetID+Component+NetworkContext+ConfigGeneration | inv |
| §5.11 | 295–305 | Observation ≠ diagnosis ≠ action; recurrence не заменяет независимые evidence families | inv |
| §5.12 | 307–314 | Visibility before inference: incomplete bidirectional visibility блокирует hold/auto-recovery/promotion | inv |
| §5.13 | 316–318 | Useful progress: ACK-only/dup/retransmission не достаточны для silent recovery | inv |
| §5.14 | 320–322 | Exact client-resolution binding: probe привязан к DNS-ответу, виденному клиентом | inv |
| §5.15 | 324–335 | Transport path proof: promotion требует causal chain ClientKey→Binding→counters→generation→milestone | inv |
| §5.16 | 337–339 | Capability projection, не ownership: профили не владеют executor/WARP/monitoring/lease | inv |
| §5.17 | 341–343 | No recursive fallback: transport/recovery graph acyclic; WARP не fallback сам себе; control path не уходит direct | inv |

### 5.2. Hold/replay (§42–45, строки 1213–1287)

| ID | Строки | Содержание | Тип |
|---|---|---|---|
| §42 HeldPacket | 1215–1230 | HeldPacket структура; holding только в bounded reassembly mode | schema |
| §43 Abort/release paths | 1232–1242 | Каждый hold path: complete/timeout/FIN-RST/pressure/malformed/shutdown/generation-change — все release unchanged или fail-open | MUST |
| §44 Stream-to-packet map | 1244–1261 | Планировщик в logical stream offsets, executor → TCP sequence ranges | schema |
| §45 Semantic markers | 1263–1286 | Маркеры ClientHello/SNI/host/SLD; marker resolver только на complete parsed ClientHello; ECH → unavailable | schema |

### 5.3. WARP (§132–136, строки 2796–2833)

| ID | Строки | Содержание | Тип |
|---|---|---|---|
| §132 Base transport architecture | 2798–2812 | Bundled version-pinned b4-warpd; без runtime downloads и внешнего usque; chain enrollment→pin→CONNECT-IP→TUN→scoped route | MUST |
| §133 Scope and path proof | 2814–2816 | WARP не global default; только exact authorized targets; promotion требует current causal trace + counter deltas, no direct leak | MUST |
| §134 Camouflage | 2818–2820 | Только при отдельной авторизации; established MASQUE bypasses mutation; post_cutoff_mutations==0 | MUST |
| §135 Nested WARP и non-RU | 2822–2826 | Parent/child SessionGen, dependency link, ownership; non-RU gate: multi-provider quorum, IP continuity, DNS/IPv6 proof, prompt revocation | MUST |
| §136 Causal observability и cleanup | 2828–2832 | Generation-aware события для всех transitions; P0 нельзя silently sample; own cleaned, foreign не трогать; verdict'ы WARP_BASE_READY/WARP_CAUSAL_TRACE_READY | MUST |

### 5.4. Ключевые архитектурные разделы (общая архитектура)

| ID | Строки | Содержание | Тип |
|---|---|---|---|
| §6 Полный pipeline | 349–405 | Packet→evidence→decision→plan→execute полная цепочка и потоки данных | arch |
| §7 Пакетная структура | 407–515 | Модульная декомпозиция пакетов/компонентов | arch |
| §8 Service ownership | 517–535 | Сервисные компоненты и зоны ответственности | arch |
| §9–14 Identity/evidence/decision | 539–704 | ClientKey, ClassificationPhase, evidence model, порядок, confidence, ambiguity | arch |
| §27–30 Capture envelope | 945–1003 | Обязательный контракт envelope, provenance mark, queue readiness, offload self-check | arch |
| §32–38 TCP FSM/reassembly | 1022–1154 | FSM правила, reassembly modes, overlap policy, exact declared length | arch |
| §40–41 ECH policy | 1180–1211 | ECH evidence, confirmation/contradiction | arch |
| §49 Amplification budget | 1349–1363 | Бюджеты amplification для injected packets | arch |
| §50–53 Strategy model | 1366–1442 | Transport technique ≠ fake profile; preconditions; TLS record split | arch |
| §60 Isolated sandbox | 1544–1576 | Изолированный Discovery sandbox | arch |
| §75–79 Runtime/canary/rollback | 1847–1916 | Transactional apply, last-good, canary, cooldown, rollback | arch |
| §120–121 Evolution/monitor | 2674–2703 | Evolutionary replacement, monitor model | arch |
| §142–143 Principal verdicts и hard gates | 2886–2930 | Глобальные классы hard gates | arch |
| §145 No flag-day migration | 2951+ | Запрет flag-day миграций | arch |

Итого по документу 5: 40 требований (17 инвариантов + 4 Hold/replay + 5 WARP + 14 ключевых разделов).

---

## Сводка

| Документ | Количество требований |
|---|---|
| 1. B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md | 14 |
| 2. B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md | 22 |
| 3. B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md | 39 |
| 4. B4_FORK_PATCH_PLAN.md | 43 |
| 5. B4_FORK_ARCHITECTURE_v2.4.md | 40 |
| **Итого** | **158** |

### 5 самых важных требований

1. **WARP_CAUSAL_TRACE_READY** (FIELD_TEST 3146–3152, IV 3917, 2481–2489, ARCH §136): сквозной release verdict — FT-AC+FT-AD+FT-AE PASS, все WARP hard gates zero, real Keenetic path-counter proof, real Android forwarded-flow correlation; не выводится из connectivity (IV п.140); обязателен для full-fork PASS при WARP в scope (IV п.146).
2. **§28A.5 warp_recommendation YAML** (SP 3257–3290): 9 полей capability projection управляют показом кнопки "Проверить через WARP"; causal_trace_ready/path_proof обязательны до production recommendation.
3. **§133 WARP scope and path proof** (ARCH 2814–2816) + **FT-AD** (3071–3102): WARP не global default; promotion требует current TransportPathProof с packet/byte counter deltas и BindingID/RouteTokenID/SessionGen.
4. **IV-17 WARP causal tracing suite** (IV 4078–4105): validation-of-observability с mutants; единственный источник verdict'а WARP_CAUSAL_TRACE_READY.
5. **BLOCKED_TARGET_VALIDATION** (IV 1149, 3382, 3414, 3438, 3930): missing target evidence никогда не даёт PASS; blocks release; применяется на всех уровнях (field, silent, WARP).

### Противоречия и неоднозначности

1. **Нумерация acceptance criteria**: в задании указано 1..77 (1–59/60–67/68–77), фактически в документе IV v1.5 критериев 86: §21 — 1–12; §45 (заголовок "редакции 1.3") содержит 13–42; затем подразделы 43–67 (1.2) и 68–86 (1.3). Сдвиг: критерии 1.2 фактически 43–67, а не 60–67; граница 1.3 — 68, а не 68–77 продолжается до 86.
2. **Заголовок §45** ("Расширенные acceptance criteria редакции 1.3") вводит в заблуждение: блок 13–42 не помечен редакцией, хотя следует за §44 и логически относится к 1.1/1.2-контенту; версии критериев не отделены явными маркерами.
3. **Несогласованные ссылки на версии документов**: SP v1.6 §28A.5/§28A.6 ссылаются на "Service Profiles v1.5 compiler" (IV 2406) и "Field Test v1.5", при этом ARCH 15 (п.2461 FIELD_TEST) ссылается на "B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM v1.5" (строка 25), тогда как текущая версия — v1.6; цепочка документов (FIELD_TEST 25) отстаёт на одну редакцию.
4. **Дублирование verdict-контракта**: WARP_CAUSAL_TRACE_READY определён в двух документах (FIELD_TEST 3146–3152 и IV 3905–3918) с разным составом условий (FIELD_TEST: 3 суита + hard gates; IV: + trace schema compatibility + state parity + real Keenetic/Android); ARCH §136 добавляет "WARP_BASE_READY" как отдельный verdict. Требования согласованы по духу, но не текстуально идентичны.
5. **Источники требований registry (IV §23.1, 1100–1113) устарели**: перечисляют IV-1…IV-12, FT-A…FT-L, SP-1…SP-15 — не включают IV-13…IV-17, FT-AC…FT-AE, SP-20…SP-23, SP-30…SP-32, добавленные редакциями 1.2–1.5 (эти добавлены отдельными реестрами §44/§49/§58).
6. **Порог "16 KiB" в PATCH_PLAN (929–930)**: "success threshold > typical 16 KiB cutoff" помечен как "classifier label, not hard-coded logic" — потенциальный конфликт с IV §22 body policy, требующей exact offset persistence; явного согласования порога между документами нет.
7. **SP §28A.4 vs SP-30**: §28A.4 запрещает WARP-recommendation при "local WAN outage/control failure" (forbidden), но SP-30 DoD допускает рекомендацию при "one destination IP, unhealthy controls" — формулировки расходятся в трактовке unhealthy controls (DoD описывает их как не-достаточные, таблица 28A.4 — как forbidden-кейс); требуется уточнение границы.
8. **PATCH_PLAN ссылается на ARCH v2.3** (строка 4), а цепочка документов (FIELD_TEST 15) — на "B4_FORK_ARCHITECTURE.md v2.3", хотя в репозитории лежит v2.4; патч-план не переиздан под v2.4.
