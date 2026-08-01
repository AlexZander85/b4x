# Аудит пакета `src/warp` против 44 требований WARP v1.2

**Дата:** 2026-07-31
**Объект:** `D:\b4x\src\warp` (18 исходников + 18 тест-файлов = 36 файлов; в задании указано 24 — фактически 36)
**Метод:** полное чтение всех исходников и тестов; grep по ключевым символам; `go test ./warp/...` и `go vet` в `golang:1.25.3` (Docker, `src` смонтирован read-only) — 19/19 PASS, vet чистый. Локальный Go toolchain на хосте отсутствует.
**Статус пакета в production:** не подключён — 0 импортеров `github.com/daniellavrushin/b4/warp` во всём `src/` (подтверждено grep по всем `*.go` вне пакета, включая `nfq`, `http`, `config`). Все реализации ниже помечены `unwired`.

Характер пакета: **модель + валидация без side-effect** — только типы, структуры, pure-функции и валидаторы. В пакете нет ни одного системного вызова (нет ioctl/setsockopt/netlink/Unix socket), нет сетевого кода, нет persistence, нет HTTP-обработчиков, нет горутин, нет счётчиков hard gates, нет эмиссии событий.

## Мастер-таблица: 44 требования

| Требование | Статус в пакете | Evidence (файл:символ) | Заметки |
|---|---|---|---|
| ADR-WARP-1 (bundled b4-warpd, pinned, /usr/libexec, third_party/usque) | PARTIAL (unwired) | `manifest.go:EngineManifest.Valid` — требует `BinaryName=="b4-warpd"`, `Bundled`, `!RuntimeDownload` | Есть только валидатор манифеста. Нет сборки из pinned source, нет SBOM, нет layout `/usr/libexec/b4/`, нет `third_party/usque/` |
| ADR-WARP-2 (структурированный IPC по Unix socket, лог — secondary) | ABSENT | — (в пакете нет `net`, сокетов, IPC) | `trace.go:TracePipeline` — in-memory очередь, не IPC. Лог-парсинг не заменён ничем |
| ADR-WARP-3 (нет user shell hooks, bounded timeout, роутинг только через B4 RouteManager) | ABSENT | — | Ни кода hooks, ни точек вызова RouteManager нет ни в пакете, ни вне его |
| ADR-WARP-4 (один native TUN b4warp0, H2/TCP/443, MTU 1280, IPv6 off, H3 — capability) | PARTIAL (unwired) | `tun.go:TunLease.Valid` — `MTU >= 1280` | MTU-константа в модели есть; создание TUN-устройства, H2/443-соединение, IPv6-off отсутствуют |
| ADR-WARP-5 (маршрут только по TransportAuthorization + generation-owned token; negative SNI revokes) | PARTIAL (unwired) | `authorization.go:TransportAuthorization` (RouteGeneration, AllowForwarded/AllowControl); `RevokeOnNegativeEvidence`; `RouteGeneration` | Механика revoke есть; `CaptureCandidate` не существует; привязка маршрута к токену не реализована |
| ADR-WARP-6 (non-RU — вторая изолированная сессия, dual-netns, same-namespace запрещён) | PARTIAL (unwired) | `isolation.go:IsolationReport.Valid` — разные InstanceID и разные marks; `nested.go:NestedBackend` (Namespace/Veth/NAT) | Валидация изоляции есть; фактическое создание двух netns/TUN и запрет same-namespace без proof — отсутствуют |
| ADR-WARP-7 (geo attestation: ≥2 провайдера, без RU/direct WAN, TTL 120s без grace) | PARTIAL (unwired) | `geo.go:BuildGeoAttestation` — Quorum=2, RU/unknown → Revoked; `GeoAttestation.Valid` — без grace | **Расхождение: FreshUntil = now+5min (300s), а норматив 120s**; нет проверки direct WAN; нет вердикта PASS_NON_RU |
| §15 NDM apply order (TUN→MTU→адрес→NDM→проверка kernel state; fallback iproute2) | ABSENT | — | В пакете нет ничего про NDM, netdev, iproute2, kernel state |
| §16 MTU/MSS (MTU 1280 до роутинга; NDM adjust-mss иначе один generation-owned clamp; no double clamp; PMTU тесты) | PARTIAL (unwired) | `tun.go:TunLease.Valid`; `authorization.go:TransportAuthorization.MSSClamp int` | Поле clamp есть, двойного clamp не проверяется; PMTU-тесты 1280/1281/1500/SYN/UDP отсутствуют |
| §62.1 Required events (таксономия lifecycle/MASQUE событий, layer-specific failure class) | ABSENT | — (grep по `warp_process_started`, `warp_masque_connected` и т.п. = 0) | Нет ни одного имени события из таксономии; `trace.go:TransportTraceEnvelope.Event` — произвольная строка; нет `MasquePhaseTrace`/failure classes |
| §62.2 Path proof (proof = counter deltas до/после; ProofKind router/forwarded/geo/dns/ipv6) | PARTIAL (unwired) | `geo.go:GeoObservation.CounterDelta` | Типа `TransportPathProof`/`ProofKind` нет; delta только в гео-наблюдениях |
| §72 Base hard gates (10 счётчиков == 0) | ABSENT | — | Счётчиков hard gates в пакете нет вообще (grep `gate|Count|Counter` = 0, кроме имени поля) |
| §73 Non-RU hard gates (8) | ABSENT | — | То же; нет `nonru_*` счётчиков |
| §73A Camouflage hard gates (12) | ABSENT | — | То же; нет `masque_*` счётчиков |
| §73B Causal trace hard gates (28) | ABSENT | — | То же; нет `warp_trace_*`/`warp_nested_*`/`warp_geo_*` счётчиков |
| §74 Promotion verdict (WARP_CAUSAL_TRACE_READY + gates → PASS; PASS_EXPERIMENTAL; FAIL) | ABSENT | — (grep по вердиктам = 0) | Констант вердиктов нет ни в пакете, ни вне |
| WARP-1 (freeze коммитов, SBOM, threat model; hash mismatch ломает build) | PARTIAL (unwired) | `manifest.go:EngineManifest` — SourceCommit/SourceHash/LicenseHash обязательны | Hash-поля в модели есть; SBOM/threat model/breaking build нет; deliverable `WARP_1_REFERENCE_AUDIT.md` отсутствует |
| WARP-2 (сборка из pinned source, транзакционные upgrade/rollback/uninstall) | PARTIAL (unwired) | `manifest.go:PackageTransition` — Committed/Rollback | Модель транзакции есть; логики upgrade/rollback/uninstall и deliverable нет |
| WARP-3 (secret store 0600/encrypted, consent, bounded registration, redaction, rollback) | PARTIAL (unwired) | `secrets.go:SecretStore` (копирование при Get, Redacted); `EnrollmentTransaction` (Commit/Rollback) | **In-memory только**: нет файла, нет 0600, нет шифрования, нет consent flow; deliverable отсутствует |
| WARP-4 (IPC supervisor, TransportTraceEnvelope, BootID/generation, P0/P1/P2, persistence, checksums) | PARTIAL (unwired) | `trace.go:TransportTraceEnvelope` (SchemaVersion=2, BootID/ProcessID/SessionID/ParentSessionID, Route/ConfigGeneration, Sequence, Priority, Checksum=sha256 Seal); `TracePipeline` (bounded 256, P2 отбрасывается при переполнении, P0/P1 — никогда) | Envelope и pipeline реализованы; supervisor/IPC/persistence событий отсутствуют; deliverable WARP_4_* отсутствуют |
| WARP-5 (TUN/NDM lifecycle: registry, netdev-before-NDM, MTU до route, state verify, stale reconcile) | PARTIAL (unwired) | `tun.go:TunRegistry` (Claim — foreign collision reject; Release; Reconcile); `TunLease.State` (absent/owned/verified/stale) | Registry есть; netdev/NDM взаимодействия, верификации kernel state нет |
| WARP-6 (SO_MARK/BINDTODEVICE, endpoint pin обязателен, MarkAllocator, recursion guards, proxy env off) | PARTIAL (unwired) | `routing.go:MarkAllocator` (старт 0x4000, collision → error); `DialPolicy` (Mark/BindDevice/EndpointPin/DirectControl/ProxyEnvDisabled); `ValidateNoRecursion` | Модель и guard есть; реальных setsockopt/mark-применения нет |
| WARP-7 (scoped PBR: TransportAuthorization, атомарные destination sets, поколения, MSS, DNS follow-binding, negative-evidence revoke) | PARTIAL (unwired) | `authorization.go:TransportAuthorization` (MSSClamp, DNSBinding, ConfigGeneration, RevokeOnNegativeEvidence) | Revoke есть; destination sets, PBR-применение к маршрутам отсутствуют |
| WARP-8 (liveness/self-heal: layered health, forwarded canary, retry/cooldown, fail-open/closed-scoped, restart storm) | PARTIAL (unwired) | `health.go:HealthTracker` (состояния, FailureStreak, Cooldown 1min, CanRetry); `FailurePolicy` (FailOpenScoped/FailClosedScoped) | Слои health и cooldown есть; canary, предотвращение restart storm нет |
| WARP-C1 (control auth до первого SYN: TransportControlPurpose/Authorization, поколения; destination/SNI-only отвергается) | PARTIAL (unwired) | `camouflage_auth.go:TransportControlPurpose` (base-control/camouflage/established); `TransportControlAuthorization.Valid(gen,cfg)` — требует SocketID+FlowKey+EndpointHash+InstanceID+Purpose и совпадение поколений | Типы и strict-валидация есть; регистрация до первого SYN и verdict-классы (`VerdictClass`) не используются нигде |
| WARP-C2 (enrollment camouflage: отдельный retry budget, redaction, запрет proxy/credentials; policy не авторизует data-plane) | PARTIAL (unwired) | `enrollment.go:EnrollmentPolicy` (DirectOnly, MaxAttempts≤5, `DataPlaneAuthorization` запрещён в Valid); `DefaultEnrollmentPolicy` | Ограничение на авторизацию data-plane реализовано; отдельных retry-бюджетов стратегий, redaction диагностики нет |
| WARP-C3 (cover SNI: canonical/builtin/user-explicit, pinning во всех режимах, нет insecure fallback) | PARTIAL (unwired) | `cover_sni.go:CoverSNIMode` (3 режима); `CoverSNIConfig.Valid` — EndpointPin обязателен; `Insecure()` | Пиннинг в модели есть; перехвата SNI (в `sni`/`nfq`/dial path) нет — модуль никто не вызывает |
| WARP-C4 (handshake-only адаптер: approved primitives, ceilings, запрет мутации established stream) | PARTIAL (unwired) | `adapter.go:TransportCamouflageAdapter` — Valid = Authorized && !Established && budget>0; `Apply` лимиты; `Cutoff()` → Established | Контракт адаптера реализован точно; «approved primitives» (whitelist примитивов) нет |
| WARP-C5 (CONNECT-IP cutoff: переход по masque_connected, атомарное снятие eligibility, established bypass, fallback) | PARTIAL (unwired) | `cutoff.go:CutoffMachine.Apply(MasqueConnectedEvent)` — поколения + monotonic sequence; `HardFallback()` | FSM есть; атомарности eligibility при переходе, established bypass на уровне пакетов нет |
| WARP-C6 (auto-selection C0–C6: отдельные candidate generations, forwarded probe + stability window, expiry) | PARTIAL (unwired) | `selection.go:SelectLeastInvasive` — требует Protocol+Router+Forwarded+Stable; `Candidate.Invasive`; `CandidateResult.ExpiresAt` | Каталога C0–C6 нет; **ExpiresAt никогда не заполняется**; stability window и WAN/endpoint/build-expiry не реализованы |
| WARP-9 (nested backend: dual-netns, inner control через base SO_MARK, TunnelDependencyLink, exact cleanup) | PARTIAL (unwired) | `nested.go:NestedBackend` (Namespace/Veth/NAT, TunnelDependencyLink, CleanupOwned); `InvalidateParent`; `Cleanup` | Модель и флаги владения cleanup есть; создания netns/veth/NAT, SO_MARK-проброса нет |
| WARP-10 (non-RU discovery: multi-provider quorum, attestation TTL, revocation, DNS через inner, IPv6 off, counter deltas) | PARTIAL (unwired) | `geo.go:GeoObservation` (Provider/Class/DNSProof/IPv6Proof/CounterDelta); `BuildGeoAttestation` (quorum 2, RU→Revoked, disagreement→Revoked) | Quorum и revocation есть; **TTL 300s вместо 120s**; IPv6-off/DNS-через-inner не реализованы; deliverable WARP_10_* отсутствуют |
| WARP-C7 (outer/inner изоляция: независимые marks/policies, раздельные cutoff/bypass tokens, revoke inner при падении base) | PARTIAL (unwired) | `isolation.go:IsolationReport` (Outer/Inner InstanceState, ParentLinkValid, InnerRevokedBeforeParent) | **`InnerRevokedBeforeParent` есть в структуре, но `Valid()` его НЕ проверяет**; раздельных токенов нет |
| WARP-C8 (passive RST: наблюдение/классификация, enforcement off by default, canary suppression, rollback) | PARTIAL (unwired) | `rst.go:RSTObservation.SpoofLike` (Early+SequenceValid+WindowValid); `RSTDefense.AllowEnforcement` (off by default, canary window); `Rollback()` | Классификация и default-off есть; пайплайна наблюдения RST из packet path нет |
| WARP-C9 (camouflage API/UI/observability: trace schema v2, completeness/mismatch exposure, запрет claims invisibility, redaction) | PARTIAL (unwired) | `product.go:ProductStatus` (TraceComplete/GenerationMismatch/Explanation); `TraceExport` (Redacted/Complete/MaxBytes, `Bounded()` обнуляет Payload) | Типы наблюдаемости и redaction есть; API/UI отсутствуют; deliverable WARP_C9_* отсутствуют |
| WARP-C10 (target validation: Keenetic MediaTek, candidate matrix, GSO/segmentation parity, все hard gates, rollback) | ABSENT | — | Ничего: нет матрицы кандидатов, нет GSO-параллельности, нет вердикта BLOCKED_TARGET_VALIDATION; deliverable отсутствуют |
| WARP-11 (product integration: API/UI, Service Profile cloudflare-warp-masque, forbidden_countries [RU]) | PARTIAL (unwired) | `product.go:ProductControl` (test/select/reset) | Только enum управления; нет API-handler'ов, нет Service Profile-дельты (проверено: `serviceprofile` не ссылается на warp); deliverable отсутствует |
| WARP-12 (release gate: Keenetic+Android validation, TestSession→Binding→RouteToken→PathProof, causal trace, cleanup ownership) | ABSENT | — | Нет TestSession/Binding/RouteToken, нет causal-trace отчёта, нет вердикта BLOCKED_TARGET_VALIDATION; deliverable отсутствуют |
| §75 Base DoD (pin, consent, MTU до route, NDM verified, liveness перед route, path proof counters, trace completeness PASS) | PARTIAL (unwired) | Фрагменты: `tun.go` (MTU), `health.go` (liveness), `geo.go` (deltas), `product.go` (TraceComplete) | Сводной проверки DoD нет; consent/NDM-verified отсутствуют |
| §76 Non-RU DoD (checkbox off by default, изоляция, quorum 2, revocation, no silent fallback, revocation latency) | PARTIAL (unwired) | `geo.go` (quorum, revocation), `isolation.go` (изоляция) | Checkbox'а по умолчанию off, замера revocation latency нет |
| §76A Camouflage DoD (отдельная авторизация, pinning, least-invasive, bounded budgets, cutoff, zero post-cutoff mutation, gates zero) | PARTIAL (unwired) | `camouflage_auth.go`, `cover_sni.go`, `selection.go`, `adapter.go`, `cutoff.go` | Все части по отдельности есть; «gates zero» невозможно — счётчиков нет |
| §76B Causal trace DoD (единый versioned envelope, monotonic sequence, P0 не сэмплируются, trace I/O не блокирует packet path, trace==runtime state) | PARTIAL (unwired) | `trace.go:TransportTraceEnvelope.Valid` (SchemaVersion==2, Sequence>prev, checksum); `TracePipeline.Publish` (P0/P1 никогда не отбрасываются, P2 — при полной очереди) | Envelope/sequence/P0 выполнены; «trace == runtime state» (проекция состояния из trace) нет |
| §77 Final invariants (4: authorized scoped traffic → verified WARP; camouflage generation-owned до CONNECT-IP; trace completeness; non-RU без свежих evidence запрещён) | PARTIAL (unwired) | Фрагменты: `authorization.go` (scoped auth), `adapter.go` (established), `geo.go:Valid` (свежесть) | Инвариант-чекеров/вердиктов нет |
| Appendix B reports (stage ID, commits, requirements, tests, router status, trace schema, path-proof deltas, cleanup proof, verdict) | ABSENT | — | Генерации stage-отчётов нет нигде |

**Итог по таблице: IMPLEMENTED = 0 / PARTIAL = 32 / ABSENT = 12.**

## Точки интеграции (ожидаемый контракт)

Пакет спроектирован как «библиотека моделей»: ни одна функция не требует внешних зависимостей и **все они обязаны вызываться извне** (nfq/http/config/engine). Подтверждено: вызовов нет (grep по `b4/warp` вне пакета = 0). Ожидаемые call-sites:

| Модуль-потребитель | Ожидаемый вызов | Функция пакета | Статус |
|---|---|---|---|
| nfq / packetmark / tproxy | применение SO_MARK к пакетам и проверка recursion | `MarkAllocator.Allocate/Release`, `ValidateNoRecursion`, `DialPolicy.Valid` | не вызывается |
| nfq (sniffing/SNI) | перехват SNI, валидация cover-конфига перед dial | `CoverSNIConfig.Valid/Insecure` | не вызывается |
| http/engine (MASQUE client) | инъекция события `masque_connected` при переходе CONNECT-IP | `CutoffMachine.Apply`, `TransportCamouflageAdapter.Cutoff` | не вызывается |
| engine (lifecycle) | эмиссия обязательных событий в trace | `TracePipeline.Publish` (нет имён событий §62 — эмиттить нечего) | не вызывается |
| config/http (enrollment) | consent flow, сохранение секретов, транзакция | `SecretStore`, `EnrollmentTransaction`, `EnrollmentPolicy.Valid` | не вызывается |
| engine (liveness) | наблюдение health, решение о retry/fail-open | `HealthTracker.Observe/CanRetry`, `FailurePolicy` | не вызывается |
| geodat/stun + routing | сбор GeoObservation, построение attestation, gate маршрута | `BuildGeoAttestation`, `GeoAttestation.Valid` | не вызывается |
| tun/NDM | claim интерфейса до создания netdev | `TunRegistry.Claim/Release/Reconcile` | не вызывается |
| config/upgrade | проверка манифеста движка | `ValidateManifest`, `PackageTransition.Valid` | не вызывается |
| observability/http API | экспорт trace с redaction/bounds | `TraceExport.Bounded`, `TracePipeline.Snapshot` | не вызывается |
| http API (product) | обработка test/select/reset | `ProductControl` (enum) — обработчиков нет | не вызывается |

## Заглушки / TODO / незавершённое

- `grep TODO|FIXME|XXX|not implemented|panic(` по пакету: **0 совпадений** — пакет без заглушек, но и без side-effect кода.
- Все `return nil` (9 шт.) — штатные успешные возвраты валидаторов, не заглушки.
- Скрытые незавершённости (не помечены TODO, но «мёртвые» поля):
  - `geo.go:52` — `FreshUntil = now.Add(5*time.Minute)`: **расхождение с нормативом 120s** (ADR-WARP-7, WARP-10).
  - `isolation.go:12` — `InnerRevokedBeforeParent` нигде не устанавливается и не проверяется.
  - `selection.go:15` — `CandidateResult.ExpiresAt` никогда не заполняется (нет expiry/стабильности).
  - `camouflage_auth.go:22` — `VerdictClass` (bypass/camouflage/established) объявлен, нигде не используется.
  - `trace.go:39` — `TracePipeline.degraded` никогда не выставляется.
  - `product.go:19` — `TraceExport.MaxBytes` используется как длина в штуках, не байтах.
- Нет ни одного счётчика hard gates (§72/§73/§73A/§73B) и ни одного вердикта (§74/§76A/§76B/WARP-C10/WARP-12) — verification gates в принципе невыполнимы на текущем коде.

## Тесты (19 функций в 18 файлах; все PASS в golang:1.25.3, `go vet` чист)

- Покрытие: unit-тесты моделей/валидаторов — по одному на файл (secrets_test.go — 2). Проверяют: бюджет адаптера и запрет мутации после Cutoff; scoped auth + revoke; exact identity поколений; pin обязателен; cutoff rejects wrong gen/duplicate; enrollment не авторизует data-plane; geo quorum/RU-revocation; health cooldown; cross-instance marks; manifest без runtime download; nested invalidation/cleanup; trace export redaction/bounds; recursion guard; RST default-off; secret copy/redaction + rollback; least-invasive selection; trace envelope sequence/checksum/schema; TUN foreign collision/MTU.
- **trace_test.go:** покрывает только monotonic sequence + checksum + schema compat. НЕТ тестов: causal trace, secret leak counter (`warp_trace_secret_leak_total`), P0 не отбрасывается (проверяется только дубликат sequence), приоритетная эвикция P2, трассировка full-queue.
- **Hard gates:** тестов на §72/§73/§73A/§73B нет ни одного (счётчиков нет).
- Нет тестов: PMTU 1280/1281/1500/SYN/UDP (§16), NDM order (§15), IPC/supervisor (WARP-4), persistence, restart/rollback, интеграционных.

## Вердикт

- **0 из 44 требований IMPLEMENTED** (ни одно не выполнено end-to-end), **32 PARTIAL** (все — только «модель/валидация»), **12 ABSENT** (IPC, NDM, таксономия событий, все hard-gate счётчики, вердикты, target validation, release gate, Appendix B).
- **Пакет к интеграции НЕ ГОТОВ (частично готов как основа):** он корректен как библиотека моделей (19/19 тестов, vet чист), но не содержит ни одного side-effect — нет TUN/netlink, сокетов, marks, счётчиков gates, эмиссии событий, persistence и API. Интеграция требует: (1) добавления потребителей в nfq/http/engine (сейчас 0 вызовов), (2) реализации событийной таксономии §62, (3) счётчиков hard gates и вердиктов, (4) исправления TTL geo 300s→120s, (5) реального выполнения deliverable-документов WARP-1..12, WARP-C1..C10, Appendix B.
