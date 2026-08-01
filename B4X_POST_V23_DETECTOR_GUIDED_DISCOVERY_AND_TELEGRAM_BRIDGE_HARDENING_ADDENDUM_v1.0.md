# B4X Post-v2.3 Detector-Guided Discovery & Transparent Telegram Bridge Hardening Addendum

**Версия:** 1.0  
**Дата:** 2026-07-29  
**Статус:** обязательный post-v2.3 companion addendum для B4X  
**Основание:** upstream issues [`DanielLavrushin/b4#278`](https://github.com/DanielLavrushin/b4/issues/278) и [`DanielLavrushin/b4#277`](https://github.com/DanielLavrushin/b4/issues/277)  
**База:** B4 `1.73.0`, commit `7160ee8f066bbbed1c713b4d0114db4e8acbc882`, B4X branch `agent/classifier-v2.3-capture-envelope`  
**Область:** структурированный профиль DPI/сети, безопасная передача detector evidence в Discovery/Optimizer, freshness/revalidation, explainable search planning, delayed-first-data lifecycle прозрачного MTProto bridge, bounded pending budgets, prefix-preserving fail-open, Android/Keenetic validation  
**Главные принципы:** detector profile изменяет порядок поиска, но не заменяет target-specific proof; zero-byte timeout никогда не считается успешно обработанным соединением и не разрешает silent drop

---

## 0. Нормативный статус и место в проекте

Этот addendum добавляет две независимые generic capabilities:

```text
network-diagnostic-profile-guided-discovery
transparent-mtproto-delayed-handshake-hardening
```

Документ не переоткрывает и не перенумеровывает завершённые Stage 1–36 патч-плана v2.3. Он вводит два companion stage tracks:

```text
DDI-1 … DDI-10
TGB-1 … TGB-10
```

где:

- `DDI` — Detector–Discovery Integration;
- `TGB` — Transparent Telegram Bridge hardening.

Tracks независимы по runtime-коду и MAY реализовываться параллельно. Production promotion любого track требует завершения его собственных gates и регистрации в Field Test / Service Profiles / Implementation Validation.

### 0.1. Нормативная последовательность

```text
B4_FORK_ARCHITECTURE.md v2.4
→ B4_FORK_PATCH_PLAN.md Stage 1–36
→ B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md
→ B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md
→ B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md
→ B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM.md
→ B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM.md
→ этот addendum:
   ├─ DDI-1…DDI-10
   └─ TGB-1…TGB-10
→ Field Test Automation update
→ Service Profiles / Beginner UX update
→ Implementation Validation update
→ production promotion
```

Допускается реализовать `TGB-1…TGB-6` раньше некоторых optional transport stages, поскольку issue #277 является локальным correctness/lifecycle defect. Однако итоговый `TGB_READY` запрещён без общей validation infrastructure B4X.

### 0.2. Приоритет требований

При расхождении требований действует следующий приоритет:

```text
B4_FORK_ARCHITECTURE.md v2.4
→ Cross-Service Isolation для scope/authorization
→ RST/GSO и PPE для packet visibility/correctness
→ Silent Path Failure для inference/recovery safety
→ этот addendum для Detector→Discovery и MTProto bridge lifecycle
→ Field Test / Service Profiles / Implementation Validation как release gates
→ upstream issue suggestions и implementation notes
```

### 0.3. Общие запреты

B4X MUST NOT:

1. считать detector profile готовой production-конфигурацией;
2. пропускать target-specific baseline и candidate validation только из-за detector result;
3. безусловно исключать семейство стратегий по одному старому detector test;
4. переносить разрешённый SNI из detector прямо в production set без Discovery/canary;
5. применять профиль другого WAN/network context;
6. выдавать `provider DPI confirmed` без ограниченного evidence verdict;
7. закрывать прозрачное Telegram-соединение только потому, что клиент не отправил байты за 5 секунд;
8. возвращать `handled=true` для zero-byte timeout;
9. держать неограниченное число idle/preconnect sockets;
10. терять уже прочитанный prefix при handoff/fail-open;
11. создавать бесконечную цепочку bridge → worker → direct → bridge;
12. скрывать resource saturation под обычным `empty conn` логом.

---

# Часть I. Закреплённые проблемы и verified gaps

## 1. Issue #278 — Detector и Discovery работают как раздельные системы

Upstream issue #278 фиксирует ожидаемую пользовательскую цепочку:

```text
DPI Detector
→ profile of current network interference
→ Discovery tests most likely candidates first
→ exhaustive search only when hints fail
```

В B4 1.73.0 фактическая цепочка остаётся следующей:

```text
DPI Detector
→ diagnostic history for UI

Discovery
→ independent DNS/baseline/failure analysis
→ independent strategy enumeration
```

### 1.1. Verified API gap

Текущий `DiscoveryRequest` содержит только:

```go
type DiscoveryRequest struct {
    CheckURL        string
    CheckURLs       []string
    SkipDNS         bool
    SkipCache       bool
    PayloadFiles    []string
    ValidationTries int
    TLSVersion      string
    IPVersion       string
}
```

Он не содержит:

- detector suite/profile ID;
- profile selection mode;
- network-context match requirement;
- freshness/revalidation policy;
- разрешение использовать найденные SNI как candidates;
- explainability requirements.

`StartSuiteOptions` также не содержит detector evidence/profile.

### 1.2. Verified persistence gap

`detector.HistoryEntry` сохраняет:

- suite ID/status/tests;
- start/end timestamps;
- DNS/DNS availability/domain/TCP/SNI/Telegram results.

Он не сохраняет обязательный context envelope:

- schema version;
- B4X binary/build version;
- config generation;
- WAN interface identity;
- gateway/network fingerprint;
- public egress/ASN provenance;
- resolver path fingerprint;
- target scope;
- profile freshness state;
- confidence/provenance каждого derived hint;
- content hash/signature;
- revalidation history.

Следовательно, raw history entry нельзя безопасно использовать как reusable Discovery input.

### 1.3. Existing B4X foundation

B4X уже имеет необходимые building blocks:

- structured `ProbeOutcome`;
- transfer failure signatures;
- adaptive matrix;
- baseline-none / baseline-production / candidate comparison;
- bounded shadow probes;
- deterministic seed and probe budgets;
- isolated Discovery sandbox;
- score model and promotion gates;
- fake-profile catalog;
- capture visibility gate.

Новый track MUST встроиться в эти механизмы, а не создать второй optimizer.

## 2. Issue #277 — zero-byte timeout уничтожает прозрачные Telegram flows

Issue #277 фиксирует воспроизводимую последовательность:

```text
bridge accept
→ ровно около 5 секунд без client payload
→ bridge empty conn ... -> drop
```

При этом обычный MTProto proxy B4, явно настроенный в Telegram Android, работает.

### 2.1. Verified runtime defect

Текущий код выполняет:

```go
_ = client.SetReadDeadline(time.Now().Add(5 * time.Second))
head, herr := io.ReadFull(client, init[:4])
if herr != nil && head == 0 {
    return true, nil
}
```

`true, nil` означает:

```text
connection claimed as handled
+ no handoff connection
→ listener returns
→ socket closes
```

Это не fail-open. Это silent destructive drop.

### 2.2. Verified listener contract

TPROXY listener вызывает следующие fallback paths только если bridge вернул `handled=false`:

```text
Bridge.Handle
→ optional FailOpenViaWorker
→ failOpenDirect
```

Поэтому zero-byte `handled=true` блокирует оба fallback paths.

### 2.3. Additional verified lifecycle gap

После полного успешного decode текущий bridge при ошибке `DialObfuscatedDCWithPool` также возвращает:

```text
handled=true, nil
```

и уничтожает соединение, хотя raw client handshake уже мог быть сохранён для bounded worker/direct handoff.

### 2.4. Config/resource gap

Текущий `MTProtoConfig` содержит общий `MaxConnections`, `TCPUserTimeoutSec` и `IdleTimeoutSec`, но не содержит transparent bridge-specific:

- first-byte soft/hard timeout;
- handshake completion timeout;
- pending global/per-client budget;
- zero-byte policy;
- overflow policy;
- delayed-handshake metrics;
- preconnect classification;
- config-generation snapshot.

---

# Часть II. Track DDI — Detector-Guided Discovery

## 3. Цель DDI

DDI должен превратить Detector из отдельной диагностической страницы в optional, freshness-gated источник priors для существующего Discovery/Optimizer.

Нормативная схема:

```text
DetectorSuite raw results
→ immutable NetworkDiagnosticProfile
→ context/freshness validation
→ bounded fast revalidation
→ DiscoveryHintCompiler
→ DiscoveryPlanHints
→ existing adaptive matrix
→ target-specific baseline and candidate proof
→ report of actual search savings
```

Detector profile является только advisory input.

```text
profile evidence ≠ target proof
profile hint ≠ ActionAuthorization
profile recommendation ≠ production promotion
```

## 4. NetworkDiagnosticProfile

### 4.1. Canonical model

```go
type NetworkDiagnosticProfile struct {
    SchemaVersion     uint16
    ProfileID         string
    SourceSuiteID     string
    CreatedAt         time.Time
    CompletedAt       time.Time
    ExpiresAt         time.Time

    BuildID           string
    ConfigGeneration  uint64
    ContentSHA256     string

    NetworkContext    NetworkContextFingerprint
    TargetScope       DiagnosticTargetScope

    DNS               DNSDiagnosticEvidence
    TLS               []TLSDiagnosticEvidence
    TCP               []TCPDiagnosticEvidence
    AllowedSNI        []SNICandidateEvidence
    Telegram          *TelegramDiagnosticEvidence
    FailureHypotheses []FailureHypothesis

    Confidence        ProfileConfidence
    State             DiagnosticProfileState
    Revalidation      RevalidationState
}
```

### 4.2. Network context fingerprint

```go
type NetworkContextFingerprint struct {
    WANInterfaceID    string
    GatewayFingerprint string
    EgressIPHash      string
    EgressPrefixClass string
    ASN               string
    ProviderLabel     string
    ResolverHash      string
    IPv4Available     bool
    IPv6Available     bool
    CapturedAt        time.Time
}
```

Privacy requirements:

- raw public IP MUST NOT be exported by default;
- gateway MAC MUST be hashed/redacted;
- resolver list MAY be represented by stable hash plus provider labels;
- SSID, subscriber identifiers and raw LAN client addresses MUST NOT enter the profile;
- issue bundles require explicit opt-in for less-redacted context.

### 4.3. Target scope

Detector results MUST distinguish at least:

```text
generic-network
specific-domain
specific-ASN/provider target
telegram-DC
DNS-provider
TLS-version + IP-family
```

A generic provider-wide fat-probe threshold MUST NOT be treated as exact threshold for every domain/CDN.

### 4.4. Profile states

```go
type DiagnosticProfileState string

const (
    ProfileFresh         DiagnosticProfileState = "fresh"
    ProfileRevalidated   DiagnosticProfileState = "revalidated"
    ProfileStale         DiagnosticProfileState = "stale"
    ProfileConflicting   DiagnosticProfileState = "conflicting"
    ProfileIncompatible  DiagnosticProfileState = "incompatible"
    ProfileExpired       DiagnosticProfileState = "expired"
    ProfileRevoked       DiagnosticProfileState = "revoked"
)
```

Only `fresh` and `revalidated` profiles MAY affect the automatic candidate order.

`stale` MAY be displayed and MAY seed a manual debug run only after an explicit warning, but MUST NOT affect automatic Discovery before fast revalidation.

`conflicting`, `incompatible`, `expired` and `revoked` profiles MUST NOT affect candidate order.

## 5. Freshness and revalidation

### 5.1. Default age model

Recommended defaults:

```yaml
detector_discovery:
  fresh_ttl: 6h
  revalidatable_ttl: 24h
  fast_revalidate: true
```

Semantics:

```text
age <= 6h and exact context match
→ fresh

6h < age <= 24h and exact/compatible context
→ requires fast revalidation

age > 24h
→ expired
```

Any WAN interface, gateway, egress ASN, resolver fingerprint or IP-family capability change forces revalidation regardless of age.

### 5.2. Fast revalidation

Fast revalidation MUST be bounded and SHOULD include only the signals needed to verify assumptions used by the planned hints:

- one trusted DNS comparison when DNS evidence will be used;
- one TLS 1.2 and/or TLS 1.3 baseline when TLS ordering will change;
- one TCP reachability probe when IP/transport block is suspected;
- one small fat-probe bracket confirmation when size threshold will seed parameters;
- one allowed-SNI confirmation before placing it into Fake SNI candidate set.

Fast revalidation MUST have:

```text
separate probe budget
separate timeout
separate events
no production side effects
no learned-IP writes
no promotion
```

### 5.3. Conflict handling

```text
stored profile says TLS 1.3 blocked
+ current baseline TLS 1.3 succeeds
→ mark relevant evidence conflicting
→ suppress associated hint
→ continue ordinary Discovery
```

One conflict MUST NOT invalidate unrelated evidence automatically. Conflict state is per evidence item and aggregated conservatively at profile level.

## 6. Evidence model

### 6.1. Evidence item

```go
type DiagnosticEvidenceItem struct {
    EvidenceID     string
    Kind           string
    Target         string
    IPFamily       string
    TLSVersion     string
    ResolverPath   string
    Value          any
    Confidence     float64
    SampleCount    uint32
    ObservedAt     time.Time
    ValidUntil     time.Time
    Provenance     string
    RevalidatedAt  time.Time
    RevalidateVerdict string
}
```

Derived hints MUST retain references to contributing evidence IDs.

### 6.2. Failure hypotheses

Allowed hypotheses include:

```text
dns_poisoning_suspected
dns_interception_suspected
doh_unavailable
before_tcp_failure
ip_block_suspected
immediate_rst_suspected
tls13_specific_failure
tls12_specific_failure
clienthello_size_sensitive
near_threshold_drop
midstream_reset
silent_stall
throughput_clamp
transport_fallback_likely
```

Detector MUST NOT emit `rkn_confirmed` as a reusable profile verdict.

## 7. DiscoveryHintCompiler

### 7.1. Output contract

```go
type DiscoveryPlanHints struct {
    ProfileID          string
    ProfileState       DiagnosticProfileState
    ContextMatch       string
    Revalidated        bool

    PriorityBoosts     []CandidatePriorityHint
    PriorityPenalties  []CandidatePriorityHint
    DeferredFamilies   []DeferredFamilyHint
    SeedParameters     []ParameterSeedHint
    ResolverCandidates []ResolverHint
    FakeSNICandidates  []FakeSNIHint
    TransportHints     []TransportHint

    RequiredBaselines  []BaselineRequirement
    AppliedEvidenceIDs []string
    SuppressedHints    []SuppressedHint
    Budget             HintBudget
}
```

### 7.2. Allowed influence

Detector hints MAY:

- reorder strategy families;
- seed bounded parameter ranges;
- add verified resolver candidates;
- add allowed-SNI candidates to Discovery-only candidate catalog;
- prioritize TLS/IP-family comparisons;
- defer low-probability families until hinted candidates fail;
- prioritize transport confirmation when direct IP reachability fails;
- reduce duplicate diagnostics when equivalent evidence is fresh and revalidated;
- request specific shadow probes.

### 7.3. Forbidden influence

Detector hints MUST NOT:

- remove baseline-none;
- remove baseline-production;
- skip exact target validation;
- skip same-client controls;
- create or edit production sets;
- enable WARP/SOCKS/TUN globally;
- authorize packet mutation;
- authorize cross-service routing;
- permanently blacklist a strategy family;
- suppress exhaustive fallback after all hinted candidates fail;
- override capture visibility gates.

## 8. Hint mapping rules

### 8.1. DNS poisoning/interception

When fresh and revalidated DNS evidence exists, Discovery MAY:

1. prioritize trusted DoH/system-forward resolvers;
2. reuse verified reference IPs as probe targets;
3. defer repeated full DNS diagnostics;
4. keep one mandatory current DNS baseline;
5. compare direct resolver and candidate resolver causally.

It MUST NOT assume every target domain is poisoned because one detector domain was poisoned.

### 8.2. TLS 1.2 / TLS 1.3 asymmetry

```text
TLS 1.2 available
+ TLS 1.3 unavailable
→ boost TLS 1.3-sensitive candidates
→ preserve separate TLS 1.2 control
→ never merge outcomes
```

Discovery MAY propose a TLS-filtered set only after target-specific proof and ordinary profile/canary gates.

### 8.3. Immediate RST

Fresh immediate-RST evidence MAY boost:

- bounded disorder/desync families;
- fake-packet families;
- Passive RST observe diagnostics;
- order-changing primitives.

It MUST NOT automatically enable active Passive RST suppression or controlled RST injection.

### 8.4. Timeout/stall before useful TLS progress

Fresh timeout/stall evidence MAY boost:

- split/multisplit;
- fragmentation;
- ClientHello marker positions;
- fake profile variations;
- resolver/IP-family/TLS shadow probes.

It MUST NOT classify timeout as DPI without differential proof.

### 8.5. TCP fat-probe threshold

A detected threshold is represented as an interval, not one exact integer:

```go
type ThresholdInterval struct {
    LowerFailBound int
    UpperPassBound int
    Confidence     float64
}
```

The compiler MAY seed candidates around marker/size positions relative to this interval. It MUST:

- clamp values to action budgets;
- avoid packet sizes invalid for target MTU/MSS;
- include values below and above the interval;
- validate each value on the target domain;
- widen search after hinted candidates fail.

### 8.6. Allowed SNI

Allowed SNI evidence MAY enter a Discovery-only `FakeSNICandidateSet` when:

- value is syntactically valid;
- evidence is fresh/revalidated;
- source/provenance is retained;
- duplicates and self-target SNI are handled explicitly;
- privacy policy allows display/storage.

It MUST NOT be copied directly into a production set.

### 8.7. IP/transport block suspicion

When TCP cannot reach target IP and independent controls show local network health, Discovery MAY prioritize:

- interface/TUN/SOCKS/WARP transport confirmation;
- alternate IP family;
- alternate reference endpoint.

A minimal direct strategy budget MUST still run unless exact TCP reachability is impossible and this impossibility is revalidated.

## 9. Search planner merge

The final candidate order MUST be derived from both sources:

```text
stored detector profile priors
+ current target baseline outcome
+ current capture/visibility capability
+ configured strategy catalog
+ previous last-good/canary evidence
→ deterministic SearchPlan
```

Current target baseline has higher authority than stored profile priors.

Recommended precedence:

```text
hard safety/capability gates
→ current baseline evidence
→ fresh revalidated detector evidence
→ recent target-specific last-good evidence
→ generic catalog defaults
```

### 9.1. Determinism

The same:

```text
profile content hash
+ target
+ strategy catalog version
+ config generation
+ adaptive seed
```

MUST produce the same initial SearchPlan.

### 9.2. Exhaustive fallback

When hinted candidates fail or conflict:

```text
hinted phase exhausted
→ ordinary adaptive matrix
→ full bounded catalog search
```

The final report MUST state whether detector hints:

- reduced probe count;
- reduced wall time;
- found the winner earlier;
- were neutral;
- were misleading/conflicting.

## 10. DDI API contract

### 10.1. Discovery request extension

```go
type DiscoveryRequest struct {
    // existing fields

    DetectorProfileID   string `json:"detector_profile_id,omitempty"`
    DetectorProfileMode string `json:"detector_profile_mode,omitempty"` // off|auto|selected
    RevalidateProfile   *bool  `json:"revalidate_detector_profile,omitempty"`
}
```

Semantics:

```text
off
→ detector profile is ignored

auto
→ choose newest context-compatible profile and revalidate as required

selected
→ use exact profile ID or reject request if unavailable/incompatible
```

`selected` MUST NOT bypass freshness or safety rules.

### 10.2. StartSuiteOptions extension

```go
type StartSuiteOptions struct {
    // existing fields

    DetectorProfile *NetworkDiagnosticProfile
    DetectorMode    DetectorProfileMode
    HintPolicy      DetectorHintPolicy
}
```

Passing mutable detector history pointers is forbidden. Runtime receives an immutable snapshot or compiled hints.

### 10.3. New endpoints

```text
GET  /api/detector/profiles
GET  /api/detector/profiles/{id}
POST /api/detector/profiles/{id}/revalidate
POST /api/detector/profiles/{id}/revoke
GET  /api/discovery/{id}/plan
GET  /api/discovery/{id}/hint-report
```

Raw profile export MUST be redacted by default.

### 10.4. Discovery response/status

Response/status MUST expose:

```json
{
  "detector_profile": {
    "id": "...",
    "state": "revalidated",
    "context_match": "exact",
    "applied_hint_count": 5,
    "suppressed_hint_count": 2
  },
  "plan": {
    "hinted_candidates": 8,
    "fallback_candidates": 24
  }
}
```

## 11. DDI UI/UX

Discovery UI MUST offer:

```text
Использовать результаты DPI Детектора
○ Не использовать
● Автоматически выбрать актуальный профиль
○ Выбрать сохранённый профиль
```

UI displays:

- profile timestamp;
- freshness badge;
- network-context match;
- revalidation status;
- applied hints;
- suppressed/conflicting hints;
- estimated probe savings;
- actual probe/time savings in final report.

Warnings:

```text
Результат детектора используется только для изменения порядка тестов.
Каждая найденная конфигурация всё равно проверяется на выбранном домене.
```

Default mode:

```text
auto when an exact-context fresh profile exists
otherwise off with recommendation to run Detector
```

Automatic use MAY be disabled globally by privacy/operator policy.

## 12. DDI persistence and migration

- Preserve existing `detector_history.json` compatibility.
- Do not silently treat legacy history entries as production-safe profiles.
- Legacy entries MAY be imported as `incompatible-legacy` metadata.
- A new profile store SHOULD use atomic write/rename and bounded entry count.
- Corrupt profile entries MUST be skipped individually.
- Content hash MUST cover normalized evidence and context.
- Profile revocation MUST survive restart.
- Storage writes MUST be rate-limited and not occur per packet/probe event.

Suggested file:

```text
detector_profiles_v1.json
```

## 13. DDI observability

Required events:

```text
detector_profile_created
detector_profile_context_checked
detector_profile_revalidation_started
detector_profile_revalidation_completed
detector_profile_conflict
discovery_hint_compiled
discovery_hint_applied
discovery_hint_suppressed
discovery_hinted_phase_exhausted
discovery_fallback_search_started
discovery_hint_savings_reported
```

Required metrics:

```text
detector_profiles_total{state}
detector_profile_revalidation_total{verdict}
discovery_detector_profile_use_total{mode,state}
discovery_detector_hint_total{kind,decision}
discovery_detector_hint_probe_savings
discovery_detector_hint_time_savings_ms
discovery_detector_hint_misleading_total
discovery_detector_profile_context_mismatch_total
```

High-cardinality profile IDs, domains, IPs and provider names MUST NOT be metric labels.

---

# Часть III. Track TGB — Transparent Telegram Bridge Hardening

## 14. Цель TGB

TGB должен поддержать Telegram Android connections, которые создаются заранее и не отправляют MTProto handshake в первые 5 секунд, не превращая bridge в unbounded idle socket sink.

Нормативная схема:

```text
TPROXY accept
→ bounded first-data gate
→ no-data preconnect state OR prefix classification
→ transparent MTProto decode when possible
→ WS/DC relay
→ bounded worker/direct handoff on unsupported/failure path
→ relay or explicit terminal verdict
```

## 15. Новый bridge outcome contract

Boolean `handled` недостаточен. Вводится structured outcome:

```go
type BridgeDisposition string

const (
    BridgeClaimed       BridgeDisposition = "claimed"
    BridgeHandoff       BridgeDisposition = "handoff"
    BridgeParked        BridgeDisposition = "parked"
    BridgeRejected      BridgeDisposition = "rejected"
    BridgeTerminalError BridgeDisposition = "terminal_error"
)

type BridgeOutcome struct {
    Disposition BridgeDisposition
    Conn        net.Conn
    Prefix      []byte
    Reason      string
    BytesRead   int
    Waited      time.Duration
    RouteTried  []string
}
```

Rules:

- `claimed` means bridge owns relay lifecycle;
- `handoff` means listener MUST continue to worker/direct path using preserved bytes;
- `parked` means a bounded pending manager owns the connection;
- `rejected` is only allowed for explicit policy/budget reasons and MUST be observable;
- `terminal_error` MUST include evidence that no safe handoff exists.

A zero-byte deadline cannot produce `claimed` or silent `terminal_error`.

## 16. First-data state machine

```go
type TransparentHandshakeState string

const (
    TGAccepted          TransparentHandshakeState = "accepted"
    TGWaitingFirstByte  TransparentHandshakeState = "waiting_first_byte"
    TGIdlePreconnect    TransparentHandshakeState = "idle_preconnect"
    TGReadingPrefix     TransparentHandshakeState = "reading_prefix"
    TGReadingHandshake  TransparentHandshakeState = "reading_handshake"
    TGDecoded           TransparentHandshakeState = "decoded"
    TGHandoff           TransparentHandshakeState = "handoff"
    TGRelaying          TransparentHandshakeState = "relaying"
    TGClosed            TransparentHandshakeState = "closed"
)
```

### 16.1. Soft and hard deadlines

Recommended defaults:

```yaml
system:
  mtproto:
    transparent:
      first_byte_soft_timeout_sec: 15
      first_byte_hard_timeout_sec: 45
      handshake_timeout_sec: 10
```

Semantics:

- soft timeout identifies delayed/preconnect behavior;
- soft timeout MUST NOT close the connection;
- hard timeout bounds idle socket lifetime;
- partial handshake timeout starts only after first byte/progress;
- deadlines use monotonic time and are not extended indefinitely by config reload.

### 16.2. Zero-byte behavior

Soft и hard deadlines разделены (FB-14 решение 14).

#### Soft deadline

```text
zero bytes
→ не closed
→ не handled/claimed
→ park в bounded PendingHandshakeManager
→ wait until first byte or hard deadline
```

Первый байт до hard deadline возвращает connection в normal handshake classification с сохранением prefix и без duplication/loss.

#### Hard deadline

Zero-byte connection может быть завершён только как observable:

```text
no bytes
→ close as idle_preconnect_expired
→ explicit metric/event
→ reason
→ correct socket cleanup
→ pending-budget release
→ не unsupported MTProto
→ не successful handle
→ не silent drop
```

Запрещено:

```text
fixed 5-second deadline
→ head == 0
→ handled=true
→ nil connection
```

> **superseded (FB-14 решение 14):** прежняя формулировка «close as idle_preconnect_expired» (962-969) уточнена разделением soft/hard deadline и явным запретом silent fixed-5s drop; DoD «never silently claimed and dropped after five seconds» сохраняется. Field proof должен включать delayed-first-byte > 5 s, partial prefix, client close, cancellation, reload/shutdown и pending-budget exhaustion.

Optional policy MAY hand off to a lazy worker route at soft timeout, but MUST NOT dial an upstream until first client byte unless explicitly configured.

### 16.3. First byte after 5 seconds

A client that sends its first byte at 5–45 seconds MUST receive the same classification and relay behavior as a client that sends immediately, subject to budgets and shutdown.

## 17. PendingHandshakeManager

### 17.1. Purpose

The manager bounds idle/preconnect resource use without destroying valid delayed handshakes.

```go
type PendingHandshakeLimits struct {
    MaxGlobal       int
    MaxPerClient    int
    HardTimeout     time.Duration
    MaxPrefixBytes  int
}
```

Recommended Keenetic defaults:

```yaml
max_pending_global: 64
max_pending_per_client: 8
max_prefix_bytes: 64
```

### 17.2. Scope key

Per-client budget MUST use normalized LAN client identity when available:

```text
ClientKey
→ source IP fallback only when ClientKey unavailable
```

Destination IP alone is forbidden as a resource-accounting key.

### 17.3. Overflow policy

```yaml
pending_overflow_policy: worker-failopen
```

Allowed values:

```text
worker-failopen
direct-failopen
close-newest
```

Default preference:

```text
configured worker available
→ lazy worker fail-open
otherwise direct fail-open
otherwise explicit close-newest
```

`close-oldest` is forbidden by default because it may destroy the connection closest to sending data.

Every overflow MUST be observable.

### 17.4. Cleanup

Pending entries MUST be released on:

- first data;
- hard timeout;
- client close;
- listener shutdown;
- config generation retirement;
- context cancellation;
- budget manager replacement.

No goroutine, timer or socket leak is allowed.

## 18. Prefix preservation

All paths MUST preserve exact bytes already read from the client.

Required cases:

```text
0 bytes
1–3 bytes
4–63 bytes
64-byte valid handshake
64-byte invalid/reserved handshake
additional coalesced payload
```

The bridge MUST retain a raw immutable copy before decode/mutation.

```go
rawPrefix := append([]byte(nil), init[:n]...)
```

Handoff uses a prefix-preserving connection abstraction.

No byte may be:

- lost;
- duplicated;
- reordered;
- decoded twice;
- sent both to WS relay and fail-open path.

## 19. Classification outcomes

### 19.1. Reserved/non-obfuscated prefix

```text
first 4 bytes reserved/non-obfuscated
→ handoff with exact prefix
→ worker/direct path
```

### 19.2. Partial prefix

```text
1–3 bytes then timeout/EOF
→ handoff with exact prefix when connection remains usable
→ otherwise explicit partial_client_close
```

### 19.3. Partial 64-byte handshake

```text
4–63 bytes then timeout
→ handoff with exact prefix
→ do not claim MTProto decode success
```

### 19.4. Valid obfuscated handshake

```text
64 bytes valid
→ resolve DC using exact original destination and handshake evidence
→ dial configured upstream route
→ relay
```

### 19.5. DC ambiguity

When IP mapping and handshake DC disagree:

- keep current deterministic precedence policy;
- record both evidence values;
- do not silently rewrite persistent mappings;
- allow bounded alternate route on dial failure;
- include ambiguity in trace.

## 20. Upstream failure and handoff

Current destructive behavior after `DialObfuscatedDCWithPool` failure MUST be replaced.

Required route ladder:

```text
primary transparent WS/DC route
→ optional configured worker route
→ optional direct fail-open route
→ explicit terminal failure
```

Each route may be attempted at most once per connection unless a documented endpoint-variant policy applies.

### 20.1. Raw handshake replay

If primary bridge decode succeeded but upstream dial failed, handoff MUST replay the original raw 64-byte client handshake, not decoded bytes.

### 20.2. No routing recursion

Every bridge-originated upstream connection MUST carry the correct bypass/processed mark and MUST NOT re-enter the same TPROXY set.

### 20.3. Failure ownership

Terminal close is allowed only when:

- client closed;
- hard idle timeout expired;
- explicit resource policy rejected the connection;
- all configured bounded routes failed;
- listener is shutting down;
- protocol state cannot be replayed safely and reason is recorded.

## 21. Configuration model

```go
type MTProtoTransparentConfig struct {
    FirstByteSoftTimeoutSec int    `json:"first_byte_soft_timeout_sec"`
    FirstByteHardTimeoutSec int    `json:"first_byte_hard_timeout_sec"`
    HandshakeTimeoutSec     int    `json:"handshake_timeout_sec"`
    MaxPendingGlobal        int    `json:"max_pending_global"`
    MaxPendingPerClient     int    `json:"max_pending_per_client"`
    PendingOverflowPolicy   string `json:"pending_overflow_policy"`
    ZeroBytePolicy          string `json:"zero_byte_policy"`
}
```

Suggested defaults:

```yaml
system:
  mtproto:
    transparent:
      first_byte_soft_timeout_sec: 15
      first_byte_hard_timeout_sec: 45
      handshake_timeout_sec: 10
      max_pending_global: 64
      max_pending_per_client: 8
      pending_overflow_policy: worker-failopen
      zero_byte_policy: park
```

Validation limits:

```text
soft timeout: 1…60 s
hard timeout: soft…180 s
handshake timeout: 1…60 s
max pending global: 1…1024
max pending per client: 1…64 and <= global
```

Low-memory platforms MAY receive lower effective defaults through capability/profile projection, but no runtime auto-tuning may exceed configured maxima.

## 22. Config snapshot and hot apply

Each accepted connection MUST use an immutable config-generation snapshot for:

- timeout values;
- pending limits/policy;
- upstream domains;
- marks;
- route ladder.

A config reload:

- affects new connections;
- MUST NOT reset elapsed deadlines on existing connections;
- MAY cancel entries only when the old generation is explicitly retired;
- MUST cleanly close/reconcile old WS pool resources;
- MUST not mix old prefix state with new upstream secrets/policy.

## 23. TGB API/UI

### 23.1. Status API

Expose:

```json
{
  "transparent_bridge": {
    "pending": 3,
    "pending_limit": 64,
    "oldest_pending_ms": 12400,
    "delayed_handshake_total": 17,
    "overflow_total": 0,
    "worker_handoff_total": 2,
    "direct_handoff_total": 0
  }
}
```

No client IP is included by default.

### 23.2. UI

Beginner UI:

```text
Ожидание первого Telegram handshake: Авто
```

Advanced UI exposes:

- soft/hard timeout;
- max pending connections;
- per-device limit;
- overflow policy;
- live pending count;
- recent delayed-handshake outcomes.

Warning:

```text
Большие таймауты и лимиты увеличивают расход памяти и числа открытых соединений.
B4X применяет ограничения глобально и отдельно для каждого устройства.
```

## 24. TGB observability

Required events:

```text
tg_bridge_accept
tg_bridge_first_byte
tg_bridge_soft_timeout
tg_bridge_idle_parked
tg_bridge_delayed_handshake_resumed
tg_bridge_hard_timeout
tg_bridge_pending_overflow
tg_bridge_prefix_handoff
tg_bridge_handshake_decoded
tg_bridge_primary_dial_failed
tg_bridge_worker_handoff
tg_bridge_direct_handoff
tg_bridge_terminal_close
```

Required metrics:

```text
mtproto_bridge_connections_total{outcome}
mtproto_bridge_first_byte_delay_ms
mtproto_bridge_pending_current
mtproto_bridge_pending_peak
mtproto_bridge_pending_overflow_total{policy}
mtproto_bridge_delayed_handshake_total{verdict}
mtproto_bridge_handoff_total{route,reason}
mtproto_bridge_prefix_bytes_total{outcome}
mtproto_bridge_terminal_drop_total{reason}
```

High-cardinality client/destination values are forbidden as labels.

---

# Часть IV. Cross-track integration

## 25. Detector Telegram evidence

Detector Telegram results MAY be included in `NetworkDiagnosticProfile` as evidence of:

- DC IP reachability;
- throughput/stall behavior;
- direct-path failure;
- target DC coverage.

They MAY help Service Profiles recommend:

- direct packet strategy;
- transparent `mtproto-ws`;
- explicit MTProto proxy;
- generic transport fallback.

They MUST NOT:

- auto-enable transparent bridge;
- change bridge timeouts without config apply;
- authorize a route for unrelated traffic;
- treat explicit MTProto proxy success as proof that transparent bridge works;
- hide a TGB lifecycle failure.

## 26. Failure Inbox and diagnostics

DDI and TGB MUST produce separate issue/failure records.

Examples:

```text
detector_profile_context_mismatch
detector_hint_conflict
detector_hint_misleading
telegram_delayed_handshake_supported
telegram_pending_budget_exhausted
telegram_primary_bridge_failed_worker_succeeded
telegram_all_routes_failed
```

A successful worker/direct fallback MUST NOT erase the primary bridge failure; both are reported.

## 27. Service Profile integration

Telegram service profile MAY declare:

```yaml
delivery_mode: hybrid
transports:
  - direct-strategy
  - mtproto-ws-transparent
  - mtproto-explicit-proxy
recovery_order:
  - mtproto-ws-transparent
  - mtproto-explicit-proxy
  - generic-transport
```

Profile compiler MUST verify capabilities and route scope. It cannot expand Telegram routing to destination-global shared infrastructure without ordinary B4X authorization.

Detector-guided Discovery policy is declared separately:

```yaml
discovery:
  detector_profile_mode: auto
  require_fast_revalidation: true
  exhaustive_fallback: true
```

## 28. Security and privacy

- Detector profiles contain no secrets.
- MTProto secrets remain in existing secret/config handling and are never included in traces.
- Allowed SNI candidates are ordinary public hostnames but MAY still be redacted in public issue bundles.
- Client identity is redacted in logs/API by default.
- Profile import requires schema/hash validation.
- External profile import is disabled by default.
- No profile may execute code or provide raw packet-builder instructions.
- Pending manager must be resistant to LAN socket exhaustion by per-client limits.
- Unauthorized LAN clients cannot query detailed detector profiles or pending-connection state without API permission.

---

# Часть V. Testing and validation

## 29. DDI test matrix

### 29.1. Unit tests

- profile schema validation;
- content hash determinism;
- context exact/compatible/mismatch states;
- freshness transitions;
- evidence conflict aggregation;
- hint compilation per failure class;
- threshold interval clamping;
- allowed-SNI validation/deduplication;
- deterministic plan ordering;
- exhaustive fallback activation;
- legacy history migration.

### 29.2. Property/fuzz tests

- profile JSON decoder;
- evidence arrays and bounds;
- malformed timestamps/durations;
- content hash normalization;
- threshold intervals;
- planner with arbitrary hint combinations;
- no panic/unbounded allocation for large legacy history.

### 29.3. Integration tests

- detector suite → profile persistence;
- profile selection via exact ID;
- auto selection by context;
- stale profile → fast revalidation;
- context mismatch → ordinary Discovery;
- conflicting baseline suppresses hint;
- hinted candidate wins early;
- hints fail → full bounded search;
- profile does not leak into production/candidate sandbox;
- restart persistence and revocation.

### 29.4. Causal tests

For every claimed search optimization compare:

```text
same target/catalog/seed without detector profile
vs
same target/catalog/seed with detector profile
```

Report:

- probes executed;
- wall time;
- winning candidate rank;
- final winner equality/difference;
- validation results;
- misleading hint count.

A reduction in tests that changes the winner without adequate proof is not a PASS.

## 30. TGB test matrix

### 30.1. Deterministic connection tests

Using fake clock and controlled `net.Conn`:

1. first byte immediately;
2. first byte at 4.9 s;
3. first byte at 5.1 s;
4. first byte at 14.9 s;
5. first byte after soft timeout;
6. first byte just before hard timeout;
7. zero bytes through hard timeout;
8. client closes before first byte;
9. 1–3 bytes then delay;
10. 4–63 bytes then delay;
11. valid 64-byte handshake;
12. reserved/non-obfuscated first four bytes;
13. coalesced handshake + payload;
14. primary upstream failure;
15. worker success after primary failure;
16. direct success after worker failure;
17. all routes fail;
18. config reload while parked;
19. listener shutdown while parked;
20. cancellation race.

### 30.2. Prefix invariants

For every handoff case assert:

```text
bytes received by fallback == bytes originally sent by client
```

No duplicates or omissions.

### 30.3. Resource tests

- global limit enforced;
- per-client limit enforced;
- overflow policy exact;
- counters return to zero;
- no leaked goroutines/timers/sockets;
- 1000 sequential delayed connections remain bounded;
- concurrent config reload does not exceed limits;
- low-memory behavior degrades explicitly.

### 30.4. TPROXY integration

Network namespace/TPROXY tests MUST prove:

- original destination IP/port preserved;
- bypass mark prevents recursion;
- IPv4 behavior;
- IPv6 behavior when supported;
- worker/direct handoff receives exact destination;
- transparent bridge does not capture unrelated set traffic.

## 31. Real target validation

### 31.1. Issue #277 reproduction

Target setup:

```text
Keenetic/Entware
official Telegram Android
no proxy configured in Telegram
mobile data disabled
Telegram GeoSite/GeoIP set
routing mode mtproto-ws
```

Required evidence:

- connection accepted;
- at least one real delayed-first-data flow observed or controlled equivalent injected;
- no unconditional 5-second drop;
- successful bridge handshake/relay OR explicit bounded fallback;
- no increase in unrelated connection failures;
- pending limits not exceeded;
- restart/WAN flap cleanup.

### 31.2. Explicit MTProto proxy control

The existing explicit proxy path remains a control and must continue to work. Its success does not substitute for transparent path proof.

### 31.3. DDI target validation

Run Detector and Discovery on the same network/target:

```text
run A: detector profile disabled
run B: exact fresh profile enabled
run C: deliberately stale/conflicting profile
```

PASS requires:

- B reduces or does not materially increase bounded probe cost;
- B retains target-specific validation;
- C suppresses misleading hints and falls back normally;
- all runs preserve same safety controls;
- no false production promotion.

---

# Часть VI. Hard gates and release verdicts

## 32. DDI hard gates

```text
discovery_profile_without_context_validation_total == 0
discovery_profile_stale_without_revalidation_total == 0
discovery_profile_cross_wan_use_total == 0
discovery_profile_mutable_runtime_pointer_total == 0
discovery_profile_hint_without_provenance_total == 0
discovery_profile_hint_overrode_current_baseline_total == 0
discovery_profile_skipped_target_validation_total == 0
discovery_profile_disabled_exhaustive_fallback_total == 0
discovery_profile_direct_production_write_total == 0
discovery_profile_allowed_sni_direct_promotion_total == 0
discovery_profile_threshold_out_of_budget_total == 0
discovery_profile_capture_gate_bypass_total == 0
discovery_profile_cross_service_action_total == 0
discovery_profile_false_pass_total == 0
```

## 33. TGB hard gates

```text
mtproto_bridge_zero_byte_handled_drop_total == 0
mtproto_bridge_fixed_5s_destructive_timeout_total == 0
mtproto_bridge_unbounded_pending_total == 0
mtproto_bridge_pending_per_client_limit_bypass_total == 0
mtproto_bridge_prefix_loss_total == 0
mtproto_bridge_prefix_duplicate_total == 0
mtproto_bridge_route_recursion_total == 0
mtproto_bridge_primary_failure_silent_drop_total == 0
mtproto_bridge_overflow_without_reason_total == 0
mtproto_bridge_shutdown_leak_total == 0
mtproto_bridge_config_reload_deadline_reset_total == 0
mtproto_bridge_wrong_original_destination_total == 0
mtproto_bridge_secret_in_trace_total == 0
mtproto_bridge_false_handshake_success_total == 0
```

## 34. Release verdicts

DDI:

```text
DDI_SCHEMA_READY
DDI_REVALIDATION_READY
DDI_HINT_PLANNER_READY
DDI_TARGET_VALIDATED
DDI_PRODUCTION_READY
```

TGB:

```text
TGB_STATE_MACHINE_READY
TGB_PENDING_BUDGET_READY
TGB_PREFIX_HANDOFF_READY
TGB_ANDROID_VALIDATED
TGB_PRODUCTION_READY
```

Combined:

```text
ISSUE_278_RESOLVED
ISSUE_277_RESOLVED
```

`ISSUE_278_RESOLVED` requires proof of real integration and measured search impact, not only a new request field.

`ISSUE_277_RESOLVED` requires real/controlled delayed-first-byte proof and zero silent destructive drops, not only changing `5` to `30`.

---

# Часть VII. Implementation stages

## DDI-1 — Baseline audit and fixtures

Deliverables:

- map Detector suite/history/API lifecycle;
- map Discovery start/options/planner lifecycle;
- fixture profiles for DNS, TLS asymmetry, RST, timeout, fat threshold, allowed SNI, IP block;
- negative fixtures for stale/mismatched/conflicting contexts;
- implementation report and commit.

## DDI-2 — Versioned profile schema

Deliverables:

- `NetworkDiagnosticProfile` types;
- normalized content hash;
- bounds/validation;
- redacted export;
- schema migration contract;
- unit/fuzz tests.

## DDI-3 — Network context and freshness

Deliverables:

- WAN context collector;
- exact/compatible/mismatch comparator;
- TTL state machine;
- context-change invalidation;
- privacy tests.

## DDI-4 — Profile envelope, persistence and delivery (consumer of ABD-compiled `BlockingProfile`)

Deliverables:

- profile envelope/versioning вокруг immutable `BlockingProfile` payload (компиляция — `ABD-10`, не DDI);
- freshness и expiry;
- `NetworkContextID`/`ConfigGeneration` compatibility;
- atomic bounded profile store;
- revalidation (отклонение stale/incompatible, без перекомпиляции evidence);
- selection и delivery в guided Discovery;
- revoke/delete lifecycle.

**Ownership (FB-14 решение 1):** DDI не реализует второй compiler `raw evidence → BlockingProfile` и не меняет semantics `BlockingProfile`. DDI владеет только envelope/freshness/persistence/revalidation/selection/delivery и может отклонить stale/incompatible profile, но не перекомпилирует evidence и не повышает confidence.

> **superseded:** прежняя формулировка «raw suite → profile compiler» (до FB-14) удалена. Компиляция raw evidence → `BlockingProfile` принадлежит исключительно ABD (`ABD-10`, см. `B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md` §0.3).

## DDI-5 — Fast revalidation

Deliverables:

- bounded revalidation planner;
- evidence-specific probes;
- conflict handling;
- no-side-effect sandbox;
- API/status/events.

## DDI-6 — Discovery API integration

Deliverables:

- request/options extensions;
- profile selection modes;
- immutable snapshot plumbing;
- plan/hint-report endpoints;
- backward compatibility.

## DDI-7 — Hint compiler and deterministic search planning

Deliverables:

- mapping rules;
- priority boost/penalty/defer semantics;
- threshold seeding;
- allowed-SNI candidate integration;
- current baseline precedence;
- exhaustive fallback.

## DDI-8 — UI and observability

Deliverables:

- profile selector/freshness badge;
- applied/suppressed hint explanation;
- metrics/events;
- savings report;
- RU/EN strings.

## DDI-9 — Integration and causal validation

Deliverables:

- same-seed A/B comparisons;
- stale/conflict tests;
- restart/migration tests;
- resource bounds;
- issue bundle support.

## DDI-10 — Router/target release validation

Deliverables:

- real Detector → Discovery runs;
- target-specific validation proof;
- measured probe/time savings;
- negative-control proof;
- release verdict report.

## TGB-1 — Baseline audit and delayed-connection fixtures

Deliverables:

- map bridge/listener/fallback lifecycle;
- reproduce exact 5-second drop;
- fake-clock/fake-conn fixtures;
- delayed-first-byte corpus;
- implementation report.

## TGB-2 — Structured bridge outcome contract

Deliverables:

- replace boolean ownership ambiguity;
- explicit disposition/reason;
- compatibility adapter if required;
- listener integration tests.

## TGB-3 — First-data state machine

Deliverables:

- soft/hard deadline semantics;
- progress-aware handshake timeout;
- zero-byte no-drop behavior;
- config snapshot;
- deterministic state tests.

## TGB-4 — PendingHandshakeManager

Deliverables:

- global/per-client budgets;
- bounded lifecycle;
- overflow policy;
- shutdown/reload cleanup;
- resource tests.

## TGB-5 — Prefix-preserving handoff

Deliverables:

- raw immutable prefix capture;
- 0/1–3/4–63/64+ byte cases;
- worker/direct replay;
- no duplicate/loss properties.

## TGB-6 — Upstream route ladder

Deliverables:

- primary/worker/direct bounded route plan;
- no recursion;
- dial failure handoff;
- explicit terminal verdict;
- route metrics.

## TGB-7 — Config, migration and API

Deliverables:

- transparent config subtree;
- defaults/validation;
- legacy config behavior;
- live status API;
- config generation handling.

## TGB-8 — UI and diagnostics

Deliverables:

- beginner auto mode;
- advanced timeout/budget controls;
- pending status;
- reason-specific trace;
- privacy-safe issue bundle.

## TGB-9 — Packet-path and stress validation

Deliverables:

- TPROXY IPv4/IPv6 tests;
- marks/original destination proof;
- 1000-connection bounded stress;
- reload/shutdown race tests;
- no leak benchmark.

## TGB-10 — Keenetic and Android validation

Deliverables:

- reproduce issue #277 setup;
- prove delayed connections survive beyond 5 seconds;
- prove successful bridge or bounded fallback;
- explicit proxy control;
- WAN flap/reboot validation;
- release verdict report.

---

# Часть VIII. Companion document updates

After `DDI-10` and `TGB-10`:

1. Field Test Automation MUST add:
   - detector-guided A/B search suite;
   - stale/conflicting-profile suite;
   - Telegram delayed-first-byte suite;
   - pending-budget/overflow suite;
   - prefix replay and route-ladder suite.

2. Service Profiles MUST add:
   - declarative detector profile policy;
   - Telegram transparent handshake policy;
   - explicit proxy control/fallback projection;
   - capability and promotion requirements.

3. Implementation Validation MUST register:
   - `DDI-1…DDI-10`;
   - `TGB-1…TGB-10`;
   - all hard gates;
   - `ISSUE_278_RESOLVED` and `ISSUE_277_RESOLVED` verdicts;
   - validation-of-validation tests preventing false PASS.

---

# Definition of Done

The addendum is complete only when all of the following are true:

- Detector creates a versioned, scoped and freshness-aware diagnostic profile.
- Discovery can optionally select an exact profile and explain every applied/suppressed hint.
- Current target baseline overrides conflicting stored assumptions.
- Hints can reduce search cost but cannot disable target proof or exhaustive fallback.
- Measured A/B reports show whether the profile actually helped.
- A zero-byte Telegram connection is never silently claimed and dropped after five seconds.
- Delayed Telegram handshakes can resume within the bounded hard window.
- Pending sockets are bounded globally and per client.
- Partial/full prefixes are preserved exactly across handoff.
- Primary bridge dial failure can use configured bounded worker/direct fallback.
- TPROXY original destination and bypass marks remain correct.
- Real Keenetic/Android validation is complete.
- Companion Field Test, Service Profiles and Implementation Validation are updated.
- All hard gates are zero.

