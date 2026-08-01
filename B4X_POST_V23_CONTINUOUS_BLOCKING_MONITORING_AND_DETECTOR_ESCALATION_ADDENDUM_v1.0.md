# B4X Post-v2.3 Continuous Blocking Monitoring & Detector Escalation Addendum

**Версия:** 1.0  
**Дата:** 2026-07-30  
**Статус:** обязательный post-v2.3 companion addendum для B4X  
**База:** `B4_FORK_ARCHITECTURE.md` v2.3, завершённый `B4_FORK_PATCH_PLAN.md` v2.3, B4X branch `agent/classifier-v2.3-capture-envelope`, `B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.1.md`  
**Reference inspiration:** `belotserkovtsev/ladon` pinned at `8af5e68cadea16c177f17fb6a50f1e0b6931aa8d` (MIT), behavior-only clean-room extraction  
**Область:** эволюционная модернизация существующих B4/B4X monitoring/watchdog/Failure Inbox mechanisms, demand-driven runtime observations, temporal health model, client-resolution correlation, safe escalation into ABD, DDI, Discovery, WARP recommendation and canary control plane  
**Главная пользовательская цепочка:** реальный клиентский трафик → bounded passive monitoring → объяснимая гипотеза проблемы → quick/deep ABD → свежий `BlockingProfile` → DDI → guided Discovery/transport recommendation → scoped canary → promote/rollback  
**Главный migration-инвариант:** B4X не выполняет flag-day rewrite и не сохраняет legacy direct-apply semantics; новый monitoring core внедряется рядом с текущим Watchdog, принимает source-of-truth роль через shadow/cutover stages, а старый API/UI временно работает как compatibility adapter  
**Главный safety-инвариант:** monitoring observation, recurrence или provisional health failure никогда не являются `BlockingProfile`, `ActionAuthorization`, `TransportAuthorization` или разрешением на изменение production config

---

## 0. Нормативное решение: доработка, а не переписывание с нуля

### 0.1. Решение

B4X MUST применить **strangler-style evolutionary replacement**:

```text
существующие monitoring/watchdog surfaces
→ compatibility adapters
→ новый ContinuousBlockingMonitor core
→ shadow parity
→ controlled cutover
→ удаление legacy direct apply
```

Это означает:

- `src/tables/monitor.go` сохраняется как отдельный infrastructure-integrity monitor;
- существующий `/api/watchdog/*`, UI и config keys временно сохраняются;
- `src/watchdog` перестаёт быть владельцем diagnosis/promotion и становится adapter layer;
- новый package `src/monitor` становится владельцем observations, health state, temporal aggregation, trigger scheduling и ABD escalation;
- `src/diagnostics/failure_inbox.go` переиспользуется как bounded intake/projection, затем перестаёт быть параллельным source of truth;
- `src/observability` остаётся metrics/trace/export sink, но не становится temporal database;
- DNS/SNI/QUIC correlation, `ClientKey`, `ConfigGeneration`, PPE visibility и candidate canary infrastructure переиспользуются;
- legacy `watchdog.checkDomain()` и `applyBatchResults()` выводятся из production path поэтапно;
- прямой путь `failure → Discovery → config mutation` запрещается сразу после включения production-safe monitoring mode.

### 0.2. Почему не full rewrite

Полное переписывание с нуля создаст ненужный риск:

1. потеря API/UI/config compatibility;
2. параллельные источники truth для health и failures;
3. повторная реализация client identity, DNS correlation, bounded telemetry и canary accounting;
4. высокий риск regression в shutdown/reload/table lifecycle;
5. длительный период, когда legacy Watchdog и новый monitor одновременно меняют config;
6. отсутствие измеримой shadow parity;
7. невозможность безопасного rollback на промежуточных stages.

### 0.3. Почему недостаточно «просто расширить Watchdog»

Текущий Watchdog владеет сразу четырьмя несовместимыми обязанностями:

```text
scheduled active health check
+ diagnosis trigger
+ Discovery orchestration
+ direct config mutation
```

Новая архитектура разделяет их:

```text
Monitoring
→ здоровье и необходимость диагностики

ABD
→ активное доказательное исследование

DDI
→ network-context/freshness envelope

Discovery
→ поиск кандидатов

Action/Transport control plane
→ canary, promotion, rollback
```

Поэтому решение является не косметическим refactor одного файла, а **заменой внутреннего ядра с сохранением внешней совместимости**.

### 0.4. Capability и stages

Этот addendum вводит capability:

```text
continuous-blocking-monitoring-and-detector-escalation
```

и companion stages:

```text
MON-1 … MON-12
```

где `MON` означает **Continuous Monitoring**.

---

# Часть I. Нормативный статус и зависимости

## 1. Место в post-v2.3 последовательности

```text
B4_FORK_ARCHITECTURE.md v2.4
→ B4_FORK_PATCH_PLAN.md Stage 1–36
→ Cross-Service Isolation
→ RST/GSO hardening
→ Keenetic PPE per-flow offload
→ WARP/MASQUE v1.2
→ Silent Path Failure and Scoped Recovery
→ Adaptive Blocking Detector v1.1
→ этот addendum: MON-1…MON-12
→ Detector-Guided Discovery / DDI
→ Service Profiles / Beginner UX
→ Field Test Automation
→ Implementation Validation
→ production promotion
```

Monitoring MAY быть реализован после базовых classifier/capture/Failure Inbox primitives и параллельно с частью ABD schemas, но `MON-8` и далее требуют стабильного ABD TargetPlan/probe request contract.

## 2. Ownership boundaries

| Область | Владелец |
|---|---|
| firewall/routing rule integrity | `tables.Monitor` / Infrastructure Integrity |
| passive flow/DNS/SNI/QUIC observations | `MON` |
| monitored subject identity | `MON` + Service Profiles |
| exact client-resolution snapshot | `MON`/DNS correlation |
| temporal recurrence, decay, recovery | `MON` |
| source heartbeat and visibility suppressors | `MON` consuming PPE/capture state |
| active quick/deep probes | `ABD` |
| evidence graph and `BlockingProfile` | `ABD` |
| reusable network envelope and freshness | `DDI` |
| candidate search and ranking | existing Discovery |
| WARP/transport availability and path proof | WARP subsystem |
| canary, promotion, rollback | Action/Transport control plane |
| metrics/trace/issue bundle projection | observability |
| legacy `/api/watchdog/*` compatibility | Watchdog adapter |

## 3. Нормативная модель

```text
Client traffic
→ MonitorObservation
→ MonitorSubject
→ MonitorAssessment
→ DiagnosticTriggerDecision
→ MonitorDiagnosticRequest
→ ABD TargetPlan overlay
→ EvidenceGraph
→ BlockingProfile
→ DDI NetworkDiagnosticProfile
→ DiscoverySearchPrior / TransportRecommendation
→ scoped canary
→ promote or rollback
```

Запрещённая модель:

```text
HTTP GET failed N times
→ Discovery
→ overwrite SetConfig
```

---

# Часть II. Audit текущей реализации

## 4. `tables.Monitor`: сохранить и переименовать концептуально

Существующий `src/tables/monitor.go` проверяет:

- наличие B4 iptables/nftables chains;
- jumps из `FORWARD`, `POSTROUTING`, `PREROUTING`, `OUTPUT`;
- DNS request/response NFQUEUE hooks;
- TCP capture hook;
- processed mark accept rule;
- masquerade;
- MSS clamp;
- routing interface changes;
- потерю policy-routing rules;
- periodic re-resolution;
- автоматическое восстановление rules.

Это не blocking monitor. Нормативное имя responsibility:

```text
InfrastructureIntegrityMonitor
```

Он MUST:

- сохранить собственный lifecycle;
- публиковать structured health snapshots;
- подавлять MON auto-diagnose при неполной capture visibility;
- не создавать service-level blocking hypotheses;
- не запускать ABD/Discovery напрямую.

## 5. Legacy Watchdog: сохранить surface, заменить core

Текущий `src/watchdog`:

- использует статический список domains;
- выполняет router-origin HTTP GET;
- ставит `SO_MARK`;
- проверяет TLS certificate;
- читает до фиксированных 16 KiB;
- требует минимум 1 KiB;
- классифицирует block-page redirect/body;
- повышает частоту после failure;
- после retries запускает Discovery;
- применяет лучший result к существующему или новому set;
- сохраняет config.

Полезные элементы для переиспользования:

- enable/disable lifecycle;
- pinned monitored targets;
- status API;
- force-check command;
- cooldown UI concept;
- graceful shutdown hooks;
- config save plumbing только как final authorized transaction adapter.

Элементы, которые MUST быть удалены из production-safe path:

- `ValidationTries: 1` как достаточный promotion proof;
- domain-only scope;
- router-origin success как forwarded-client proof;
- fixed 16 KiB universal availability test;
- unbounded one-goroutine-per-domain batch;
- direct `applyBatchResults()`;
- создание `watchdog-*` set без Service Profile/authorization scope;
- изменение существующего set без baseline/control/canary;
- `SkipDNS: true` без client-resolution provenance;
- один `StatusHealthy/Degraded/Escalating` enum как полная модель.

### 5.1. 16 KiB — bounded memory budget, не protocol threshold (FB-14 решение 11)

`16 KiB` в legacy watchdog («читает до фиксированных 16 KiB», §5) и в availability-проверках является **безопасным default memory budget `max_reassembly_bytes_per_flow`** для Keenetic/OpenWrt-class targets, а не универсальной границей ClientHello, DPI или application data.

Допускается configurable повышение (например, до `32 KiB` или иного validated maximum) только при одновременных bounds:

```text
per-flow
+ per-client
+ global memory
+ segment count
+ timeout
+ concurrent reassemblies
```

При превышении configured bound:

```text
explicit bounded abort
+ metric/event
+ safe fail-open/ambiguity result
```

Запрещён ложный `complete` verdict.

> **superseded (FB-14 решение 11):** формулировки «фиксированные 16 KiB» (строка 214) и «fixed 16 KiB universal availability test» (строка 237) трактуются в соответствии с настоящим пунктом; validation matrix должна включать small, boundary, above-boundary и configured-maximum cases, включая fragmented/out-of-order/retransmission layouts.

## 6. Failure Inbox: переиспользовать как intake/projection

Текущий `src/diagnostics/failure_inbox.go` уже обеспечивает:

- passive-only contract;
- source-scoped `ClientKey`;
- destination/protocol validation;
- bounded candidate count;
- bounded evidence/signals/reasons;
- short retention;
- redacted DNS/QUIC evidence;
- no candidate creation from ordinary DNS traffic alone;
- suggested diagnostic actions;
- privacy-safe trace event.

Недостаёт:

- `NetworkContextID`;
- explicit `ConfigGeneration` in inbox key;
- Service Profile/component scope;
- success/recovery observations;
- client-resolution snapshot ID;
- temporal buckets beyond short retention;
- recurrence versus independence;
- source health;
- diagnostic request lifecycle;
- persisted assessment;
- ABD run/profile references.

Migration rule:

```text
FailureInbox
→ initially source adapter into MON
→ later UI/API projection of MonitorAssessment
```

Он MUST NOT оставаться вторым independent source of truth после `MON-11`.

## 7. Observability: sink, не database

`src/observability` сохраняется как:

- bounded metric registry;
- bounded redacted trace ring;
- issue bundle exporter;
- evidence/probe summary sink.

Он MUST NOT использоваться для:

- восстановления full monitoring state;
- temporal confidence;
- durable recurrence counters;
- deduplication truth;
- trigger idempotency;
- long-term client-resolution history.

## 8. CanaryMonitor: переиспользовать, но не расширять до общего monitor

`src/nfq/canary_monitor.go` полезен для candidate validation:

- bounded flow map;
- eligibility after classification;
- TCP/UDP return progress;
- RST accounting;
- TTL/eviction;
- aggregate snapshots.

Он остаётся в candidate/canary plane. MON MAY потреблять его summary после ABD/Discovery, но MUST NOT использовать SYN-ACK-only canary progress как proof полной service health.

## 9. Scoped failure state: оставить short-lived enforcement helper

`src/nfq/scoped_failure_state.go` хранит attempts, temporary blocked state, escalation hops и sent-RST state, привязанные к client/domain/set/config generation.

Он MUST:

- остаться короткоживущим runtime helper;
- не стать temporal monitoring database;
- не переживать несовместимые config/network generations;
- публиковать observations в MON через adapter;
- не выпускать MonitoringAssessment самостоятельно.

---

# Часть III. Reference extraction: Ladon

## 10. Pinned reference

```yaml
reference:
  project: belotserkovtsev/ladon
  commit: 8af5e68cadea16c177f17fb6a50f1e0b6931aa8d
  license: MIT
  extraction_mode: behavior-only-clean-room
  useful_roles:
    - demand-driven intake from real DNS traffic
    - query/CNAME/answer correlation
    - preference for client-observed resolved endpoints
    - provisional inline probe plus authoritative background lane
    - local-versus-remote stage-aware comparison
    - temporal recurrence and hysteresis
    - bounded deduplication and queueing
    - domain-family/cohort hints
```

## 11. Что переносится

B4X принимает следующие идеи:

1. мониторить реально востребованные targets, а не только статический список;
2. связывать probe с exact DNS answer, который видел клиент;
3. сохранять CNAME provenance;
4. разделять provisional fast lane и authoritative ABD;
5. запускать expensive remote observer только после local failure или explicit need;
6. накапливать recurrence во времени;
7. использовать cohort только как diagnostic priority hint;
8. сохранять outcome каждого address, а не только first success;
9. различать observer unavailable и target failed;
10. различать exact-endpoint и independent-resolution comparisons.

## 12. Что не переносится

B4X MUST NOT наследовать:

- первый failure → tunnel route;
- monitor verdict → production action;
- любое TCP failure → DPI;
- `remote fail → clear`;
- TLS alert как безусловный origin-alive proof;
- TLS1.3/TLS1.2 asymmetry как confirmed ECH/SNI block;
- broad eTLD+1 routing after sibling confirmations;
- unverified TLS as certificate-integrity evidence;
- один fixed body window как universal block threshold;
- observer result без capability declaration.

---

# Часть IV. Goals, non-goals и invariants

## 13. Goals

MON MUST:

- наблюдать service/component health на реальном client traffic;
- поддерживать pinned targets и demand-discovered targets;
- связывать DNS, SNI, QUIC, flow progress, retries и controls;
- сохранять exact client-resolution provenance;
- различать health, suspicion и diagnosis states;
- накапливать temporal recurrence с decay/hysteresis;
- обнаруживать recovery;
- учитывать capture/PPE/queue/WAN suppressors;
- планировать bounded quick/deep ABD requests;
- не дублировать ABD probes/evidence graph;
- не дублировать DDI freshness store;
- не дублировать Discovery optimizer;
- объяснять пользователю, почему диагностика предложена или подавлена;
- работать в ресурсных пределах Keenetic;
- мигрировать legacy Watchdog без API flag day;
- поддерживать deterministic tests и rollback.

## 14. Non-goals

MON не должен:

- заменять `tables.Monitor`;
- быть packet classifier;
- хранить raw packets;
- сохранять полную DNS history по умолчанию;
- компилировать final `BlockingProfile`;
- решать, какая packet mutation победила;
- автоматически включать WARP по одному timeout;
- автоматически менять production config;
- выполнять broad Internet scanning;
- утверждать provider-wide blocking по одному target;
- объединять клиентов, сети или Service Profiles ради статистики без явной aggregate policy;
- считать router-origin probe эквивалентом Android/forwarded proof.

## 15. Core invariants

```text
MonitorObservation
≠ BlockingProfile
≠ ActionAuthorization
≠ TransportAuthorization
```

```text
recurrence
≠ independence
```

```text
router-origin health
≠ forwarded-client health
```

```text
configured route
≠ observed path proof
```

```text
one destination IP
≠ one service identity
```

```text
same eTLD+1
≠ same Service Profile/component
```

```text
fast lane result
≠ authoritative ABD result
```

```text
old Watchdog API compatibility
≠ legacy direct apply compatibility
```

---

# Часть V. Target architecture

## 16. Package layout

Рекомендуемая структура:

```text
src/monitor/
  types.go
  config.go
  service.go
  observation_bus.go
  subject_resolver.go
  resolution_store.go
  temporal.go
  suppressors.go
  source_health.go
  fastlane.go
  trigger_planner.go
  scheduler.go
  abd_adapter.go
  ddi_adapter.go
  recommendation_adapter.go
  persistence.go
  migration.go
  api_projection.go
  metrics.go
  events.go
  *_test.go

src/watchdog/
  adapter.go
  legacy_api.go
  legacy_config.go
  deprecation.go
```

После final cutover:

- `watchdog/checker.go` MUST быть удалён или оставлен только как test fixture adapter;
- `watchdog/applier.go` MUST быть удалён из production build;
- `watchdog/watchdog.go` MUST делегировать в `monitor.Service`;
- legacy API types MAY оставаться до следующей major API version.

## 17. Runtime graph

```text
NFQ/DNS/TUN/PPE/Android events
        │
        ▼
MonitorObservationBus
        │
        ├─ source health / visibility
        ├─ client resolution snapshots
        ├─ subject identity
        └─ passive flow progress
        │
        ▼
TemporalEvidenceAccumulator
        │
        ▼
MonitorAssessmentStore
        │
        ▼
DiagnosticTriggerPlanner
        │
        ├─ suppress
        ├─ notify
        ├─ quick ABD
        └─ deep ABD
        │
        ▼
ABD → BlockingProfile → DDI
        │
        ▼
Discovery / WARP recommendation
        │
        ▼
scoped canary → promote/rollback
```

## 18. Control plane separation

`monitor.Service` MUST иметь только narrow interfaces:

```go
type ABDRequester interface {
    Submit(ctx context.Context, req MonitorDiagnosticRequest) (DiagnosticRunRef, error)
    Cancel(ctx context.Context, runID string) error
}

type DiagnosticProfileReader interface {
    GetBlockingProfile(ctx context.Context, profileID string) (*BlockingProfileSummary, error)
}

type RecommendationPublisher interface {
    Publish(ctx context.Context, recommendation MonitorRecommendationRef) error
}
```

MON MUST NOT импортировать packet action executor или напрямую сохранять `SetConfig`.

---

# Часть VI. Schemas

## 19. MonitorScopeKey

```go
type MonitorScopeKey struct {
    ClientScope        ClientScopeKey
    ServiceProfileID   string
    ComponentID        string
    DomainIdentityID   string
    TargetRole         string

    DestinationIPHash  string
    DestinationPort    uint16
    L4Protocol         uint8
    IPFamily           string

    BindingID          string
    PathMode           string

    NetworkContextID   string
    ConfigGeneration   uint64
}
```

Rules:

- `ClientScope` обязателен для forwarded observations;
- router-origin subject использует explicit `router-origin` role;
- target/control role обязателен после Service Profile resolution;
- unresolved service identity сохраняется как provisional subject;
- cross-client merge запрещён;
- cross-network merge запрещён;
- cross-generation merge запрещён;
- destination-only subject не может запускать deep ABD без identity refinement.

## 20. MonitorObservation

```go
type MonitorObservation struct {
    SchemaVersion       uint16
    ObservationID       string
    Scope               MonitorScopeKey

    Source               ObservationSource
    OutcomeCode          string
    FailureAttribution   FailureAttribution
    Authority            EvidenceAuthority

    ObservedAt           time.Time
    ExpiresAt            time.Time
    MonotonicNS          uint64

    ResolutionSnapshotID string
    FlowTraceID          string
    EvidenceRefs         []string

    UniqueBytesIn        uint64
    UniqueBytesOut       uint64
    PacketCountIn        uint64
    PacketCountOut       uint64
    RetryCount           uint16

    SourceHealthID       string
    VisibilitySnapshotID string
}
```

## 21. ObservationSource

```text
dns_query
dns_answer
dns_timeout
dns_contradiction
packet_sni
reassembled_sni
quic_sni
quic_initial
quic_response
tcp_syn
tcp_synack
tcp_rst
conntrack_unreplied
tls_alert
tls_server_hello
http_headers
http_body_progress
unique_inbound_progress
silent_stall
flow_retry
queue_drop
ppe_visibility
classifier_ambiguous
cross_service_scope_violation
route_scope_rejected
android_milestone
control_success
control_failure
watchdog_pinned_probe
abd_result
canary_result
```

Каждый source MUST иметь schema, bounded payload, authority class и freshness policy.

## 22. EvidenceAuthority

```go
type EvidenceAuthority string

const (
    AuthorityPassiveObservation EvidenceAuthority = "passive-observation"
    AuthorityProvisionalFast    EvidenceAuthority = "provisional-fast"
    AuthorityAuthoritativeABD   EvidenceAuthority = "authoritative-abd"
    AuthorityAndroidCanary      EvidenceAuthority = "android-canary"
)
```

Authority controls:

- passive/provisional не компилируют `BlockingProfile`;
- repeated passive evidence не меняет authority;
- only ABD output может стать authoritative diagnosis;
- only scoped canary может подтвердить real-client candidate behavior;
- authority downgrade обязателен при stale source/network context.

## 23. ClientResolutionSnapshot

```go
type ClientResolutionSnapshot struct {
    SchemaVersion       uint16
    SnapshotID          string
    ClientKeyHash       string
    NetworkContextID    string
    ConfigGeneration    uint64

    OriginalQNameHash   string
    QueryIDHash         string
    QueryType           string
    ResolverID          string
    ResolverTransport   string

    CNAMEChainHashes    []string
    Answers             []ResolvedEndpoint
    AnswerOrder         []uint16
    TTLs                []uint32

    ObservedAt          time.Time
    ValidUntil          time.Time
    ProvenanceRefs      []string
}

type ResolvedEndpoint struct {
    IPHash              string
    IPFamily            string
    AddressIndex        uint16
    TTL                 uint32
}
```

Requirements:

- terminal A/AAAA MUST быть attributed к original QName через transaction/CNAME graph;
- snapshot immutable;
- probe input содержит selected endpoint и reason;
- new lookup не может silently replace client-observed answer;
- expired answer может использоваться только как historical context, не exact endpoint proof;
- all address outcomes сохраняются.

## 24. AddressOutcomeVector

```go
type AddressOutcome struct {
    EndpointHash       string
    AddressIndex       uint16
    TCPOutcome         string
    TLSOutcome         string
    HTTPOutcome        string
    QUICOutcome        string
    LatencyMS          uint32
    UniqueBodyBytes    uint64
    Attribution        FailureAttribution
}
```

First-success racing MAY ускорять user-visible result, но MUST NOT удалять failures остальных attempted addresses.

## 25. MonitorSubject

```go
type MonitorSubject struct {
    SubjectID           string
    Scope               MonitorScopeKey
    Origin              string
    // service-profile | pinned-watchdog | observed-demand | failure-inbox

    Enabled              bool
    Priority             uint8
    MonitoringPolicyID   string

    FirstObservedAt      time.Time
    LastObservedAt       time.Time
    LastDemandAt         time.Time
    ExpiresAt            time.Time

    ResolutionRefs       []string
    DeclaredControls     []string
    PrivacyClass         string
}
```

## 26. MonitorAssessment

```go
type MonitorAssessment struct {
    AssessmentID         string
    SubjectID            string
    Scope                MonitorScopeKey

    HealthState          HealthState
    DiagnosticState      DiagnosticState

    FirstObservedAt      time.Time
    LastObservedAt       time.Time
    LastSuccessAt        time.Time
    LastFailureAt        time.Time

    RecurrenceScore      float64
    IndependenceScore    float64
    ContradictionScore   float64

    ObservationBuckets   []TemporalEvidenceBucket
    SupportingRefs       []string
    ContradictionRefs    []string
    ActiveSuppressors    []string

    TriggerDecision      *DiagnosticTriggerDecision
    ActiveDiagnosticRun  string
    BlockingProfileID    string
    DDIProfileID         string
    RecommendationID     string

    ExpiresAt            time.Time
}
```

## 27. Две независимые state axes

### 27.1. HealthState

```text
unknown
healthy
degraded
failing
recovering
recovered
```

### 27.2. DiagnosticState

```text
passive
suspected
correlated
suppressed
queued_quick
running_quick
quick_inconclusive
queued_deep
running_deep
profile_ready
profile_stale
recommendation_ready
canary_running
resolved
expired
```

Запрещено заменять обе оси одним `healthy/degraded/escalating` enum.

---

# Часть VII. Observation intake

## 28. MonitorObservationBus

Bus MUST:

- принимать typed observations;
- валидировать source schema;
- назначать event ID;
- проверять network/config generation;
- выполнять bounded queueing;
- применять per-source backpressure;
- отделять P0 safety events от P1/P2 analytics;
- сохранять drop counters;
- не блокировать packet path на durable write;
- поддерживать deterministic test clock;
- иметь source heartbeat.

## 29. Source adapters

Нужны adapters:

```text
FailureInboxAdapter
DNSObservationAdapter
ClassifierObservationAdapter
SPFObservationAdapter
PPEVisibilityAdapter
CanaryObservationAdapter
LegacyWatchdogPinnedTargetAdapter
AndroidFieldSignalAdapter
```

Adapter не должен менять authority исходного evidence.

## 30. DemandTargetInbox

Реальные client DNS/SNI/QUIC observations могут создать demand candidate:

```go
type ObservedDemandTarget struct {
    ObservationID       string
    ClientKeyHash       string
    DomainIdentityID    string
    ServiceProfileID    string
    ComponentID         string
    ObservationSource   string
    NetworkContextID    string
    ConfigGeneration    uint64
    FirstObservedAt     time.Time
    LastObservedAt      time.Time
    ObservationCount    uint32
    ExpiresAt            time.Time
}
```

Demand intake MAY:

- создать provisional subject;
- увеличить priority существующего subject;
- обновить client-resolution snapshot;
- запланировать fast lane;
- предложить пользователю диагностику.

Demand intake MUST NOT:

- автоматически добавить domain в production set;
- создать wildcard Service Profile;
- запустить unbounded scan;
- сохранить clear domain в export по умолчанию;
- объединить clients;
- считать query proof service failure.

## 31. Intake budgets

Минимальные budgets:

```yaml
intake:
  max_new_subjects_per_hour: 128
  max_subjects_total: 2048
  max_per_client_per_hour: 32
  max_pending_identity_resolution: 64
  max_resolution_snapshots: 4096
  max_cname_depth: 16
  max_answers_per_snapshot: 32
```

Overload behavior:

- drop lowest-priority unseen subjects first;
- never drop already failing P0 subject silently;
- preserve counter and reason;
- never fall back to direct action.

---

# Часть VIII. Temporal model

## 32. TemporalEvidenceBucket

```go
type TemporalEvidenceBucket struct {
    Start               time.Time
    End                 time.Time
    ObservationCount    uint32
    SuccessCount        uint32
    FailureCount        uint32
    DistinctSources     uint16
    DistinctEndpoints   uint16
    DistinctFlows       uint16
    DistinctFingerprints uint16
    DistinctWANIntervals uint16
    SourceFamilyBitmap  uint64
}
```

## 33. Recurrence versus independence

```text
recurrence_score
→ как часто проблема повторяется

independence_score
→ насколько разные evidence families подтверждают её
```

Примеры:

```text
50 SYN timeouts одного flow pattern
→ high recurrence
→ low independence
```

```text
SYN timeout + QUIC no-response + healthy unrelated control
+ exact endpoint success via healthy reference observer
→ stronger independence
```

## 34. Hysteresis

Health escalation MUST требовать больше evidence, чем recovery demotion или наоборот в соответствии с policy, но thresholds должны быть явными.

Recommended default:

```text
unknown → degraded:
  2 failures separated by >= 10s

 degraded → failing:
  3 recurrent failures
  or 2 independent failure families

 failing → recovering:
  1 authoritative success or 2 passive successes

 recovering → healthy:
  3 separated successes and no active contradiction
```

## 35. Decay

Temporal evidence MUST:

- иметь half-life;
- истекать по network context;
- сбрасывать authority после WAN change;
- сохранять historical audit отдельно от active score;
- не переноситься через incompatible ConfigGeneration;
- demote after sustained success.

## 36. Cohort hints

```go
type DomainCohortHypothesis struct {
    CohortID             string
    ServiceProfileID     string
    ComponentID          string
    RegistrableDomainHash string
    ConfirmedMembers     []string
    CandidateMembers     []string
    DistinctEndpointSets uint16
    DistinctASNs         uint16
    Confidence           string
    ExpiresAt            time.Time
}
```

Cohort effect limited to:

- probe priority;
- control reuse suggestion;
- TargetPlan overlay suggestion.

Cohort MUST NOT:

- authorize wildcard routing;
- cross Service Profile/component;
- include public suffix/shared hosting without explicit profile declaration;
- hide healthy sibling contradictions.

---

# Часть IX. Visibility, source health и suppressors

## 37. SourceHealthSnapshot

```go
type SourceHealthSnapshot struct {
    SourceID             string
    State                string
    // healthy | degraded | stale | unavailable
    LastHeartbeat        time.Time
    QueueDepth           uint32
    DroppedEvents        uint64
    LastErrorCode        string
    NetworkContextID     string
    ConfigGeneration     uint64
}
```

## 38. VisibilitySnapshot

MON consumes:

- NFQUEUE readiness;
- processed-mark verification;
- queue/user drops;
- PPE/offload suspicion;
- packet/byte counter freshness;
- GSO normalization state;
- capture envelope generation;
- routing rule health;
- DNS observation coverage;
- Android test-session identity where applicable.

## 39. Suppressors

Required suppressors:

```text
global_wan_failure
capture_visibility_incomplete
queue_drop_pressure
ppe_offload_bypass_suspected
source_heartbeat_stale
network_context_transition
config_generation_transition
resolver_outage
origin_multi_path_failure
healthy_target_recently_observed
insufficient_target_identity
resource_budget_exhausted
manual_pause
active_user_discovery
active_conflicting_diagnostic
```

Suppressor behavior:

- visible in UI/API;
- no hidden trigger skip;
- exact expiry/revalidation condition;
- no auto-diagnose while critical suppressor active;
- manual diagnose MAY override selected non-safety suppressors with warning;
- critical visibility suppressors cannot be overridden for packet-sensitive verdicts.

---

# Часть X. Provisional fast lane

## 40. Fast lane purpose

Fast lane answers only:

```text
стоит ли запускать authoritative ABD?
```

It does not answer:

```text
какая блокировка доказана?
какую strategy включить?
```

## 41. Fast lane plan

Allowed probes:

- exact client-resolved endpoint TCP reachability;
- bounded TLS progress with declared fingerprint;
- bounded HTTP headers/body progress if safe;
- local direct/native path only;
- one healthy control where budget permits.

## 42. Fast lane outputs

```text
provisional_available
provisional_failure
provisional_stage_failure
provisional_ambiguous
provisional_suppressed
```

Output MAY:

- update assessment;
- increase priority;
- schedule ABD;
- notify user.

Output MUST NOT:

- compile final `BlockingProfile`;
- start Discovery;
- enable WARP;
- mutate config;
- count as independent evidence family more than once;
- bypass controls.

## 43. Fast lane budgets

```yaml
fast_lane:
  max_parallelism: 1
  max_per_hour: 24
  max_per_subject_per_hour: 3
  connect_timeout: 2s
  tls_timeout: 3s
  body_timeout: 5s
  max_body_bytes: 16KiB
  max_total_duration: 8s
```

`max_body_bytes` is a resource cap, not universal success/failure threshold.

---

# Часть XI. Diagnostic trigger planner

## 44. DiagnosticTriggerDecision

```go
type DiagnosticTriggerDecision struct {
    DecisionID          string
    SubjectID           string
    RequestedMode       string
    // none | quick | deep
    ReasonCodes         []string
    SupportingRefs      []string
    SuppressorRefs      []string
    BudgetLeaseID       string
    CreatedAt           time.Time
    ExpiresAt           time.Time
}
```

## 45. Quick ABD trigger

Quick ABD MAY start when:

- two independent passive source families indicate failure;
- one recurring family spans required time separation and controls are healthy;
- explicit typed block response is observed under healthy visibility;
- provisional fast lane fails and target identity is sufficient;
- user requests diagnosis;
- legacy Watchdog force-check is translated to quick ABD.

## 46. Deep ABD trigger

Deep ABD MAY start when:

- quick ABD returns probable but incomplete hypothesis;
- failure is persistent across windows;
- multi-IP/address-selective outcomes conflict;
- transport recommendation requires reference/QUIC/L4 evidence;
- user selects deep diagnosis;
- reusable `BlockingProfile` is needed for DDI/Discovery.

## 47. Trigger prerequisites

```text
valid MonitorScopeKey
+ current NetworkContextID
+ current ConfigGeneration
+ healthy source heartbeat
+ sufficient visibility
+ resource lease
+ target provenance
+ no global WAN outage
+ no conflicting run
```

## 48. Scheduler

Scheduler MUST provide:

- global/per-client/per-service budgets;
- quick/deep queues;
- deterministic priority;
- coalescing of equivalent requests;
- cancellation on WAN/config transition;
- no duplicate concurrent ABD run for same scope;
- backoff/cooldown;
- starvation prevention;
- persisted run references;
- safe restart recovery.

---

# Часть XII. ABD integration

## 49. MonitorDiagnosticRequest

```go
type MonitorDiagnosticRequest struct {
    SchemaVersion        uint16
    RequestID            string
    AssessmentID         string
    SubjectID            string
    Mode                 string

    Scope                MonitorScopeKey
    TargetPlanOverlay    TargetPlanOverlay
    ResolutionSnapshots  []ClientResolutionSnapshotRef
    PassiveEvidenceRefs  []string
    ControlHealthRefs    []string
    VisibilitySnapshotID string

    NetworkContextID     string
    ConfigGeneration     uint64
    BudgetLeaseID        string
    RequestedAt          time.Time
    ExpiresAt            time.Time
}
```

## 50. TargetPlanOverlay

Overlay MAY:

- prioritize observed endpoints;
- include real client CNAME/answer chain;
- include relevant service component;
- add same-service/unrelated controls;
- request exact-endpoint and independent-resolution modes;
- select quick/deep budget.

Overlay MUST NOT:

- remove mandatory ABD controls;
- broaden action scope;
- mark passive observation authoritative;
- disable full bounded fallback;
- define a second probe schema.

## 51. ABD response

MON consumes only structured refs:

```go
type MonitorDiagnosticResult struct {
    RunID               string
    AssessmentID        string
    CompletionState     string
    BlockingProfileID   string
    EvidenceGraphID     string
    NetworkContextID    string
    ConfigGeneration    uint64
    CompletedAt         time.Time
    ValidUntil          time.Time
}
```

Partial/cancelled run:

- may update UI;
- may preserve evidence refs;
- cannot set `profile_ready`;
- cannot trigger DDI/Discovery.

## 52. Multi-vantage requirements

Observer MUST declare:

```go
type ObserverCapability struct {
    DNS                 bool
    TCP                 bool
    TLS                 bool
    CertificateVerify   bool
    HTTPHeaders         bool
    HTTPBodyProgress    bool
    QUIC                bool
    IPFamilies          []string
    FingerprintIDs      []string
}
```

Comparison modes:

```text
exact_endpoint
independent_resolution
```

HTTP hypothesis requires HTTP-capable observer. Observer unavailable means no opinion, not target failure.

---

# Часть XIII. DDI, Discovery и transport recommendations

## 53. DDI handoff

MON MUST NOT cache/reuse `BlockingProfile` independently of DDI.

```text
ABD BlockingProfile
→ DDI NetworkDiagnosticProfile
→ context/freshness/revalidation
```

MON stores only references and current status projection.

## 54. Discovery handoff

MON does not call Discovery from passive/provisional states.

Allowed:

```text
profile_ready
+ DDI profile valid
+ user/policy allows recommendation
→ guided Discovery request
```

Discovery still performs:

- baseline-none;
- baseline-production;
- candidate validation;
- controls;
- bounded fallback;
- ranking;
- canary handoff.

## 55. WARP recommendation

IP/SYN/CIDR path hypotheses MAY create:

```text
WARP suitable to test
```

only after:

- authoritative ABD profile;
- fresh DDI context;
- exact service/component/client scope;
- healthy controls;
- WARP base readiness;
- current WARP causal trace/path proof capability.

Monitoring itself MUST NOT enable WARP.

## 56. Recovery monitoring

After candidate promotion, MON MAY observe:

- target health;
- control health;
- recurrence reduction;
- new failures;
- binding/path changes;
- rollback signals.

But rollback authorization belongs to canary/action policy, not MON directly.

---

# Часть XIV. Legacy Watchdog migration

## 57. Compatibility strategy

Legacy endpoints remain initially:

```text
GET    /api/watchdog/status
POST   /api/watchdog/check
POST   /api/watchdog/domains
DELETE /api/watchdog/domains/{domain}
POST   /api/watchdog/enable
POST   /api/watchdog/disable
```

They translate to MON:

| Legacy command | New meaning |
|---|---|
| add domain | create pinned MonitorSubject |
| delete domain | disable/delete pinned subject |
| enable | enable MON pinned-target source |
| disable | pause pinned source; passive global source policy separate |
| force check | submit bounded quick diagnostic |
| status | project MonitorAssessment into legacy fields |

### 57.1. Legacy API lifetime — event-driven cutover (FB-14 решение 3)

Cutover является **событийным**, а не привязанным к календарной дате. `legacy_watchdog_api=true` допускается только как shadow/read-only compatibility surface:

Legacy endpoint НЕ имеет права:

```text
- менять config;
- создавать sets;
- запускать direct Discovery apply;
- владеть scheduler/state;
- выполнять promotion/rollback;
- служить вторым mutating source of truth.
```

Cutover разрешён только после одновременного прохождения:

```text
Monitoring shadow parity
+ scheduler readiness
+ ABD/DDI integration readiness
+ transactional apply path readiness
+ rollback readiness
+ API migration tests
```

После cutover:

```text
- любые legacy POST/PUT/PATCH/DELETE /api/watchdog/* возвращают 410 Gone
  или стабильную migration error;
- read-only GET alias разрешён максимум один совместимый minor release;
- read-only alias читает Monitoring state и не хранит собственный state;
- затем маршруты полностью удаляются;
- одновременно никогда не допускаются два mutating sources of truth.
```

`MON_PRODUCTION_READY` запрещён, если хотя бы один legacy mutating path достижим из production router.

> **superseded (FB-14):** прежняя формулировка §57 «Legacy endpoints remain initially» без явного события cutover уточнена настоящим пунктом; правило §60 (Phases A–F) сохраняется как механизм, но его входные условия определяются §57.1.

## 58. Status projection

Legacy fields are derived:

```text
StatusHealthy
← health healthy/recovered

StatusDegraded
← degraded/failing/suppressed

StatusQueued
← queued_quick/queued_deep

StatusEscalating
← running_quick/running_deep/canary_running
```

Projection MUST expose `compatibility_projection=true` in v2 API/debug output.

## 59. Direct apply removal

`applyBatchResults()` MUST be disabled in production-safe mode.

```yaml
monitoring:
  legacy_watchdog_api: true
  legacy_watchdog_direct_apply: false
```

`legacy_watchdog_direct_apply=true`:

- MAY exist only in migration test build or explicit unsafe development mode;
- MUST emit startup warning;
- MUST block production readiness;
- MUST increment hard-gate counter;
- MUST NOT be available in beginner UI.

## 60. Cutover stages

```text
Phase A — shadow
legacy Watchdog remains active for health checks
MON observes and predicts; no triggers/actions

Phase B — trigger shadow
MON produces trigger decisions
legacy Watchdog still executes, decisions compared

Phase C — diagnostic cutover
force-check/scheduled failures invoke ABD through MON
legacy direct Discovery disabled

Phase D — API cutover
/api/watchdog projects MON state
new /api/monitor/v1 becomes canonical

Phase E — apply cutover
all recommendations go through DDI/canary/action plane
legacy applier removed

Phase F — cleanup
old checker/applier deleted after compatibility window
```

Rollback at each phase MUST be documented and tested.

---

# Часть XV. Persistence and restart

## 61. Persistent stores

Separate stores:

```text
MonitorSubjectStore
MonitorAssessmentStore
ResolutionSnapshotStore
TemporalBucketStore
DiagnosticRunReferenceStore
```

## 62. Storage properties

- versioned schema;
- atomic checkpoint;
- content hash;
- bounded retention;
- corruption detection;
- restart-safe idempotency;
- generation/network context binding;
- privacy classification;
- deterministic migration;
- no raw packet storage;
- no secrets.

## 63. Restart behavior

After restart:

- active runs reattached or marked interrupted;
- expired leases invalidated;
- stale network-context assessments demoted;
- source heartbeats reset to unknown;
- no automatic action based only on persisted provisional state;
- legacy status projection remains available;
- incomplete write cannot produce `profile_ready`.

---

# Часть XVI. Configuration

## 64. Canonical config

```yaml
continuous_monitor:
  enabled: true
  mode: recommend
  # off | observe | recommend | auto-diagnose | auto-canary

  sources:
    pinned_targets: true
    service_profiles: true
    observed_dns: true
    observed_sni: true
    observed_quic: true
    flow_health: true
    failure_inbox: true
    android_signals: true

  intake:
    max_new_subjects_per_hour: 128
    max_subjects_total: 2048
    max_per_client_per_hour: 32
    subject_ttl: 24h

  temporal:
    bucket: 5m
    window: 24h
    minimum_time_separation: 30s
    recovery_successes: 3
    decay_half_life: 6h

  triggers:
    minimum_independent_families: 2
    minimum_recurrence: 3
    require_healthy_controls: true
    require_visibility: true

  diagnostics:
    quick_parallelism: 1
    deep_parallelism: 1
    max_quick_per_hour: 24
    max_deep_per_day: 4
    reference_only_after_local_failure: true

  privacy:
    retain_clear_domains_locally: true
    export_clear_domains: false
    retain_full_dns_history: false
    pseudonym_rotation: 24h

  compatibility:
    legacy_watchdog_api: true
    legacy_watchdog_direct_apply: false
```

## 65. Mode semantics

| Mode | Поведение |
|---|---|
| off | no MON intake; infrastructure monitor unaffected |
| observe | assessments only |
| recommend | user-visible diagnostic recommendations |
| auto-diagnose | bounded ABD auto-trigger allowed |
| auto-canary | candidate canary may auto-start only after separate release gates |

No mode authorizes production promotion without action-plane policy.

---

# Часть XVII. API and UI

## 66. Canonical API

```text
GET    /api/monitor/v1/status
GET    /api/monitor/v1/subjects
POST   /api/monitor/v1/subjects
GET    /api/monitor/v1/subjects/{id}
PATCH  /api/monitor/v1/subjects/{id}
DELETE /api/monitor/v1/subjects/{id}

GET    /api/monitor/v1/assessments
GET    /api/monitor/v1/assessments/{id}
POST   /api/monitor/v1/assessments/{id}/diagnose-quick
POST   /api/monitor/v1/assessments/{id}/diagnose-deep
POST   /api/monitor/v1/assessments/{id}/suppress
POST   /api/monitor/v1/assessments/{id}/dismiss

GET    /api/monitor/v1/sources
GET    /api/monitor/v1/budgets
GET    /api/monitor/v1/events
GET    /api/monitor/v1/compatibility
```

## 67. Beginner UI

Panels:

```text
Infrastructure
Services and components
Needs attention
Active diagnostics
Recommendations
History
```

User-facing statuses:

```text
Работает
Наблюдается нестабильность
Есть признаки проблемы
Проверка временно отложена
Выполняется быстрая диагностика
Требуется глубокая диагностика
Вероятная блокировка
Диагностика завершена
Найден кандидат обхода
Кандидат проверяется
Восстановлено
```

UI MUST NOT show `Заблокировано` from passive timeout alone.

## 68. Explanation model

Each assessment exposes:

- what was observed;
- on which device/client;
- service/component;
- current network context;
- how often and over what period;
- independent evidence families;
- healthy/failed controls;
- active suppressors;
- why quick/deep diagnosis was or was not triggered;
- authoritative ABD result if available;
- next safe action.

---

# Часть XVIII. Metrics and events

## 69. Metrics

```text
monitor_observations_total
monitor_observation_rejected_total
monitor_observation_dropped_total
monitor_subjects_active
monitor_subject_created_total
monitor_subject_expired_total
monitor_resolution_snapshot_total
monitor_resolution_mismatch_total
monitor_assessment_transition_total
monitor_recurrence_score_histogram
monitor_independence_score_histogram
monitor_suppressor_active_total
monitor_trigger_decision_total
monitor_trigger_suppressed_total
monitor_diagnostic_queue_depth
monitor_diagnostic_started_total
monitor_diagnostic_completed_total
monitor_diagnostic_canceled_total
monitor_source_heartbeat_state
monitor_budget_exhausted_total
monitor_legacy_api_projection_total
monitor_legacy_direct_apply_attempt_total
monitor_recovery_total
```

Labels MUST be bounded enums. Client/domain/assessment IDs MUST NOT be metric labels.

## 70. Events

```text
monitor_observation_ingested
monitor_observation_rejected
monitor_subject_created
monitor_subject_resolved
monitor_subject_expired
monitor_resolution_snapshot_created
monitor_assessment_state_changed
monitor_suppressor_activated
monitor_suppressor_cleared
monitor_trigger_created
monitor_trigger_suppressed
monitor_diagnostic_queued
monitor_diagnostic_started
monitor_diagnostic_completed
monitor_diagnostic_inconclusive
monitor_profile_linked
monitor_profile_stale
monitor_recommendation_linked
monitor_recovery_detected
monitor_legacy_api_projected
monitor_legacy_direct_apply_blocked
```

## 71. Event envelope

Events SHOULD use generation-aware envelope compatible with WARP trace principles:

```text
event_id
sequence
wall_time
monotonic_ns
boot_id_hash
process_start_id
config_generation
network_context_id
subject_id_hash
assessment_id_hash
parent_event_id
```

---

# Часть XIX. Privacy and security

## 72. Privacy

Default export:

- hashed/pseudonymous client identity;
- redacted domain identity;
- no raw DNS packet;
- no full ClientHello;
- no public IP unless explicitly requested and redacted policy permits;
- no SSID/gateway clear values;
- no WARP credentials/tokens;
- bounded event history.

## 73. Local clear-domain policy

Clear domains MAY be retained locally for usable UI only when:

- explicit local policy enabled;
- encrypted/permission-restricted storage where platform allows;
- never exported by default;
- TTL enforced;
- user can clear history;
- sensitive categories may be excluded.

## 74. Observer security

Remote/reference observer:

- explicit configuration;
- certificate/authentication;
- capability attestation;
- timeout and rate limits;
- no proxy secrets in trace;
- no action authorization;
- health lease;
- revocation;
- exact target scope.

---

# Часть XX. Resource model

## 75. Keenetic budgets

MON MUST account:

- RAM for subjects/buckets/snapshots;
- CPU for correlation;
- disk writes;
- NFQUEUE/PPE pressure;
- active probe concurrency;
- DNS observation volume;
- event buffer pressure;
- Android test availability.

## 76. Degradation order

Under pressure:

```text
reduce low-priority event retention
→ reduce provisional fast-lane rate
→ defer deep diagnostics
→ defer quick diagnostics
→ stop new demand subjects
→ preserve existing P0 failures and safety suppressors
```

Never degrade to direct apply.

---

# Часть XXI. Testing

## 77. Unit tests

Must cover:

- scope normalization;
- cross-client rejection;
- generation/network separation;
- CNAME attribution;
- multi-IP outcome retention;
- recurrence versus independence;
- decay/hysteresis;
- recovery transitions;
- suppressor precedence;
- trigger idempotency;
- budget leasing;
- legacy projection;
- no direct apply.

## 78. Property and fuzz tests

Properties:

- observation order permutations yield deterministic normalized assessment;
- duplicate events never increase independence;
- stale events never revive current assessment;
- cross-WAN events never merge;
- malformed DNS/CNAME graph cannot escape bounds;
- restart checkpoint cannot create profile-ready state;
- compatibility projection cannot mutate source state;
- no unbounded cardinality.

## 79. Synthetic network lab

Scenarios:

- healthy target;
- origin down globally;
- local SYN drop;
- RST after ClientHello;
- TLS fingerprint asymmetry;
- DNS poisoning;
- QUIC-only drop;
- HTTP body cutoff;
- small object;
- address-selective filtering;
- CDN IP rotation;
- WAN transition;
- resolver transition;
- queue drops;
- PPE bypass;
- source heartbeat loss;
- remote observer unavailable;
- exact-endpoint remote success;
- independent-resolution disagreement;
- recovery after transient outage.

## 80. Migration parity tests

Shadow comparison MUST record:

- domains legacy Watchdog checked;
- legacy outcomes;
- MON fast-lane outcomes;
- trigger decisions;
- false positive/negative differences;
- resource usage;
- no config mutations from MON shadow;
- no duplicate active probe storms.

## 81. Fault injection

- crash during checkpoint;
- disk full;
- event queue overflow;
- clock jump;
- process restart;
- stale heartbeat;
- ABD unavailable;
- DDI unavailable;
- Discovery active;
- cancellation race;
- config reload;
- WAN reconnect;
- legacy API spam;
- observer timeout.

## 82. Real router validation

Must validate on target Keenetic/Entware:

- NFQUEUE mode;
- TUN mode;
- PPE enabled/disabled;
- low memory;
- high DNS volume;
- dual-stack policy;
- router-origin versus forwarded-client separation;
- reboot/restart persistence;
- table-rule restoration interaction;
- no monitoring self-interference.

## 83. Real Android validation

Must prove:

- actual Android client identity;
- service/component mapping;
- exact client DNS answer correlation;
- passive failure observation;
- quick/deep ABD escalation;
- no router-origin substitution;
- recommendation/canary linkage;
- recovery detection;
- negative controls unaffected.

---

# Часть XXII. Hard gates

## 84. Observation and authority gates

```text
monitor_observation_direct_action_total == 0
monitor_provisional_profile_compiled_total == 0
monitor_passive_discovery_start_total == 0
monitor_passive_warp_enable_total == 0
monitor_fast_lane_action_total == 0
monitor_fast_lane_promoted_as_authoritative_total == 0
```

## 85. Scope gates

```text
monitor_destination_only_deep_trigger_total == 0
monitor_cross_client_merge_total == 0
monitor_cross_service_merge_total == 0
monitor_cross_component_merge_total == 0
monitor_cross_wan_evidence_merge_total == 0
monitor_cross_generation_evidence_merge_total == 0
monitor_router_origin_as_forwarded_proof_total == 0
```

## 86. Temporal gates

```text
monitor_duplicate_evidence_independence_total == 0
monitor_temporal_persistence_without_time_separation_total == 0
monitor_success_suppressor_ignored_total == 0
monitor_recovered_subject_not_demoted_total == 0
monitor_expired_evidence_used_total == 0
monitor_decay_disabled_without_policy_total == 0
```

## 87. Resolution gates

```text
monitor_probe_without_resolution_binding_total == 0
monitor_client_dns_answer_replaced_silently_total == 0
monitor_cname_terminal_ip_misattributed_total == 0
monitor_multi_ip_partial_failure_hidden_total == 0
monitor_first_success_erased_address_failures_total == 0
monitor_stale_resolution_used_as_exact_proof_total == 0
```

## 88. Trigger and resource gates

```text
monitor_trigger_without_visibility_total == 0
monitor_trigger_without_budget_total == 0
monitor_trigger_during_global_wan_failure_total == 0
monitor_trigger_with_stale_source_heartbeat_total == 0
monitor_duplicate_concurrent_abd_run_total == 0
monitor_unbounded_target_intake_total == 0
monitor_unbounded_probe_parallelism_total == 0
monitor_self_interference_total == 0
```

## 89. Multi-vantage gates

```text
monitor_http_hypothesis_from_tcp_tls_only_observer_total == 0
monitor_observer_unavailable_as_target_failure_total == 0
monitor_exact_endpoint_service_resolution_conflated_total == 0
monitor_observer_capability_unproven_total == 0
monitor_reference_result_as_action_authorization_total == 0
```

## 90. ABD/DDI/Discovery gates

```text
monitor_abd_request_without_target_plan_total == 0
monitor_abd_partial_result_profile_ready_total == 0
monitor_abd_result_bypassed_ddi_total == 0
monitor_discovery_without_authoritative_profile_total == 0
monitor_discovery_skipped_mandatory_baseline_total == 0
monitor_recommendation_without_scope_total == 0
monitor_warp_recommendation_without_ip_path_evidence_total == 0
```

## 91. Legacy migration gates

```text
monitor_legacy_watchdog_direct_apply_total == 0
monitor_legacy_watchdog_created_unvalidated_set_total == 0
monitor_legacy_watchdog_overwrote_set_without_canary_total == 0
monitor_legacy_api_projection_mutation_total == 0
monitor_shadow_and_active_writer_overlap_total == 0
```

## 92. Reliability/privacy gates

```text
monitor_required_event_drop_hidden_total == 0
monitor_source_heartbeat_stale_auto_diagnose_total == 0
monitor_checkpoint_corruption_false_ready_total == 0
monitor_restart_reused_expired_lease_total == 0
monitor_sensitive_dns_history_export_total == 0
monitor_secret_trace_leak_total == 0
monitor_high_cardinality_metric_label_total == 0
```

---

# Часть XXIII. Release verdicts

## 93. Verdicts

```text
MON_OBSERVATION_READY
MON_DEMAND_INTAKE_READY
MON_RESOLUTION_CORRELATION_READY
MON_TEMPORAL_MODEL_READY
MON_VISIBILITY_SUPPRESSORS_READY
MON_TRIGGER_PLANNER_READY
MON_ABD_ESCALATION_READY
MON_LEGACY_WATCHDOG_MIGRATED
MON_PRODUCTION_READY
```

## 94. `MON_PRODUCTION_READY`

Requires:

- all `MON-1…MON-12` complete;
- all hard gates zero;
- ABD production readiness;
- DDI production readiness for reusable profiles;
- Service Profile scope readiness;
- real router and Android evidence;
- legacy direct apply disabled;
- shadow/cutover report;
- restart/fault tests;
- privacy validation;
- no false production action.

---

# Часть XXIV. Implementation stages

## MON-1 — Current monitoring audit and compatibility freeze

Deliverables:

- exact map of `tables.Monitor`, `watchdog`, Failure Inbox, observability, canary and scoped failure state;
- pinned current behavior fixtures;
- legacy API/config/UI contract inventory;
- direct mutation path map;
- resource baseline;
- Ladon provenance entries;
- rollback plan.

Exit gates:

- all legacy behavior reproducible;
- direct apply path identified;
- no untracked monitoring writer;
- compatibility freeze approved.

## MON-2 — Core schemas and observation bus

Deliverables:

- `MonitorScopeKey`;
- `MonitorObservation`;
- authority taxonomy;
- observation bus;
- source adapters;
- bounded queues/backpressure;
- event envelope;
- unit/fuzz tests.

Exit gates:

- no cross-client/network/generation merge;
- packet path non-blocking;
- dropped events visible.

## MON-3 — Subjects, demand intake and resolution snapshots

Deliverables:

- `MonitorSubject`;
- pinned Watchdog adapter;
- Service Profile subjects;
- demand target inbox;
- query/CNAME/answer correlation;
- multi-IP outcome vector;
- intake budgets;
- privacy rules.

Exit gates:

- exact client resolution preserved;
- ordinary DNS demand cannot create action;
- unbounded target growth impossible.

## MON-4 — Passive flow-health correlation

Deliverables:

- flow progress observations;
- DNS/SNI/QUIC/failure correlation;
- SPF adapter;
- router-origin/forwarded separation;
- control-role mapping;
- success/recovery observations.

Exit gates:

- SYN-ACK-only is not universal service success;
- same-client target/control scope preserved;
- destination-only ambiguity visible.

## MON-5 — Temporal accumulation, hysteresis and cohorts

Deliverables:

- temporal buckets;
- recurrence/independence scores;
- decay;
- recovery FSM;
- cohort hints;
- deterministic persistence;
- property tests.

Exit gates:

- duplicates cannot increase independence;
- sustained success demotes failure;
- cohorts cannot authorize wildcard action.

## MON-6 — Source health, visibility and suppressors

Deliverables:

- source heartbeat;
- infrastructure/PPE/capture visibility adapters;
- suppressor engine;
- WAN/config transition handling;
- global outage control;
- UI explanations.

Exit gates:

- no auto-diagnose under stale/invalid visibility;
- suppressors observable and expiring;
- infrastructure failure cannot become service block proof.

## MON-7 — Provisional fast lane and scheduler

Deliverables:

- bounded fast lane;
- quick/deep queues;
- resource leases;
- coalescing/idempotency;
- cancellation/restart;
- cooldown/backoff;
- overload policy.

Exit gates:

- fast lane never compiles profile or starts action;
- budgets enforced;
- no duplicate runs.

## MON-8 — ABD escalation adapter

Deliverables:

- `MonitorDiagnosticRequest`;
- TargetPlan overlay;
- client-resolution refs;
- visibility/control refs;
- ABD run lifecycle;
- partial/cancelled handling;
- multi-vantage capability contract.

Exit gates:

- ABD remains active-probe owner;
- partial run cannot produce ready profile;
- observer stage mismatch cannot increase confidence.

## MON-9 — DDI, Discovery and recommendation integration

Deliverables:

- DDI profile refs;
- stale/incompatible handling;
- guided Discovery request policy;
- WARP recommendation handoff;
- no direct Discovery from passive state;
- explanation model.

Exit gates:

- authoritative profile and DDI freshness required;
- mandatory baselines preserved;
- Monitoring cannot authorize WARP/action.

## MON-10 — Canary, recovery and rollback observation

Deliverables:

- canary summary adapter;
- Android milestone correlation;
- promoted binding observation;
- target/control recovery model;
- rollback signal publication;
- no direct rollback authorization.

Exit gates:

- router-origin proof cannot satisfy Android gate;
- recovery linked to exact binding/path;
- rollback remains action-plane decision.

## MON-11 — API/UI/persistence and Watchdog compatibility cutover

Deliverables:

- `/api/monitor/v1`;
- legacy `/api/watchdog/*` adapter;
- compatibility status projection;
- durable stores/migrations;
- beginner/advanced UI;
- direct applier disabled;
- shadow/cutover reports.

Exit gates:

- old clients continue reading status;
- force-check maps to bounded diagnosis;
- no legacy config mutation path;
- single source of truth.

## MON-12 — Field validation and production release

Deliverables:

- synthetic lab;
- fault injection;
- Keenetic resource tests;
- real Android validation;
- multi-WAN/restart tests;
- privacy audit;
- hard-gate report;
- companion addenda updates;
- final verdict.

Exit gates:

- all hard gates zero;
- shadow parity acceptable;
- direct apply removed;
- no monitoring self-interference;
- `MON_PRODUCTION_READY` issued by umbrella validation only.

---

# Часть XXV. Companion document updates

## 95. Adaptive Blocking Detector v1.2 alignment

ABD v1.2 SHOULD add only adapter contracts:

- `MonitorDiagnosticRequest`;
- `TargetPlanOverlay`;
- `ClientResolutionSnapshotRef`;
- `EvidenceAuthority`;
- `MultiVantageComparison`;
- `MonitorAssessmentRef`;
- Ladon provenance.

ABD MUST NOT absorb continuous observation/temporal state.

## 96. Field Test Automation

Add suites:

```text
FT-MON-A  legacy Watchdog compatibility and no-direct-apply
FT-MON-B  demand intake and exact client-resolution correlation
FT-MON-C  passive flow health and control separation
FT-MON-D  temporal recurrence, decay and recovery
FT-MON-E  source health, PPE/capture suppressors
FT-MON-F  fast lane and trigger budgets
FT-MON-G  MON → ABD quick/deep escalation
FT-MON-H  ABD → DDI → Discovery/WARP recommendation chain
FT-MON-I  restart/fault/storage/privacy
FT-MON-J  real Keenetic + Android end-to-end
```

## 97. Service Profiles / Beginner UX

Must define:

- monitored components;
- target/control roles;
- passive success milestones;
- health thresholds;
- demand-discovery policy;
- WARP recommendation eligibility;
- beginner labels;
- privacy defaults;
- no hardcoded service branching.

## 98. Implementation Validation

Must register:

- `MON-1…MON-12`;
- schemas/APIs/config;
- all hard gates;
- legacy migration mutants;
- false trigger mutants;
- restart/corruption mutants;
- observer capability mutants;
- real router/Android proof;
- `MON_PRODUCTION_READY`.

---

# Definition of Done

This addendum is complete only when all statements are true:

- Existing monitoring functionality is preserved through compatibility adapters during migration.
- `tables.Monitor` remains infrastructure integrity, not service blocking detection.
- Legacy Watchdog no longer owns Discovery promotion or direct config mutation.
- Failure Inbox feeds or projects the canonical MonitoringAssessment model and is not a competing source of truth.
- Real DNS/SNI/QUIC demand can create bounded diagnostic subjects without creating actions.
- Client-observed DNS answer and CNAME chain are preserved for active probes.
- Per-address failures are not hidden by first success.
- Passive health, provisional fast-lane and authoritative ABD evidence remain distinct.
- Health and diagnostic state use separate axes.
- Temporal recurrence, independence, decay, hysteresis and recovery are implemented.
- Cross-client, cross-service, cross-component, cross-WAN and cross-generation evidence merge is impossible.
- Visibility/PPE/queue/source-health suppressors block unsafe auto-diagnose.
- Trigger scheduler is bounded, idempotent and restart-safe.
- Monitoring submits typed requests to ABD rather than reimplementing Detector.
- ABD remains the only owner of active probe evidence graph and BlockingProfile.
- DDI remains the owner of reusable network-context profile freshness.
- Discovery remains the only candidate search/scoring engine.
- WARP recommendation requires authoritative IP/path evidence and never comes directly from passive monitoring.
- Router-origin probes cannot substitute forwarded Android proof.
- Legacy `/api/watchdog/*` remains temporarily compatible but maps to new semantics.
- `applyBatchResults()` is absent from production-safe path.
- Shadow/cutover migration has measured parity and rollback.
- Persistent state cannot create false `profile_ready` after crash/restart.
- Metrics and exports remain bounded and privacy-safe.
- Keenetic resource tests and real Android tests pass.
- Field Test, Service Profiles and Implementation Validation are updated.
- All hard gates are zero.
- `MON_PRODUCTION_READY` is issued only by umbrella Implementation Validation.
