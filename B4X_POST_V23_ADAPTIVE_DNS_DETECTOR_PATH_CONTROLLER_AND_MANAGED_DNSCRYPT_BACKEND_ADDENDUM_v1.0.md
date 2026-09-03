# B4X Post-v2.3 Adaptive DNS Detector, Path Controller & Managed DNSCrypt Backend Addendum

**Версия:** `1.0`  
**Дата:** `2026-08-02`  
**Статус:** проект обязательного post-v2.3 companion addendum для owner review  
**База:** `B4_FORK_ARCHITECTURE_v2.4.md`, `B4_FORK_PATCH_PLAN.md` v2.3, действующие post-v2.3 addenda, `B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md`, `B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md`  
**Основная платформа:** Keenetic/Entware; реальные Android/LAN-клиенты; Windows/Docker/CI как controlled field-test environment  
**Целевая capability:** `adaptive-dns-path-control`  
**Стадии:** `ADNS-1 … ADNS-15`  
**Reference implementation 1:** `UPB-SysSec/DPYProxy`, pinned commit `28cb05985672275ea96d4083c403739894820375`, Apache-2.0  
**Reference implementation 2:** `DNSCrypt/dnscrypt-proxy`, pinned commit `c3ba78fac8a37fd05c1a4faba77300a9dc03a9dd`, ISC  
**Главная пользовательская цепочка:** Android/LAN DNS request или Monitoring degradation → B4X DNS differential diagnosis → deterministic path candidates → existing Discovery validation → generation-bound `DNSPathProfile` → `DNSPathManager` primary/fallback binding → transactional canary/promote/rollback → continuous health and recovery  
**Главный safety-инвариант:** DNS observation или один успешный resolver не являются разрешением на глобальное переключение. Любой adaptive selection проходит controls, freshness, exact path identity, canary и transactional rollback; `dnscrypt-proxy` является управляемым backend provider, а не вторым policy/optimizer owner.

---

# 0. Owner summary

## 0.1. Что получает пользователь

После реализации пользователь сможет выбрать:
```text
DNS mode:
( ) Current / system
( ) Manual
(•) Adaptive
```

В режиме `Adaptive` роутер сам поддерживает рабочий DNS-путь для текущего WAN:
```text
Android отправляет DNS-запрос
        ↓
B4X DNS Detector / Controller
        ↓
проверяет current primary
        ↓
при деградации запускает bounded differential matrix
        ↓
выбирает новый primary + независимые fallbacks
        ↓
проверяет на controls и выбранном Android-клиенте
        ↓
transactional switch
        ↓
monitoring, failover, recovery, rollback
```

Пользователю не требуется вручную выбирать один вечный DoH-провайдер. Система хранит scoped профиль для текущего WAN и понимает, почему конкретные пути разрешены, исключены или временно деградированы.

## 0.2. Как есть сейчас и как станет

| Область | Сейчас в B4X | После addendum |
|---|---|---|
| Системный DNS | Видимый system-forward path и DNS observations | Полноценный candidate с health, correctness и rollback |
| UDP resolver | Detector умеет проверять доступность и сравнивать A records | Детерминированный per-resolver path с A/AAAA/CNAME/NXDOMAIN/SERVFAIL validation |
| TCP resolver | Используется как отдельная диагностика/возможность | Автоматический fallback при UDP drop/injection/truncation |
| TCP segmentation | Нет canonical path verdict и on-wire proof | Bounded experiment; production only after actual segmentation proof |
| DoH | Selected DoH и system-vs-DoH shadow comparison | Несколько native DoH candidates, explicit resolver/path identity и failover |
| DoT/DoH3/DoQ | Не являются единым adaptive path catalog | Native optional providers с capability/readiness gates |
| DNSCrypt/Anonymized/ODoH | Нет managed provider в canonical DNS control plane | Managed `dnscrypt-proxy` backend под ownership B4X |
| Выбор пути | Пользовательский/локальный selection и Detector hints | Correctness-first scoring, diversity-aware primary/fallback profile |
| Переключение | Нет единой transaction/current-generation profile chain | Prepare → canary → promote → monitor → rollback |
| WAN change | Отдельные DNS observations имеют TTL/generation | Весь path profile stale/revalidated по `NetworkContextID` |

## 0.3. Важная source-derived корректировка topology

Исходный целевой эскиз требует уточнения. Актуальный `dnscrypt-proxy` подтверждённо предоставляет:
- DNSCrypt и PQDNSCrypt;
- Anonymized DNSCrypt через relays;
- DoH поверх HTTP/2;
- DoH поверх HTTP/3/QUIC при включённой capability;
- ODoH;
- signed resolver sources, cache, performance-aware server selection и forcing TCP для поддерживаемых upstream paths.

Он **не является DoT- или DoQ-клиентом**. Поэтому нормативная topology v1.0 следующая:
```text
B4X DNS Detector / Controller
          │
          ├── native system forward
          ├── native UDP
          ├── native TCP
          ├── native TCP-segmentation experiment
          ├── native DoT
          ├── native DoH
          ├── native DoH3
          ├── native DoQ
          └── managed dnscrypt-proxy backend
                ├── DNSCrypt / PQDNSCrypt
                ├── Anonymized DNSCrypt
                ├── DoH over HTTP/2
                ├── DoH over HTTP/3 where supported
                └── ODoH
```

DoT и DoQ реализуются нативными B4X providers либо получают честный `UNSUPPORTED/BLOCKED_BY_CAPABILITY`; запрещено приписывать их `dnscrypt-proxy`.

## 0.4. Минимизация новых сущностей

Добавляются только две архитектурно значимые вещи:
1. `DNSPathProfile` — единственный новый persisted diagnostic/runtime profile payload;
2. `DNSPathManager` — логический runtime-компонент внутри существующего `TransportService`/DNS control plane, а не новый top-level service.

Не создаются:
- второй Detector;
- второй Discovery/optimizer;
- отдельный DNS policy daemon;
- параллельный source of truth для resolver health;
- Python runtime DPYProxy;
- глобальный iptables owner;
- скрытый resolver selection внутри backend, не видимый B4X;
- новый production apply path вне `TransactionalRuntime`.

## 0.5. Простая пользовательская модель

```text
Adaptive DNS включён:
- система сначала использует текущий здоровый primary;
- при сбое быстро пробует last-good fallback;
- затем выполняет bounded diagnosis;
- выбирает correctness-valid и устойчивый path;
- проверяет его на Android/controls;
- применяет и продолжает наблюдение;
- после восстановления может вернуться к более простому path.
```

Режим default-off для существующих установок. Обновление не меняет DNS-поведение пользователя без явного выбора `Adaptive` либо migration policy, одобренной владельцем.

# Часть I. Нормативный статус и архитектурное место

## 1. Назначение

Этот addendum расширяет существующие DNS parser/correlation, ABD, DDI, Discovery и runtimecontrol единым adaptive DNS path control contract.
Он решает четыре задачи:
1. доказательно различать DNS poisoning, injection, drop, resolver failure, encrypted-transport blocking и обычную upstream ошибку;
2. автоматически тестировать конечный bounded набор resolver × transport paths;
3. выбирать primary и независимые fallbacks с привязкой к WAN/context/generation;
4. управлять optional `dnscrypt-proxy` как backend provider без передачи ему policy ownership.

## 2. Нормативная последовательность

```text
B4_FORK_ARCHITECTURE_v2.4
→ B4_FORK_PATCH_PLAN v2.3
→ Cross-Service Isolation
→ RST/GSO Hardening
→ PPE Per-Flow Offload
→ Silent Path Failure and Scoped Recovery
→ Continuous Blocking Monitoring
→ Adaptive Blocking Detector and Guided Strategy Search
→ Detector-Guided Discovery / DDI hardening
→ этот addendum: ADNS-1…ADNS-15
→ Service Profiles / Beginner UX companion update
→ Field Test Automation companion update
→ Implementation Validation companion update
→ production promotion
```

## 3. Приоритет требований

```text
Architecture v2.4
→ owner decisions / conflict-resolution records
→ existing subsystem addenda
→ этот addendum для adaptive DNS path control
→ Field Test / Implementation Validation как release gates
→ reference-project behavior notes
```

## 4. Обязательная граница объектов

```text
DNSObservation
≠ DNSPathProbeOutcome
≠ DNSFailureHypothesis
≠ DNSPathProfile
≠ DiscoverySearchPrior
≠ DNSPathCandidate
≠ DNSPathBinding
≠ TransportAuthorization
≠ production promotion
```

Ни один объект слева не может автоматически превращаться в объект справа.

## 5. Запрещённые shortcut paths

```text
one timeout → resolver blocked
one different A record → poisoning confirmed
first successful resolver → global primary
last UDP response → trusted answer
DoH TLS handshake → DNS correctness PASS
backend process alive → resolver path healthy
DNSPathProfile → direct config mutation
resolver latency winner → promotion without controls
stale WAN profile → reuse
backend internal random selection → canonical path identity
cached diagnostic answer → fresh validation proof
router-origin DNS success → Android client proof
```

## 6. Не-цели v1.0

- создание универсального публичного DNS scanner;
- встраивание DPYProxy Python process;
- HTTP request smuggling или любые DPYProxy HTTP attack strategies;
- подмена общего B4X Detector отдельным DNS-only detector;
- глобальное принудительное изменение DNS всех клиентов без canary;
- автоматическое доверие resolver privacy claims без provenance;
- обещание анонимности;
- использование ODoH или Anonymized DNS как доказательства отсутствия censorship;
- обход IP/SNI/TLS blocking, если DNS уже корректен;
- скрытый runtime download непроверенного binary или resolver list;
- DoT/DoQ attribution к `dnscrypt-proxy`;
- бесконечный background probing.

# Часть II. Reference audit и принятые идеи

## 7. DPYProxy-DNS: подтверждённая модель

Pinned DPYProxy implementation предоставляет modes:
```text
AUTO
UDP
TCP
TCP_FRAG
DOT
DOH
DOH3
DOQ
LAST_RESPONSE
```

Его AUTO mode перебирает resolver/mode combinations, проверяет test domain, сохраняет working configuration и может повторно использовать её при запуске.
Полезные идеи для B4X:
- resolver и transport являются независимыми измерениями;
- working path необходимо повторно подтверждать несколькими попытками;
- TCP segmentation может быть отдельным experiment;
- UDP response race можно наблюдать, а не сворачивать в first-response result;
- last-good configuration ускоряет startup;
- encrypted и unencrypted transports проверяются одной нормализованной матрицей.

## 8. Почему DPYProxy не встраивается буквально

В production B4X запрещено переносить его runtime как есть, потому что reference implementation:
- написан на Python и создаёт отдельный proxy lifecycle;
- использует статические resolver lists;
- по умолчанию ориентирован на один censored domain;
- может валидировать ответы по заранее заданным IP ranges;
- перемешивает candidates случайно;
- не имеет production-grade unit/integration coverage в самом проекте;
- не поддерживает IPv6 в заявленном roadmap состоянии;
- не знает B4X `ClientKey`, `NetworkContextID`, `ConfigGeneration`, controls, canary и rollback;
- не разделяет authoritative Detector evidence и runtime selection ownership в терминах B4X.

B4X принимает algorithmic idea, но реализует selection нативно и детерминированно.

## 9. LAST_RESPONSE: принимается только как observer

DPYProxy `LAST_RESPONSE` отправляет UDP query, ждёт до timeout и возвращает последний полученный response. В B4X этот порядок сам по себе не считается безопасным правилом выбора.
Вводится diagnostic experiment:
```text
UDPResponseRaceObservation:
- collect all candidate responses in bounded window
- validate source tuple, transaction ID, question and message structure
- retain arrival order and timing
- compare each response with encrypted/reference paths
- classify early-injection / duplicate / conflicting / inconclusive
- never trust "last" solely because it arrived last
```

Production query path не использует literal `last answer wins`. Возможный future policy требует отдельного owner decision.

## 10. dnscrypt-proxy: подтверждённые возможности

- DNSCrypt v2 и PQDNSCrypt;
- DoH over TLS 1.3;
- HTTP/3 for DoH where enabled/supported;
- Anonymized DNSCrypt relays;
- ODoH servers and relays;
- IPv4/IPv6 upstream selection;
- DNSSEC-aware resolver filtering;
- signed resolver source lists;
- explicit server allowlist/denylist;
- forcing TCP for supported connections;
- cache and negative cache;
- performance-aware resolver selection;
- loopback listeners and local DoH server capability;
- ARM, ARM64, MIPS, MIPSLE and other Linux builds.

## 11. Что B4X использует из dnscrypt-proxy

B4X использует его только как managed transport/backend provider:
```text
B4X owns:
policy, candidate order, scope, diagnosis, correctness,
profile, failover, generation, canary, promotion, rollback

managed dnscrypt-proxy owns:
protocol implementation, encrypted upstream connection,
relay protocol, certificate/source parsing, bounded local cache
```

Process liveness или внутренний resolver RTT не заменяют B4X end-to-end DNS proof.

## 12. Неиспользуемые или ограниченные dnscrypt-proxy функции

- внутреннее случайное/скрытое multi-server balancing запрещено в causal diagnostic mode;
- автоматическое resolver-list update допускается только через B4X signed/atomic update policy;
- query logging выключено по умолчанию;
- EDNS client subnet выключен по умолчанию;
- local DoH listener не публикуется в LAN в v1.0;
- filtering/blocklists/cloaking не входят в adaptive censorship diagnosis;
- hot reload не считается transactional apply;
- bootstrap system DNS не может рекурсивно указывать на сам B4X listener.

## 13. License и supply-chain policy

| Reference | License | Использование |
|---|---|---|
| DPYProxy | Apache-2.0 | Algorithm/reference audit; Python runtime не vendor/import |
| dnscrypt-proxy | ISC | Optional pinned managed binary/source build с notices и hash manifest |

Любой distributed binary MUST иметь: commit/version provenance, build target, SHA-256, license notice, reproducible/pinned build record и platform capability manifest.

# Часть III. Existing B4X baseline и нормативная delta

## 14. Уже существующий фундамент

Этот addendum не переписывает DNS с нуля. Сохраняются и расширяются:
- structured parser для A, AAAA, CNAME, HTTPS/SVCB, NXDOMAIN, SERVFAIL, truncation, multiple answers и TTL;
- source-scoped DNS evidence до первого TCP/UDP flow;
- DoH system-forward visibility;
- negative DNS evidence без создания positive host hint;
- resolver failover cleanup stale positive mapping;
- Detector checks `TestDNS`/`TestDNSAvail` и DoH-vs-UDP comparison;
- fake NXDOMAIN, empty answer, fake/local/stub IP и repeated stub detection;
- existing DDI/Discovery contract, mandatory baselines, controls и full bounded fallback.

## 15. Gap, который закрывает addendum

Текущий фундамент ещё не является единым autonomous resolver transport control plane. Не хватает:
- canonical path identity `resolver × transport × route × IP family × generation`;
- correctness-first profile с primary/fallbacks;
- native UDP/TCP/DoT/DoH/DoH3/DoQ provider contract;
- доказанной on-wire TCP segmentation capability;
- managed DNSCrypt/Anonymized/ODoH backend lifecycle;
- deterministic candidate ordering вместо random trial;
- cache/generation isolation;
- transactional switch and rollback;
- Monitoring-driven failover/recovery;
- Android source-scoped canary;
- principal verdicts, hard gates и validation-of-validation.

## 16. Target architecture

```text
MonitorService
  observes DNS health/drift and schedules bounded diagnosis
        ↓
DetectorService / ABD DNS differential suite
  produces authoritative DNS path evidence
        ↓
DDI
  stores/validates fresh DNSPathProfile envelope
        ↓
DiscoveryService
  evaluates DNS path candidates and mandatory controls
        ↓
TransportService / DNSPathManager
  prepares provider, binding, cache and listener generation
        ↓
TransactionalRuntime
  canary → promote → rollback → last-good
        ↓
MonitorService
  observes stability, failure and recovery
```

## 17. Service ownership

| Subsystem | Владеет | Не владеет |
|---|---|---|
| MonitorService | passive DNS degradation, recurrence, trigger scheduling | active resolver selection or config mutation |
| DetectorService/ABD | active DNS probes, controls, normalized outcomes, hypotheses | production apply |
| DDI | profile envelope, context/freshness/revalidation | raw resolver execution |
| DiscoveryService | candidate ordering, differential evaluation, scoring | backend lifecycle |
| TransportService/DNSPathManager | provider adapters, active binding, health snapshots, fast failover | blocking truth |
| TransactionalRuntime | prepare/canary/promote/rollback/last-good | evidence interpretation |
| Observability | metrics/trace/report sink | mutable DNS profile truth |
| dnscrypt-proxy | encrypted DNS protocol execution | B4X policy, primary selection or promotion |

## 18. Dependency direction

```text
capture/parser/client identity
        ↓
Detector DNS experiments
        ↓
EvidenceGraph / BlockingProfile
        ↓
DDI / DNSPathProfile
        ↓
Discovery DNS candidates
        ↓
DNSPathManager provider binding
        ↓
runtimecontrol transaction
```

Forbidden imports/dependencies:
- `monitor → mutable DNSPathManager internals`;
- `detector → dnscrypt process lifecycle`;
- `dnscrypt supervisor → DDI/Discovery policy`;
- `Discovery → direct iptables/process mutation`;
- `backend logs → authoritative diagnosis without normalized observer`;
- `packet hot path → resolver catalog policy engine`.

# Часть IV. Пользовательская и конфигурационная модель

## 19. Operating modes

```go
type DNSOperatingMode string

const (
    DNSModeCurrent    DNSOperatingMode = "current"
    DNSModeManual     DNSOperatingMode = "manual"
    DNSModeAdaptive   DNSOperatingMode = "adaptive"
    DNSModeDiagnostic DNSOperatingMode = "diagnostic-only"
)
```

### 19.1. `current`

- сохраняет существующее поведение;
- adaptive selection не запускается;
- observability остаётся доступной;
- никакой managed backend не стартует автоматически.

### 19.2. `manual`

- пользователь pin-ит path/resolver;
- health и warnings работают;
- автоматический failover только если отдельно разрешён;
- система не меняет manual pin без явной policy.

### 19.3. `adaptive`

- quick startup revalidation;
- primary + diverse fallback profile;
- Monitoring-driven switch/recovery;
- managed backend используется только если enabled и ready;
- все изменения transactional.

### 19.4. `diagnostic-only`

- выполняет матрицу и строит profile preview;
- не меняет production DNS binding;
- подходит для field test и owner review.

## 20. Beginner UI

```text
DNS mode: Adaptive
Status: Healthy
Primary: DNSCrypt / resolver group A
Fallback 1: Native DoH / provider B
Fallback 2: Native TCP / resolver C

Reason:
- ISP UDP DNS returned conflicting answer
- UDP/53 control showed early injection
- current encrypted paths passed A/AAAA/CNAME/NXDOMAIN controls

Last switch: 12 min ago
Rollback: ready
```

Beginner UI не показывает green `Healthy`, если profile stale, fallback отсутствует, backend unverified или controls не пройдены.

## 21. Advanced policy

```yaml
dns:
  mode: adaptive

  adaptive:
    enabled: true
    allow_native_classic: true
    allow_native_encrypted: true
    allow_managed_dnscrypt_backend: true
    allow_anonymized_dnscrypt: false
    allow_odoh: false
    allow_pqdnscrypt: false

    preference: balanced
    require_dnssec_capable: false
    require_nolog_claim: true
    require_nofilter_claim: true

    max_quick_candidates: 8
    max_deep_candidates: 24
    max_parallel_probes: 1
    cooldown: 10m
    failed_search_cooldown: 1h
    recovery_hysteresis: 30m

    manual_exclusions: []
    pinned_primary: ""
    pinned_fallbacks: []
```

## 22. Policy profiles

| Preference | Приоритет |
|---|---|
| `lowest-latency` | correctness → stability → latency → resource cost |
| `balanced` | correctness → stability → diversity → latency → privacy |
| `privacy` | correctness → no-log/no-filter provenance → anonymization → stability → latency |
| `minimum-dependency` | correctness → native/simple paths → stability → encrypted backend |

Ни одна preference не может понизить correctness, controls, certificate validation или generation freshness.

## 23. Network context binding

Profile MUST включать минимум:
- `NetworkContextID`;
- `ConfigGeneration`;
- `ProcessInstanceID` или equivalent runtime epoch;
- WAN interface identity hash;
- public network/ASN/provider hints where safely available;
- IPv4/IPv6 capability snapshot;
- resolver catalog version;
- provider capability versions;
- created/validated/expiry timestamps.

WAN change, interface replacement, route change, provider binary change или significant policy change переводят profile в `STALE` до bounded revalidation.

# Часть V. Canonical data model

## 24. Path identity

```go
type DNSPathFamily string

const (
    DNSPathSystemForward       DNSPathFamily = "system-forward"
    DNSPathUDP                 DNSPathFamily = "udp"
    DNSPathTCP                 DNSPathFamily = "tcp"
    DNSPathTCPSegmented        DNSPathFamily = "tcp-segmented"
    DNSPathDoT                 DNSPathFamily = "dot"
    DNSPathDoH                 DNSPathFamily = "doh"
    DNSPathDoH3                DNSPathFamily = "doh3"
    DNSPathDoQ                 DNSPathFamily = "doq"
    DNSPathDNSCrypt            DNSPathFamily = "dnscrypt"
    DNSPathPQDNSCrypt          DNSPathFamily = "pqdnscrypt"
    DNSPathAnonymizedDNSCrypt  DNSPathFamily = "anonymized-dnscrypt"
    DNSPathODoH                DNSPathFamily = "odoh"
)

type DNSPathID struct {
    Family            DNSPathFamily
    ResolverID        string
    RelayID           string
    EndpointID        string
    IPFamily          string
    RouteBindingID    string
    ProviderVersion   string
    CatalogVersion    string
}
```

`DNSPathID` canonical serialization MUST быть deterministic. Raw endpoint IP/domain не используется как Prometheus label.

## 25. Probe outcome

```go
type DNSPathProbeOutcome struct {
    PathID              DNSPathID
    Scope               MonitorScopeKey
    QuerySuiteID        string
    Attempt             uint16

    TransportStage      string
    ResponseClass       string
    RCode               int
    Truncated           bool
    DNSSECState         string
    AnswerFingerprint   string
    CNAMEFingerprint    string
    HTTPSFingerprint    string

    Latency             time.Duration
    ResponseCount       uint16
    ArrivalOrderDigest  string

    FailureCode         ProbeFailureCode
    Attribution         FailureAttribution
    EvidenceRefs        []string
    ObservedAt          time.Time
}
```

## 26. Единственный persisted profile

```go
type DNSPathProfile struct {
    ProfileID           string
    Status              string
    Scope               MonitorScopeKey
    NetworkContextID    string
    ConfigGeneration    uint64
    RuntimeEpoch        string

    SourceBlockingProfileID string
    QuerySuiteVersion       string
    ResolverCatalogVersion  string
    PolicyDigest            string

    CandidateOutcomes   []DNSPathProbeOutcome
    Primary             DNSPathID
    Fallbacks           []DNSPathID
    Excluded            []DNSPathExclusion

    PoisoningDetected   bool
    InjectionDetected   bool
    UDPDropDetected     bool
    Port53Blocked       bool
    EncryptedPathBlocked bool
    ResolverSpecific    bool
    IPFamilySpecific    bool

    Confidence          ConfidenceSummary
    CreatedAt           time.Time
    ValidatedAt         time.Time
    ValidUntil          time.Time
    ContentHash         string
}
```

Это единственный новый persisted domain profile. `CandidateOutcomes`, `Exclusion` и runtime receipts являются nested records, а не отдельными competing profile stores.

## 27. Profile validity

`DNSPathProfile.Valid()` возвращает true только если:
1. scope и network context валидны;
2. generation/runtime epoch совместимы;
3. query suite и resolver catalog version известны;
4. primary присутствует среди validated candidate outcomes;
5. primary прошёл correctness, target и mandatory controls;
6. каждый fallback прошёл те же mandatory correctness controls;
7. fallbacks не являются идентичными aliases одного path;
8. profile не expired и не marked stale;
9. content hash соответствует canonical payload;
10. нет blocking hard-gate violation.

## 28. Response fingerprint

Сравнение ответов MUST учитывать:
- question name/type/class;
- RCODE;
- A/AAAA answer set без зависимости от порядка;
- CNAME chain;
- HTTPS/SVCB parameters relevant to endpoint selection;
- TTL range и impossible TTL anomalies;
- TC/AD/CD flags;
- EDNS OPT/EDE where present;
- DNSSEC validation state;
- authoritative/reference provenance;
- negative answer SOA semantics where available.

Различающийся CDN answer set не означает poisoning без control/reference/context analysis.

## 29. Cache partition key

```text
DNSCachePartitionKey =
    NetworkContextID
  + ConfigGeneration
  + DNSPathID
  + QueryNameHash
  + QType
  + DNSSECPolicy
  + ClientScopeClass
```

Запрещено использовать cached positive answer старого path/generation как fresh proof нового path.

## 30. Runtime binding

```go
type DNSPathBinding struct {
    BindingID          string
    Scope              RouteScope
    ProfileID          string
    Primary            DNSPathID
    Fallbacks          []DNSPathID
    ConfigGeneration   uint64
    RuntimeEpoch       string
    PreparedAt         time.Time
    PromotedAt         time.Time
    ValidUntil         time.Time
}
```

Binding является runtime state, а не вторым diagnostic profile.

# Часть VI. Provider contract

## 31. Общий интерфейс

```go
type DNSPathProvider interface {
    ID() DNSPathID
    Capabilities() DNSPathCapabilities

    Prepare(ctx context.Context, req DNSPrepareRequest) (PreparedDNSPath, error)
    Probe(ctx context.Context, prepared PreparedDNSPath, q DNSProbeQuery) (DNSPathProbeOutcome, error)
    Resolve(ctx context.Context, prepared PreparedDNSPath, q DNSQuery) (DNSResponse, error)
    Health(ctx context.Context, prepared PreparedDNSPath) DNSPathHealth
    Retire(ctx context.Context, prepared PreparedDNSPath) error
}
```

Provider не выбирает себя и не выполняет promotion.

## 32. System forward provider

- использует текущий system/router resolver path;
- фиксирует effective nameserver/route identity;
- детектирует recursion, если system resolver указывает на B4X loopback listener;
- не считается independent control, если он фактически проходит через тот же managed backend;
- может быть простейшим preferred path после recovery.

## 33. Native UDP provider

- явный resolver endpoint и source mark;
- transaction/source tuple validation;
- bounded retransmission policy;
- multi-response observation available in diagnostic mode;
- не принимает first response без structural/correctness validation.

## 34. Native TCP provider

- RFC-compliant length-prefixed DNS messages;
- используется для TC fallback и UDP-drop differential;
- connection reuse bounded and generation-owned;
- partial read/write and timeout stages explicit;
- no recursive system resolver dependency.

## 35. Native TCP segmentation experiment

- `TCP_FRAG` означает stream segmentation, не IPv4 fragmentation;
- несколько `write()` не доказывают on-wire segment boundaries;
- production readiness требует capture/GSO/MSS parity evidence;
- candidate применим только к exact DNS query path;
- без proof verdict `BLOCKED_REPRESENTATION_UNKNOWN`.

## 36. Native DoT provider

- TLS certificate and hostname validation mandatory;
- SNI/no-SNI differential diagnostic only; no-SNI with disabled verification prohibited;
- bootstrap address explicit;
- IPv4/IPv6 state explicit;
- DoT availability не означает answer correctness.

## 37. Native DoH provider

- wire-format `application/dns-message` preferred;
- HTTP status, TLS, DNS message and answer correctness separated;
- endpoint/path/hostname/bootstrap identity canonical;
- protected/direct socket route to avoid recursion;
- HTTP proxy usage is separate candidate, not hidden fallback.

## 38. Native DoH3 provider

- requires current QUIC/UDP path capability;
- Alt-Svc/probe behavior explicit;
- UDP/443 blocking classified separately;
- fallback to HTTP/2 is visible as a different path outcome;
- unsupported router build returns `UNSUPPORTED`, not fake PASS.

## 39. Native DoQ provider

- RFC-compliant transaction ID semantics;
- certificate/SNI validation mandatory;
- current QUIC capability and IPv4/IPv6 coverage required;
- no attribution to dnscrypt-proxy;
- separate resource budget from application QUIC traffic.

## 40. Managed dnscrypt-proxy provider families

| Family | Backend mode | Notes |
|---|---|---|
| DNSCrypt | managed dnscrypt-proxy | UDP/TCP behavior explicit in generated config |
| PQDNSCrypt | managed dnscrypt-proxy | optional; CPU capability and server support required |
| Anonymized DNSCrypt | managed dnscrypt-proxy + relay | resolver and relay identities both bound |
| DoH HTTP/2 | managed dnscrypt-proxy | single explicit server per causal instance |
| DoH HTTP/3 | managed dnscrypt-proxy `http3` | optional; no hidden HTTP/2 fallback in path identity |
| ODoH | managed dnscrypt-proxy + ODoH relay | optional source/catalog and privacy policy |

## 41. Provider capability states

```text
UNKNOWN
UNSUPPORTED
AVAILABLE
READY
DEGRADED
STALE
FAILED
BLOCKED_BY_POLICY
BLOCKED_BY_DEPENDENCY
```

`UNSUPPORTED`, `SKIPPED`, `MISSING` и `STALE` никогда не преобразуются в `READY`.

# Часть VII. Managed dnscrypt-proxy lifecycle

## 42. Packaging

Managed backend MUST поставляться или устанавливаться только одним из одобренных способов:
1. pinned reproducible B4X package с platform-specific binary hash;
2. signed Entware/B4X package, version pinned в capability manifest;
3. explicit user-provided binary path, прошедший hash/version/license check.

Runtime download arbitrary latest binary запрещён.

## 43. Supervisor ownership

```text
DNSPathManager
  └── ManagedDNSBackendSupervisor
        ├── verify binary + manifest
        ├── generate isolated config
        ├── allocate loopback listener
        ├── start process
        ├── wait for functional query readiness
        ├── publish health
        ├── rotate generation
        └── retire/cleanup
```

Readiness не определяется fixed sleep или PID existence.

## 44. Deterministic instance identity

Для diagnosis и promotion causal identity MUST быть однозначной:
```text
one managed instance
→ one explicit upstream resolver/server
→ optional one explicit relay
→ one protocol family
→ one IP family preference
→ one generated config digest
→ one loopback listener
→ one B4X DNSPathID
```

Скрытый random/load-balanced server pool внутри instance запрещён для canonical candidate evaluation.

## 45. Diagnostic и production roles

| Role | Cache | Lifetime | Purpose |
|---|---|---|---|
| diagnostic instance | off или controlled unique names | ephemeral | fresh differential evidence |
| production active instance | bounded policy-controlled | generation-bound | serve promoted path |
| production standby | optional warm | generation-bound | fast failover |

На constrained router одновременно допускается максимум один active и один diagnostic/standby instance, если resource profile не доказал большее.

## 46. Generated config requirements

- listen only on loopback address/port owned by B4X;
- explicit `server_names` or stamps;
- single causal resolver/route per instance;
- no EDNS client subnet by default;
- query log disabled by default;
- source list update disabled unless B4X update policy enables it;
- resolver list cache and signatures verified;
- IPv6 enabled only when current capability ready;
- HTTP/3 enabled only for DoH3 candidate;
- ODoH sources enabled only for ODoH candidate;
- cache policy explicit;
- cert refresh concurrency reduced for device class;
- no local LAN listener exposure.

## 47. Bootstrap and recursion prevention

Bootstrap rules:
1. prefer resolver stamps/endpoints containing IP addresses;
2. use pinned signed cached resolver lists before network bootstrap;
3. bootstrap queries never carry user application qnames;
4. system bootstrap path must not resolve back through the same B4X listener;
5. outbound backend sockets use dedicated mark/bypass route;
6. nested proxy/WARP bootstrap requires explicit dependency graph;
7. bootstrap failure produces `BLOCKED_BOOTSTRAP`, not fallback to hidden unsafe system DNS.

## 48. Resolver list update

```text
download signed source
→ verify minisign/key/version
→ parse and validate bounded catalog
→ write candidate file
→ test with isolated backend instance
→ atomic replace
→ retain last-good
→ rollback on failure
```

Update cadence is a separate configuration. Ordinary query handling does not depend on live catalog download.

## 49. Cache policy

Logical cache ownership remains with `DNSPathManager`. Backend storage MAY be used, but policy is explicit:
- diagnostic evidence cannot come from unknown/stale cache;
- cache is partitioned by managed instance/path generation;
- promotion creates or reuses only compatible cache generation;
- rollback restores last-good cache or starts clean according to policy;
- negative cache TTL bounded;
- path switch cannot leave stale positive mapping attributed to new resolver;
- raw cache contents are not exported.

## 50. Logs and privacy

- raw qname query log off by default;
- diagnostic temporary logs require explicit test-session policy;
- standard metrics use path family/result only;
- resolver identity is stable hash in ordinary reports;
- full endpoint details only in local owner artifact;
- no TLS key log except explicit lab-only session;
- cleanup removes temporary configs/logs/sockets.

## 51. Resource budgets

```text
default router policy:
- max active adaptive DNS runs: 1
- max parallel path probes: 1
- max managed instances: 2
- cert refresh concurrency: 1
- bounded max_clients by device profile
- bounded cache size by device profile
- PQDNSCrypt default off on uncalibrated devices
- ODoH default off
- HTTP/3/DoQ only when QUIC readiness is current
- budget breach → degrade/stop, never expand automatically
```

## 52. Crash and retirement

- backend crash invalidates current health immediately;
- fast failover may use already-ready standby/last-good native path;
- restart loops are bounded with backoff;
- generation change retires old process/listener/config after in-flight drain;
- shutdown removes listeners, pid files, temp configs and owned rules;
- foreign process/resources are never killed by name-only matching.

# Часть VIII. DNS differential diagnosis

## 53. Trigger conditions

Adaptive diagnosis может запускаться по:
- startup/current-WAN quick revalidation;
- persistent Monitoring DNS degradation;
- repeated NXDOMAIN/SERVFAIL/timeout anomaly;
- client-observed vs independent resolution contradiction;
- UDP/DoH availability drift;
- primary path health failure;
- catalog/provider/config generation change;
- explicit user/field-test request.

Один transient timeout не запускает deep matrix.

## 54. Query suite

Minimum canonical suite:
| Case | Purpose |
|---|---|
| A | IPv4 positive answer |
| AAAA | IPv6 positive answer |
| CNAME chain | canonical/final answer preservation |
| HTTPS/SVCB | ECH/service metadata preservation |
| known NXDOMAIN | negative answer integrity |
| controlled SERVFAIL | error-path semantics |
| large/truncated response | UDP TC → TCP fallback |
| multiple answers | set comparison |
| DNSSEC-valid | validation-capable path |
| DNSSEC-bogus controlled fixture | failure handling |
| same-service control | target-specific differential |
| unrelated control | general path health |

Public targets используются только при reviewed Service Profile. Controlled field fixtures предпочтительны для mutation/failure claims.

## 55. Four-way comparison

```text
R1 target query through candidate path
R2 target query through independent reference path
R3 control query through candidate path
R4 control query through independent reference path
```

Дополнительно сохраняются client-observed exact-endpoint resolution и independent-current-resolution как разные experiments.

## 56. Quick matrix

1. текущий primary functional/correctness probe;
2. last-good fallback;
3. system forward;
4. native UDP and TCP pair;
5. configured native DoH;
6. last-good managed encrypted path if ready;
7. mandatory controls;
8. stop when stable minimum-complexity path and diverse fallback are proven.

## 57. Deep matrix

Deep mode expands only when quick matrix cannot produce a complete profile:
1. additional resolver endpoints from bounded signed catalog;
2. DoT/DoH/DoH3/DoQ according to current capabilities;
3. TCP segmentation experiment when evidence suggests port-53 DPI parsing;
4. DNSCrypt/PQDNSCrypt;
5. Anonymized DNSCrypt;
6. ODoH;
7. UDP response-race observer;
8. IPv4/IPv6 differential;
9. one dimension at a time before combined candidate changes.

## 58. Outcome classes

```text
PASS_CORRECT
PASS_DIFFERENT_BUT_VALID
TIMEOUT
CONNECTION_REFUSED
TLS_CERT_FAILURE
TLS_ALERT
HTTP_STATUS_FAILURE
QUIC_UNAVAILABLE
MALFORMED_DNS
QUESTION_MISMATCH
RCODE_MISMATCH
ANSWER_CONFLICT
EARLY_INJECTION_SUSPECTED
TRUNCATED_REQUIRES_TCP
DNSSEC_INVALID
RESOLVER_POLICY_FILTERED
CACHE_STALE
INCONCLUSIVE
OBSERVER_UNAVAILABLE
```

## 59. Poisoning and injection rules

`PoisoningDetected=true` требует не менее одного из:
- candidate path returns structurally valid but control/reference-contradicting answer repeatedly;
- same forged/stub answer appears across unrelated target names while independent paths disagree;
- early UDP response is contradicted by later source-valid response and encrypted/reference quorum;
- known NXDOMAIN becomes positive/block-page response consistently;
- DNSSEC validation proves response invalid, при этом independent path valid.

Один CDN IP mismatch или TTL difference недостаточен.

## 60. UDP response-race interpretation

| Pattern | Verdict |
|---|---|
| one response, reference-consistent | normal UDP outcome |
| early conflicting + later reference-consistent | early injection suspected |
| multiple identical valid responses | duplicate, not poisoning |
| multiple conflicting, no reference quorum | inconclusive |
| last response malformed/question mismatch | reject, never trust by order |

## 61. Truncation and TCP fallback

```text
UDP response TC=1
→ native TCP same resolver/query
→ compare complete answer
→ record UDP/TCP pair as one causal experiment
→ never cache truncated answer as complete
```

## 62. Encrypted transport stages

Каждый encrypted path разделяет stages:
```text
route/bootstrap
→ TCP or QUIC connect
→ TLS/certificate/SNI
→ HTTP/relay protocol where applicable
→ DNS message parse
→ answer correctness
→ control comparison
```

Connect/TLS success не равен DNS success.

## 63. IPv4/IPv6

- A and AAAA tested independently;
- provider endpoint IPv4/IPv6 reachability explicit;
- IPv6 `UNSUPPORTED` не скрывается;
- IPv6-specific failure не удаляет valid IPv4 path;
- profile records IP-family-specific outcome and fallback.

## 64. Correctness quorum

Reference quorum не означает majority of arbitrary public resolvers. Он строится из independent evidence families:
- controlled authoritative fixture;
- DNSSEC validation;
- client-observed exact endpoint and fresh independent resolution;
- multiple providers with distinct network/protocol paths;
- same-service/unrelated controls;
- current application milestone when applicable.

# Часть IX. Selection, profile compilation и Discovery

## 65. Candidate scoring

```text
eligible only if correctness gates pass

score =
    stability
  + diversity contribution
  + privacy preference match
  + DNSSEC capability
  - latency
  - timeout/retry rate
  - CPU/RAM cost
  - correlated dependency risk
  - catalog/provider uncertainty
  - policy mismatch
```

Минимально сложный native path выше managed/anonymized path при одинаковой correctness/stability, если user preference не требует privacy mode.

## 66. Deterministic ordering

Candidate order MUST быть детерминирован для одинаковых profile/policy/catalog inputs. Random shuffle из DPYProxy не переносится.
Tie-breaker: canonical `DNSPathID` ordering.

## 67. Failure-to-family prior

| Evidence | Boost | Penalize/Exclude |
|---|---|---|
| early UDP injection | TCP, DoT, DoH, DNSCrypt | system/UDP primary |
| UDP timeout, TCP works | TCP, DoT/DoH | UDP paths |
| UDP+TCP port 53 fail, DoH works | DoH/DNSCrypt/ODoH | classic port 53 |
| DoH TLS/SNI blocked, DNSCrypt works | DNSCrypt/Anonymized DNSCrypt | affected DoH endpoint |
| UDP/443 blocked | DoH HTTP/2, TCP-based paths | DoH3/DoQ |
| resolver-specific wrong answer | different resolver/provider | affected resolver all transports until revalidated |
| IPv6 endpoint failure | IPv4 paths | IPv6 candidate for current context |
| all DNS paths correct | non-DNS Discovery families | unnecessary resolver churn |

## 68. Fallback diversity

Fallback ladder SHOULD избегать correlated failure:
```text
primary: DNSCrypt resolver A
fallback 1: native DoH provider B
fallback 2: native TCP resolver C

not preferred:
primary: DoH provider A endpoint 1
fallback 1: DoH provider A endpoint 2
fallback 2: DoH provider A endpoint 3
```

Одинаковый operator/provider/route dependency снижает diversity score.

## 69. DDI contract

```text
DNS authoritative evidence
→ BlockingProfile DNS hypotheses
→ NetworkContext freshness
→ DNSPathProfile compilation/revalidation
→ DiscoverySearchPrior for DNS candidates
→ existing Discovery baselines/controls/full fallback
```

`DNSPathProfile` не является `TransportAuthorization`.

## 70. Discovery contract

Discovery MUST:
- сохранять baseline-current и baseline-production;
- тестировать current primary before replacement;
- использовать profile only for ordering/budget/exclusions;
- проверять mandatory target/control queries;
- проверять exact client/service scope where possible;
- не удалять full bounded fallback;
- не считать router-origin result Android proof;
- создавать canonical candidate receipt для runtimecontrol.

## 71. Promotion requirements

Candidate DNS path может быть promoted только при:
1. fresh profile/context/generation;
2. provider readiness;
3. correctness suite PASS;
4. same-service and unrelated controls PASS;
5. source-scoped Android/LAN canary PASS;
6. cache migration/partition readiness;
7. rollback readiness;
8. no blocking hard gate;
9. metrics/API/report parity.

# Часть X. DNSPathManager runtime

## 72. Logical placement

`DNSPathManager` является logical component внутри existing TransportService/DNS control plane. Package layout MAY быть:
```text
src/transport/dns/
  manager.go
  model.go
  policy.go
  health.go
  selection.go
  cache.go
  transaction.go
  providers/
    system.go
    udp.go
    tcp.go
    tcp_segment.go
    dot.go
    doh.go
    doh3.go
    doq.go
    dnscrypt.go
  managed/
    supervisor.go
    config.go
    catalog.go
    lifecycle.go
```

Detector/DDI/Discovery ownership remains in their existing packages.

## 73. Request flow

```text
client DNS request
→ parse + ClientKey + transaction context
→ select current binding for scope/generation
→ cache lookup in compatible partition
→ primary provider resolve
→ validate response envelope
→ return to client + publish DNSObservation
→ on failure apply bounded per-request fallback policy
→ update health without changing global profile inline
```

## 74. Per-request fallback

Fast fallback is allowed only among already promoted/ready profile paths. A new unvalidated candidate cannot be tried inline on arbitrary user query.
Default behavior:
```text
primary timeout/failure
→ one ready fallback attempt if request deadline permits
→ preserve original transaction ID/question
→ return response
→ publish failure event
→ schedule diagnosis outside request hot path
```

## 75. In-flight generation

- new requests use new promoted binding generation;
- in-flight requests may finish on old generation within bounded drain;
- responses from retired generation are not inserted into new cache partition;
- hard cutover only for security/correctness violation;
- retirement cleanup is owner-led and observable.

## 76. Transactional switch

```text
PREPARE
- provider/backend ready
- loopback/listener allocated
- route/mark ready
- cache generation ready
- health query PASS

CANARY
- detector queries
- selected Android/client scope
- mandatory controls

PROMOTE
- atomic binding swap
- retain last-good
- start observation window

ROLLBACK
- restore last-good binding/cache
- retire failed candidate
- preserve evidence and reason
```

## 77. Recovery to simpler path

Adaptive mode не должен навсегда оставаться на дорогом encrypted/anonymized path.
```text
simpler path revalidated repeatedly
+ current primary stable
+ recovery hysteresis elapsed
+ controls PASS
→ canary simpler path
→ promote or retain current
```

Flapping предотвращается cooldown/hysteresis and minimum stability samples.

## 78. Manual override semantics

- manual primary pin is policy upper bound;
- если path unsafe/incorrect, UI показывает failure и не скрывает проблему;
- optional emergency fallback requires explicit setting;
- adaptive discovery may recommend alternative without silently replacing pin;
- removing pin returns control to profile selection.

# Часть XI. Monitoring integration

## 79. Health axes

```text
transport_health
correctness_health
control_health
latency_health
resource_health
backend_health
profile_freshness
fallback_readiness
```

Общий green status возможен только при compatible composition, а не по одному transport ping.

## 80. Failure recurrence

Monitoring агрегирует:
- timeouts/failures by path family;
- response contradictions;
- client-observed service DNS failures;
- backend crashes/restarts;
- fallback usage;
- cache anomalies;
- WAN/context changes;
- control health.

Passive recurrence инициирует bounded ABD request, но не меняет binding самостоятельно.

## 81. Fast failover vs deep diagnosis

```text
known promoted fallback ready
→ fast transactional failover
→ monitor result
→ schedule bounded revalidation

no ready fallback or correctness contradiction
→ hold last safe behavior where possible
→ deep diagnosis
→ no blind resolver switch
```

## 82. Profile expiry

Expiry зависит от:
- network context stability;
- path family risk;
- resolver/catalog update;
- recent failure/drift;
- manual policy;
- backend version change.

Expired profile может использоваться только как ordering prior после fast revalidation, не как promotion proof.

# Часть XII. API, UX, observability и artifacts

## 83. API

```text
GET  /api/dns/v1/config
PUT  /api/dns/v1/config
GET  /api/dns/v1/status
GET  /api/dns/v1/profile
POST /api/dns/v1/diagnose
POST /api/dns/v1/revalidate
POST /api/dns/v1/canary
POST /api/dns/v1/rollback
GET  /api/dns/v1/providers
GET  /api/dns/v1/artifacts/{run_id}
```

Write endpoints используют registered schema, authorization, generation precondition и idempotency key.

## 84. Status payload

```json
{
  "mode": "adaptive",
  "verdict": "READY",
  "network_context_id": "wan-...",
  "config_generation": 42,
  "profile_id": "dnsprof-...",
  "primary": {
    "family": "dnscrypt",
    "resolver_id_hash": "r-...",
    "health": "healthy"
  },
  "fallbacks": [
    {"family": "doh", "health": "ready"},
    {"family": "tcp", "health": "ready"}
  ],
  "diagnosis": {
    "udp_injection_suspected": true,
    "port53_blocked": false,
    "confidence": 0.92
  },
  "rollback_ready": true,
  "explanation": [
    "system UDP returned an early conflicting answer",
    "DNSCrypt and native DoH passed target and controls"
  ]
}
```

## 85. Metrics

- `b4_dns_path_probe_total{family,stage,result}`
- `b4_dns_path_probe_duration_seconds{family,stage}`
- `b4_dns_path_response_conflict_total{family,class}`
- `b4_dns_path_injection_suspected_total{family}`
- `b4_dns_path_selection_total{primary_family,reason}`
- `b4_dns_path_switch_total{from_family,to_family,result}`
- `b4_dns_path_fallback_total{from_family,to_family,result}`
- `b4_dns_path_profile_state{state}`
- `b4_dns_path_backend_state{backend,state}`
- `b4_dns_path_backend_restart_total{reason}`
- `b4_dns_path_cache_event_total{event}`
- `b4_dns_path_cleanup_total{result}`
- `b4_dns_path_query_total{family,result,cached}`
- `b4_dns_path_readiness{verdict}`

Raw resolver name, IP, qname, client IP/MAC и profile ID запрещены как unbounded metric labels.

## 86. Causal trace

```text
DNS_QUERY_OBSERVED
→ DNS_PATH_SELECTED
→ PROVIDER_PREPARED
→ PROBE_SENT
→ RESPONSE_RECEIVED
→ RESPONSE_NORMALIZED
→ CONTROL_COMPARED
→ PROFILE_COMPILED
→ CANDIDATE_CANARY_STARTED
→ CANDIDATE_CANARY_RESULT
→ BINDING_PROMOTED or ROLLBACK_STARTED
→ OLD_GENERATION_RETIRED
→ CLEANUP_COMPLETE
```

Каждое событие включает trace ID, run ID, scope, path family, generation и monotonic sequence.

## 87. Standard report

Standard report показывает:
- current primary/fallback families;
- why selected;
- correctness and control summary;
- poisoning/injection/drop hypotheses with confidence;
- provider readiness;
- profile freshness;
- canary/promotion/rollback result;
- redacted evidence refs;
- resource budget outcome.

Raw qnames/endpoints require explicit local diagnostic export.

# Часть XIII. Principal verdicts и hard gates

## 88. Principal verdicts

| Verdict | Meaning |
|---|---|
| ADNS_DETECTOR_READY | DNS differential query suite, controls and attribution ready |
| ADNS_NATIVE_CLASSIC_READY | system/UDP/TCP provider set ready |
| ADNS_TCP_SEGMENT_EXPERIMENT_READY | on-wire segmentation evidence ready |
| ADNS_NATIVE_ENCRYPTED_READY | applicable DoT/DoH/DoH3/DoQ providers ready |
| ADNS_MANAGED_BACKEND_READY | pinned managed dnscrypt backend ready |
| ADNS_PROFILE_READY | fresh complete DNSPathProfile ready |
| ADNS_FAILOVER_READY | primary/fallback transaction and rollback ready |
| ADNS_ANDROID_CANARY_READY | source-scoped real client proof ready |
| ADNS_PRODUCTION_READY | all enabled/applicable dependencies ready |

## 89. Zero-tolerance gates

- `dns_path_action_without_authorization_total`
- `dns_cross_client_answer_leak_total`
- `dns_recursive_loop_total`
- `dns_bootstrap_user_query_leak_total`
- `dns_invalid_certificate_accepted_total`
- `dns_question_mismatch_accepted_total`
- `dns_last_response_order_only_accept_total`
- `dns_hidden_backend_selection_total`
- `dns_stale_profile_applied_total`
- `dns_cache_cross_generation_reuse_total`
- `dns_promotion_without_controls_total`
- `dns_promotion_without_android_canary_total`
- `dns_unverified_backend_binary_total`
- `dns_unsigned_catalog_applied_total`
- `dns_cleanup_incomplete_total`
- `dns_foreign_resource_mutation_total`
- `dns_raw_query_export_total`

Оцениваются по current validation window/generation delta, а не lifetime absolute total.

## 90. Current-generation readiness inputs

- `dns_provider_unavailable_total`
- `dns_backend_crash_total`
- `dns_catalog_stale_total`
- `dns_profile_invalidation_total`
- `dns_udp_injection_suspected_total`
- `dns_response_conflict_total`
- `dns_cache_reset_total`
- `dns_ipv6_path_unavailable_total`
- `dns_quic_path_unavailable_total`
- `dns_resource_budget_exhausted_total`

Они не являются lifetime direct blockers. Их current-generation effect вычисляется совместно с owner state, applicability и successful revalidation.

## 91. Telemetry counters

- `dns_path_query_total`
- `dns_path_probe_total`
- `dns_path_switch_total`
- `dns_path_fallback_total`
- `dns_backend_restart_total`
- `dns_cache_hit_total`
- `dns_cache_miss_total`
- `dns_profile_compile_total`
- `dns_profile_revalidation_total`

## 92. Fail-closed semantics

```text
enabled capability
+ applicable provider/path
+ missing producer/evidence
→ BLOCKED_MISSING_PRODUCER or BLOCKED_MISSING_EVIDENCE
→ no promotion

counter reset in same validation run
→ BLOCKED_COUNTER_RESET / STALE
→ new baseline and revalidation required

backend unsupported
→ UNSUPPORTED / NOT_APPLICABLE with reason
→ never PASS
```

## 93. Required hard-gate chain

```text
real failure producer
→ internal state/counter
→ principal verdict evaluator
→ Validation API
→ /metrics
→ Field Test report
→ PromotePending blocker
→ rollback/cleanup evidence
```

# Часть XIV. Tests and validation

## 94. Unit tests

- canonical `DNSPathID` serialization/hash;
- profile validity/freshness;
- response fingerprint normalization;
- A/AAAA/CNAME/HTTPS/NXDOMAIN/SERVFAIL parsing;
- candidate deterministic ordering;
- fallback diversity scoring;
- cache partition/generation;
- manual pin semantics;
- resolver catalog validation;
- last-response observer classification;
- DoH HTTP fallback represented as separate path;
- metrics label cardinality.

## 95. Controlled integration matrix

FaultLab MUST поддерживать:
- valid UDP resolver;
- early forged UDP response + later valid response;
- UDP drop / TCP success;
- UDP truncation / TCP complete answer;
- fake NXDOMAIN;
- block-page/stub IP;
- CNAME chain alteration;
- AAAA-only and IPv6 failure;
- invalid DNSSEC response;
- DoT certificate failure;
- DoH HTTP error/body corruption;
- DoH3/DoQ UDP block;
- resolver-specific differing but valid CDN answer;
- managed backend crash;
- catalog signature failure;
- cache stale/cross-generation fixture.

## 96. Managed backend tests

- binary hash/version/license verification;
- generated config contains one explicit causal resolver/route;
- loopback only listener;
- functional readiness query;
- no hidden server switching;
- signed source update and rollback;
- bootstrap no-user-query leakage;
- process crash and bounded restart;
- old generation retirement;
- temp config/log/socket cleanup;
- ARM/MIPS target execution where claimed.

## 97. Transaction tests

- prepare failure leaves current binding unchanged;
- canary failure rolls back;
- promotion atomicity;
- in-flight old-generation drain;
- cache partition swap;
- standby failover;
- rollback after backend crash;
- restart/reboot restores last-good only if context compatible;
- WAN change invalidates binding/profile;
- manual pin cannot be overwritten silently.

## 98. Android/LAN field tests

- actual client DNS query observed with ClientKey;
- first application flow receives source-scoped DNS hint;
- official Android app target reaches required milestone;
- same-client unrelated controls remain healthy;
- multiple Android clients do not leak answers/policy;
- Private DNS/App DoH visibility limitation reported honestly;
- adaptive path switch visible in trace;
- rollback restores client service.

## 99. Resource/performance tests

- CPU/RAM under active encrypted path;
- startup time;
- query latency p50/p95/p99;
- cache effectiveness;
- managed process restart cost;
- concurrent client load;
- NFQUEUE/PPE/GSO side effects;
- router low-memory behavior;
- PQDNSCrypt/ODoH only after device-class calibration.

## 100. Mutation/meta-suite

- `remove provider producer` → suite MUST detect and block
- `make stale profile appear fresh` → suite MUST detect and block
- `accept last response solely by order` → suite MUST detect and block
- `disable certificate verification` → suite MUST detect and block
- `route bootstrap through B4X listener recursively` → suite MUST detect and block
- `enable hidden dnscrypt multi-server random selection` → suite MUST detect and block
- `reuse cache from prior generation` → suite MUST detect and block
- `promote without unrelated control` → suite MUST detect and block
- `promote without Android canary` → suite MUST detect and block
- `report different primary in API and /metrics` → suite MUST detect and block
- `skip cleanup but return PASS` → suite MUST detect and block
- `replace signed catalog with unsigned file` → suite MUST detect and block
- `crash backend after canary before promotion` → suite MUST detect and block
- `change WAN after profile compilation` → suite MUST detect and block

## 101. Real-target release evidence

Production claim требует реального Keenetic + Android run. Controlled fixtures доказывают correctness и failure handling, но не заменяют ISP/WAN behavior.
Если relevant censorship target отсутствует:
```text
IMPLEMENTED / LAB_VALIDATED / BLOCKED_BY_TARGET_EVIDENCE
```

а не ложный `PASS`.

# Часть XV. Implementation stages ADNS-1…ADNS-15

## ADNS-1 — Reference audit and owner decisions

- Pin DPYProxy and dnscrypt-proxy commits/licenses.
- Record source-derived correction: DoT/DoQ are native, not dnscrypt backend.
- Approve `LAST_RESPONSE` as diagnostic observer only.
- Map existing DNS code and production roots.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-2 — Canonical schemas and registries

- Implement DNSPathID, outcomes, profile, binding and provider capability schema.
- Add generated resolver/path family registries.
- Add migration/versioning and schema tests.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-3 — Existing parser/correlation hardening

- Complete A/AAAA/CNAME/HTTPS/NXDOMAIN/SERVFAIL/truncation handling.
- Preserve source-scoped first-flow correlation.
- Add response fingerprint and negative evidence tests.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-4 — Native classic providers

- System forward, UDP and TCP providers through common interface.
- Recursion detection, marks/routes, transaction validation.
- Functional production-root tests.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-5 — TCP segmentation and UDP race observer

- Implement bounded TCP stream segmentation candidate.
- Prove on-wire behavior through capture/GSO/MSS evidence.
- Implement multi-response observer; never literal last-wins.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-6 — Native encrypted providers

- DoT, DoH, DoH3 and DoQ adapters.
- Certificate/SNI/bootstrap/IPv4/IPv6 stages.
- Explicit unsupported/degraded states.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-7 — Managed backend packaging and supervisor

- Pinned binary manifests for supported router architectures.
- Loopback lifecycle, config generation, readiness and cleanup.
- No runtime arbitrary download.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-8 — Managed DNSCrypt provider adapters

- DNSCrypt/PQDNSCrypt, Anonymized DNSCrypt, DoH/H3 and ODoH path identities.
- One causal resolver/relay per instance.
- Signed catalog/bootstrap/cache policy.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-9 — Differential Detector and profile compiler

- Quick/deep query suites and controls.
- Poisoning/injection/drop/transport attribution.
- Compile fresh canonical DNSPathProfile.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-10 — DDI and Discovery integration

- Profile freshness/revalidation.
- Failure-to-family prior and deterministic ordering.
- Mandatory baselines/controls/full fallback retained.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-11 — DNSPathManager and transactional binding

- Prepare/canary/promote/rollback.
- In-flight generation drain and cache partitions.
- Fast fallback only among ready promoted paths.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-12 — Monitoring, failover and recovery

- Health axes and persistent failure trigger.
- Fast failover, deep diagnosis scheduling, cooldown/hysteresis.
- Return-to-simpler-path recovery canary.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-13 — API, UX, metrics and trace

- Registered endpoints and beginner/advanced UI.
- Prometheus/API/report/internal parity.
- Privacy/cardinality controls.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-14 — Validation and mutation closure

- Unit/integration/race/fuzz/meta suites.
- Hard-gate producer/consumer chains.
- FaultLab and validation-of-validation evidence.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

## ADNS-15 — Keenetic/Android field evidence and cutover

- Real router architecture/resource proof.
- Real Android source-scoped canary.
- Shadow → canary → controlled cutover.
- Closure artifacts, commits, push and clean worktree.

**Stage DoD:** build, vet, targeted tests, full tests, evidence artifact, отдельный commit и push. Missing target evidence возвращает `BLOCKED_BY_TARGET`, а не PASS.

# Часть XVI. Acceptance criteria

## 102. Functional

1. Режим `Adaptive` существует, сохраняется и default-off для existing installs.
2. При выключенном adaptive никакой automatic path switch не происходит.
3. System/UDP/TCP/native encrypted/managed providers имеют canonical identity.
4. Detector строит correctness-bearing outcomes, а не availability-only.
5. DNSPathProfile содержит validated primary и diverse fallbacks.
6. Discovery реально тестирует candidate paths.
7. DNSPathManager применяет только promoted profile binding.
8. Fast failover использует только already-ready fallback.
9. Monitoring инициирует revalidation и recovery.
10. Android client получает рабочий DNS и source-scoped first-flow evidence.

## 103. Safety

1. Нет blind first-success selection.
2. Нет literal last-response-wins.
3. Нет certificate verification bypass.
4. Нет recursive bootstrap/query loop.
5. Нет stale profile/cache reuse.
6. Нет hidden backend resolver switching.
7. Нет promotion без controls и Android canary.
8. Нет raw query leakage в metrics/standard export.
9. Нет runtime unpinned binary/catalog.
10. Нет incomplete cleanup после cancel/restart/rollback.

## 104. Architecture

1. Один MonitorService trigger owner.
2. Один Detector/ABD evidence owner.
3. Один DDI freshness/profile envelope owner.
4. Один Discovery candidate optimizer.
5. Один TransportService/DNSPathManager runtime owner.
6. Один TransactionalRuntime apply/rollback owner.
7. `dnscrypt-proxy` не является policy owner.
8. DPYProxy Python runtime отсутствует.

## 105. Evidence

1. Каждый principal verdict имеет producer, consumer, gate, reset/applicability и evidence.
2. Internal state, `/metrics`, API и Field Test report совпадают.
3. Missing/skipped/stale/unsupported не трактуются как PASS.
4. Mutation suite доказывает невозможность shortcut paths.
5. Controlled fixtures и real-target evidence разделены.

## 106. Release rule

```text
ADNS_PRODUCTION_READY == PASS
```

и все включённые/applicable companion verdicts PASS. Optional disabled provider может быть `NOT_APPLICABLE` только с registered policy reason.

# Часть XVII. Architectural Decision Records

## ADR-ADNS-001 — One adaptive DNS control plane

Не создаётся второй DNS optimizer или policy daemon.

## ADR-ADNS-002 — Native selection, external backend

DPYProxy idea реализуется нативно; dnscrypt-proxy используется как managed provider.

## ADR-ADNS-003 — Source-correct protocol ownership

DoT/DoQ принадлежат native providers; dnscrypt backend не заявляет их.

## ADR-ADNS-004 — Correctness before latency

Fast wrong resolver никогда не выше slower correct resolver.

## ADR-ADNS-005 — Last response is evidence, not policy

Arrival order alone не определяет trusted answer.

## ADR-ADNS-006 — One causal resolver per managed instance

Hidden backend balancing запрещён в diagnostic/promotion path.

## ADR-ADNS-007 — Profile is scoped and expiring

WAN/context/generation changes invalidate or require revalidation.

## ADR-ADNS-008 — Cache is path/generation aware

Cross-generation cached answer не является fresh proof.

## ADR-ADNS-009 — Fast fallback only to ready paths

Новый candidate не тестируется inline на произвольном user query.

## ADR-ADNS-010 — Monitoring triggers, runtimecontrol mutates

Monitoring не переключает resolver binding напрямую.

## ADR-ADNS-011 — Android proof remains mandatory

Router-origin query success не заменяет client/application canary.

## ADR-ADNS-012 — Signed offline-capable catalogs

Ordinary operation не зависит от live downloads.

## ADR-ADNS-013 — Managed backend is optional

Native adaptive mode может работать без dnscrypt-proxy; claims remain capability-specific.

## ADR-ADNS-014 — Recovery prefers minimum complexity

После доказанного восстановления система может вернуться к simpler path.

## ADR-ADNS-015 — No false production PASS

Lab validation без real target остаётся blocked by target evidence.

# Appendix A. Пользовательский сценарий

## A.1. До блокировки

```text
primary: system UDP resolver
fallback: native TCP
status: healthy
```

## A.2. ISP начинает подменять UDP answers

```text
Monitoring:
- repeated wrong/stub answer pattern
- independent DoH answer differs
- unrelated controls show same early response behavior
- current primary correctness degraded
```

## A.3. Diagnosis

```text
system UDP       EARLY_INJECTION_SUSPECTED
native UDP       EARLY_INJECTION_SUSPECTED
native TCP       PASS_CORRECT
native DoH       PASS_CORRECT
DNSCrypt         PASS_CORRECT
DoH3             UDP/443 unavailable
```

## A.4. Compiled profile

```text
primary: DNSCrypt resolver A
fallback 1: native DoH provider B
fallback 2: native TCP resolver C
excluded:
- system UDP: early injection suspected
- DoH3: UDP/443 unavailable
```

## A.5. Apply

```text
prepare managed backend
→ detector controls PASS
→ selected Android canary PASS
→ promote
→ monitor stability
→ retain previous binding as rollback target
```

# Appendix B. Example config

```yaml
dns:
  mode: adaptive

  adaptive:
    enabled: true
    preference: balanced

    providers:
      system_forward: true
      udp: true
      tcp: true
      tcp_segmented: diagnostic-only
      dot: true
      doh: true
      doh3: auto
      doq: auto

      managed_dnscrypt:
        enabled: true
        binary_source: bundled-pinned
        dnscrypt: true
        pqdnscrypt: auto
        anonymized_dnscrypt: false
        doh: true
        doh3: auto
        odoh: false

    selection:
      max_quick_candidates: 8
      max_deep_candidates: 24
      max_parallel_probes: 1
      attempts_quick: 2
      attempts_validation: 5
      require_unrelated_controls: true
      require_android_canary: true
      diversity_weight: 20

    lifecycle:
      cooldown: 10m
      failed_search_cooldown: 1h
      recovery_hysteresis: 30m
      profile_ttl: 24h
      retain_last_good: true

    privacy:
      raw_query_logs: false
      edns_client_subnet: false
      standard_export_redacted: true
```

# Appendix C. Example DNSPathProfile

```json
{
  "profile_id": "dnsprof-91b4...",
  "status": "ready",
  "network_context_id": "wan-2fc1...",
  "config_generation": 42,
  "query_suite_version": "adns-suite-v1",
  "resolver_catalog_version": "catalog-2026-08-01",
  "primary": {
    "family": "dnscrypt",
    "resolver_id": "resolver-hash-a",
    "provider_version": "dnscrypt-proxy@c3ba78f"
  },
  "fallbacks": [
    {"family": "doh", "resolver_id": "resolver-hash-b"},
    {"family": "tcp", "resolver_id": "resolver-hash-c"}
  ],
  "excluded": [
    {
      "family": "udp",
      "reason": "early-injection-suspected",
      "evidence_refs": ["ev-101", "ev-102"]
    },
    {
      "family": "doh3",
      "reason": "udp-443-unavailable",
      "evidence_refs": ["ev-103"]
    }
  ],
  "confidence": {
    "score": 0.92,
    "supports": 4,
    "contradictions": 0
  },
  "valid_until": "2026-08-03T18:00:00Z"
}
```

# Appendix D. Example generated managed backend config policy

```toml
# Generated by B4X for one causal path instance
listen_addresses = ['127.0.0.1:55331']
server_names = ['explicit-reviewed-server']

ipv4_servers = true
ipv6_servers = false

dnscrypt_servers = true
doh_servers = false
odoh_servers = false

force_tcp = false
http3 = false

require_nolog = true
require_nofilter = true

# B4X owns causal selection; no hidden pool
lb_strategy = 'first'
lb_estimator = false

# Production cache policy is generation-bound
cache = true
cache_size = 1024

# Privacy defaults
# query_log.file intentionally unset
# edns_client_subnet intentionally unset

cert_refresh_concurrency = 1
ignore_system_dns = true
```

Actual supported keys MUST be validated against pinned backend version. Config generator must reject unknown/deprecated keys.

# Appendix E. Agent implementation prohibitions

Coding agent MUST NOT:
- vendor/run DPYProxy Python process;
- claim dnscrypt-proxy supports DoT or DoQ;
- create second DNS optimizer/service source of truth;
- let dnscrypt-proxy randomly choose hidden servers in causal mode;
- trust PID/listener as readiness;
- disable TLS certificate validation;
- implement literal last-response-wins;
- promote from one successful query;
- skip A/AAAA/CNAME/NXDOMAIN/SERVFAIL controls;
- reuse cached diagnostic answers as fresh proof;
- reuse profile across WAN/generation without revalidation;
- publish raw qnames/IPs in metrics;
- download arbitrary binaries/catalogs at runtime;
- expose managed listener to LAN by default;
- mutate production DNS outside TransactionalRuntime;
- claim production PASS without real Keenetic/Android evidence.

# Appendix F. Definition of Done

```text
[ ] owner accepts source correction for DoT/DoQ ownership
[ ] adaptive DNS setting implemented and default-safe
[ ] canonical DNSPathID and DNSPathProfile generated schemas
[ ] structured parser coverage complete
[ ] system/UDP/TCP providers production-reachable
[ ] TCP segmentation has on-wire proof or honest blocked state
[ ] native DoT/DoH/DoH3/DoQ capability states explicit
[ ] pinned managed dnscrypt backend supervisor
[ ] DNSCrypt/PQ/Anonymized/DoH3/ODoH provider identities
[ ] signed catalog and bootstrap policy
[ ] last-response observer never selects by order alone
[ ] quick/deep differential matrix
[ ] correctness-first deterministic scoring
[ ] diverse primary/fallback profile
[ ] DDI freshness/revalidation
[ ] existing Discovery consumes DNS prior/candidates
[ ] transactional prepare/canary/promote/rollback
[ ] cache generation isolation
[ ] Monitoring failover/recovery/cooldown
[ ] Android source-scoped canary
[ ] metrics/API/report/internal parity
[ ] hard-gate producer/consumer chains
[ ] mutation/meta-suite
[ ] controlled FaultLab evidence
[ ] real Keenetic/Android evidence or BLOCKED_BY_TARGET
[ ] full build/vet/test/race/fuzz-smoke green
[ ] stage commits pushed and worktree clean
```

# Appendix G. Pinned references

## G.1. DPYProxy

```text
repository: UPB-SysSec/DPYProxy
commit: 28cb05985672275ea96d4083c403739894820375
license: Apache-2.0
usage: algorithm/reference audit only; no Python runtime dependency
```

## G.2. dnscrypt-proxy

```text
repository: DNSCrypt/dnscrypt-proxy
commit: c3ba78fac8a37fd05c1a4faba77300a9dc03a9dd
license: ISC
usage: optional pinned managed encrypted DNS backend
```

## G.3. Current B4X integration points

```text
B4_FORK_ARCHITECTURE_v2.4.md Part VI DNS/QUIC correlation
src/detector/abd_dns.go
src/detector/abd_graph.go
src/detector/abd_profile.go
src/detector/abd_ddi.go
src/discovery/*
src/transport/*
src/runtimecontrol/*
src/monitor/*
src/http/handler/*
src/validation/*
src/fieldtest/*
specs/registries/hard_gates.yaml
```

---

# Итог

Этот addendum превращает существующую DNS-диагностику B4X в автономный, но ограниченный и доказательный DNS path control plane:
```text
Monitoring
→ DNS differential Detector
→ DNSPathProfile
→ existing Discovery
→ DNSPathManager
→ Android canary
→ transactional primary/fallback promotion
→ continuous health, failover, recovery and rollback
```

DPYProxy используется как источник идеи автоматического перебора resolver × transport, но не как Python runtime. `dnscrypt-proxy` используется как optional managed backend для DNSCrypt/PQDNSCrypt, Anonymized DNSCrypt, DoH/DoH3 и ODoH. Native B4X providers отвечают за system UDP/TCP, TCP segmentation, DoT, DoH, DoH3 и DoQ. Политика, correctness, profile, failover и promotion остаются у существующей архитектуры B4X.
