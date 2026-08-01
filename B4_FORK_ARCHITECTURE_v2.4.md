# B4X Architecture v2.4 — consolidated post-v2.3 canonical reference design

**Статус:** единый нормативный reference design B4X  
**Архитектурная редакция:** `2.4`  
**Classifier foundation:** B4 Flow Classifier `v2.3`  
**Базовая версия B4:** `1.73.0`  
**Базовый commit:** `7160ee8f066bbbed1c713b4d0114db4e8acbc882`  
**Дата редакции:** 2026-07-30  
**Основная платформа:** Keenetic/Entware, Android и другие LAN-клиенты  
**Основной продуктовый контур:** service-scoped DPI diagnosis, packet actions, alternative transports, monitoring, canary, promote и rollback

Эта редакция сохраняет classifier/action foundation v2.3 и включает архитектурные изменения из следующих нормативных документов:

- `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md`;
- `B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM.md`;
- `B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md`;
- `B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md`;
- `B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md`;
- `B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md`;
- `B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md`;
- `B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md`;
- `B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md`.

Нормативный приоритет:

1. этот файл определяет единую целевую архитектуру, ownership boundaries и системные инварианты;
2. `B4_FORK_PATCH_PLAN.md` v2.3 остаётся обязательной последовательностью реализации classifier foundation;
3. перечисленные addenda остаются детальными implementation/validation specifications для собственных stages и hard gates;
4. при расхождении архитектурных формулировок с прежней редакцией `B4_FORK_ARCHITECTURE.md` источником истины является эта редакция;
5. старые addenda и планы до закреплённых версий считаются историческими.

Архитектура не превращает все подсистемы в один монолит. Она закрепляет направленный control/data flow:

```text
visibility and identity
→ passive observation
→ authoritative diagnosis
→ bounded candidate search
→ scoped authorization
→ canary/path proof
→ promote or rollback
```

---

## 0. Нормативные термины

В документе используются следующие значения:

- **MUST** — обязательный инвариант production-реализации;
- **SHOULD** — требование, от которого допустимо отступить только с документированным обоснованием;
- **MAY** — опциональное расширение;
- **Core Fix** — минимальный набор изменений, решающий обнаруженные дефекты классификации и TCP lifecycle;
- **Productization** — Discovery, canary, transactional apply, автоматический выбор и диагностика;
- **Strategy Catalog** — опциональные техники обхода после завершения Core Fix;
- **CaptureCandidate** — предварительная принадлежность flow к service/set, достаточная для наблюдения и удержания, но не для destructive action;
- **ActionAuthorization** — generation-bound разрешение выполнить packet action в точном client/service/component/flow scope;
- **MonitorObservation** — пассивный или provisional факт о реальном runtime, который сам по себе не является диагнозом;
- **MonitorAssessment** — temporal health state и решение о необходимости bounded диагностики;
- **BlockingProfile** — immutable authoritative результат ABD с hypotheses, exclusions, confidence, scope и expiry;
- **TransportBinding** — ограниченная привязка target scope к generic transport capability;
- **RecoveryLease** — временное generation-bound разрешение на scoped recovery с rollback target;
- **Service Profile** — декларативный control-plane manifest, который компилируется в обычные B4 objects и не владеет runtime capability lifecycle.

---

# Часть I. Постановка задачи

## 1. Наблюдения из реальных Android-трассировок

Архитектура основана на трассировках официального YouTube и ReVanced в реальной LAN, а не на одном `curl`-запросе.

Наблюдались:

- отдельные B4-сеты для YouTube API, UI и `googlevideo.com`;
- несколько Android-устройств в одной сети;
- DoH и обычный DNS;
- QUIC с последующим TCP fallback;
- Android ClientHello размером примерно `1.7–1.8 KiB`;
- ClientHello, разделённый между TCP-сегментами примерно как `1396 + остаток`;
- ECH ClientHello без доступного внутреннего SNI;
- серии повторных SYN/ClientHello с backoff;
- позднее переключение приложения на другой flow или CDN, после чего UI или видео начинали работать;
- случаи, когда стратегия успешно применялась к уже классифицированному flow, но первый flow до этого долго оставался неклассифицированным.

Типовая проблемная цепочка:

```text
DNS отвечает быстро
→ Android открывает первый TCP/UDP flow
→ clear SNI отсутствует из-за split ClientHello или ECH
→ B4 не связывает DNS-ответ с первым flow конкретного клиента
→ нужный API/UI/VIDEO set не выбран
→ DPI-стратегия не применяется либо применяется слишком поздно
→ Cronet ждёт retransmission/backoff
→ создаётся новый flow или выбирается другой CDN IP
→ новый flow случайно получает clear SNI или уже learned IP
→ интерфейс/видео начинает работать
```

Следствие:

> Перестановка `pastseq`, `timestamp`, `duplicate`, задержек и fake-пакетов не исправляет системно дефект, если сбой произошёл до выбора сета.

## 2. Подтверждённые архитектурные ограничения B4

### 2.1. Packet-local TLS parsing

Текущий TLS parser получает payload одного NFQUEUE-пакета. Полной sequence-aware сборки ClientHello нет.

### 2.2. Недостаточная DNS→first-flow корреляция

DNS path знает клиента, hostname, matched set и A/AAAA, но не создаёт надёжное краткоживущее source-scoped доказательство для первого TCP/UDP flow.

### 2.3. Глобальный learned-IP

Модель `destination IP → один hostname/set` недостаточна для shared Google/CDN IP и создаёт риск cross-client contamination.

### 2.4. ECH скрывает внутренний SNI

ECH нельзя пассивно расшифровать без server-side key. Нужно не «ломать ECH», а классифицировать flow по другим свежим доказательствам.

### 2.5. Неявный путь чистого SYN

Для fake SNI/fragmentation matched packet может попасть в generic drop/reinject path даже без explicit SYN technique. Это требует жёсткого инварианта clean SYN.

### 2.6. Недостаточно формализован kernel capture path

TCP FSM и reassembly бесполезны, если userspace не видит:

- второй сегмент ClientHello;
- SYN-ACK/ServerHello progress;
- FIN/RST;
- либо повторно получает собственные injected packets.

### 2.7. Discovery не отделяет причину от симптома

Один TLS connect/HTTP status не различает:

- DNS/CDN variation;
- reset/drop;
- ClientHello-size sensitivity;
- TLS 1.2/1.3 difference;
- IPv4/IPv6 difference;
- body truncation;
- throughput clamp;
- classifier failure.

## 3. Цели

Форк MUST:

1. детерминированно классифицировать первый YouTube flow конкретного клиента;
2. собирать split TCP ClientHello в ограниченной памяти;
3. работать при ECH через source-scoped DNS/QUIC evidence;
4. никогда не прогонять чистый SYN через TLS action executor без explicit SYN technique;
5. отделять классификацию от packet mutation;
6. применять action один раз к логическому first flight, а не к каждому retransmission;
7. видеть обе стороны TCP lifecycle на Keenetic;
8. иметь fail-open поведение при нехватке данных/ресурсов;
9. поддерживать отдельные стратегии для API, UI и VIDEO sets;
10. уметь воспроизводимо доказать, почему кандидат работает или не работает на реальном Android-клиенте;
11. поддерживать transactional hot apply, canary, promote и rollback;
12. сохранять совместимость существующих конфигов B4, пока новые режимы не включены;
13. исключать cross-service и cross-component actions на shared CDN/IP infrastructure;
14. сохранять корректность classifier/action path при GSO/GRO и поддерживать conditional normalization только по требованию `ActionPlan`;
15. использовать Keenetic PPE per-flow exclusion и bidirectional visibility gate вместо безусловного глобального отключения offload;
16. выявлять silent path failures по unique useful progress, suppressors и differential proof, а не по одному timeout;
17. поддерживать continuous demand-driven monitoring реального клиентского трафика без прямого production action;
18. строить evidence-bearing `BlockingProfile` через bounded active ABD probes и stage-aware reference observers;
19. передавать Detector hints в Discovery только через freshness-aware DDI search priors;
20. предоставлять встроенный base WARP/MASQUE transport с target-scoped routing, causal trace и rollback;
21. поддерживать experimental nested WARP/`НЕ РФ` только через explicit dependency graph и geo quorum gates;
22. компилировать Service Profiles в обычные packet/config/transport objects без service-specific веток в runtime core;
23. предлагать WARP при подтверждённой IP/SYN/CIDR блокировке только как candidate to test;
24. сохранить transparent Telegram bridge при delayed first data, bounded pending sessions и prefix-preserving fallback;
25. обеспечивать end-to-end causal proof от Android/client flow до action/transport/path/app milestone;
26. выпускать production capability только после subsystem-specific Field Test и Implementation Validation verdicts.

## 4. Не-цели

В Core Fix не входят:

- расшифровка `ClientHelloInner` ECH;
- глобальный MITM TLS;
- безусловный прокси всего Google/YouTube;
- широкие статические Google CIDR как замена классификатору;
- автоматическое применение агрессивной техники после одной удачной пробы;
- прямой перенос исходников референсных проектов без проверки лицензии;
- реализация всех zapret2/Flowseal техник до готовности action idempotency;
- признание monitoring recurrence или одного Watchdog HTTP failure доказанной блокировкой;
- destination-global route, failure, escalation, RST или transport state;
- автоматическое включение WARP по одному IP/timeout без authoritative ABD и scoped canary;
- использование router-origin probe как замены forwarded Android/client proof;
- перенос capability lifecycle в Service Profile pack;
- recursive transport fallback, direct leakage control traffic и бесконечная route rotation;
- сохранение legacy Watchdog chain `failure → Discovery → direct config mutation` в production-safe mode.

---

# Часть II. Системные инварианты

## 5. Главные инварианты

### 5.1. Classification before action

```text
packet/flow evidence
→ ClassificationDecision
→ ActionPlan
→ executor
```

Ни fake SNI, ни split, ни duplicate, ни disorder не запускаются без решения classifier.

### 5.2. Clean SYN

```text
TCP SYN
+ payload length = 0
+ explicit SynFake/TCPMD5/SYN-technique отсутствует
→ NF_ACCEPT
```

Обычный SYN нельзя drop/reinject только потому, что set использует fake SNI или fragmentation для будущего ClientHello.

### 5.3. Fail-open

При timeout, budget exhaustion, malformed stream, ambiguous evidence ниже порога или internal error:

```text
release held packets unchanged
clear temporary state
record reason
continue direct path
```

### 5.4. Source scope

DNS/QUIC evidence по умолчанию MUST включать identity клиента. Глобальная запись допустима только как low-confidence compatibility fallback.

### 5.5. Logical first-flight idempotency

Один логический ClientHello получает один `ActionToken`. Retransmission тех же stream bytes не создаёт новую fake/split sequence.

### 5.6. Config generation safety

Flow и evidence не должны удерживать долгоживущие указатели на mutable config. Решение ссылается на immutable `SetID`, `StrategyID`, snapshot/generation.

### 5.7. Bounded resources

Все stores и buffers имеют:

- memory limits;
- per-client limits;
- per-flow limits;
- TTL/timeouts;
- deterministic eviction;
- metrics;
- fail-open.

### 5.8. Provenance for generated packets

Каждый injected/replayed/modified packet MUST иметь processed provenance mark, который kernel rules и userspace распознают и не ставят повторно в B4 queue.


### 5.9. CaptureCandidate не является ActionAuthorization

```text
IP/DNS/port/static match
→ CaptureCandidate
→ collect/hold/observe

positive current domain evidence
+ effective per-set policy
+ exact scope
→ ActionAuthorization
```

Destination IP, CIDR, legacy learned-IP или port-only match не разрешают destructive packet/QUIC/routing action на shared infrastructure.

### 5.10. Полный service scope

Failure, escalation, RST, blocked cache, route binding, recovery lease и transport binding MUST включать минимум:

```text
ClientKey
+ ServiceProfileID/SetID
+ ComponentID или TargetRole
+ destination/protocol identity
+ NetworkContextID
+ ConfigGeneration
```

### 5.11. Observation не равна diagnosis и action

```text
MonitorObservation
≠ MonitorAssessment
≠ BlockingProfile
≠ ActionAuthorization
≠ TransportAuthorization
```

Recurrence повышает temporal persistence, но не заменяет независимые evidence families.

### 5.12. Visibility before inference

Capture/PPE/GSO/queue/source heartbeat state является обязательным suppressor input. При incomplete bidirectional visibility:

```text
hold/replay, auto-diagnose, auto-canary, recovery and promotion
→ blocked or downgraded
```

### 5.13. Useful progress before silent recovery

ACK-only, duplicate bytes, retransmission и один SYN-ACK не считаются достаточным application progress. Silent failure inference опирается на unique ranges, protocol milestones, fresh success suppressors и differential proof.

### 5.14. Exact client-resolution binding

Active probes MUST сохранять связь с DNS/CNAME/A/AAAA answer, который фактически видел клиент. Independent re-resolution выполняется отдельным experiment и не подменяет client-observed endpoint.

### 5.15. Transport path proof

Transport success без current route/binding/path proof не разрешает promotion. Для forwarded flow требуется causal chain:

```text
ClientKey/TestSession
→ ServiceProfile/Component
→ BindingID/RouteTokenID
→ route/rule/mark/interface counters
→ transport session generation
→ application milestone
```

### 5.16. Capability projection, не ownership

Service Profiles и UI policy могут только ограничивать generic capability и запрашивать его. Они не владеют packet executor, WARP process/TUN/routes, monitoring temporal state, ABD evidence graph или recovery lease lifecycle.

### 5.17. No recursive fallback

Transport/recovery graph MUST быть acyclic и bounded. WARP не может выбрать себя как fallback; nested WARP требует explicit parent/child generations; control path не может незаметно выйти direct.

---

# Часть III. Целевая схема и модули

## 6. Полный pipeline

```text
Infrastructure integrity + capture/PPE/GSO visibility
              │
              ▼
Netfilter/NFQUEUE/TUN capture envelope
              │
              ▼
Packet parser + direction + ClientKey/FlowKey
              │
              ▼
DNS/SNI/QUIC correlation + ClientResolutionSnapshot
              │
              ▼
TCP/UDP lifecycle + unique useful progress + protocol milestones
              │
              ├──────────────────────────────────────────────┐
              ▼                                              ▼
CaptureCandidate / classifier evidence                MonitorObservationBus
              │                                              │
              ▼                                              ▼
Cross-service policy + confidence + phase             MonitorSubject/Assessment
              │                                              │
              ▼                                              ▼
ActionAuthorization                             bounded quick/deep ABD request
              │                                              │
              ▼                                              ▼
ActionPlan + representation requirements          EvidenceGraph/BlockingProfile
              │                                              │
              ▼                                              ▼
Idempotent packet executor                    DDI freshness/search-prior compiler
              │                                              │
              └───────────────┬──────────────────────────────┘
                              ▼
                 Discovery candidate sandbox
          packet strategy / DNS / SOCKS / TUN / base WARP
                              │
                              ▼
           scoped Android/forwarded-client canary
                              │
                              ▼
    causal path proof + controls + promote/rollback/lease
                              │
                              ▼
        Monitoring recovery observation + telemetry
```

Запрещённые shortcut paths:

```text
IP candidate → destructive action
monitor failure → Discovery/config mutation
BlockingProfile → direct production strategy
profile manifest → capability lifecycle mutation
transport connect success → promotion without path proof
```

## 7. Пакетная структура

Рекомендуемая направленная структура:

```text
src/capture/
  envelope.go
  marks.go
  readiness.go
  gso_capability.go
  gso_normalizer.go
  offload_check.go
  ppe/

src/classifier/
  identity.go
  phase.go
  evidence.go
  policy.go
  authorization.go
  tcp_fsm.go
  tcp_reassembly.go
  tls_metadata.go

src/action/
  planner.go
  representation.go
  token.go
  executor.go
  replay.go
  packet_builder.go
  budgets.go

src/progress/
  unique_ranges.go
  milestones.go
  visibility_gate.go
  suppressors.go

src/monitor/
  observation_bus.go
  subjects.go
  assessments.go
  temporal.go
  resolution_store.go
  trigger_planner.go
  persistence.go
  watchdog_adapter.go

src/detector/
  contracts.go
  target_plan.go
  probes/
  observers/
  evidence_graph.go
  blocking_profile.go
  monitor_adapter.go

src/discovery/
  sandbox.go
  catalog.go
  guided_prior.go
  probes.go
  scorer.go
  canary.go
  promote.go
  rollback.go

src/transport/
  binding.go
  health.go
  warp/
  socks/
  tun/

src/recovery/
  planner.go
  leases.go
  rollback_monitor.go

src/serviceprofile/
  schema.go
  compiler.go
  ownership.go
  recommendation.go
  packs/

src/observability/
  metrics.go
  events.go
  causal_trace.go
  issue_bundle.go
```

Фактические package names MAY отличаться, но зависимости MUST сохранять направление:

```text
capture/progress/classifier
        ↓
authorization/action

monitor → detector → DDI/discovery

serviceprofile → public compiler/capability interfaces

transport/recovery → routing/action control-plane interfaces
```

`classifier`, `monitor` и `detector` не импортируют mutable `nfq` internals. `ServiceProfile` не импортируется packet hot path как service-specific policy engine.

## 8. Service ownership

| Service | Владеет | Не владеет |
|---|---|---|
| `InfrastructureIntegrityService` | rules, interfaces, NDM/PPE capability, visibility heartbeat | blocking diagnosis |
| `ClassifierService` | identity, evidence, phase, capture candidate, action authorization | packet mutation |
| `ProgressService` | unique ranges, milestones, suppressors, visibility snapshots | recovery authorization |
| `ActionService` | plans, tokens, representation transforms, packet execution | target discovery |
| `MonitorService` | passive observations, subjects, temporal health, diagnostic triggers | BlockingProfile, actions, config mutation |
| `DetectorService` | active probes, controls, observers, EvidenceGraph, BlockingProfile | continuous monitoring, production apply |
| `DiscoveryService` | sandbox, candidate catalog, scoring, full bounded fallback | detector truth, direct apply |
| `TransportService` | WARP/SOCKS/TUN lifecycle, bindings, route/path proof | service policy ownership |
| `RecoveryService` | leases, bounded recovery ordering, rollback monitoring | diagnosis creation |
| `ServiceProfileCompiler` | declarative manifests, ownership metadata, policy upper bounds, recommendations | runtime capability lifecycle |
| `TransactionalRuntime` | generation apply, canary, promotion, rollback, last-good | evidence interpretation |

Каждый side effect имеет одного владельца и generation-bound token. Никакая подсистема не должна одновременно быть источником evidence и единственным авторизатором собственного corrective action.

---

# Часть IV. Identity, evidence и decision

## 9. Идентичность клиента

```go
type ClientKey struct {
    L3Family  uint8
    SourceIP  netip.Addr
    SourceMAC [6]byte
    IfIndex   int
    VLAN      uint16
}
```

Правила:

- MAC является дополнительным атрибутом, а не единственным ключом;
- если MAC временно неизвестен, `SourceIP + ingress context` достаточно для временной записи;
- после ARP resolution запись MAY быть объединена с MAC-aware identity;
- guest/LAN/VLAN не должны смешиваться;
- смена DHCP lease не должна бесконечно сохранять старые hints.

Trace MUST явно показывать:

```text
client_identity=full|ip-only|unresolved
source_mac_lookup=hit|miss|late
```

## 10. ClassificationPhase

```go
type ClassificationPhase uint8

const (
    PhaseInspecting ClassificationPhase = iota
    PhasePartial
    PhaseAmbiguous
    PhaseResolved
    PhaseFinal
)
```

Смысл:

- `Inspecting` — данных пока недостаточно;
- `Partial` — протокол распознан, есть неполный ClientHello или слабое evidence;
- `Ambiguous` — есть несколько допустимых set/domain candidates;
- `Resolved` — выбран кандидат, решение может быть подтверждено новым evidence;
- `Final` — policy больше не должна менять set для данного flow.

Отсутствие SNI в первом packet никогда не является автоматически `FinalUnknown`.

## 11. Evidence model

```go
type EvidenceSource uint8

const (
    EvidencePacketSNI EvidenceSource = iota
    EvidenceReassembledSNI
    EvidenceQUICSNI
    EvidenceDNSAnswer
    EvidenceDNSHTTPS
    EvidenceStaticHost
    EvidenceStaticIP
    EvidenceLegacyLearnedIP
    EvidencePortProtocol
)
```

```go
type Evidence struct {
    Source         EvidenceSource
    Client         ClientKey
    DestinationIP  netip.Addr
    Domain         string
    SetID          string
    Confidence     uint8
    DomainEvidence bool
    ECHRelated     bool
    CreatedAt      time.Time
    ExpiresAt      time.Time
    ConfigGen      uint64
    Reason         string
}
```

```go
type ClassificationDecision struct {
    Phase        ClassificationPhase
    Selected     *Evidence
    Candidates   []Evidence
    Reason       string
    Confidence   uint8
    ECHPresent   bool
    TLSMetadata  TLSMetadata
    FlowKey      FlowKey
    ConfigGen    uint64
    Final        bool
}
```

Decision MUST сохранять все кандидаты для trace. Один `Source` без evidence set недостаточен.

## 12. Базовый порядок evidence

Рекомендуемый порядок при одинаковой валидности:

```text
reassembled clear SNI
packet-local complete clear SNI
source-scoped QUIC SNI
source-scoped fresh DNS answer
static hostname rule
source-scoped learned observation
static IP/CIDR
legacy global learned IP
port/protocol fallback
```

Но policy учитывает не только источник, а:

- freshness;
- client scope;
- set consistency;
- number of candidates;
- ECH state;
- config generation;
- negative evidence;
- explicit source-device restrictions.

## 13. Confidence

Примерная шкала:

```text
95–100  complete/reassembled clear SNI with set match
85–94   fresh source-scoped QUIC SNI
75–89   fresh source-scoped DNS answer with one matching set
55–74   multiple DNS candidates narrowed by protocol/port
35–54   static shared IP/CIDR or legacy learned IP
0–34    unknown/weak fallback
```

Порог destructive action настраивается отдельно от порога non-destructive classification.

```go
type ConfidenceThresholds struct {
    Classify      uint8
    Mutate        uint8
    Destructive   uint8
    ProxyFallback uint8
}
```

## 14. Ambiguity policy

Если один shared IP связан с несколькими hostname/set candidates:

1. не перезаписывать запись одним последним hostname;
2. хранить bounded candidate list;
3. сортировать по source/freshness/client scope;
4. использовать clear/reassembled SNI для разрешения;
5. при сохранении ambiguity не применять destructive strategy ниже порога;
6. MAY использовать scoped generic strategy или route fallback.

---

# Часть V. Source-scoped Host Hint Store

## 15. Ключ и значение

```go
type HintKey struct {
    Client        ClientKey
    DestinationIP netip.Addr
    L4Proto       uint8
}
```

```go
type HostHint struct {
    Candidates []HintCandidate
    CreatedAt  time.Time
    ExpiresAt  time.Time
    LastUsedAt time.Time
}
```

```go
type HintCandidate struct {
    Domain     string
    SetID      string
    Source     EvidenceSource
    Confidence uint8
    ExpiresAt  time.Time
    ConfigGen  uint64
}
```

## 16. TTL semantics

TTL MUST быть абсолютным, а не бесконечно скользящим.

```text
ExpiresAt = min(DNS TTL, configured cap, source cap)
```

Lookup MAY обновлять `LastUsedAt` для LRU, но не продлевать DNS validity.

Рекомендуемые caps:

- DNS A/AAAA: `min(record TTL, 5 min default cap)`;
- QUIC SNI: `30–120 s`;
- reassembled SNI observation: `1–5 min` для того же клиента;
- legacy learned IP: короткий low-confidence cap.

## 17. Bounded storage

Лимиты:

- global entries;
- entries per client;
- candidates per destination;
- bytes per client;
- expiry heap/GC interval.

Eviction:

```text
expired
→ lowest confidence
→ oldest unused
→ oldest created
```

## 18. Generation safety

Hint хранит `SetID` и `ConfigGen`, но не `*SetConfig`.

При lookup:

```text
set still exists?
source device still allowed?
protocol/port still match?
config generation compatible?
```

Старый hint либо revalidated, либо удаляется.

---

# Часть VI. DNS и QUIC correlation

## 19. Structured DNS parser

Поддержать:

- A;
- AAAA;
- CNAME chains;
- HTTPS/SVCB;
- NXDOMAIN;
- SERVFAIL;
- truncated response;
- multiple answers;
- TTL;
- DNS transaction context;
- DoH system-forward path.

```go
type DNSObservation struct {
    Client       ClientKey
    QueryName    string
    Canonical    string
    Answers      []DNSAddress
    HTTPSRecords []HTTPSRecord
    RCode        int
    ResolverID   string
    Timestamp    time.Time
}
```

## 20. DNS → first-flow integration

После DNS response:

```text
query hostname
→ resolve matching B4 set(s) for this client
→ for every A/AAAA create source-scoped hint
→ attach TTL and config generation
→ make hint available before first TCP/UDP flow
```

Это MUST работать и для:

- B4 DoH redirect;
- system DNS, если packet path виден;
- CNAME final answers;
- несколько A/AAAA.

Пример ключа:

```text
(client 192.168.1.152 / MAC / LAN, 74.125.108.231, TCP)
→ rr2---...googlevideo.com
→ youtube-video
→ TTL 60s
```

## 21. QUIC → TCP handoff

Если B4 видит QUIC Initial:

```text
parse SNI
→ create source-scoped UDP evidence
→ mirror short-lived host hint for TCP destination
→ apply configured QUIC allow/reject/mutate policy
```

Даже если QUIC отклоняется, распознанный hostname должен быть доступен последующему TCP fallback.

Ключ MUST включать клиента. Глобальный QUIC learned IP недостаточен.

## 22. ECH-related DNS metadata

HTTPS/SVCB MAY содержать ECHConfig. Это не раскрывает inner SNI, но усиливает metadata:

```text
DNS query hostname known
+ HTTPS/SVCB indicates ECH capability
+ outer ClientHello has ECH
→ DNS evidence remains valid and expected
```

Не использовать ECHConfig как доказательство другого hostname.

## 23. Negative DNS evidence

NXDOMAIN/SERVFAIL не создаёт positive host hint. Оно создаёт diagnostic event и MAY участвовать в Discovery verdict.

Resolver failover не должен оставлять stale positive mapping от неуспешного transaction.

---

# Часть VII. DomainOnly v2

## 24. Семантика

Старый boolean недостаточен. Нужны режимы:

```go
type DomainOnlyMode string

const (
    DomainStrict       DomainOnlyMode = "strict"
    DomainScopedHints  DomainOnlyMode = "scoped-hints"
    DomainLegacy       DomainOnlyMode = "legacy"
    DomainDisabled     DomainOnlyMode = "disabled"
)
```

### `strict`

Только clear/reassembled SNI или explicit hostname rule.

### `scoped-hints`

Разрешает свежий source-scoped DNS/QUIC evidence как domain evidence. Это рекомендуемый режим для ECH/Android.

### `legacy`

Сохраняет прежнюю семантику для совместимости.

### `disabled`

Разрешает static IP/CIDR и другие configured fallbacks.

## 25. Domain evidence

`DomainOnly` проверяет не наличие строки hostname, а `Evidence.DomainEvidence` и confidence.

Глобальный learned IP не становится domain evidence автоматически.

---

# Часть VIII. Kernel Capture Envelope

## 26. Назначение

Capture envelope определяет, какие пакеты одного flow гарантированно проходят через userspace B4.

```go
type CaptureEnvelope struct {
    OutgoingPacketLimit uint32
    IncomingPacketLimit uint32
    AlwaysQueueSynAck   bool
    AlwaysQueueFin      bool
    AlwaysQueueRst      bool
    AlwaysQueueQuicInit bool
    ProcessedMark       uint32
}
```

## 27. Обязательный контракт

Kernel rules MUST:

- ставить в queue первые `N` исходящих TCP/UDP packets;
- ставить в queue первые `N` ответных packets;
- отдельно захватывать SYN-ACK;
- отдельно захватывать FIN/RST;
- исключать `ProcessedMark`;
- использовать queue bypass в согласованном fail-open режиме;
- учитывать IPv4 и IPv6;
- не смешивать production и Discovery queues.

`N` должен покрывать ожидаемый ClientHello и server progress. Fixed `15` MAY быть initial default, но не hard-coded semantic guarantee.

## 28. Processed provenance mark

Все пакеты, созданные B4:

- fake;
- replay;
- split segment;
- disorder segment;
- injected RST;
- QUIC reject response;

получают mark до raw send.

При повторном входе mark вызывает immediate bypass.

## 29. Queue readiness

Runtime считается готовым не после fixed sleep и не по строке лога, а после проверки:

```text
/proc/net/netfilter/nfnetlink_queue
queue number + owner process
```

Это применяется к production hot apply и Discovery workers.

## 30. Flow offload self-check

На Keenetic hardware/software offload может обходить netfilter или делать counters неполными.

B4 MUST диагностировать:

```text
capture_envelope_active
incoming_progress_visible
processed_mark_verified
flow_offload_bypass_suspected
queue_drop
user_drop
```

Self-check не обязан автоматически отключать ускорение, но MUST объяснять, что classifier не видит нужные packets.

---

# Часть IX. TCP lifecycle и reassembly

## 31. Flow key

```go
type FlowKey struct {
    Client ClientKey
    SrcIP  netip.Addr
    DstIP  netip.Addr
    SrcPort uint16
    DstPort uint16
    Proto   uint8
}
```

Direction normalization должна быть однозначной.

## 32. TCP FSM

```go
type TCPFlowPhase uint8

const (
    TCPNew TCPFlowPhase = iota
    TCPSynSeen
    TCPEstablished
    TCPClientHelloPartial
    TCPClientHelloComplete
    TCPActionPlanned
    TCPActionApplied
    TCPServerProgress
    TCPClosed
)
```

Дополнительные terminal reasons:

```text
timeout
rst
fin
budget
malformed
config-generation-change
```

## 33. FSM правила

- clean SYN не входит в TLS executor;
- SYN-ACK переводит flow в established/progress state;
- payload до established MAY приниматься для tolerant TCP Fast Open handling, но отдельно маркируется;
- ClientHello partial не считается unknown final;
- action применяется только после допустимого state;
- incoming TLS/HTTP progress прекращает first-flight mutation;
- FIN/RST немедленно освобождает held packets и state;
- generation change не должен оставлять old action token активным.

## 34. TCP reassembly

```go
type TCPReassemblyState struct {
    BaseSeq      uint32
    Ranges       RangeSet
    Bytes        []byte
    DeclaredNeed int
    FirstSeen    time.Time
    LastSeen     time.Time
    HeldPackets  []HeldPacket
    OverlapState OverlapState
}
```

Поддержать:

- ClientHello в одном сегменте;
- split между 2+ сегментами;
- out-of-order;
- exact retransmission;
- duplicate ranges;
- benign overlap;
- conflicting overlap;
- multiple TLS records;
- coalesced trailing records;
- TCP sequence wrap-safe comparison;
- ECH metadata;
- FIN/RST/timeout abort.

## 35. Exact declared length

После получения TLS record header parser вычисляет exact expected length.

```text
record header 5 bytes
+ declared record length
```

Затем проверяет handshake header и nested ClientHello length.

Нельзя считать complete по «нашли строку SNI» или «получили два packets».

## 36. Limits

Начальные ориентиры:

```text
max bytes per flow:       16 KiB
max held packets:         8–16
max reassembly time:      250–750 ms configurable
max flows global:         bounded by router class
max flows per client:     bounded
max conflicting overlaps: 0 before fail-open
```

PQ/large ClientHello MAY потребовать configurable bound выше 16 KiB, но default должен быть безопасным для Keenetic.

## 37. Reassembly modes

```go
type ReassemblyMode string

const (
    ReassemblyOff     ReassemblyMode = "off"
    ReassemblyObserve ReassemblyMode = "observe"
    ReassemblyAuto    ReassemblyMode = "auto"
    ReassemblyAlways  ReassemblyMode = "always"
)
```

### `observe`

Собирает metadata, но не hold/replay.

### `auto`

Hold только если первый payload похож на неполный ClientHello и classification без него недостаточна.

### `always`

Только debug/targeted mode; не production default.

## 38. Overlap policy

- exact duplicate — ignored/idempotent;
- identical overlap — accepted;
- conflicting overlap — abort and fail-open;
- trace MUST содержать overlap reason.

Не пытаться «угадывать», какой byte stream увидит endpoint.

---

# Часть X. TLS metadata и ECH-aware policy

## 39. TLSMetadata

```go
type TLSMetadata struct {
    IsClientHello       bool
    Complete            bool
    RecordVersion       uint16
    LegacyVersion       uint16
    SupportedVersions   []uint16
    SNI                 string
    ALPN                []string
    ECHPresent          bool
    ECHOuterName        string
    ClientHelloSize     int
    RecordCount         int
    TrailingBytes       int
    ParseError          string
}
```

Parser возвращает structured metadata, а не только `(host, version)`.

## 40. ECH policy

ECH path:

```text
ECH present
+ clear SNI absent/outer only
→ do not finalize unknown
→ query source-scoped DNS/QUIC hints
→ evaluate ambiguity/confidence
→ resolve set or use configured unknown-flow policy
```

MUST NOT:

- считать outer SNI внутренним YouTube hostname без rule;
- глобально кэшировать shared IP как domain evidence;
- применять hostname-marker strategy, требующую clear SNI, когда его нет.

## 41. Confirmation and contradiction

Если DNS hint выбрал `youtube-video`, а позднее reassembled clear SNI подтверждает его — confidence повышается.

Если clear SNI противоречит hint:

```text
clear SNI wins
stale/conflicting hint demoted or removed
metric conflict_total incremented
```

---

# Часть XI. Hold/replay и action execution

## 42. HeldPacket

```go
type HeldPacket struct {
    PacketID     uint32
    Direction    Direction
    SeqStart     uint32
    SeqEnd       uint32
    PayloadStart uint32
    PayloadEnd   uint32
    RawTemplate  []byte
    ArrivedAt    time.Time
}
```

Holding применяется только в bounded reassembly mode.

## 43. Abort/release paths

Каждый hold path MUST иметь:

- complete → plan/execute/release;
- timeout → release unchanged;
- FIN/RST → release/clear;
- memory pressure → release oldest flow unchanged;
- malformed/conflict → release unchanged;
- runtime shutdown → release or verdict fail-open;
- config generation change → reclassify or release, не применять stale plan.

## 44. Stream-to-packet map

```go
type StreamRange struct {
    Start uint32
    End   uint32
}
```

```go
type PacketSpan struct {
    PacketIndex int
    Stream      StreamRange
    SeqStart    uint32
}
```

Action planner работает в logical stream offsets, executor отображает их на TCP sequence ranges.

## 45. Semantic markers

```go
type LogicalMarker string

const (
    MarkerClientHelloStart LogicalMarker = "clienthello-start"
    MarkerSNIExtensionStart LogicalMarker = "sni-extension-start"
    MarkerHostStart         LogicalMarker = "host-start"
    MarkerSLDMiddle         LogicalMarker = "sld-middle"
    MarkerHostEnd           LogicalMarker = "host-end"
    MarkerClientHelloEnd    LogicalMarker = "clienthello-end"
)
```

```go
type SplitPosition struct {
    Absolute *uint32
    Marker   LogicalMarker
    Delta    int32
}
```

Marker resolver MUST работать только на complete parsed ClientHello. Для ECH/no clear host host-based markers unavailable.

## 46. ActionPlan

```go
type PlannedWrite struct {
    Range        StreamRange
    Kind         WriteKind
    Order        int
    SeqDelta     int32
    Repeat       uint8
    Delay        time.Duration
    Fooling      FoolingConfig
    PayloadRef   string
}
```

```go
type ActionPlan struct {
    Token        ActionToken
    Flow         FlowKey
    StrategyID   string
    Writes       []PlannedWrite
    AcceptOriginal bool
    DropOriginal   bool
    Amplification  float64
    Reason         string
}
```

Planner MUST иметь dry-run output для trace/Discovery.

## 47. Packet builder

Executor строит packet из проверенного template:

- корректирует IP/TCP lengths;
- checksums;
- TCP sequence/ack;
- timestamp/MD5 options только по explicit technique;
- marks packet processed;
- сохраняет endpoint logical byte stream для split/disorder техник;
- не редактирует произвольный retransmission packet in-place без stream map.

## 48. ActionToken

```go
type ActionToken struct {
    FlowHash      uint64
    ClientHelloID uint64
    StrategyID    string
    ConfigGen     uint64
}
```

Правила:

- exact retransmission не повторяет action;
- partial overlap не создаёт второй action;
- новый connection tuple создаёт новый token;
- после `TCPServerProgress` token закрывается;
- rollback invalidates candidate-generation tokens.

## 49. Amplification budget

```go
type ActionBudgets struct {
    MaxWritesPerHello uint16
    MaxFakeBytes      uint32
    MaxAmplification  float64
    MaxDelay          time.Duration
}
```

Fake-mix strategies запрещены до появления этих limits и metrics.

---

# Часть XII. Strategy model

## 50. Разделение transport technique и fake profile

```go
type StrategyDefinition struct {
    ID            string
    Technique     Technique
    Positions     []SplitPosition
    SegmentOrder  SegmentOrder
    FakeProfileID string
    Fooling       FoolingConfig
    Preconditions StrategyPreconditions
    Budgets       ActionBudgets
}
```

```go
type FakePayloadProfile struct {
    ID                 string
    Template           string
    ReplaceSNI         string
    RandomizeSessionID bool
    RandomizeSNI       bool
    PaddingMode        string
    SeedPolicy         string
    Source             string
    Provenance         string
    SHA256             string
}
```

## 51. Core techniques

Core Fix должен поддержать существующие B4 техники через новый planner/executor без изменения их внешней семантики.

Опциональные после Core Fix:

- marker-based `multisplit`;
- `multidisorder`;
- `hostfakesplit`;
- `fakedsplit`;
- `fakeddisorder`;
- explicit TLS record split;
- controlled RST injection;
- additional fake payload profiles.

## 52. Preconditions

Каждая strategy декларирует:

```go
type StrategyPreconditions struct {
    MinConfidence      uint8
    RequiresClearSNI   bool
    RequiresCompleteCH bool
    AllowedTCPPhases   []TCPFlowPhase
    FirstFlightOnly    bool
    ECHAllowed         bool
}
```

Executor не должен самостоятельно угадывать preconditions.

## 53. TLS record split

Это отдельная техника, не TCP segmentation alias.

Она MUST:

- создавать валидные TLS record boundaries;
- сохранять handshake byte stream;
- сохранять trailing/coalesced records;
- корректно пересчитывать record lengths;
- работать через logical plan;
- не применяться к non-ClientHello.

---

# Часть XIII. Real ClientHello Laboratory и fake compiler

## 54. Назначение

Форк должен уметь использовать реальный Android ClientHello как диагностический и кандидатный fake profile, не смешивая capture с production автоматически.

Pipeline:

```text
выбранный LAN-клиент
→ короткий capture TCP/443
→ production-grade reassembly
→ TLS validation
→ metadata/privacy processing
→ immutable captured artifact
→ compile variants
→ isolated Discovery
→ manual/canary promotion
```

## 55. CapturedHelloProfile

```go
type CapturedHelloProfile struct {
    ID             string
    SourceClientID string
    SourceApp      string
    ObservedDomain string
    TLSVersion     uint16
    ALPN           []string
    ECHPresent     bool
    RawSize        int
    CompiledSize   int
    CapturedAt     time.Time
    SHA256         string
    PrivacyState   string
    Provenance     string
}
```

Экспортируемый профиль не содержит raw MAC/IP.

## 56. Capture requirements

- фильтр по выбранному client identity;
- ограниченное окно времени;
- IPv4/IPv6;
- TCP sequence-aware reassembly;
- out-of-order/retransmission handling;
- ECH marker;
- complete TLS validation;
- no automatic telemetry upload;
- explicit user action to save profile.

## 57. Fake Profile Compiler

Режимы:

```text
raw-captured
compact-compatible
fingerprint-preserving
single-packet-safe
multi-packet-fake
```

Compiler MUST:

- не изменять исходный artifact;
- заменять SNI только структурно;
- пересчитывать record/handshake/extension lengths;
- валидировать ALPN/version/extensions;
- оценивать MTU для IPv4/IPv6/TCP options;
- показывать removed/changed extensions;
- сохранять provenance/hash;
- отклонять malformed result.

`multi-packet-fake` доступен только после sequence-aware executor и idempotency.

## 58. Privacy

Captured ClientHello может содержать fingerprinting metadata.

Поэтому:

- raw bytes хранятся локально;
- issue bundle по умолчанию содержит hash, size и redacted metadata;
- экспорт raw payload требует явного действия;
- retention настраивается;
- автоматическая синхронизация запрещена.

---

# Часть XIV. Discovery v2.3

## 59. Цель Discovery

Discovery отвечает не только «какая стратегия открывает URL», а:

> какая минимально агрессивная конфигурация стабильно обслуживает API, UI и video flows конкретного client group, и какой слой был причиной сбоя.

## 60. Isolated Experiment Sandbox

Три обязательных режима:

```text
baseline-none
baseline-production
candidate
```

### `baseline-none`

Flow исключён и из production B4, и из candidate executor.

### `baseline-production`

Тестируется текущая active generation.

### `candidate`

Отдельная queue, source-port range, marks и candidate generation.

Worker owns:

- NFQUEUE number;
- source-port range;
- temporary chains;
- process/runtime instance;
- logs;
- cleanup token.

Readiness проверяется по kernel queue owner. После crash/reboot выполняется leaked sandbox cleanup.

## 61. DiscoveryVariant

```go
type DiscoveryVariant struct {
    StrategyID    string
    FakeProfileID string
    FakeSNI       string
    ResolverID    string
    IPFamily      IPFamilyMode
    TLSProfileID  string
    TargetProfile string
}
```

Полный декартов продукт не запускается без ограничений. Используется adaptive/staged search.

## 62. Target profiles

```text
youtube-api
youtube-ui
youtube-video-cdn
youtube-body
youtube-throughput
youtube-cdn-switch
youtube-cold-start
youtube-resume-after-stall
```

Video probes должны использовать реальные CDN shards/large resources, а не только homepage.

## 63. TLS/ClientHello profiles

```text
tls12-compact
tls13-compact
tls13-standard
tls13-large
tls13-pq-like
ech-outer
android-captured
```

Размерный sweep MAY включать:

```text
512, 768, 1024, 1280, 1400, 1500, 1700, 2000 bytes
```

Он диагностический, не production default.

## 64. ProbeOutcome

```go
type ProbeOutcome struct {
    TCPConnected        bool
    TCPReset            bool
    TimedOut            bool
    TLSResponseType     TLSResponseType
    HTTPStatus          int
    TTFB                time.Duration
    BodyBytes           int64
    FailureOffset       int64
    ThroughputBps       int64
    Retransmissions     int
    FlowRetries         int
    PacketAmplification float64
    CPUTime             time.Duration
    Verdict             DiagnosticVerdict
    EvidenceSummary     []Evidence
}
```

## 65. Layered success model

Stages:

```text
DNS resolved
→ TCP connected
→ TLS response (ServerHello or Alert)
→ HTTP headers
→ body progress
→ body threshold
→ sustained throughput
→ CDN switch/resume
```

TLS Alert доказывает server response, но не полную service success.

## 66. Failure signatures

```go
type TransferFailureSignature string

const (
    FailureNone               TransferFailureSignature = "none"
    FailureDNS                TransferFailureSignature = "dns"
    FailureBeforeTCP          TransferFailureSignature = "before_tcp"
    FailureBeforeTLS          TransferFailureSignature = "before_tls"
    FailureAfterTLSBeforeBody TransferFailureSignature = "after_tls_before_body"
    FailureNear16KiB          TransferFailureSignature = "near_16k"
    FailureMidstreamReset     TransferFailureSignature = "midstream_reset"
    FailureStall              TransferFailureSignature = "stall"
    FailureThroughputClamp    TransferFailureSignature = "throughput_clamp"
)
```

Хранится точный byte offset; `near_16k` — кластер/диапазон, а не жёсткое равенство.

## 67. DiagnosticVerdict

```text
available
dns_failure
ip_block_suspected
dpi_reset
dpi_drop
tls_profile_specific
resolver_specific
ip_family_specific
body_truncated
midstream_reset
throttled
classifier_unresolved
capture_path_incomplete
```

## 68. Shadow probes

Основной дешёвый probe запускается первым. При `RST/drop/timeout` допускается один или несколько bounded shadow probes:

```text
TLS 1.2 compact ↔ TLS 1.3 standard
IPv4 ↔ IPv6
system DNS ↔ selected DoH
standard ↔ large ClientHello
direct ↔ configured proxy fallback
```

Shadow result используется для causal verdict, не автоматически для promotion.

## 69. Adaptive matrix

Рекомендуемый поиск:

```text
1. baseline-none
2. baseline-production
3. cheapest candidate strategy
4. same candidate across API/UI/video
5. on failure vary one dimension at a time
6. only then explore fake profile/SNI/size combinations
7. stop when stable minimum-complexity candidate found
```

## 70. Scoring

```text
service success
+ stability across samples/CDN
+ body/throughput
- startup latency
- retransmissions
- flow retries
- packet amplification
- CPU/memory cost
- collateral scope
- confidence risk
```

Минимально сложная рабочая стратегия выше агрессивной с тем же success rate.


## 70A. Detector-guided Discovery contract

Discovery принимает только validated `DiscoverySearchPrior`, скомпилированный DDI из свежего `BlockingProfile`:

```text
BlockingProfile
→ network/config freshness check
→ bounded fast revalidation when required
→ DiscoverySearchPrior
→ mandatory baseline-none and baseline-production
→ guided candidates
→ full bounded fallback when guided set fails
```

Hints изменяют порядок, budget и необходимые differential probes, но не являются target proof и не могут отключить simpler candidates или controls.

Candidate families включают обычные packet techniques, resolver changes, TCP/QUIC fallback, SOCKS/TUN и base WARP. Каждый transport candidate тестируется только для exact target/client/service/component scope.

## 70B. Transparent Telegram bridge separation

Transparent Telegram/MTProto bridge является отдельным runtime capability, а не Discovery strategy. Его lifecycle MUST поддерживать:

- delayed-first-data/preconnect state;
- soft и hard deadlines;
- bounded global/per-client pending budgets;
- prefix-preserving handoff для уже прочитанных bytes;
- primary WS/DC dial fallback;
- non-recursive direct fallback;
- cleanup goroutines/sockets при reload, timeout и shutdown.

Zero-byte timeout не считается успешно обработанной session и не разрешает silent drop.

---

# Часть XV. Passive Failure Candidate Inbox

## 71. Источники

Failure inbox получает события из:

- conntrack `UNREPLIED`;
- TCP `SYN_SENT`;
- B4 repeated flow retries;
- reassembly timeout;
- ambiguous/low-confidence classification;
- queue drops;
- capture-path self-check;
- application probe failures.

Не использовать conntrack byte counters как основной failure signal при offload.

## 72. Модель

```go
type FailureCandidate struct {
    Client          ClientKey
    DestinationIP   netip.Addr
    DestinationPort uint16
    Protocol        uint8
    ConntrackState  string
    FirstSeen       time.Time
    LastSeen        time.Time
    DNSCandidates   []Evidence
    SetCandidates   []string
    FlowRetries     int
    SuggestedAction string
}
```

## 73. Correlation

```text
failing destination
+ client identity
→ source-scoped DNS/QUIC lookup
→ probable domain/set
→ confidence/reason
```

## 74. Действия и роль в Continuous Monitoring

Failure Inbox является compatibility projection `MonitorAssessment`, а не параллельным source of truth. Из inbox:

- открыть 30s trace;
- начать pcap;
- захватить ClientHello;
- запустить isolated Discovery;
- экспортировать issue bundle;
- временно canary candidate на этом client group.

Никакая destructive action, Discovery run или WARP binding не запускается автоматически только из conntrack failure. После Monitoring cutover legacy Watchdog/Inbox API MUST делегировать `MonitorService`.

---

# Часть XVI. Runtime, canary и rollback

## 75. Transactional apply

```text
parse candidate config
→ schema validation
→ build immutable matcher/runtime
→ allocate queue/marks
→ readiness check
→ canary health checks
→ atomic generation switch
→ drain/retire previous generation
```

При ошибке previous generation остаётся активной.

## 76. Last-good

Персистить:

- config schema version;
- generation hash;
- strategy IDs;
- set IDs;
- validation summary;
- B4 version;
- timestamp;
- canary outcome.

Не персистить live flow/reassembly/hint state как часть config.

## 77. Canary

Scope включает:

- конкретный `ClientKey`/device group;
- `ServiceProfileID`/SetID и `ComponentID`;
- protocol/IP family/target role;
- candidate generation и transport binding;
- процент новых flows;
- bounded duration и minimum samples;
- same-service и unrelated same-client controls;
- explicit stop condition и rollback target.

Для transport candidate обязательны current `BindingID`, `RouteTokenID` и route/path counter deltas. Router-origin success не заменяет Android/forwarded-client milestone.

## 78. Cooldown и anti-flapping

Ключ состояния минимум:

```text
set/route
+ client group
+ protocol
+ candidate generation
```

Не использовать global hostname-only escalation.

## 79. Rollback

Rollback MUST:

- атомарно вернуть last-good generation;
- завершить candidate workers;
- очистить held packets/state;
- invalidates candidate tokens;
- записать reason/outcomes;
- не удалять diagnostic history.

---

# Часть XVII. Confidence-based route fallback

## 80. Роль fallback

TUN/SOCKS — escape path для unresolved/ambiguous flows, а не замена classifier.

```go
type UnknownFlowPolicy string

const (
    UnknownAcceptDirect UnknownFlowPolicy = "direct"
    UnknownUseGeneric   UnknownFlowPolicy = "generic"
    UnknownRouteProxy   UnknownFlowPolicy = "proxy"
)
```

## 81. Требования

- per-set/per-device scope;
- SO_MARK/rule isolation;
- no double processing;
- healthcheck;
- connection pooling;
- last-good route;
- cooldown;
- bounded UDP idle timeout;
- explicit capability matrix;
- clear observability.

Fallback MAY быть реализован после Core Fix/Productization.


## 81A. Transport fallback hierarchy

Рекомендуемый bounded порядок:

```text
direct packet candidate
→ DNS/TCP/QUIC compatible fallback
→ configured SOCKS/TUN
→ base WARP
→ explicit nested/non-RU experimental route
```

Переход разрешён только при fresh evidence, exact scope и current capability health. Recursive fallback запрещён. `НЕ РФ` не является generic block workaround и требует отдельного geo requirement, multi-provider quorum, DNS/IPv6 path proof и fail-closed route gate.

---

# Часть XVIII. Observability и privacy

## 82. Метрики classifier

```text
classifier_decisions_total{phase,source,set}
classifier_evidence_candidates_total{source}
classifier_ambiguous_total{reason}
classifier_confidence_histogram
classifier_hint_hits_total{source}
classifier_hint_expired_total{source}
classifier_hint_conflicts_total{source_a,source_b}

capture_packets_total{direction,reason}
capture_processed_bypass_total
capture_queue_drop_total
capture_user_drop_total
capture_offload_suspected_total

tcp_flow_phase_total{phase}
tcp_clean_syn_pass_total
tcp_syn_injection_total{reason}
tcp_reassembly_started_total
tcp_reassembly_completed_total
tcp_reassembly_aborted_total{reason}
tcp_reassembly_bytes_current
tcp_reassembly_flows_current

tcp_action_planned_total{strategy}
tcp_action_applied_total{strategy}
tcp_action_suppressed_total{reason}
tcp_action_token_reuse_total
tcp_packet_amplification_histogram

ech_clienthello_total
ech_fallback_total{source}

discovery_probe_total{verdict,target_profile}
discovery_failure_offset_histogram
discovery_shadow_probe_total{dimension}
discovery_candidate_promoted_total
discovery_candidate_rollback_total{reason}
```

## 83. Trace schema

Каждый flow trace должен показывать:

```text
client identity quality
flow key/direction
capture reason
TCP FSM transition
reassembly ranges/need/status
TLS metadata including ECH/size
all evidence candidates
selected evidence/confidence
DomainOnly decision
strategy preconditions
ActionPlan dry-run
ActionToken
processed mark
incoming server progress
final outcome/release reason
config generation
```

## 84. Privacy

- публичная telemetry редактирует IP/MAC/domain по policy;
- raw packets/ClientHello локальны;
- issue bundle по умолчанию redacted;
- user-controlled retention;
- no automatic raw capture upload;
- hashes/provenance вместо binary payload, когда этого достаточно.


## 84A. Unified causal trace

Required events используют common envelope:

```text
SchemaVersion, EventID, TraceID, ParentEventID, Sequence
wall time + monotonic time
BootIDHash + ProcessStartID
ConfigGen + RouteGen + SessionGen
Client/flow/service/component/binding/route identifiers
phase/state/reason/result
```

P0/P1 required events сохраняются через bounded memory ring и persistent checksum segments; packet path не блокируется на I/O. Required-event loss, event-order violation, stale generation mutation, trace/runtime mismatch и secret leakage являются hard-gate failures.

Monitoring metrics не должны использовать raw domain/IP/client в unbounded labels. Clear target identifiers допускаются только в локальном privacy-controlled evidence store.

---

# Часть XIX. Config и UI

## 85. Feature flags

Configuration separates capability, policy upper bound and effective runtime mode:

```text
configured mode
∩ platform/capture capability
∩ validation verdicts
∩ current source/transport health
= effective mode
```

Principal modes SHOULD use `disabled|observe|recommend|auto-diagnose|auto-canary` where applicable. `auto-diagnose` never means auto-apply. Aggressive RST, nested WARP and legacy Watchdog direct apply are not beginner defaults.


Минимальные flags:

```text
classifier_v2_enabled
scoped_dns_hints_enabled
quic_tcp_handoff_enabled
tcp_fsm_enabled
capture_envelope_enabled
tcp_reassembly_mode
auto_hold_replay_enabled
action_planner_v2_enabled
discovery_v23_enabled
clienthello_lab_enabled
failure_inbox_enabled
transactional_apply_enabled
proxy_fallback_enabled
```

Core flags вводятся поэтапно и поддерживают observe-only.

## 86. Backend config

Добавить группы:

- client identity;
- hint store limits/TTLs;
- confidence thresholds;
- DomainOnly mode;
- capture envelope and processed mark;
- TCP FSM/reassembly limits;
- hold/replay timeout;
- action budgets;
- semantic markers;
- Discovery sandbox/matrix;
- fake profile storage/compiler;
- canary/cooldown/rollback;
- fallback route;
- privacy/retention.

## 87. UI

UI SHOULD показывать:

- active architecture/runtime generation;
- per-set classifier mode;
- source-scoped hints diagnostics;
- flow/reassembly state;
- capture envelope status/offload warning;
- strategy dry-run;
- Discovery baselines and causal verdict;
- Failure Inbox;
- captured ClientHello candidates;
- compiled profile differences/MTU status;
- canary/promote/rollback controls;
- last-good generation.

Advanced options скрыты по умолчанию.

---

# Часть XX. Concurrency, memory и lifecycle

## 88. Concurrency model

Предпочтительно sharded stores:

```text
flow shard by normalized 5-tuple hash
hint shard by client+destination hash
action token shard by flow hash
```

Нельзя держать global lock во время raw send, DNS parsing или disk persistence.

## 89. Timers/GC

- centralized expiry wheel/heap либо bounded periodic scan;
- shutdown context;
- no goroutine per packet;
- per-flow timer только если доказана допустимая стоимость;
- deterministic cleanup in tests.

## 90. Backpressure

При queue pressure:

1. не начинать новое hold/reassembly;
2. fail-open новые ambiguous flows;
3. завершать low-confidence oldest holds;
4. сохранять clean SYN/ACK path;
5. emit metrics.

---

# Часть XXI. Compatibility и migration

## 91. Совместимость config

Существующие JSON-конфиги должны загружаться без ручной миграции.

Defaults при отсутствии новых полей:

```text
classifier_v2: observe/off according to release phase
DomainOnly: legacy
reassembly: off/observe
capture envelope: compatibility profile
auto hold: off
new strategies: disabled
```

## 92. Dual-run validation

На переходном этапе classifier v1 и v2 MAY работать в compare-only режиме:

```text
v1 decision
v2 shadow decision
no v2 action
trace differences
```

Это помогает найти collateral regressions.

## 93. Rollout phases

```text
Phase 0: audit/fixtures
Phase 1: observe classifier/evidence/FSM
Phase 2: scoped DNS/QUIC decision without hold
Phase 3: observe reassembly
Phase 4: auto hold/replay for canary client
Phase 5: planner v2 for existing strategies
Phase 6: Discovery/transactional apply
Phase 7: optional strategy catalog/fallback
```


## 93A. Post-v2.3 subsystem rollout

```text
A. shared schemas and shadow observability
B. cross-service/GSO/PPE visibility gates
C. Monitoring shadow and trigger shadow
D. manual authoritative ABD
E. Monitoring → ABD diagnostic cutover
F. DDI/guided Discovery
G. base WARP and Service Profile recommendations
H. API/UI cutover from legacy Watchdog
I. auto-canary cohorts after release verdicts
J. experimental camouflage/nested non-RU
```

Legacy API MAY remain as adapter, но direct Watchdog apply MUST быть удалён до `MON_PRODUCTION_READY`.

---

# Часть XXII. Verification strategy

## 94. Unit tests

Обязательные категории:

- DNS A/AAAA/CNAME/HTTPS/SVCB;
- source-scoped TTL and ambiguity;
- ClientKey partial/full identity;
- TCP sequence arithmetic/wrap;
- RangeSet out-of-order/duplicate/overlap;
- TLS exact length/multiple records/trailing bytes;
- ECH metadata;
- clean SYN;
- FSM transitions;
- ActionToken idempotency;
- semantic marker resolution;
- packet builder checksums/marks;
- Discovery verdict/scoring;
- fake compiler lengths/MTU;
- transactional rollback;
- CaptureCandidate/ActionAuthorization separation;
- effective per-set DomainOnly and negative hostname revocation;
- GSO first-pass token and representation invariance;
- PPE visibility verdicts and generation invalidation;
- unique progress/suppressor independence;
- monitoring temporal decay/recovery;
- client-resolution/CNAME/per-address outcomes;
- stage-aware observer comparison;
- WARP causal event order, route proof and cleanup ownership;
- Service Profile deterministic compilation and recommendation safety.

## 95. Fuzzing

Fuzz targets:

- DNS parser;
- TLS metadata parser;
- TCP range insertion;
- stream-to-packet mapping;
- fake profile compiler;
- config migration.

Properties:

- no panic;
- bounded allocation;
- malformed input fail-open;
- no inconsistent nested lengths;
- no action without valid decision/token.

## 96. Integration tests

### Android YouTube

- official app;
- ReVanced;
- QUIC enabled with B4 parse/reject;
- QUIC disabled;
- ECH present;
- split ClientHello;
- cold ARP state;
- multiple LAN clients;
- API/UI/video sets;
- CDN switch;
- video start/resume;
- background/foreground app.

### Transport

- IPv4/IPv6;
- TCP/UDP/QUIC;
- DoH/system DNS;
- offload on/off where available;
- packet loss/reordering/duplication;
- queue pressure;
- config hot apply during flow.

## 97. Field acceptance criteria

Для целевого client group:

- first API/UI/video flow получает expected set без ожидания случайного clear-SNI retry;
- split ClientHello классифицируется после bounded reassembly;
- ECH flow получает source-scoped DNS/QUIC classification;
- clean SYN не raw-reinject при отсутствии explicit SYN technique;
- no cross-client hostname leakage;
- retransmission не повторяет action;
- ServerHello progress останавливает first-flight mutation;
- body/throughput probes стабильны;
- rollback не оставляет queue/chains/state;
- CPU/memory подходят целевому Keenetic;
- Gmail/Google Feed and other same-client negative controls receive zero unrelated actions;
- GSO and MSS representations produce the same classifier/action decision;
- PPE per-flow exclusion proves bidirectional visibility or disables sensitive modes;
- silent recovery has differential proof, exact lease and rollback;
- Monitoring does not auto-act from passive evidence;
- ABD binds probes to client-observed resolution and preserves partial-IP failures;
- guided Discovery retains mandatory baselines/full fallback;
- base WARP proves target-scoped forwarded path and cleanup;
- Service Profile WARP suggestion appears only for fresh IP/SYN/CIDR hypotheses and remains test-first.

---

# Часть XXIII. Definition of Done

## 98. Core Fix DoD

Core Fix завершён, когда:

1. capture envelope проверен на целевом Keenetic;
2. clean SYN invariant покрыт tests и trace;
3. evidence/phase/confidence модель используется в decision path;
4. DNS→first-flow source-scoped correlation работает до первого TCP/UDP payload;
5. QUIC→TCP handoff работает;
6. observe и auto reassembly собирают Android split ClientHello;
7. ECH fallback не зависит от global learned IP;
8. action planner работает по logical stream offsets;
9. retransmission idempotency доказана tests;
10. все error paths fail-open.

## 99. Productization DoD

1. isolated baseline-none/production/candidate;
2. structured ProbeOutcome;
3. API/UI/video/body/throughput probes;
4. resolver/IP-family/TLS-profile differential diagnostics;
5. Failure Inbox;
6. ClientHello Laboratory and safe compiler;
7. last-good/canary/cooldown/rollback;
8. issue bundle and privacy controls.

## 100. Optional Strategy Catalog DoD

Новая техника считается готовой только если:

- declarative preconditions;
- planner dry-run;
- ActionToken idempotency;
- amplification budget;
- unit/integration tests;
- Discovery comparison with simpler candidates;
- canary rollback;
- no collateral expansion.


## 100A. Cross-service, visibility and recovery DoD

- capture candidate never grants action by destination alone;
- reassembled clear SNI is authoritative positive/negative evidence;
- all failure/route/RST/QUIC state uses full scope;
- GSO observe path remains zero-copy until normalization is required;
- PPE capability is detected behaviorally and has bidirectional self-test;
- silent failure uses unique progress, suppressors and differential proof;
- recovery is lease-based, bounded and rollback-observed.

## 100B. Monitoring and ABD DoD

- legacy Watchdog no longer owns direct Discovery/apply;
- Monitoring preserves exact client-resolution and temporal health without action authority;
- quick/deep triggers are budgeted and visibility-gated;
- ABD builds an immutable EvidenceGraph and scoped `BlockingProfile`;
- passive/provisional evidence cannot compile final profile;
- observer comparison is stage-aligned;
- every accepted monitoring request receives terminal diagnostic result.

## 100C. Transport and Service Profile DoD

- base WARP is bundled/version-pinned and does not require external runtime installation;
- WARP route is target-scoped, recursion-safe, causally traced and fully cleaned;
- nested/non-RU remains experimental and fail-closed on geo/DNS/IPv6 uncertainty;
- Service Profile compiler is deterministic and preserves managed/manual ownership;
- profile policy can only narrow capabilities;
- WARP recommendation is `eligible-to-test` before canary and `validated` only after target/control/path proof.

---

# Часть XXIV. Референсные проекты и лицензии

## 101. Обязательные read-only references

| Проект | Смотреть |
|---|---|
| B4 | фактический integration/config/UI/runtime path |
| zapret2 | packet retention/replay, semantic split/fooling concepts |
| z2k | Keenetic orchestration, readiness, lifecycle fixes |
| nDPI | classification phases, protocol metadata, flow state |
| SpoofDPI | bounded logical ClientHello handling |
| DPIBreak | sequence-aware packet construction |
| SNI-Spoofing | TCP FSM and fake gating |
| GreenTunnel | explicit TLS record split |
| nfqws2-keenetic | capture envelope, connmark, processed mark, offload warnings |
| nfqws2-keenetic-strategy-selector | sandbox, probes, real ClientHello capture, conntrack failure grouping |
| YT-DPI | differential TLS/IP-family diagnostics, layered verdicts, RST-path ideas |
| Ladon | demand-driven DNS intake, provisional/authoritative lanes, temporal recurrence, stage-aware observer concepts |
| usque | MASQUE/CONNECT-IP implementation reference and protocol behavior |
| usque-keenetic | Keenetic packaging/lifecycle reference for WARP, not runtime dependency |
| Cloudflare WARP protocols/docs | enrollment, keys, MASQUE endpoint behavior and privacy assumptions |

## 102. Дополнительные references

- Flowseal/zapret-discord-youtube — candidate strategy catalog, not classifier design;
- zapret-gui — Discovery/failover/control-plane concepts;
- wstunnel — proxy lifecycle/pooling only;
- nDPI — reference, not dependency unless separately approved.

## 103. Заимствование кода

Перед прямым переносом любого фрагмента MUST:

1. определить license конкретного repository/file/revision;
2. проверить совместимость с лицензией B4 fork;
3. сохранить attribution/provenance;
4. предпочесть clean-room reimplementation интерфейса/идеи, если license неясна;
5. не переносить binary blobs без provenance и rights.

`nfqws2-keenetic-strategy-selector` использовать как read-only reference до явного подтверждения лицензии проверяемой ревизии.

---

# Часть XXV. Итоговый reference design

## 104. Ключевая формула архитектуры

```text
Infrastructure and capture visibility
+ cross-service-safe identity/authorization
+ GSO/PPE-aware packet representation
+ bounded TCP/protocol progress model
+ continuous passive monitoring
+ authoritative multi-vantage ABD
+ freshness-aware guided Discovery
+ scoped packet/transport candidates
+ causal canary/path proof
+ transactional promote/rollback
+ declarative Service Profiles
```

## 105. Главный продуктовый результат

После реализации первый Android YouTube flow должен классифицироваться не «когда повезёт увидеть clear SNI», а на основе воспроизводимой совокупности доказательств конкретного клиента.

B4X должен уметь ответить на пять разных вопросов:

1. **Какому клиенту, сервису и компоненту принадлежит flow?**
2. **Разрешено ли выполнять packet или routing action в этом scope?**
3. **Что именно наблюдается: runtime degradation, origin failure или blocking hypothesis?**
4. **Какой минимальный candidate помогает цели и не ломает controls?**
5. **Доказано ли на реальном клиенте, что promoted path соответствует решению и может быть безопасно откачен?**

Такой контур превращает B4X из набора packet techniques и простого Watchdog в production-grade service-aware diagnosis, action и transport platform.

---

# Часть XXVI. Architectural Decision Records (ADRs)

## ADR-001 — Capture Envelope, Marks and Offload Policy

* **Offload Policy**: `capture.offload_policy`: `detect`, `exclude` (default), `disable-global`.
* **Mark scheme**:
  * `0x40000000` — `B4_PROCESSED_SKB` (packet-level mark)
  * `0x20000000` — `B4_MANAGED_CONN` (connmark)
  * `0x10000000` — `B4_SANDBOX_CONN` (connmark)
  * `0xF0000000` — reserved B4 mask. Configurable via `MarkConfig`.
* **Raw Socket**: Set `SO_MARK = B4_PROCESSED_SKB`. Packets matching `B4_PROCESSED_SKB` hit `RETURN / ACCEPT` in chain start and NEVER enter `NFQUEUE`. `B4_PROCESSED_SKB` is NEVER copied to `CONNMARK`.
* **Kernel Capture Envelope Defaults**:
  * Outgoing packet window: 24
  * Incoming packet window: 16
  * Always queue SYN-ACK: true
  * Always queue FIN/RST: true
* **Platform Offload Adapters**: OpenWrt excludes `ct mark & B4_MANAGED_CONN != 0` from flowtable. Keenetic performs runtime visibility self-test (SYN, ClientHello segment 1, ClientHello segment 2, SYN-ACK/ServerHello). Upon failure: `capture capability = incomplete`, `hold/replay = disabled`, observe mode active.

## ADR-002 — Packet Hold Deadlines and Fail-Open

* **Timers**:
  * Hold initial deadline: 80 ms
  * Hold hard deadline: 250 ms
  * Reassembly state TTL: 1800 ms
* **Fail-Open Policy**: Upon hard timeout, all held packets released unchanged in arrival order. Flow transitions to observe-only. Preferred implementation mechanism: pending NFQUEUE handles & late verdict.
* **Resource Budgets**:
  * Max held packets per flow: 16
  * Max held flows per client: 8
  * Max held bytes per client/interface: 256 KiB
  * Global held-packet budget: 4 MiB
  * Global observe/reassembly budget: 8 MiB

## ADR-003 — Retransmission and ActionToken Policy

* **Retransmission Matrix**:
  * **Original NF_ACCEPT**: Retransmission receives `NF_ACCEPT`, suppress fake action.
  * **Original Replaced/NF_DROP**: Suppress fake/duplicate components, drop retransmitted original, replay canonical `REAL-only plan` (preserving split boundaries & TCP SEQ, max 1 replay).
  * **Range ACKed by Server**: `NF_DROP` duplicate.
  * **ACK Visibility Uncertain**: Fail-open `NF_ACCEPT`.
  * **Server Progress Confirmed**: Stop first-flight mutation.

## ADR-004 — Private DNS Visibility Policy

* **Evidence Resolution Order**:
  `clear/reassembled TCP SNI` -> `source-scoped QUIC SNI` -> `source-scoped visible DNS` -> `explicit domain/static evidence` -> `safe fallback`.
* **DoT / Private DNS Policy**: `private_dns_policy`: `observe` (default), `allow`, `diagnostic-block-853` (manual opt-in with TTL).
* **DNS Visibility States**: `DNSVisibilityUnknown`, `DNSVisibilityClassic`, `DNSVisibilityB4DoH`, `DNSVisibilityPrivateDoTSuspected`, `DNSVisibilityAppDoHSuspected`, `DNSVisibilityUnavailable`.

## ADR-005 — Discovery Resource Budget

* **Execution Policy**: Default max active Discovery runs = 1, parallel probes = 1 (max 2 if RAM > 256 MiB & CPU cores >= 4).
* **Modes**: `Quick` (1 worker, 128 KiB cap, pause 500ms), `Standard` (1 worker, 512 KiB cap, pause 750ms), `Deep` (1-2 workers, 2 MiB cap, manual trigger only).
* **Auto-Pause Triggers**: Free RAM < 32 MiB, Load Avg > 1.5x, NFQUEUE queue/user drops > 0, held-packet budget > 50%.
* **Passive Inbox**: Passive log/conntrack collector only; no background heavy probes without explicit opt-in.

---

# Часть XXVII. Cross-Service Scope Isolation

## 106. Effective domain policy

Каждый set/component получает effective policy:

```text
strict | scoped-hints | legacy | disabled
```

Global legacy default не может молча расширять новый classifier v2 profile. Migration validator MUST помечать unsafe combinations.

## 107. Candidate and authorization split

`CaptureCandidate` содержит возможные eligible sets и причину capture. `ActionAuthorization` требует current positive domain evidence либо явно безопасную service-specific policy. Clear/reassembled SNI другого сервиса немедленно отзывает provisional candidate.

Legacy learned-IP остаётся compatibility hint с low confidence и не является authoritative для packet action, QUIC mutation, block cache или route binding.

## 108. Scoped side effects

Все runtime side effects используют полный key:

```text
ClientKey + Set/Service + Component + Destination + Protocol + ConfigGen
```

Destination-global `IPBlockDetect`, escalation, RST bookkeeping, blocked cache и routing state запрещены. QUIC action требует service authorization до mutation/drop/fallback.

## 109. Cross-service negative controls

Promotion samples MUST включать same-client unrelated controls. Для Google/YouTube обязательны Gmail и Google Feed/API controls. Любой `unrelated_control_action_total > 0` блокирует rollout.

---

# Часть XXVIII. RST/GSO Hardening

## 110. Reassembly correctness path

Complete reassembled SNI является first-class classifier evidence и может подтверждать либо опровергать provisional IP/DNS candidate. Reassembly не является только diagnostic side channel.

## 111. GSO capability model

GSO/GRO — свойство packet representation/capture capability, а не target domain. Fast path:

```text
observe/classify super-packet without mutation
→ normalize only when ActionPlan requires packet-level transform
→ attach first-pass token
→ secondary queue cannot reclassify/re-authorize
```

Decision, scope и authorization должны совпадать между GSO и equivalent MSS layouts.

## 112. Transactional topology

GSO queue/rules/marks применяются transactionally: prepare → readiness → switch → retire. Rollback возвращает previous topology и очищает temporary queues/tokens.

## 113. Passive RST

Default mode — observe. RST classification использует direction, sequence/window plausibility, TTL/hop baseline, server progress и independent evidence. Aggressive suppression доступна только после отдельного release gate и не может затронуть controls.

---

# Часть XXIX. Keenetic PPE Per-Flow Offload

## 114. Policy

```text
detect | exclude | disable-global
```

Default production goal — `exclude`: удерживать только B4-managed handshake/diagnostic window на CPU, а established compatible traffic возвращать в PPE.

## 115. Capability and self-test

Модель роутера не считается доказательством. Capability определяется по kernel target/match/tables/locks/privileges и проверяется:

```text
Level 0 static
Level 1 passive live
Level 2 controlled bidirectional A/B
```

Verdicts: complete, outgoing-only, incomplete, unknown. Hold/replay, reassembly-based auto action, silent recovery и auto-diagnose требуют current complete visibility.

## 116. Lifecycle

Rule compiler и cleanup являются idempotent, переживают NDM regeneration и crash recovery, не удаляют foreign resources и публикуют reasoned status/capabilities API.

---

# Часть XXX. Silent Path Failure and Scoped Recovery

## 117. Useful progress

Progress определяется unique bytes и protocol milestones:

```text
TCP handshake
→ TLS ServerHello/Alert
→ HTTP headers
→ unique body bytes
→ sustained throughput/app milestone
```

Duplicate ACK/data и retransmission не обновляют progress clock.

## 118. Suppressors and differential proof

До suspicion/action обязательны: minimum age, fast parallel-flow suppression, fresh same-scope success, compatible-protocol success, server/application response, app lifecycle, visibility/resource state, classification ambiguity и control health.

Confidence ladder:

```text
suspicion → correlated → differential → recurrent-validated
```

## 119. Recovery planner

Recovery order минимально агрессивный и scope-bound. Каждый candidate получает `RecoveryLease` с expiry, generation, exact binding и rollback target. Recursive fallback и global route changes запрещены.

WARP-path failure не запускает WARP recursively. Strict non-RU policy не ослабляется recovery candidate.

---

# Часть XXXI. Continuous Blocking Monitoring

## 120. Evolutionary replacement

Существующая функция мониторинга дорабатывается strangler-style:

```text
legacy Watchdog API/UI/config
→ compatibility adapter
→ MonitorService shadow
→ trigger shadow
→ diagnostic cutover
→ API cutover
→ direct-apply removal
```

`tables.Monitor` остаётся Infrastructure Integrity. Failure Inbox становится projection canonical assessments. Observability остаётся sink/export, не temporal database.

## 121. Monitor model

Core entities:

```text
MonitorScopeKey
MonitorObservation
ClientResolutionSnapshot
MonitorSubject
MonitorAssessment
DiagnosticTriggerDecision
```

Scope включает client/service/component/domain/endpoint/protocol/network/config generation. Health и diagnostic state являются независимыми axes.

## 122. Temporal evidence

Monitoring хранит bounded buckets, recurrence, independence, contradictions, decay и recovery. Повторы одного source повышают recurrence, но не evidence independence.

Demand intake из DNS/SNI/QUIC допускается только с provenance, TTL, privacy policy и per-client/global budgets.

## 123. Trigger planner

Quick/deep ABD request создаётся при independent signals, time-separated recurrence с healthy controls, typed block evidence или explicit user action. Trigger подавляется при WAN outage, stale visibility, queue/PPE degradation, exhausted budget и stale context.

Monitoring никогда не создаёт BlockingProfile, route token или production config.

---

# Часть XXXII. Adaptive Blocking Detector and DDI

## 124. Authoritative active diagnosis

ABD получает explicit `TargetPlan` или validated `MonitorDiagnosticRequest + TargetPlanOverlay`. Overlay не может удалить mandatory controls/baselines.

Active matrix покрывает DNS, TCP, TLS, HTTP body progress, QUIC, IPv4/IPv6, ClientHello fingerprints, packet/byte thresholds и reference paths.

## 125. Resolution and address outcomes

```text
client-observed exact endpoint experiment
≠ independent-current-resolution experiment
```

Каждый A/AAAA endpoint получает отдельный outcome vector; first success не скрывает blocked/reset/stalled siblings.

## 126. Evidence authority and attribution

```text
passive-monitoring
provisional-fast
authoritative-abd
android-canary
```

Physical `ProbeFailureCode`, `FailureAttribution`, `BlockingHypothesis` и recommendation являются разными полями. Provisional evidence влияет на priority, но не компилирует final profile.

## 127. Stage-aware observers

Observer объявляет capabilities. HTTP/body hypothesis требует observer HTTP/body progress; TCP/TLS-only observer не подтверждает higher-layer failure. `observer unavailable` означает отсутствие мнения, а не target failure.

Exact-endpoint и independent-resolution comparisons не смешиваются.

## 128. BlockingProfile and DDI

`BlockingProfile` immutable, scoped и expiring. Он содержит hypotheses, exclusions, confidence, evidence refs, network/config context и monitor assessment provenance.

DDI компилирует profile в `NetworkDiagnosticProfile/DiscoverySearchPrior`, проверяет freshness/context и при необходимости выполняет bounded revalidation. Detector result не является ActionAuthorization.

---

# Часть XXXIII. Guided Discovery and Telegram Bridge

## 129. Guided search

DDI prior выбирает ранние candidate families, но Discovery сохраняет:

- baseline-none;
- baseline-production;
- same-service/unrelated controls;
- one-dimension-at-a-time differentials;
- full bounded fallback;
- resource budgets;
- target-specific canary.

Savings считаются только без потери mandatory coverage/quality.

## 130. Transport candidates

IP/SYN/CIDR hypotheses повышают priority scoped SOCKS/TUN/base-WARP candidates. DNS-only, QUIC-only, SNI/fingerprint и threshold failures сначала используют соответствующие narrower families.

## 131. Telegram bridge

Bridge использует explicit FSM:

```text
accepted → waiting-first-data → classified/handoff
         → soft-deadline pending
         → primary dial/fallback
         → closed/cleanup
```

Pending sessions bounded globally/per-client. Уже прочитанный prefix сохраняется точно. Fallback защищён от TPROXY recursion. Reload/shutdown закрывает sockets и goroutines deterministically.

---

# Часть XXXIV. Built-in WARP/MASQUE Transport

## 132. Base transport architecture

B4X bundles a version-pinned `b4-warpd`/equivalent implementation; runtime binary downloads and external `usque` installation are not required.

Base chain:

```text
enrollment consent/key store
→ endpoint pin
→ TCP/TLS/HTTP2
→ CONNECT-IP/MASQUE
→ TUN packet pump
→ target-scoped route binding
→ health/reconnect/cleanup
```

## 133. Scope and path proof

WARP is not global default. Route applies only to exact authorized client/service/component targets. Promotion requires current causal trace and packet/byte counter deltas proving traffic entered the intended binding and did not leak direct.

## 134. Camouflage

Camouflage protects WARP control connection only when separately authorized. Established MASQUE packets bypass camouflage mutation; after cutoff `post_cutoff_mutations == 0`. Ordinary service action authorization cannot authorize WARP control camouflage.

## 135. Nested WARP and non-RU

Experimental nested mode has explicit parent/child `SessionGen`, dependency link, namespace/veth/NAT ownership, parent health and route-token validation.

Non-RU route gate requires multi-provider geo quorum, public-IP continuity, DNS/IPv6 path proof and prompt revocation. It is not a country selector or availability guarantee.

## 136. Causal observability and cleanup

Every process/session/TUN/socket/H2/CONNECT-IP/route/geo/DNS/cleanup transition emits generation-aware events. P0 required events cannot be silently sampled. Owned resources are cleaned; foreign resources are never removed.

Release verdicts include `WARP_BASE_READY` and `WARP_CAUSAL_TRACE_READY` before profile recommendation or production binding.

---

# Часть XXXV. Service Profiles and Beginner UX

## 137. Declarative framework

A `ServiceProfileManifest` declares components, targets, controls, allowed packet/transport/recovery modes and policy upper bounds. Compiler deterministically produces ordinary B4 objects with ownership/provenance metadata and preview diff.

Manual, pinned and excluded objects are preserved. Safety-relevant changes cannot be hidden in generic diff.

## 138. Capability projection

Profiles consume readiness/capability verdicts from classifier, GSO/PPE, SPF, Monitoring, ABD, WARP and canary subsystems. A profile can narrow effective mode but cannot elevate an unavailable/unvalidated capability.

## 139. Beginner recommendations

Beginner UI uses uncertainty-aware states:

```text
observed instability
→ likely cause
→ candidate suitable to test
→ validating
→ validated/rejected/inconclusive
```

For IP/SYN/CIDR blocking base WARP MAY be offered as `eligible-to-test` only with fresh `BlockingProfile`, exact scope, healthy controls/reference path and WARP causal readiness. `validated` requires scoped target/control/Android/path proof. `НЕ РФ` appears only for explicit geo requirement.

## 140. Profile release rule

Target success alone is insufficient. Promotion requires zero unrelated-control actions, exact side-effect scope, current representation/transport proof and rollback readiness.

---

# Часть XXXVI. Unified Release Architecture

## 141. Capability dependency graph

```text
Classifier/Capture v2.3
→ CSI + GSO/RST + PPE visibility
→ Progress/SPF
→ MON observation/temporal/trigger
→ ABD adapter/resolution/multi-vantage/production
→ DDI/guided Discovery
→ scoped canary/runtime control
→ base WARP causal readiness
→ Service Profile recommendation readiness
```

Telegram bridge hardening MAY proceed in parallel after its capture/routing dependencies.

## 142. Principal verdicts

```text
CSI_PRODUCTION_READY
GSO_RUNTIME_READY
PASSIVE_RST_OBSERVE_READY
PPE_BIDIRECTIONAL_VISIBILITY_READY
SILENT_PATH_OBSERVATION_READY
SILENT_PATH_RECOVERY_READY
MON_PRODUCTION_READY
ABD_MONITOR_ADAPTER_READY
ABD_CLIENT_RESOLUTION_READY
ABD_MULTI_VANTAGE_READY
ABD_PRODUCTION_READY
DDI_PRODUCTION_READY
GUIDED_DISCOVERY_READY
WARP_BASE_READY
WARP_CAUSAL_TRACE_READY
PROFILE_WARP_RECOMMENDATION_READY
TELEGRAM_BRIDGE_PRODUCTION_READY
```

Exact names from detailed addenda/validation registry take precedence if a companion specification defines a stricter spelling.

## 143. Global hard-gate classes

Production promotion is blocked by any non-zero event in these classes:

- action without current authorization;
- cross-client/service/component leakage;
- decision mismatch across packet representations;
- visibility/source-health bypass;
- provisional evidence used as final diagnosis;
- missing mandatory baseline/control;
- stale network/config/route/session generation;
- route/path proof missing;
- recursive/direct transport leakage;
- required trace loss/order/state mismatch;
- incomplete cleanup/foreign resource mutation;
- secret leakage or unbounded metric cardinality.

---

# Часть XXXVII. Consolidated Implementation Order

## 144. Recommended file order

```text
1. B4_FORK_ARCHITECTURE.md (this document)
2. B4_FORK_PATCH_PLAN.md
3. B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md
4. B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md
5. B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md
6. B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM.md
7. B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md
8. B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md
9. B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md
10. B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md
11. B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md
12. B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md
13. B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md
```

Field Test and Implementation Validation fixtures are implemented continuously with each stage; only the final umbrella run is last.

## 145. No flag-day migration

Every large subsystem follows observe/shadow/canary/cutover phases. Compatibility surfaces remain until parity and rollback are proven. Legacy unsafe direct-apply paths are disabled before declaring the new subsystem production-ready.

---

# Часть XXXVIII. Additional Architectural Decision Records

## ADR-006 — Cross-Service Authorization

Destination-only evidence is capture-only on shared infrastructure. Destructive actions and route bindings require current positive domain/service authorization; negative clear/reassembled hostname evidence revokes provisional candidates.

## ADR-007 — GSO Representation

GSO is a representation capability. Observe/classify without normalization; normalize only for an authorized plan; secondary pass consumes a single-use token and cannot repeat classification or action authorization.

## ADR-008 — PPE Visibility

Per-flow PPE exclusion is preferred over global offload disable. Sensitive automatic modes require current bidirectional functional proof and fail closed to observe/recommend when visibility degrades.

## ADR-009 — Silent Failure

Silence is not failure without age, useful-progress semantics, suppressor evaluation and corroboration. Recovery requires scoped lease, differential proof and rollback observation.

## ADR-010 — Monitoring/Detector Boundary

Monitoring owns passive temporal health and trigger decisions. ABD owns active authoritative experiments and BlockingProfile. Neither monitoring observation nor detector profile authorizes production action.

## ADR-011 — Guided Discovery

Detector output is converted through DDI into expiring search priors. Mandatory baselines, controls and full bounded fallback cannot be removed by hints.

## ADR-012 — Built-in WARP

WARP is a generic scoped transport, not global VPN default. Enrollment, path proof, control camouflage, nested dependency and cleanup have independent generations and hard gates.

## ADR-013 — Service Profile Ownership

Service Profiles are declarative compilers and policy upper bounds. They cannot own packet, detector, monitoring, transport or recovery runtime lifecycle.

## ADR-014 — Legacy Watchdog Migration

Watchdog surface is preserved as compatibility adapter during strangler migration. Legacy direct Discovery/apply and automatic `watchdog-*` set mutation are prohibited in production-safe mode.

## ADR-015 — Causal Trace

Required lifecycle events are generation-aware, ordered and durable within bounded storage. Runtime status that cannot be reconstructed from trace is a validation failure, not merely a diagnostics limitation.

