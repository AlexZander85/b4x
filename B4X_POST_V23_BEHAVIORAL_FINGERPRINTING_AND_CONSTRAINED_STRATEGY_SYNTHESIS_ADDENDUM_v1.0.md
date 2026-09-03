# B4X Post-v2.3 Behavioral Fingerprinting & Constrained Strategy Synthesis Addendum

**Версия:** `1.0`  
**Дата:** `2026-08-02`  
**Статус:** проект обязательного post-v2.3 companion addendum для owner review  
**Заменяет:** `B4X_POST_V23_DPI_BEHAVIORAL_FINGERPRINTING_ADDENDUM_v1.0.md` — прежний документ имеет статус `SUPERSEDED / DO NOT IMPLEMENT`  
**База:** `B4_FORK_ARCHITECTURE_v2.4.md`, `B4_FORK_PATCH_PLAN.md` v2.3, действующие post-v2.3 addenda, `B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md`, `B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md`  
**Основная платформа:** Keenetic/Entware; реальные Android/LAN-клиенты; Windows/Docker/CI как лабораторный controller  
**Целевая capability:** `autonomous-dpi-adaptation`  
**Состав capability:** bounded Behavioral Fingerprinting + Constrained Geneva-inspired Synthesis + existing Discovery  
**Стадии:** `AFS-1 … AFS-14`  
**Reference paper:** *Fingerprinting Deep Packet Inspection Devices by Their Ambiguities*, ACM CCS 2025, arXiv `2509.09081v1`  
**Reference implementation 1:** `AlexZander85/CenDPI`, pinned commit `8e470ac7cf8919f9c0b1ea1c019d09a3dff8c427`  
**Reference implementation 2:** `Kkevsterrr/geneva`, pinned commit `28a3fa63dff1eebe7e92dcf00f69ca480a81cd3a`, BSD-3-Clause  
**Главная пользовательская цепочка:** Monitoring фиксирует устойчивую регрессию → ABD перепроверяет тип блокировки → bounded behavioral panel уточняет особенности DPI → constrained synthesizer создаёт небольшой набор новых комбинаций из разрешённых B4X-примитивов → existing Discovery проверяет их вместе с обязательными baseline/control → Android/forwarded-client canary → transactional promote или rollback  
**Главный safety-инвариант:** fingerprint не является стратегией; synthesizer не исполняет пакеты; Discovery не применяет candidate напрямую; production action разрешается только существующей цепочкой `ActionAuthorization → ActionPlan → canary → promote/rollback`.

---

# 0. Owner summary

## 0.1. Что именно получает пользователь

После реализации пользователь может включить отдельную настройку:

```text
[ ] Автоматически создавать новые комбинации обхода при изменении DPI
```

Когда галочка выключена:

```text
обычный Monitoring
→ обычный Detector/ABD
→ существующие presets и обычный bounded Discovery
```

Когда галочка включена и текущая стратегия перестала работать:

```text
устойчивая подтверждённая регрессия
→ bounded fingerprint поведения DPI
→ генерация новых безопасных комбинаций
→ проверка в существующем Discovery
→ Android canary и controls
→ promote победителя либо сохранение last-good и отчёт об отсутствии решения
```

Система может создавать новые **комбинации**, которых раньше не было в preset-каталоге, например:

```text
TCP split около SNI
+ TLS record split
+ bounded disorder
+ padding только первого ClientHello
```

Система не может сама написать новый kernel/NFQUEUE primitive. Она комбинирует только те безопасные операции, которые уже реализованы и разрешены в B4X.

## 0.2. Почему предыдущий fingerprint-only addendum заменён

Fingerprint без synthesizer даёт в основном:

- более точную диагностику;
- лучший порядок существующих presets;
- меньше лишних Discovery probes.

Это полезно, но не создаёт нового обхода. Новый документ делает fingerprint функционально оправданным:

```text
fingerprint определяет слабость/особенность DPI
→ synthesizer использует эту информацию для ограничения пространства поиска
→ Discovery доказывает работоспособность новой комбинации
```

Поэтому отдельная production capability `dpi-behavioral-fingerprinting` не реализуется. Behavioral evidence является внутренним этапом единой capability `autonomous-dpi-adaptation`.

## 0.3. Минимизация новых сущностей

Этот документ запрещает создавать:

- отдельный `DPIBehaviorService`;
- второй Detector;
- второй optimizer;
- второй packet engine;
- независимый профильный store только ради fingerprint;
- отдельный production apply path;
- постоянный фоновый genetic search.

Используется существующая архитектура:

| Функция | Владелец |
|---|---|
| обнаружение устойчивой регрессии | `MonitorService` |
| активная диагностика и behavioral evidence | `DetectorService/ABD` |
| freshness/context и search prior | `DDI` |
| создание и проверка synthesized candidates | `DiscoveryService` |
| проверка/компиляция packet program | existing `ActionPlanner` |
| packet execution | existing `ActionService` |
| canary/promote/rollback | `TransactionalRuntime` |

Новые данные добавляются в существующие envelope/profile/run types. Отдельно сохраняется только успешный canonical synthesized plan с provenance, а не весь перебранный набор.

# Часть I. Нормативный статус и архитектурное место

## 1. Назначение

Этот addendum вводит единую capability:

```text
autonomous-dpi-adaptation
```

Capability состоит из трёх последовательно связанных частей:

```text
1. bounded Behavioral Fingerprinting inside ABD
2. constrained candidate synthesis inside Discovery
3. existing Discovery / Action / canary / runtimecontrol pipeline
```

Документ не переопределяет базовые владельцы архитектуры и не заменяет существующие addenda. Он добавляет безопасный способ расширять candidate space во время runtime без выпуска новой версии программы.

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
→ этот addendum: AFS-1…AFS-14
→ Detector-Guided Discovery / DDI hardening
→ Field Test Automation
→ Implementation Validation
→ production promotion
```

## 3. Приоритет требований

При конфликте действует:

```text
Architecture v2.4
→ owner decisions / conflict-resolution records
→ subsystem addenda
→ этот addendum для autonomous synthesis
→ Field Test / Implementation Validation как release gates
→ reference-project behavior notes
```

## 4. Обязательная граница объектов

```text
MonitorObservation
≠ MonitorAssessment
≠ MonitorDiagnosticRequest
≠ BehavioralEvidence
≠ BlockingProfile
≠ DiscoverySearchPrior
≠ SynthesisRequest
≠ SynthesizedCandidatePlan
≠ ActionAuthorization
≠ ActionPlan
≠ production promotion
```

Ни один объект слева не должен неявно превращаться в объект справа.

## 5. Запрещённые shortcut paths

```text
one timeout → synthesis
fingerprint → direct strategy
fingerprint feature → raw packet mutation
synthesizer → NFQUEUE/iptables
synthesized candidate → production config
router-origin success → Android proof
candidate target success → promotion without controls
old fingerprint → new WAN/config generation
failed cleanup → next synthesis run
```

## 6. Не-цели v1.0

В v1.0 не входят:

- точное определение производителя DPI;
- полная Geneva Python runtime;
- Scapy в production;
- произвольный Geneva DNA из пользовательского ввода;
- неограниченная генетическая эволюция;
- FlowPaint/diffusion model на роутере;
- генерация нового исполняемого Go/C-кода;
- новые kernel modules;
- произвольные malformed packets;
- HTTP request smuggling;
- IP overlap/fragmentation в automatic mode;
- global RST suppression;
- global offload disable;
- массовое публичное probing;
- автоматический bypass IP blocking без transport candidate;
- отключение full bounded Discovery fallback.

# Часть II. Reference audit и принятые идеи

## 7. CenDPI/dMAP

Из dMAP/CenDPI принимается идея:

```text
несколько bounded ambiguity probes
→ нормализованные pass/block/reset/stall outcomes
→ feature vector поведения DPI
→ ограничение вероятных operator families
```

B4X не импортирует CenDPI как процесс. Поведение реализуется нативно через существующие capture, experiment, evidence и cleanup contracts.

Полезные свойства:

- black-box behavior measurement;
- control/test differential;
- deterministic probe identity;
- explicit `inconclusive`;
- небольшой discriminative panel вместо полного fuzzing;
- profile/fingerprint привязан к network context и generation;
- повторная проверка при drift.

## 8. Geneva

Из Geneva принимается модель:

```text
trigger
+ tree/sequence of packet-level actions
+ mutation/crossover
+ fitness-based candidate selection
```

Оригинальная Geneva содержит action forests, triggers и действия `duplicate`, `drop`, `tamper`, `fragment`. В B4X это не переносится буквально. В automatic router mode используется безопасная конечная grammar поверх существующих B4X primitives.

Принимаются:

- declarative strategy representation;
- canonical serialization;
- mutation одного элемента;
- bounded crossover совместимых subplans;
- seed population;
- fitness evaluation;
- novelty/deduplication;
- evolutionary improvement по поколениям.

Не принимаются:

- собственный NFQUEUE engine;
- собственные iptables rules;
- Python/Scapy runtime dependency;
- случайные неограниченные деревья;
- прямой wire execution synthesizer-ом;
- overt training campaign без user opt-in;
- опасные действия automatic mode.

## 9. Clean-room и лицензии

### CenDPI

До явного license decision для pinned snapshot:

```text
MUST:
- использовать статью и наблюдаемое поведение как reference;
- независимо определять schemas/interfaces/tests;
- хранить provenance и commit hash;
- не копировать probe YAML, payload constants и функции.

MUST NOT:
- vendor/import CenDPI source;
- включать CenDPI binary;
- копировать top probe panel verbatim;
- скачивать CenDPI catalog в runtime.
```

### Geneva

Pinned Geneva snapshot лицензирован BSD-3-Clause. Возможен перенос идей и, при отдельном решении, кода с сохранением notices. Для B4X v1.0 всё равно используется нативная независимая Go-реализация, поскольку оригинальный engine архитектурно несовместим с единым packet-path ownership.

# Часть III. Пользовательская настройка и UX

## 10. Главная галочка

В Advanced Settings → Automation добавить отдельную настройку:

```text
[ ] Автоматически создавать новые комбинации обхода при изменении DPI
```

Canonical setting key:

```yaml
automation:
  adaptive_strategy_synthesis:
    enabled: false
```

Go projection:

```go
type AdaptiveStrategySynthesisConfig struct {
    Enabled bool `json:"enabled" yaml:"enabled"`

    MaxCandidates       uint16        `json:"max_candidates"`
    MaxGenerations      uint8         `json:"max_generations"`
    MaxActions          uint8         `json:"max_actions"`
    MaxBranches         uint8         `json:"max_branches"`
    RunTimeout          time.Duration `json:"run_timeout"`
    Cooldown            time.Duration `json:"cooldown"`
    FailedSearchCooldown time.Duration `json:"failed_search_cooldown"`

    AllowSafeFake       bool `json:"allow_safe_fake"`
    AllowBoundedDisorder bool `json:"allow_bounded_disorder"`
    AllowJitter         bool `json:"allow_jitter"`
}
```

## 11. Значение галочки

`enabled=false`:

- Monitoring и обычный Detector работают как раньше;
- behavioral probes не запускаются ради synthesis;
- Discovery использует готовые presets и обычные candidates;
- сохранённые synthesized winners могут отображаться, но новые не создаются;
- текущий уже promoted plan не откатывается автоматически только из-за выключения галочки.

`enabled=true`:

- это user opt-in на bounded active experiments;
- synthesis запускается только после подтверждённой регрессии и preflight;
- fingerprint выполняется только если обычной диагностики недостаточно для выбора candidate space;
- кандидаты создаются из allowlisted primitives;
- никакой candidate не применяется без обычного Discovery/canary/promotion.

## 12. Default и подтверждение

Default:

```text
enabled = false
```

При первом включении UI показывает подтверждение:

> При устойчивом ухудшении B4X сможет провести ограниченную активную диагностику, собрать новые комбинации из безопасных техник и проверить их. Это может занять несколько минут и временно увеличить нагрузку на роутер и число тестовых соединений. Рабочая конфигурация сохраняется до успешного canary.

## 13. Beginner UI

Beginner UI показывает только:

- галочку;
- текущий статус;
- последнюю успешную адаптацию;
- кнопку `Остановить текущую адаптацию`;
- кнопку `Вернуться к последней каталожной стратегии` при активном synthesized winner.

Статусы:

```text
Выключено
Ожидание устойчивой регрессии
Перепроверка блокировки
Анализ поведения DPI
Создание новых комбинаций
Проверка вариантов
Проверка на устройстве
Новая комбинация применена
Решение не найдено
Остановлено ограничениями безопасности
Откат выполнен
```

## 14. Advanced UI

Advanced UI показывает:

- scope: client/service/component/network/config generation;
- trigger reason;
- fingerprint evidence summary;
- operator families permitted/excluded;
- candidate budget;
- generation/population progress;
- candidates created/rejected/tested;
- controls and Android canary;
- resource pressure;
- winning plan canonical representation;
- reason for no solution;
- cleanup status;
- provenance: `preset`, `synthesized`, `historical-local`.

## 15. Global upper bound и Service Profiles

Глобальная галочка является верхним разрешением. Service Profile может дополнительно запретить synthesis:

```yaml
service_profile:
  automation:
    adaptive_strategy_synthesis: inherit | disabled
```

Service Profile не может включить synthesis, если глобальная галочка выключена.

# Часть IV. Единая runtime-цепочка

## 16. Нормальный путь

```text
Monitoring sees persistent regression
→ validates recurrence, controls and visibility
→ creates MonitorDiagnosticRequest
→ ABD ordinary revalidation
→ if ordinary diagnosis is sufficient:
     compile BlockingProfile and use existing guided Discovery
→ if current presets fail or behavior ambiguity is material:
     bounded behavioral panel
→ BehavioralEvidence added to existing EvidenceGraph/BlockingProfile
→ DDI compiles operator constraints + candidate-family prior
→ Discovery SynthesisPlanner creates bounded novel candidates
→ existing GuidedSearchPlan merges:
     mandatory baseline-none
     mandatory baseline-production
     catalog candidates
     synthesized candidates
     full bounded fallback
→ ActionPlanner statically validates each candidate
→ Discovery executes target/control matrix
→ best candidate enters Android/forwarded-client canary
→ TransactionalRuntime promotes or rolls back
→ Monitoring observes recovery/stability
```

## 17. Escalation ladder

```text
L0 transient retry
L1 ordinary Monitoring assessment
L2 quick ABD revalidation
L3 ordinary guided/full Discovery using catalog
L4 bounded behavioral fingerprint
L5 constrained synthesis + Discovery
L6 Android canary
L7 promote / rollback / no-solution cooldown
```

Synthesis MUST NOT запускаться раньше L4.

## 18. Trigger prerequisites

Automatic synthesis разрешён только когда одновременно:

- user checkbox enabled;
- current Service Profile permits it;
- persistent regression confirmed;
- same-service and unrelated controls are healthy enough to interpret result;
- network context and config generation current;
- target plan complete;
- capture/PPE/GSO visibility sufficient for required operators;
- no active conflicting Discovery/synthesis run;
- resource budget available;
- cleanup from previous run complete;
- current strategy/presets have failed according to configured escalation policy;
- cooldown expired.

## 19. Conditions that suppress synthesis

Synthesis suppressed when:

- Wi-Fi/LAN instability explains failure;
- DNS is the primary unresolved cause and DNS candidates not exhausted;
- endpoint/CDN outage likely;
- observer/control unavailable;
- route changed during run;
- PPE visibility degraded;
- GSO representation readiness insufficient;
- memory/CPU/queue pressure exceeds budget;
- user disables checkbox;
- device on battery/thermal policy forbids active test, if applicable;
- target is not authorized for active testing;
- previous no-solution cooldown active.

# Часть V. Canonical data model

## 20. Behavioral evidence без отдельного profile service

Fingerprint хранится как evidence bundle внутри существующего diagnostic profile:

```go
type BehavioralFingerprintEvidence struct {
    EvidenceID          string
    Scope               monitor.MonitorScopeKey
    NetworkContextID    string
    ConfigGeneration    uint64
    ProbeCatalogVersion string
    PanelHash           string
    FeatureVectorHash   string

    Features            []BehaviorFeature
    Attempts            []BehaviorAttemptSummary
    Confidence          float64
    NoiseScore          float64
    ConclusiveCount     uint16
    InconclusiveCount   uint16

    CreatedAt           time.Time
    ValidUntil          time.Time
    EvidenceRefs        []string
}
```

Не создаётся отдельный `DPIBehaviorProfileStore`. DDI сохраняет evidence в существующем `NetworkDiagnosticProfile` envelope.

## 21. Behavior feature

```go
type BehaviorFeature struct {
    FeatureID       string
    Group           string
    State           string
    Confidence      float64
    Supports        []StrategyOperatorFamily
    Penalizes       []StrategyOperatorFamily
    Excludes        []StrategyOperatorFamily
    EvidenceRefs    []string
}
```

Примеры групп:

```text
tcp_reassembly
out_of_order
retransmission
duplicate_segment
tls_record_depth
tls_clienthello_layout
tcp_options
checksum_handling
session_reset
packet_budget
byte_budget
ipv4_ipv6_difference
```

## 22. Synthesis request

```go
type SynthesisRequest struct {
    RequestID         string
    Scope             monitor.MonitorScopeKey
    ConfigGeneration  uint64
    BlockingProfileID string
    BehavioralEvidenceID string

    FailedCandidateIDs []string
    BaselineCandidateIDs []string
    AllowedGrammarVersion string
    ResourceBudget     discovery.ResourceBudget
    RequestedAt        time.Time
    ExpiresAt          time.Time
}
```

## 23. Strategy grammar

```go
type StrategyGrammar struct {
    Version            string
    Operators          []OperatorDefinition
    TriggerDomains     []TriggerDomain
    ParameterDomains   []ParameterDomain
    Constraints        []GrammarConstraint
    MaxActions         uint8
    MaxBranches        uint8
    MaxAmplification   float64
}
```

## 24. Synthesized candidate

```go
type SynthesizedCandidatePlan struct {
    CandidateID       string
    Scope             monitor.MonitorScopeKey
    ConfigGeneration  uint64
    GrammarVersion    string
    ParentIDs         []string
    Generation        uint8

    Trigger           CandidateTrigger
    Operations        []CandidateOperation
    Representation    action.RepresentationRequirement
    Preconditions     []string

    StaticCost        CandidateCost
    Risk              CandidateRisk
    CanonicalHash     string
    Provenance        CandidateProvenance
    CreatedAt         time.Time
}
```

```go
type CandidateProvenance struct {
    Kind                 string // synthesized
    FingerprintEvidenceID string
    BlockingProfileID    string
    SeedIDs              []string
    MutationTrace        []string
    SynthesizerVersion   string
}
```

## 25. Candidate identity

```text
CandidateID = SHA-256(
  grammar version
  + canonical trigger
  + canonical ordered operations
  + canonical bounded parameters
  + representation requirements
)
```

Mutable runtime state, timestamps and score не входят в hash.

## 26. Candidate evaluation

```go
type CandidateEvaluation struct {
    CandidateID       string
    Scope             monitor.MonitorScopeKey
    TestSessionID     string
    TargetOutcome     discovery.ProbeOutcome
    ControlOutcomes   []discovery.ProbeOutcome
    AndroidCanary     *discovery.ProbeOutcome

    StabilityScore    float64
    LatencyScore      float64
    ResourceScore     float64
    CollateralScore   float64
    Fitness           float64

    Verdict           string
    EvidenceRefs      []string
}
```

## 27. Winner persistence

Все transient candidates не добавляются в глобальный preset catalog.

Сохраняются только:

- promoted winner;
- optional bounded top-N evidence for debugging;
- canonical plan and provenance;
- scope/network/config compatibility;
- expiry/revalidation metadata.

Winning plan сохраняется через существующий learned/local candidate mechanism. При его отсутствии добавляется bounded `LocalSynthesizedWinnerStore` внутри Discovery ownership, не отдельный optimizer store.

# Часть VI. Bounded Behavioral Fingerprinting

## 28. Когда fingerprint действительно нужен

Fingerprint запускается только если хотя бы одно условие истинно:

- ordinary ABD confidence insufficient;
- несколько blocking hypotheses остаются совместимыми;
- catalog Discovery исчерпал допустимый budget без решения;
- раньше рабочая strategy family перестала работать после network drift;
- Monitoring обнаружил устойчивое изменение реакции на packet layout;
- synthesis planner не может определить safe operator subset без behavioral evidence.

## 29. Four-way differential

Каждый behavioral probe использует минимум:

```text
R1 reference/control baseline
R2 target baseline
R3 reference/control mutated
R4 target mutated
```

Дополнительные повторения нужны для noise/stability.

Пример интерпретации:

| R1 | R2 | R3 | R4 | Вывод |
|---|---|---|---|---|
| OK | FAIL | OK | OK | mutation вероятно обходит target filtering |
| OK | FAIL | FAIL | FAIL | mutation ломает endpoint/path, evidence inconclusive |
| OK | OK | OK | FAIL | mutation-specific target regression, не candidate prior |
| FAIL | * | * | * | control unhealthy, run invalid |

## 30. Risk tiers

```text
passive-observe
endpoint-safe
ambiguity-deep
research-only
```

Automatic checkbox разрешает только:

```text
passive-observe + endpoint-safe
```

`ambiguity-deep` допускается только в controlled test session и не является частью автоматической адаптации v1.0.

`research-only` не входит в production binary path либо заблокирован compile/runtime policy.

## 31. Initial automatic probe families

Разрешённый v1 panel:

- TCP segmentation boundaries;
- TLS ClientHello segmentation;
- TLS record layout variants;
- retransmission of identical bytes;
- bounded duplicate segment with identical payload;
- safe out-of-order delivery supported by existing ActionService;
- safe TCP option variants already validated by B4X;
- bounded pre/post padding;
- packet-count/byte-count observation;
- IPv4/IPv6 comparison where both paths available;
- current GSO vs equivalent MSS representation parity evidence.

Не разрешены automatic mode:

- overlapping IP fragments;
- malformed IP/TCP headers;
- corrupt checksum;
- arbitrary sequence-window violations;
- fake RST/FIN unless separately approved existing safe primitive and owner policy;
- payload-changing HTTP smuggling;
- arbitrary raw packet bytes.

## 32. Panel selection

Panel selector consumes:

- ordinary BlockingProfile;
- failed candidate families;
- current strategy decomposition;
- previous behavioral evidence if fresh enough for revalidation;
- visibility/readiness state;
- device resource class;
- test target capabilities.

It returns the smallest panel that can distinguish relevant operator families.

## 33. Bounded defaults

Recommended low-end defaults:

```yaml
fingerprinting:
  max_probes: 8
  attempts_per_probe: 2
  concurrency: 1
  max_duration: 60s
  inter_probe_delay: 500ms
  max_inconclusive_ratio: 0.25
```

Standard/high-resource router may use up to 16 probes, but automatic mode remains concurrency 1 unless target validation explicitly proves otherwise.

## 34. Freshness

Behavioral evidence key:

```text
NetworkContextID
+ WAN identity hash
+ ConfigGeneration
+ capture/PPE/GSO capability generation
+ service/component scope
+ probe catalog version
```

Any incompatible change makes evidence `STALE`, not `READY`.

# Часть VII. Constrained Geneva-inspired Synthesis

## 35. Synthesis ownership

Synthesis является частью `DiscoveryService`, потому что он создаёт candidates для search. ABD не создаёт стратегии; ActionService не выбирает стратегии.

Recommended package:

```text
src/discovery/synthesis/
```

## 36. Не full Geneva

Router implementation использует deterministic bounded evolutionary/beam search:

```text
small seed set
→ validate
→ score/prune
→ mutate/crossover within finite grammar
→ validate
→ hand candidates to existing Discovery
→ use measured outcomes as fitness
→ stop early on sufficient candidate
```

Нет отдельного долгого training process.

## 37. Automatic safe grammar v1

Allowlisted operator families:

```text
tcp_split
tls_record_split
bounded_disorder
safe_duplicate_original
pre_padding
post_padding
per_flow_jitter
safe_fake_profile     # только существующие endpoint-safe fake profiles
```

Optional regular Discovery dimensions, not synthesized packet operators:

```text
resolver change
QUIC allow/block/fallback
SOCKS/TUN/WARP transport
IP family
TLS profile
```

Они могут комбинироваться planner-ом на уровне Discovery matrix, но не становятся частью packet action tree v1.

## 38. Trigger grammar

Automatic triggers ограничены уже известными logical phases/markers:

```text
first outbound ClientHello
complete reassembled ClientHello
logical SNI marker when clear
TLS record boundary
first application request
first N packets within bounded phase
specific stream offset from parsed structure
```

Запрещены:

- arbitrary user expression;
- unbounded packet number;
- raw payload regex on sensitive content;
- destination-only trigger on shared infrastructure without current authorization;
- trigger after flow identity/generation becomes stale.

## 39. Parameter domains

Параметры берутся только из finite registries:

```yaml
split_offsets:
  - before_sni
  - inside_sni_1
  - inside_sni_mid
  - after_sni
  - clienthello_record_boundary
  - safe_numeric_offsets_from_parser

padding_bytes:
  - 1
  - 4
  - 8
  - 16
  - 32

jitter_ms:
  - 0
  - 1
  - 2
  - 4
  - 8

order_patterns:
  - in_order
  - swap_adjacent_once
```

Actual values MUST be bounded by existing parser, representation and action contracts.

## 40. Structural constraints

Automatic candidate MUST satisfy:

- max actions default 4;
- max branching operators default 1;
- max emitted packet amplification default 1.5;
- original logical byte stream preserved;
- no byte loss;
- no byte duplication at endpoint-visible stream level;
- no action after terminal authorization phase;
- no recursive trigger;
- no repeated execution for same stream-offset token;
- representation requirements explicitly declared;
- cleanup/rollback available;
- compatible with current IP family and GSO state.

## 41. Seed population

Seeds are built from:

1. `baseline-none` and `baseline-production` only as controls, not mutable parents;
2. current failed production strategy decomposition;
3. best catalog candidates from DDI prior;
4. prior successful local synthesized winners compatible with current context;
5. one-dimensional templates implied by behavioral features.

## 42. Mutation operators

Allowed mutation set:

```text
add one operator
remove one operator
replace one operator with same-risk family
swap adjacent operators
change one finite parameter
move split to neighboring logical marker
add/remove one safe branch
change bounded trigger phase
```

Every mutation is followed by canonicalization and static validation.

## 43. Crossover

Crossover is optional and bounded.

Allowed only when parent plans:

- both statically valid;
- same scope and generation;
- same representation class;
- compatible flow phase;
- combined plan remains within action/branch/amplification budget.

No arbitrary tree splicing across incompatible phases.

## 44. Determinism

Given equal:

```text
SynthesisRequest
+ grammar version
+ seed IDs
+ deterministic seed
```

planner MUST generate the same ordered candidate IDs.

Network outcomes affect later ranking, but not canonical identity.

## 45. Static validator

Before any candidate reaches network:

- schema valid;
- all operators registered;
- all parameters in domain;
- action count and branch count bounded;
- no unsafe operator;
- stream semantics preserved;
- representation compatible;
- ActionPlanner can compile;
- ActionAuthorization prerequisites expressible;
- resource estimate within budget;
- candidate not duplicate of preset or previous candidate unless explicit revalidation.

## 46. Candidate cost model

```go
type CandidateCost struct {
    Actions            uint8
    Branches           uint8
    EstimatedPackets   uint16
    Amplification      float64
    HeldBytes          uint32
    CPUUnits           uint32
    LatencyPenaltyMS   uint32
    RepresentationCost string
}
```

Cheapest safe candidates are tested first.

## 47. Fitness

Recommended normalized fitness:

```text
+ target functional milestone
+ target stability
+ Android forwarded-client success
+ same-service controls
+ unrelated controls
+ low latency
+ low packet amplification
+ low CPU/RAM/queue pressure
+ repeatability
- collateral damage
- reconnect regression
- cleanup failure
- excessive complexity
```

Target success alone cannot produce positive production fitness.

## 48. Search bounds

Recommended defaults:

```yaml
synthesis:
  max_candidates: 24
  initial_population: 6
  max_generations: 3
  max_candidates_per_generation: 8
  max_actions: 4
  max_branches: 1
  max_amplification: 1.5
  concurrency: 1
  max_duration: 180s
  early_stop_after_stable_candidate: true
```

All network bytes/requests also count against existing Discovery budget. Synthesis cannot create a second budget pool.

## 49. Early stop

Stop synthesis when:

- candidate passes required target and controls with sufficient margin;
- Android canary succeeds and promotion starts;
- budget exhausted;
- visibility/readiness becomes stale;
- user disables feature/cancels run;
- network context/config generation changes;
- repeated candidates show no improvement;
- resource pressure threshold crossed.

# Часть VIII. Existing Discovery integration

## 50. One Discovery, one candidate pipeline

Синтезированные и каталожные candidates проходят одну цепочку:

```text
candidate source
→ canonical candidate registry view
→ static ActionPlanner validation
→ GuidedSearchPlan
→ isolated target/control test
→ scoring
→ canary
→ promote/rollback
```

## 51. Исправление current branch prior handling

`src/discovery/hint_planner.go` MUST перестать игнорировать `DiscoverySearchPrior`.

Forbidden:

```go
_ = prior
```

Required behavior:

- validate prior freshness/scope/generation;
- apply family weights to catalog ordering;
- pass operator constraints to synthesis planner;
- retain mandatory baselines and exhaustive fallback;
- reject stale or malformed prior without changing plan.

## 52. GuidedSearchPlan extension

```go
type GuidedSearchPlan struct {
    Baseline              []string
    Ordered               []string
    Hints                 []SearchHint
    SynthesizedCandidates []string
    ExhaustiveFallback    bool
    Explanation           string
}
```

`SynthesizedCandidates` are references to immutable plans in current run store.

## 53. Ordering

Recommended order:

```text
baseline-none
baseline-production
cheapest high-confidence catalog candidates
cheapest high-confidence synthesized candidates
remaining catalog candidates
remaining synthesized candidates
full bounded fallback families/transports
```

Ordering MAY interleave catalog and synthesized candidates by cost/expected value.

## 54. Mandatory controls

Every synthesized candidate test includes:

- target endpoint/milestone;
- same-service control;
- unrelated control;
- current production baseline;
- exact client/service/component scope;
- current resolver/IP family/TLS profile context;
- cleanup verification.

## 55. Novelty

Candidate is `novel` when canonical hash отсутствует в:

- built-in preset catalog;
- current run;
- compatible local winner store.

Novelty влияет на reporting, но не даёт score bonus, достаточный для обхода safety criteria.

## 56. No catalog pollution

Неудачные transient synthesized candidates не добавляются в permanent catalog.

Promoted winner сохраняется как:

```text
local synthesized winner
+ exact scope/context
+ evidence refs
+ expiry/revalidation
+ source grammar/version
```

Он не становится универсальным preset для других пользователей/WAN без отдельного release process.

## 57. Promotion

Synthesized winner обязан пройти те же или более строгие gates, чем preset:

- ActionAuthorization current;
- representation ready;
- target proof;
- controls proof;
- Android/forwarded-client proof;
- current generation;
- no cross-service/client leakage;
- rollback ready;
- cleanup ready;
- stable observation window.

# Часть IX. Monitoring и автономная адаптация

## 58. Monitoring ownership

Monitoring:

- наблюдает реальные потоки;
- определяет persistent regression;
- управляет recurrence/cooldown;
- создаёт `MonitorDiagnosticRequest`;
- получает structured result;
- наблюдает recovery after promotion.

Monitoring не:

- выполняет raw probes;
- строит fingerprint;
- создаёт candidates;
- компилирует ActionPlan;
- применяет config.

## 59. Regression qualification

Automatic adaptation requires evidence such as:

- repeated target milestone failure;
- current strategy previously healthy in same context;
- sufficient passive visibility;
- healthy or interpretable controls;
- failure not explained by local network suppressor;
- persistence over configured temporal buckets;
- no active rollout/config transition.

## 60. State machine

```text
IDLE
→ REGRESSION_CANDIDATE
→ REGRESSION_CONFIRMED
→ ABD_REVALIDATING
→ FINGERPRINTING (optional)
→ SYNTHESIS_PLANNING
→ DISCOVERY_TESTING
→ CANARY
→ PROMOTING
→ STABILITY_OBSERVE
→ IDLE
```

Terminal/suppression states:

```text
NO_SOLUTION
BLOCKED_BY_VISIBILITY
BLOCKED_BY_RESOURCE
BLOCKED_BY_CONTROLS
STALE_CONTEXT
CANCELLED
ROLLED_BACK
CLEANUP_FAILED
```

## 61. Cooldowns

Separate cooldowns:

- transient regression retry;
- fingerprint refresh;
- synthesis run;
- no-solution retry;
- post-promotion stability;
- rollback quarantine for failed winner.

No busy-loop adaptation.

## 62. Configuration changes during run

On ConfigGeneration/NetworkContext change:

```text
cancel active candidates
→ stop issuing new probes
→ drain owned resources
→ cleanup
→ mark evidence/candidates stale
→ new run only after fresh Monitoring assessment
```

## 63. Recovery result handoff

Structured result to Monitoring includes:

- trigger assessment/request IDs;
- solution found/not found;
- winning candidate ID and provenance;
- target/control/canary outcomes;
- promoted generation;
- rollback status;
- next eligible retry time;
- evidence refs;
- explanation safe for UI.

# Часть X. Packet path, ActionService, GSO и PPE

## 64. Synthesizer не исполняет packets

Forbidden imports/dependencies:

```text
discovery/synthesis → mutable nfq internals
discovery/synthesis → iptables backend
discovery/synthesis → runtimecontrol apply implementation
detector/fingerprint → ActionService executor internals
```

Synthesizer emits declarative candidate only.

## 65. ActionPlanner boundary

Every synthesized plan compiles through existing ActionPlanner:

```text
SynthesizedCandidatePlan
→ policy/scope validation
→ representation requirements
→ ActionAuthorization binding
→ stream-offset idempotent ActionPlan
```

Compilation failure rejects candidate before network.

## 66. GSO

Operators requiring packet representation changes declare:

- classify readiness;
- normalization requirement;
- token requirement;
- secondary pass behavior;
- idempotency marker.

`GSO_CLASSIFY_READY` is insufficient for mutation. `GSO_RUNTIME_READY` and current authorization are required where applicable.

## 67. PPE visibility

Automatic adaptation requires current visibility proof appropriate to chosen operator. On visibility degradation:

- active synthesis stops;
- mutation candidates rejected/fail-open;
- existing production path follows its own safe fallback;
- evidence marked incomplete/stale;
- no promotion.

## 68. RST/fake operations

Automatic grammar v1 only allows fake operations already registered as endpoint-safe B4X primitives with:

- bounded count;
- exact flow scope;
- endpoint rejection proof;
- reconnect budget;
- no global firewall suppression;
- no direct passive-RST → active injection conversion.

## 69. Stream semantics

Candidate compiler MUST prove:

- same logical application bytes;
- same order at endpoint after intended transport semantics;
- no hidden byte drop;
- no repeated action on retransmission;
- no duplicate logical write;
- correct sequence/ack mapping;
- correct cleanup after cancellation.

# Часть XI. Persistence, context и reuse

## 70. Existing profile envelope

Behavioral evidence is embedded in existing `BlockingProfile` / `NetworkDiagnosticProfile` path. No second freshness subsystem.

## 71. Local winner key

```text
ServiceProfileID
+ ComponentID
+ ClientScope class
+ NetworkContextID
+ WAN identity hash
+ IP family
+ resolver/TLS profile context
+ grammar version
+ relevant capability generations
```

## 72. Reuse policy

A previous synthesized winner MAY be tested early when:

- context compatible;
- not expired;
- no rollback/quarantine record;
- operator grammar still supported;
- all current hard gates applicable;
- fresh target/control validation is performed.

It is never silently applied solely because it worked before.

## 73. Invalidation

Invalidate on:

- WAN/ASN/provider context change;
- relevant config generation change;
- parser/action grammar version change;
- strategy/operator removal;
- capture/PPE/GSO capability change;
- target plan material change;
- repeated regression under winner;
- rollback caused by collateral effect;
- expiry.

## 74. Store bounds

Recommended:

```text
max winners per scope: 4
max historical evaluations per run: 64
max retained failed plans: 16 with redacted metadata
TTL: bounded by profile/context policy
```

Raw packets/payload are not stored in standard database.

# Часть XII. API and product integration

## 75. Settings API

Extend existing config/settings API; do not create an independent daemon configuration.

Example:

```json
{
  "automation": {
    "adaptive_strategy_synthesis": {
      "enabled": true
    }
  }
}
```

## 76. Discovery run API extension

```json
{
  "scope": {
    "client_key": "...",
    "service_profile_id": "youtube",
    "component_id": "video",
    "network_context_id": "...",
    "config_generation": 42
  },
  "mode": "standard",
  "adaptive_synthesis": {
    "allowed": true,
    "trigger": "monitoring-regression",
    "max_candidates": 24
  }
}
```

Server ignores/denies `allowed=true` when global checkbox is false.

## 77. Status API

Extend existing Detector/Discovery/Monitoring surfaces. Suggested read model:

```go
type AdaptiveSynthesisStatus struct {
    Enabled             bool
    State               string
    Scope               monitor.MonitorScopeKey
    RunID               string
    TriggerAssessmentID string
    BehavioralEvidenceID string
    BlockingProfileID   string

    CandidatesGenerated uint16
    CandidatesRejected  uint16
    CandidatesTested    uint16
    BestCandidateID     string
    WinnerCandidateID   string

    StartedAt           time.Time
    Deadline            time.Time
    NextEligibleRun     time.Time
    Reasons             []string
}
```

## 78. Cancel semantics

Cancel request:

- idempotent;
- stops new candidate issuance;
- waits/drains bounded owned work;
- triggers cleanup;
- leaves current production strategy unchanged;
- marks run `cancelled`, never `pass`.

## 79. Report

Field/issue bundle includes:

- setting state;
- trigger/cooldown;
- profile/fingerprint hashes;
- grammar/synthesizer versions;
- candidate counts and rejection reasons;
- winner canonical plan redacted;
- target/control/canary verdicts;
- promotion/rollback;
- cleanup ledger;
- no raw SNI/DNS/payload by default.

# Часть XIII. Observability and causal trace

## 80. Metrics

Telemetry counters/gauges:

```text
b4_adaptive_synthesis_enabled
b4_adaptive_synthesis_runs_total{trigger,result}
b4_behavioral_fingerprint_runs_total{result}
b4_behavioral_fingerprint_probes_total{family,result}
b4_synthesis_candidates_generated_total{operator_family}
b4_synthesis_candidates_rejected_total{reason}
b4_synthesis_candidates_tested_total{result}
b4_synthesis_novel_candidates_total
b4_synthesis_winners_total{result}
b4_synthesis_promotions_total{result}
b4_synthesis_rollbacks_total{reason}
b4_synthesis_run_duration_seconds
b4_synthesis_candidate_fitness
b4_synthesis_resource_suppressed_total{resource}
b4_synthesis_no_solution_total{reason}
```

Cardinality rules:

- no raw domain, IP, client ID, candidate hash as unbounded labels;
- IDs in structured trace/report, not Prometheus labels;
- operator family finite registry only.

## 81. Required causal trace

```text
monitor.regression_candidate
monitor.regression_confirmed
abd.revalidation_started
abd.revalidation_completed
abd.behavior_panel_started
abd.behavior_probe_completed
abd.behavior_evidence_compiled
ddi.synthesis_constraints_compiled
discovery.synthesis_started
discovery.candidate_generated
discovery.candidate_static_rejected
discovery.candidate_test_started
discovery.candidate_test_completed
discovery.best_candidate_selected
canary.started
canary.completed
runtime.promotion_started
runtime.promotion_completed
runtime.rollback_started
runtime.rollback_completed
synthesis.cleanup_completed
monitor.recovery_observed
```

Every event binds:

```text
RunID
TestSessionID
AssessmentID/RequestID where applicable
NetworkContextID
ConfigGeneration
scope
candidate ID where applicable
monotonic sequence
```

## 82. Trace invariants

- no candidate test before static validation;
- no action before authorization;
- no canary before target/control evaluation;
- no promotion before canary;
- no stale-generation event consumed;
- terminal run has cleanup event;
- rollback does not reactivate stale candidate;
- candidate ID maps to one canonical plan.

# Часть XIV. Hard gates and principal verdicts

## 83. Principal verdicts

```text
BEHAVIORAL_FINGERPRINT_BOUNDED_READY
CONSTRAINED_SYNTHESIS_READY
SYNTHESIZED_DISCOVERY_READY
AUTONOMOUS_DPI_ADAPTATION_READY
```

Dependency:

```text
AUTONOMOUS_DPI_ADAPTATION_READY
= user opt-in capability implemented
+ Monitoring trigger ready
+ ABD behavioral evidence ready
+ DDI constraints/prior ready
+ constrained synthesis ready
+ existing Discovery ready
+ Action/representation ready
+ Android canary ready
+ runtime promote/rollback ready
+ all applicable hard gates pass
```

## 84. Zero-tolerance violation counters

```text
synthesis_without_user_opt_in_total
synthesis_without_persistent_regression_total
synthesis_without_fresh_profile_total
synthesis_stale_generation_used_total
synthesis_grammar_escape_total
synthesis_unsafe_operator_emitted_total
synthesis_scope_escape_total
synthesis_candidate_direct_apply_total
synthesis_without_action_authorization_total
synthesis_missing_mandatory_control_total
synthesis_router_origin_promoted_without_android_total
synthesis_candidate_identity_collision_total
synthesis_cleanup_incomplete_total
synthesis_foreign_resource_mutation_total
synthesis_unbounded_execution_total
synthesis_promotion_without_rollback_ready_total
```

## 85. Current-generation readiness inputs

```text
behavioral_control_health
behavioral_inconclusive_ratio
capture_visibility_state
ppe_visibility_state
gso_classify_readiness
gso_runtime_readiness
discovery_resource_readiness
action_grammar_compatibility
android_canary_availability
rollback_readiness
```

These are derived current-generation inputs, not lifetime zero-tolerance counters.

## 86. Gate semantics

- missing required producer/evidence is `BLOCKED`, not zero/PASS;
- stale profile is `STALE`, not usable prior;
- feature off makes synthesis gates `NOT_APPLICABLE`, but ordinary Discovery remains evaluable;
- research-only operator cannot become automatic by config typo;
- telemetry nonzero does not block unless mapped to explicit current readiness/verdict;
- lifetime historical rollback count does not permanently block future fresh generation.

## 87. Mutation tests for gates

Required mutants:

```text
force enabled=true internally while user setting false
remove regression qualification
use stale behavioral evidence
insert unknown operator into candidate
bypass static validator
call ActionService directly from synthesizer
remove unrelated control
skip Android canary
reuse candidate across generation
make cleanup no-op
remove rollback readiness check
allow unlimited generation loop
force constant READY verdict
```

Each mutant must produce FAIL/BLOCKED in the appropriate chain.

# Часть XV. Security, privacy and operational safety

## 88. Active probing disclosure

Feature is opt-in because it sends extra test traffic and can be detectable by a censor. UI must state this plainly.

## 89. Target permission

Automatic probes only target:

- exact user/service targets already authorized by profile;
- same-service controls;
- unrelated controls from approved registry;
- controlled/reference endpoints with explicit policy.

No arbitrary scanning.

## 90. Sensitive data

Standard telemetry/report MUST NOT contain:

- raw DNS history;
- raw SNI/domain unless user explicitly includes diagnostic bundle;
- client MAC/IP;
- payload bytes;
- TLS secrets;
- full pcap;
- provider credential/config secrets.

## 91. Failure safety

On internal error:

```text
stop synthesis
→ fail-open packet under existing safe path
→ preserve current/last-good production strategy
→ cleanup owned resources
→ report BLOCKED/FAILED
```

## 92. Resource safety

- one active automatic adaptation run by default;
- one network candidate test at a time;
- no independent thread explosion;
- bounded queues;
- deadlines on every stage;
- explicit cancellation;
- CPU/RAM/held packet/queue drop guards;
- no global offload changes;
- no permanent firewall rule.

## 93. Abuse-resistant grammar

Production config cannot upload arbitrary grammar. Grammar comes from signed/built-in registry and versioned generator. Expert local development may load fixtures only in non-production/test mode.

# Часть XVI. Validation strategy

## 94. L0 — static/provenance

Prove:

- pinned references and licenses recorded;
- no direct CenDPI dependency;
- no Geneva Python/Scapy runtime dependency;
- package ownership graph acyclic;
- no second NFQUEUE/iptables owner;
- setting default false;
- grammar finite and generated.

## 95. L1 — unit/property

Tests:

- canonical candidate serialization/hash;
- deterministic generation;
- grammar validation;
- action/branch/amplification bounds;
- stream semantics;
- stale scope/generation rejection;
- fingerprint feature → operator constraint mapping;
- settings semantics;
- cooldown state machine;
- persistence/invalidation;
- no duplicate candidate IDs.

## 96. L2 — fuzz

Fuzz:

- candidate decoder/parser;
- grammar registry loader;
- canonicalizer;
- mutation/crossover;
- constraint solver;
- trace decoder;
- API request validation.

Properties:

- never emit unregistered operator;
- never exceed declared bounds;
- never panic;
- canonicalization idempotent;
- invalid plans rejected before ActionPlanner.

## 97. L3 — synthetic DPI laboratory

Build deterministic fixtures:

- shallow TLS parser;
- TCP out-of-order ambiguity;
- duplicate segment ambiguity;
- packet-count threshold;
- byte-count threshold;
- reset-after-trigger;
- endpoint rejects mutation;
- controls unhealthy;
- compound/noisy path.

Expected:

- correct behavioral feature subset;
- correct operator constraints;
- synthesizer creates at least one novel valid candidate when solution expressible;
- no solution reported when grammar cannot express solution.

## 98. L4 — offline packet replay

Use pcap/trace fixtures to verify:

- generated packet program matches canonical plan;
- endpoint-visible logical stream preserved;
- retransmission idempotency;
- GSO/MSS parity where applicable;
- trace order;
- cost estimates.

## 99. L5 — Docker/network namespace lab

Validate:

- netfilter/capture integration;
- cancel/cleanup;
- queue pressure;
- route change;
- process restart;
- config generation change;
- concurrent user traffic isolation;
- target/control matrix;
- rollback.

## 100. L6 — Keenetic target

Real router evidence:

- CPU/RAM budgets;
- Entware compatibility;
- capture/PPE/GSO visibility;
- candidate cap and duration;
- no rule leakage;
- no queue/token leak;
- current production traffic remains safe;
- restart cleanup;
- setting survives config persistence.

## 101. L7 — Android forwarded-client

Scenarios:

- current preset works: no synthesis;
- transient failure: no synthesis;
- persistent regression: escalation occurs;
- catalog solution exists: catalog may win without synthesis;
- only synthesized combination works: Android canary passes;
- target works but Gmail/unrelated control breaks: candidate rejected;
- canary failure: rollback;
- user disables checkbox mid-run: cancel/cleanup;
- network changes mid-run: stale/cancel/restart fresh.

## 102. L8 — validation-of-validation

Mutate:

- opt-in gate;
- freshness check;
- control requirement;
- Android canary requirement;
- grammar limit;
- cleanup call;
- rollback readiness;
- generation binding;
- prior consumption;
- constant readiness.

Meta-suite must detect every mutation.

## 103. Performance acceptance

Automatic mode must prove on target class:

- bounded wall time;
- bounded packets/bytes;
- no sustained queue drop regression;
- no unacceptable control latency;
- no goroutine/resource leak;
- early stop works;
- disabled state has negligible overhead.

# Часть XVII. Implementation stages

## AFS-1 — Supersession and reference audit

Deliverables:

- mark prior fingerprint-only addendum superseded;
- pin CenDPI/Geneva references;
- license/clean-room record;
- current architecture/file crosswalk;
- owner approval of one-capability model.

Acceptance:

- no implementation task references old DBF stages;
- new AFS stages are canonical.

## AFS-2 — Settings and capability contract

Implement:

- global checkbox/config;
- default false;
- Service Profile upper bound;
- API persistence/migration;
- opt-in hard gate producer.

Acceptance:

- off means zero automatic fingerprint/synthesis runs;
- enabling does not immediately mutate production config.

## AFS-3 — Behavioral evidence schema inside existing profile

Implement:

- `BehavioralFingerprintEvidence`;
- feature registry;
- evidence graph integration;
- DDI freshness/context binding;
- no separate profile service/store.

## AFS-4 — Bounded behavioral panel

Implement endpoint-safe panel through existing experiment/action infrastructure.

Acceptance:

- controls;
- inconclusive;
- budgets;
- cleanup;
- IPv4 and explicit IPv6 state;
- no research probes automatic.

## AFS-5 — Feature-to-operator constraint compiler

Implement registry:

```text
behavior feature
→ boost/penalize/exclude operator family
→ required differential
→ representation prerequisite
```

Acceptance:

- deterministic;
- versioned;
- no direct strategy output;
- stale evidence rejected.

## AFS-6 — Canonical safe synthesis grammar

Implement finite generated grammar and validators.

Acceptance:

- all operators map to existing B4X ActionPlanner primitives;
- unknown/unsafe operator rejected;
- bounds enforced;
- canonical hash stable.

## AFS-7 — Deterministic bounded synthesizer

Implement:

- seed builder;
- mutation;
- bounded crossover;
- canonicalization;
- deduplication;
- cost model;
- generation/early-stop budgets.

Acceptance:

- deterministic fixtures;
- no network execution in package;
- no unsafe plans emitted.

## AFS-8 — ActionPlanner compiler bridge

Implement candidate → existing ActionPlan compilation and static rejection reasons.

Acceptance:

- no separate packet executor;
- authorization and representation contracts preserved;
- idempotency/retransmission tests.

## AFS-9 — Discovery integration

Implement prior consumption and merge synthesized candidates into current GuidedSearchPlan.

Acceptance:

- `_ = prior` removed;
- baselines/controls/full fallback retained;
- catalog and synthesized candidates share scoring pipeline;
- no direct apply.

## AFS-10 — Fitness and iterative search

Feed measured Discovery outcomes into bounded next generation.

Acceptance:

- target success alone insufficient;
- collateral/resource/stability penalties active;
- max generations/candidates enforced;
- no-solution terminal state.

## AFS-11 — Monitoring orchestration

Implement persistent-regression trigger, cooldown, cancellation, context change handling and recovery observation.

Acceptance:

- one transient failure never starts synthesis;
- no busy loop;
- user disable cancels safely;
- Monitoring remains non-mutating.

## AFS-12 — Winner persistence and UX/API

Implement:

- local winner persistence;
- provenance;
- expiry/revalidation;
- status API;
- beginner/advanced UI;
- revert-to-catalog action.

## AFS-13 — Lab/target validation

Run L0–L7, including real Keenetic and Android.

Artifacts:

```text
AFS_REFERENCE_AUDIT.md
AFS_GRAMMAR_REGISTRY_REPORT.md
AFS_SYNTHETIC_DPI_MATRIX.json
AFS_CANDIDATE_GENERATION_REPORT.json
AFS_DISCOVERY_INTEGRATION_REPORT.json
AFS_KEENETIC_RESOURCE_REPORT.json
AFS_ANDROID_CANARY_REPORT.json
AFS_CLEANUP_LEDGER.json
```

## AFS-14 — Validation-of-validation and closure

Run mutation suite and full build/vet/test/race/fuzz-smoke as applicable.

Closure requires:

- all principal verdicts PASS or explicit target BLOCKED;
- no residual direct apply path;
- remote branch commit/push evidence;
- clean worktree;
- complete evidence matrix;
- user setting documented.

# Часть XVIII. Current branch file plan

## 104. New files

Recommended:

```text
src/detector/behavior/
  evidence.go
  feature_registry.go
  panel.go
  analyzer.go
  constraints.go

src/discovery/synthesis/
  types.go
  grammar.go
  grammar_gen.go
  seed.go
  mutate.go
  crossover.go
  canonical.go
  validate.go
  cost.go
  planner.go
  fitness.go
  persistence.go
  metrics.go

specs/registries/
  behavior_features.yaml
  synthesis_grammar.yaml
  behavior_operator_mapping.yaml

tools/
  gen_behavior_features.py
  gen_synthesis_grammar.py
  gen_behavior_operator_mapping.py
```

Package layout MAY be flattened, but service ownership must remain.

## 105. Existing files to extend

```text
src/detector/abd_graph.go
src/detector/abd_profile.go
src/detector/abd_ddi.go
src/discovery/hint_planner.go
src/discovery/*
src/action/*
src/monitor/*
src/config/*
src/http/handler/*
src/runtimecontrol/*
src/validation/*
src/fieldtest/*
specs/registries/hard_gates.yaml
B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md
B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md
B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md
```

## 106. Forbidden files/components

```text
src/geneva_engine/*
python runtime dependency
second NFQUEUE manager
second iptables owner
DPIBehaviorService
StandaloneSynthesizerDaemon
runtime-downloaded grammar
user-provided raw Geneva DNA executor
```

# Часть XIX. Acceptance criteria

## 107. Functional

1. Отдельная галочка существует, default off, сохраняется и применяется.
2. При выключенной галочке автоматический fingerprint/synthesis не запускается.
3. Persistent regression может инициировать bounded chain.
4. Behavioral evidence сужает/упорядочивает operator space.
5. Synthesizer создаёт canonical novel combinations из allowlisted primitives.
6. Existing Discovery реально тестирует synthesized candidates.
7. Catalog presets, baselines, controls и full fallback сохраняются.
8. Победитель проходит Android/forwarded-client canary.
9. Promotion/rollback выполняет существующий TransactionalRuntime.
10. Успешный winner может быть безопасно переиспользован после revalidation.

## 108. Safety

1. Нет synthesis без opt-in.
2. Нет synthesis по одному transient failure.
3. Нет unsafe/research operator в automatic mode.
4. Нет direct packet execution synthesizer-ом.
5. Нет direct apply candidate-а.
6. Нет promotion без authorization, controls и Android canary.
7. Нет reuse stale context/generation.
8. Budget exhaustion завершает run, а не расширяет budget.
9. Cancel/restart/config change выполняют cleanup.
10. Failure сохраняет current/last-good strategy.

## 109. Architecture

1. Один Detector/ABD.
2. Один Discovery/optimizer.
3. Один ActionService packet executor.
4. Один TransactionalRuntime owner apply/rollback.
5. Behavioral evidence встроен в existing profile/evidence graph.
6. Synthesized candidates являются обычными Discovery candidates.
7. Service Profiles задают policy upper bound, не runtime ownership.

## 110. Evidence

1. Каждый principal verdict имеет producer/consumer/gate/evidence.
2. API, report, metrics и internal state согласованы.
3. Missing/skipped/stale не трактуется как PASS.
4. Mutation suite доказывает невозможность shortcut paths.
5. Real target evidence отделено от fixtures/mocks.

## 111. Release rule

Capability может называться production-ready только если:

```text
AUTONOMOUS_DPI_ADAPTATION_READY == PASS
```

и реальный Keenetic + Android target run доказал хотя бы:

- безопасный запуск по регрессии;
- генерацию novel candidate;
- общую Discovery цепочку;
- target + controls;
- canary;
- promotion/rollback;
- cleanup;
- отсутствие collateral damage.

Если реального DPI, требующего synthesized combination, нет, release verdict должен быть:

```text
IMPLEMENTED / LAB_VALIDATED / BLOCKED_BY_TARGET_EVIDENCE
```

а не ложный production PASS.

# Часть XX. Architectural Decision Records

## ADR-AFS-001 — One combined capability

Fingerprint-only production capability superseded. Behavioral fingerprinting реализуется только как внутренний этап autonomous adaptation.

## ADR-AFS-002 — User opt-in

Automatic strategy synthesis требует отдельной default-off галочки.

## ADR-AFS-003 — Synthesis belongs to Discovery

ABD создаёт evidence. Discovery создаёт candidates. ActionService исполняет. Runtimecontrol применяет.

## ADR-AFS-004 — Native constrained implementation

B4X не запускает Geneva Python engine. Используется нативная конечная grammar поверх существующих primitives.

## ADR-AFS-005 — New combination, not new executable primitive

Synthesizer может менять composition, order, trigger и bounded parameters, но не создавать новый kernel/packet primitive.

## ADR-AFS-006 — No direct apply

Любой synthesized candidate проходит обычный ActionPlanner, Discovery, controls, Android canary и transactional promotion.

## ADR-AFS-007 — Bounded router search

Automatic search имеет конечные population/generation/candidate/time/resource limits и concurrency 1 по умолчанию.

## ADR-AFS-008 — Full fallback retained

Fingerprint/synthesis не удаляют mandatory baselines, controls или full bounded fallback.

## ADR-AFS-009 — Behavioral evidence embedded

Отдельный behavioral profile service/store не создаётся; evidence живёт в существующем diagnostic envelope.

## ADR-AFS-010 — Local winners are scoped

Synthesized winner не становится глобальным preset. Он scoped, expiring и требует revalidation.

## ADR-AFS-011 — Monitoring triggers but never mutates

Monitoring инициирует bounded run и наблюдает результат, но не создаёт/применяет strategy.

## ADR-AFS-012 — FlowPaint remains outside v1

Diffusion model не входит в router runtime. Возможный offline teacher рассматривается отдельным research document.

# Appendix A. Пример пользовательского сценария

## A.1. До изменения DPI

```text
YouTube video
→ production strategy preset `tls-split-03`
→ Monitoring healthy
```

## A.2. После изменения DPI

```text
Monitoring:
- API/UI controls healthy
- video milestones repeatedly fail
- current strategy previously healthy
- regression persistent
```

## A.3. ABD

```text
ordinary diagnosis:
- DNS healthy
- TCP connect healthy
- TLS stalls after ClientHello
- catalog candidates fail

behavioral panel:
- TLS record split changes DPI outcome
- bounded out-of-order changes outcome
- IP family not causal
```

## A.4. Constraints

```yaml
boost:
  - tls_record_split
  - tcp_split
  - bounded_disorder
penalize:
  - padding_only
exclude:
  - ip_fragment
```

## A.5. Synthesized candidates

```text
C1 tls_record_split(before_sni)
C2 tcp_split(inside_sni_mid) + tls_record_split
C3 tcp_split(inside_sni_mid) + bounded_disorder(swap_once)
C4 tls_record_split + padding(8)
C5 tcp_split + tls_record_split + bounded_disorder
```

## A.6. Discovery

```text
baseline-none          FAIL
baseline-production    FAIL
preset candidates      FAIL
C1                     PARTIAL
C2                     PASS target, PASS controls
C3                     PASS target, unrelated control regression → REJECT
```

## A.7. Canary/promotion

```text
C2 Android canary PASS
→ transactional promote
→ Monitoring stability PASS
→ C2 saved as scoped local synthesized winner
```

# Appendix B. Example config

```yaml
automation:
  adaptive_strategy_synthesis:
    enabled: true

    max_candidates: 24
    max_generations: 3
    max_actions: 4
    max_branches: 1
    run_timeout: 180s
    cooldown: 30m
    failed_search_cooldown: 6h

    allow_safe_fake: false
    allow_bounded_disorder: true
    allow_jitter: true

detector:
  behavioral_panel:
    max_probes: 8
    attempts_per_probe: 2
    max_duration: 60s
    max_risk_tier: endpoint-safe

discovery:
  max_active_runs: 1
  max_parallel_probes: 1
  retain_full_fallback: true
```

# Appendix C. Example canonical candidate

```json
{
  "candidate_id": "syn-4d8f...",
  "grammar_version": "b4x-safe-v1",
  "scope": {
    "service_profile_id": "youtube",
    "component_id": "video",
    "network_context_id": "wan-...",
    "config_generation": 42
  },
  "trigger": {
    "phase": "first-clienthello",
    "marker": "complete-clienthello"
  },
  "operations": [
    {
      "kind": "tcp_split",
      "marker": "inside-sni-mid"
    },
    {
      "kind": "tls_record_split",
      "marker": "before-sni"
    },
    {
      "kind": "bounded_disorder",
      "pattern": "swap-adjacent-once"
    }
  ],
  "limits": {
    "max_actions": 4,
    "max_branches": 1,
    "max_amplification": 1.5
  },
  "provenance": {
    "kind": "synthesized",
    "fingerprint_evidence_id": "be-...",
    "blocking_profile_id": "bp-...",
    "synthesizer_version": "afs-v1"
  }
}
```

# Appendix D. Agent implementation prohibitions

Coding agent MUST NOT:

- реализовывать старые `DBF-1…DBF-12` как отдельный subsystem;
- создавать отдельный behavioral profile API/service/store;
- vendor/import CenDPI до license decision;
- запускать Geneva `engine.py`;
- добавлять Python/Scapy dependency в router runtime;
- создавать новый NFQUEUE queue owner;
- создавать новый iptables lifecycle owner;
- принимать arbitrary Geneva DNA из UI/API;
- включать unsafe actions automatic mode;
- считать target-only success достаточным;
- пропускать Android canary;
- сохранять все generated candidates в глобальный catalog;
- расширять budget после exhaustion;
- скрывать `BLOCKED_BY_TARGET` под PASS;
- делать setting default true;
- запускать synthesis при выключенной галочке;
- применять winner без transactional rollback readiness.

# Appendix E. Definition of Done

```text
[ ] old fingerprint-only addendum marked SUPERSEDED
[ ] global default-off checkbox implemented and persisted
[ ] no automatic run when disabled
[ ] no single-failure trigger
[ ] bounded endpoint-safe behavioral panel
[ ] behavioral evidence embedded in existing profile
[ ] DDI freshness and operator constraints
[ ] finite generated synthesis grammar
[ ] deterministic bounded candidate generation
[ ] no unsafe operator escape
[ ] existing ActionPlanner compiles candidates
[ ] existing Discovery consumes prior and candidates
[ ] mandatory baselines/controls/full fallback retained
[ ] Android canary mandatory
[ ] transactional promote/rollback
[ ] local scoped winner persistence
[ ] context/generation invalidation
[ ] cancellation and cleanup
[ ] metrics/API/report parity
[ ] hard gates and mutation tests
[ ] Docker/Keenetic/Android evidence
[ ] full build/vet/test/race/fuzz-smoke green
[ ] closure commits pushed and worktree clean
```

# Appendix F. Pinned references

## F.1. dMAP paper

```text
Fingerprinting Deep Packet Inspection Devices by Their Ambiguities
ACM CCS 2025
arXiv: 2509.09081v1
```

## F.2. CenDPI fork

```text
repository: AlexZander85/CenDPI
commit: 8e470ac7cf8919f9c0b1ea1c019d09a3dff8c427
usage: behavioral reference only; clean-room production implementation
```

## F.3. Geneva

```text
repository: Kkevsterrr/geneva
commit: 28a3fa63dff1eebe7e92dcf00f69ca480a81cd3a
license: BSD-3-Clause
usage: conceptual reference for declarative action trees, mutation, crossover and fitness
```

## F.4. Current B4X integration points

```text
src/detector/abd_graph.go
src/detector/abd_profile.go
src/detector/abd_ddi.go
src/discovery/hint_planner.go
src/action/*
src/monitor/*
src/runtimecontrol/*
specs/registries/hard_gates.yaml
```

---

# Итог

Этот addendum заменяет самостоятельный fingerprint-only проект единой пользовательски значимой системой:

```text
Behavioral Fingerprinting
+
Constrained Geneva-inspired Synthesis
+
existing Discovery
```

При включённой отдельной галочке B4X получает возможность после подтверждённой регрессии не только перебрать старые presets, но и создать ограниченный набор новых безопасных комбинаций существующих packet primitives, доказательно проверить их на target/controls/Android и применить только через текущий transactional promotion/rollback path.
