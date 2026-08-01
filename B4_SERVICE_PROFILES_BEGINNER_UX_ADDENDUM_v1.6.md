# B4 Service Profiles, Transport Profiles & Beginner UX Addendum

**Статус:** нормативное post-v2.3 companion-дополнение к `B4_FORK_ARCHITECTURE.md`, завершённому `B4_FORK_PATCH_PLAN.md`, `B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md`, `B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM.md` v1.2, `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md`, `B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM.md` v1.0, `B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM.md` v1.1, `B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM.md` v1.0, `B4_FIELD_TEST_AUTOMATION_ADDENDUM` v1.5 и `B4_AGENT_PROMPT.md` v2.3  
**Редакция:** 1.6 — полностью сохраняет редакции 1.1–1.5; синхронизируется с WARP/MASQUE v1.2, ABD v1.1, Field Test v1.5 и Implementation Validation v1.5; добавляет evidence-gated рекомендацию base WARP при подтверждённой IP/SYN/CIDR path blocking, scoped WARP validation UX и stages `SP-30`–`SP-32`  
**Дата:** 2026-07-30  
**Назначение:** добавить предустановленные профили сервисов, транспортные профили и простой режим настройки без внесения service-specific логики в packet engine B4X, гарантируя cross-service isolation, безопасную проекцию WARP/MASQUE, false-positive-safe scoped recovery, target-oriented Detector v2/guided Discovery, evidence-gated предложение base WARP для IP-level path blocking и bounded transparent Telegram bridge lifecycle.  
**Порядок выполнения:** исходные Stage 1–36 и PPE stages считаются завершёнными. Runtime optimized profiles допускается после CSI; WARP profiles и WARP recommendations — после применимых WARP/WARP-C и causal-trace gates; silent active recovery — только после применимых SPF/FT/IV gates; Detector-guided search — после ABD/DDI clean-baseline и target-validation gates; transparent Telegram bridge — после TGB resource/prefix/Android gates; GSO-active и Passive-RST-active возможности — после соответствующих RST/GSO gates.

---


## Нормативная последовательность

```text
B4_FORK_ARCHITECTURE.md v2.3
→ завершённый B4_FORK_PATCH_PLAN.md Stage 1–36
→ завершённый B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md
→ B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md
→ B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM.md v1.1
→ B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md
→ B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM.md v1.0
→ B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM.md v1.0
→ B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM.md v1.0
→ B4_FIELD_TEST_AUTOMATION_ADDENDUM v1.5
→ этот Service Profiles / Beginner UX addendum v1.6
→ B4_IMPLEMENTATION_VALIDATION_ADDENDUM v1.5
→ конкретные profile packs и их production promotion
```

При расхождении:

1. архитектура v2.3 задаёт core invariants;
2. Cross-Service Scope Isolation addendum задаёт обязательную семантику классификации, authorization и scoped side effects;
3. Built-in WARP/MASQUE v1.2 задаёт bundled transport, control-flow authorization, camouflage, nested non-RU и lifecycle invariants;
4. RST/GSO Hardening addendum задаёт packet representation, GSO lifecycle и Passive RST safety;
5. Silent Path Failure v1.0 задаёт evidence independence, suppression, differential proof, leases и rollback invariants;
6. Adaptive Blocking Detector v1.1 задаёт TargetPlan, clean-path evidence, `BlockingProfile` и guided-prior semantics;
7. Detector-Guided Discovery/TGB v1.0 задаёт DDI freshness/search integration и transparent bridge lifecycle;
8. Field Test Automation v1.4 задаёт доказательные suites и promotion gates;
9. этот документ задаёт declarative control-plane projection capabilities в profiles, compiler, UI и validation policy.

Service profile MUST NOT переопределять более строгий runtime safety gate.

# 0. Решение

Активный патч-план v2.3 **не изменяется**.

Добавляется отдельный слой:

```text
Service Profile Framework
```

Он:

- не входит в Core Fix;
- не добавляет ветки `if YouTube` / `if Discord` / `if Telegram` в packet engine;
- не создаёт параллельную систему классификации;
- не заменяет ручные sets, strategies и Discovery;
- поддерживает разные способы доставки: `direct-strategy`, `external-proxy`, `router-tunnel`, `client-configured` и `hybrid`;
- компилирует direct-компоненты в обычные сущности B4;
- компилирует router-transport компоненты в обычные scoped transport bindings B4, если соответствующая capability доступна;
- для client-configured proxy формирует health result и безопасный setup handoff, не вмешиваясь в packet path;
- использует transactional apply, canary, last-good и rollback из v2.3;
- предоставляет beginner UX и обновляемый каталог профилей.

---


## 0.1. Дополнительное решение редакции 1.2

Service Profile Framework больше не считает достаточной формулировку «обычный set проходит через обычный classifier». Compiler обязан явно проверить, что скомпилированный direct-компонент получает:

```text
CaptureCandidate
→ ClassificationDecision
→ ActionAuthorization
→ ActionPlan / scoped transport binding
```

а не старую неявную цепочку:

```text
IP/CIDR/port matched
→ service action
```

Для shared infrastructure, включая Google frontends/CDN, destination IP является только возможной причиной наблюдать flow. Он не является самостоятельным разрешением применить YouTube strategy, QUIC reject, block verdict, escalation, proxy route или Passive RST suppression.

Optimized profile считается корректным только при доказанной изоляции одновременно:

- между разными LAN-клиентами;
- между разными сервисами одного клиента;
- между API/UI/media components одного сервиса;
- между production и Discovery/canary generations;
- между ordinary MSS path и GSO capture path.

# 1. Архитектурный инвариант

Service Profile Framework работает только в control plane. Конкретный runtime path определяется явно объявленным `delivery_mode`.

## 1.1. Direct strategy

```text
flow
→ evidence
→ ordinary B4 set
→ ordinary strategy binding
→ action planner/executor
```

Используется для сервисов и компонентов, где прямой маршрут существует, а доступ восстанавливается packet-level техникой.

## 1.2. Router transport

```text
flow
→ evidence/set
→ ordinary scoped transport binding
→ external SOCKS/tunnel route
```

Используется только при наличии generic transport capability B4. Это не отдельный service-specific routing engine.

## 1.3. Client-configured transport

```text
service profile
→ direct-path diagnosis
→ proxy healthcheck
→ QR/deep-link/manual setup artifact
→ клиентское приложение подключается к proxy
```

Этот режим не создаёт packet action. B4 не меняет настройки приложения без явного client-side действия или отдельного разрешённого companion/controller.

## 1.4. Compile pipeline

```text
service manifest
→ validate
→ resolve delivery modes
→ compile ordinary sets/strategies/probes/transport bindings
→ create optional client setup artifacts
→ preview diff
→ immutable config generation
```

После компиляции packet engine не обязан знать, были объекты:

- созданы вручную;
- импортированы;
- сгенерированы мастером;
- установлены из service profile;
- обновлены profile catalog.

Запрещено:

```go
if serviceID == "youtube" {
    // special packet path
}

if serviceID == "telegram" {
    // special tunnel or proxy path
}
```

Разрешено:

```go
decision := classifier.Resolve(flow, evidence)
binding := runtime.BindingFor(decision.SetID)
```

`binding` может быть обычной packet strategy или generic scoped transport binding. Для `client-configured` компонента runtime binding может отсутствовать: профиль управляет диагностикой и настройкой клиента, а не перехватом потока.


---


## 1.5. Capability projection, а не capability ownership

Profile manifest MAY объявлять требования и допустимые режимы использования generic capabilities, но MUST NOT владеть их lifecycle.

```text
profile manifest
→ capability requirement / upper bound
→ compiler validation
→ effective runtime capability из immutable generation
```

Profile pack не создаёт самостоятельно:

- NFQUEUE queues;
- GSO normalizer topology;
- packet marks;
- `GSOPassToken` store;
- Passive RST baseline store;
- suppression budget;
- global offload policy;
- destination-global route/ipset.

Эти объекты принадлежат generic runtime/control plane и применяются transactionally.

## 1.6. Same-client cross-service isolation

`source-device scope` не решает проблему, когда YouTube, Gmail и Google app работают на одном телефоне. Поэтому обязательный scope direct-компонента включает:

```text
ClientKey
+ FlowKey
+ selected SetID / ComponentID
+ positive domain evidence
+ ConfigGen
+ ActionAuthorization
```

Ни DNS hint, ни IP failure cache, ни route binding одного YouTube flow не должны становиться authorizing state для Gmail/Google Feed flow того же клиента.

# 2. Цели

## 2.1. Beginner UX

Новичок должен иметь возможность:

```text
выбрать сервис
→ выбрать устройства
→ установить рекомендуемую конфигурацию
→ запустить проверку
→ получить понятный статус
```

без обязательного знания:

- доменной инфраструктуры сервиса;
- различий API/UI/media;
- set priorities;
- fake payload parameters;
- split markers;
- Discovery matrix;
- canary mechanics.

## 2.2. Expert compatibility

Эксперт должен сохранить полный доступ к:

- Sets;
- Strategies;
- Discovery;
- Evidence;
- Flows;
- Trace;
- profile manifests;
- compiled objects;
- preview diff;
- ownership/provenance;
- pin/exclude/manual override.

## 2.3. Upstream maintainability

Generic framework и конкретные service packs должны быть разделены так, чтобы upstream мог принять:

- schema;
- compiler;
- ownership metadata;
- import/export;
- preview diff;
- optional wizard;

не принимая на себя обязательство поддерживать конкретные YouTube/Discord/Instagram каталоги.

---

# 3. Термины

## Service Profile

Версионированное описание сервиса, его компонентов, seed rules, probes, objectives и candidate policies.

## Service Component

Логическая часть сервиса:

```text
api
ui
media
voice
gateway
messaging
cdn
```

В зависимости от `delivery_mode` компонент компилируется:

- в один или несколько обычных B4 sets и strategy bindings;
- в generic scoped transport binding;
- в client setup action и health probes;
- в комбинацию этих объектов для hybrid-компонента.

## Managed Object

Set, strategy binding, transport binding, probe, component policy или client setup descriptor, созданный profile compiler и имеющий ownership/provenance metadata.

## Manual Object

Объект, созданный пользователем вне profile compiler.

## Profile Pack

Набор manifest и связанных data files для одного сервиса.

## Profile Catalog

Набор bundled/official/community/local packs.

## Service Delivery Mode

Явно объявленный способ восстановления доступа:

```text
direct-strategy
external-proxy
router-tunnel
client-configured
hybrid
```

## Transport-required Profile

Профиль, для которого packet desync не является основным решением. Он диагностирует прямой путь и предлагает или настраивает внешний transport.

## Client Setup Artifact

Локально сформированный QR-код, deep link или инструкция для настройки proxy в клиентском приложении. Artifact не является исполняемым profile code и не должен содержаться в публичном profile pack вместе с пользовательскими secrets.

---


## Effective Domain Policy

Итоговая policy конкретного compiled set/component после объединения global defaults, profile requirements и explicit user override.

```text
strict
scoped-hints
legacy
disabled
```

Bundled optimized direct-strategy profile MUST использовать `strict` или `scoped-hints`. `legacy` допускается только как явно помеченная compatibility migration, а `disabled` — только для компонента, где IP/CIDR action является сознательно разрешённой моделью и отсутствует риск shared infrastructure.

## Capture Candidate

Предварительный кандидат, полученный из IP/CIDR, порта, capture scope или неполного evidence. Он разрешает наблюдение, reassembly и collection, но сам по себе не разрешает packet mutation, drop/reject, proxy routing, escalation или state promotion.

## Action Authorization

Иммутабельный результат policy decision, подтверждающий, что конкретный flow может использовать конкретный set/component и action class. Authorization содержит scope и config generation и не переносится на другой flow.

## Negative Control

Приложение или сценарий, который не относится к оптимизируемому компоненту, но использует потенциально общую инфраструктуру. Для YouTube обязательные same-client controls:

```text
Gmail
Google app / Discover feed
```

## Capability Requirement

Declarative требование profile/component к generic runtime capability. Оно задаёт минимум или максимально допустимый режим, но не включает capability автоматически.

# 4. Уровни поддержки профиля

Профиль обязан объявлять уровень зрелости.

```text
basic
structured
optimized
device-aware
```

## Basic

Для `direct-strategy`/`hybrid`:

- seed domains;
- один или несколько sets;
- безопасный рекомендуемый starter binding;
- обычный generic Discovery.

Для `transport-required`:

- direct-path probe;
- список поддерживаемых transport types;
- setup workflow;
- healthcheck без автоматического global routing.

## Structured

- разделение на компоненты;
- отдельные sets;
- component-specific probes;
- отдельная health summary.

## Optimized

- component-specific optimization objectives;
- API/UI/media ranking;
- CDN/body/throughput probes;
- canary policy;
- stable last-good workflow.

## Device-aware

- validation на конкретном классе клиента;
- Android workflow;
- optional exact milestones;
- declared supported app variants.

Профиль не должен называться `optimized`, если он содержит только статический список доменов.

---

# 5. Manifest schema

Концептуальный формат:

```yaml
schema: 1
id: youtube
name: YouTube
version: 2026.07.1
maturity: optimized
service_class: direct-strategy

compatibility:
  min_b4_api: 1
  required_capabilities:
    - service-profile-compiler
    - transactional-config
    - discovery-sandbox

components:
  - id: api
    display_name: API
    delivery: direct-strategy
    managed_set: youtube-api
    objective: startup-latency
    seeds:
      - type: domain-suffix
        value: youtubei.googleapis.com
    discovery_profile: service-api

  - id: ui
    display_name: UI
    delivery: direct-strategy
    managed_set: youtube-ui
    objective: startup-latency
    seeds:
      - type: domain-suffix
        value: youtube.com
      - type: domain-suffix
        value: ytimg.com
    discovery_profile: service-ui

  - id: video
    display_name: Video
    delivery: direct-strategy
    managed_set: youtube-video
    objective: media-goodput
    seeds:
      - type: domain-suffix
        value: googlevideo.com
    discovery_profile: streaming-media


classification:
  domain_policy: scoped-hints
  ip_match_role: capture-only
  negative_sni_override: true
  shared_ip_policy: ambiguous-fail-open
  legacy_learned_ip: diagnostic-only

execution:
  gso_policy: inherit
  passive_rst_policy: observe-max
  route_scope: flow-client-set-generation
  failure_state_scope: flow-client-set-domain-generation

validation:
  required_negative_controls:
    - gmail
    - google-feed
  require_zero_unrelated_actions: true

defaults:
  quic_policy: test-reject-fallback
  apply_mode: recommend

provenance:
  source: bundled
  license: project-data-license
  revision: ...
```

Это пример структуры, а не окончательный список доменов.



## 5.1. Cross-service и hardening schema

Для `direct-strategy` и packet-части `hybrid` компонента schema v1.2 добавляет:

```go
type ComponentClassificationPolicy struct {
    DomainPolicy          DomainOnlyMode
    IPMatchRole           IPMatchRole
    NegativeSNIOverride   bool
    SharedIPPolicy        SharedIPPolicy
    LegacyLearnedIPPolicy LearnedIPPolicy
}

type ComponentExecutionPolicy struct {
    GSOPolicy             ProfileGSOPolicy
    PassiveRSTPolicy      ProfilePassiveRSTPolicy
    RouteScope            ScopeRequirement
    FailureStateScope     ScopeRequirement
}

type ComponentValidationPolicy struct {
    RequiredNegativeControls []ControlScenarioID
    RequireZeroUnrelatedActions bool
}
```

Допустимые значения:

```text
IPMatchRole:
  capture-only
  action-eligible-explicit

SharedIPPolicy:
  ambiguous-fail-open
  require-positive-domain

ProfileGSOPolicy:
  inherit
  accept-only
  normalize-if-required
  direct-if-certified

ProfilePassiveRSTPolicy:
  off-max
  observe-max
  conservative-max
```

### Compiler rules

1. Bundled `optimized` YouTube component MUST компилироваться с `domain_policy=scoped-hints` либо более строгим `strict`.
2. `ip_match_role=action-eligible-explicit` запрещён для broad Google/CDN ranges и требует отдельного reviewed exception.
3. `negative_sni_override=false` запрещён для shared-infrastructure direct component.
4. Profile не может запросить `passive_rst_policy=aggressive`.
5. `conservative-max` не включает conservative автоматически; он только разрешает использовать уже подтверждённый runtime mode.
6. `direct-if-certified` допустим только для techniques, присутствующих в runtime capability matrix как GSO-safe.
7. Profile не может включать `capture.nfqueue.gso_mode=full`.
8. Profile не может ослабить incomplete-visibility fail-open gate.
9. Route/failure scopes уже, чем runtime minimum, допустимы; шире — отклоняются.
10. Старый manifest без этих полей мигрирует с безопасными effective defaults, не с permissive значениями.

### Safe migration defaults

```yaml
classification:
  domain_policy: inherit
  ip_match_role: capture-only
  negative_sni_override: true
  shared_ip_policy: ambiguous-fail-open
  legacy_learned_ip: diagnostic-only
execution:
  gso_policy: inherit
  passive_rst_policy: observe-max
```

Для существующего manual profile UI MUST показать migration warning, если его фактический compiled set использует `legacy` или `disabled` вместе с широкими IP/CIDR targets.

## 5.2. Transport-required manifest example

Telegram не должен описываться как обычный список доменов с `multisplit` или fake SNI. При подтверждённой блокировке прямого пути к Telegram DC основной вариант — внешний transport.

```yaml
schema: 1
id: telegram
name: Telegram
version: 2026.07.1
maturity: structured
service_class: transport-required

compatibility:
  min_b4_api: 1

components:
  - id: messaging
    display_name: Messaging
    delivery: client-configured
    supported_transports:
      - mtproxy
      - socks5
      - router-tunnel
    objective: connection-stability
    direct_path_probe: telegram-dc-connectivity

  - id: media
    display_name: Media
    delivery: hybrid
    supported_transports:
      - client-mtproxy
      - client-socks5
      - router-tunnel
    objective: transport-goodput

failure_policy:
  ip_block_suspected:
    prefer:
      - client-mtproxy
      - client-socks5
      - router-tunnel
    forbid_primary_fallback:
      - packet-desync-matrix

client_handoff:
  allowed:
    - tg-proxy-link
    - qr-code
    - manual-instructions
```

Ключевые ограничения:

- Telegram-клиент уже использует MTProto как протокол; для обхода нужен удалённый MTProxy, SOCKS5 или внешний tunnel path.
- MTProxy на том же роутере без внешнего незаблокированного выхода не устраняет блокировку Telegram DC.
- Profile pack не содержит публичных proxy credentials или secrets.
- B4 может проверить доступность endpoint и сформировать локальный setup artifact из пользовательской конфигурации.
- Router-level tunnel используется только через generic transport fallback и scoped policy routing.
- Packet-level technique допускается как диагностический эксперимент только при доказанной DPI-зависимости, но не как основной default при IP-block verdict.


---

# 6. Compile model

## 6.1. Вход

```go
type ServiceProfile struct {
    Schema        uint32
    ID            string
    Version       string
    Maturity      ProfileMaturity
    ServiceClass  ServiceClass
    Compatibility Compatibility
    Components    []ServiceComponent
    Defaults      ProfileDefaults
    Provenance    ProfileProvenance
}

type ServiceComponent struct {
    ID                  string
    DeliveryMode        ServiceDeliveryMode
    ManagedSet          string
    SupportedTransports []TransportKind
    Objective           Objective
    ProbeIDs            []string
}
```

## 6.2. Выход

```go
type CompiledServiceProfile struct {
    ProfileID       string
    ProfileVersion  string
    GenerationInput string

    Sets              []SetConfig
    StrategyBindings  []StrategyBinding
    TransportBindings []TransportBinding
    Probes            []ProbeDefinition
    Policies          []ComponentPolicy
    ClientActions     []ClientSetupAction

    Ownership []ManagedObjectMetadata
    Warnings  []CompileWarning
}
```

## 6.3. Pipeline

```text
parse
→ schema validation
→ compatibility validation
→ ownership resolution
→ compile ordinary packet objects, scoped transport bindings and client setup actions
→ conflict detection
→ preview diff
→ user/automation approval
→ transactional apply
→ optional canary
→ promote or rollback
```

Compiler MUST быть deterministic:

```text
same profile
+ same current config
+ same explicit overrides
= same compiled output and hash
```

---


## 6.4. Compiler authorization output

Редакция 1.2 расширяет compiled representation:

```go
type CompiledComponentSafety struct {
    EffectiveDomainPolicy DomainOnlyMode
    IPMatchRole           IPMatchRole
    RequiredCapabilities  []CapabilityRequirement
    NegativeControls      []ControlScenarioID
    MaxPassiveRSTMode     PassiveRSTMode
    GSOPolicy             ProfileGSOPolicy
    ScopeContractHash     string
}
```

`CompiledServiceProfile` MUST содержать safety projection для каждого component. Hash входит в generation hash, preview diff, validation report и promotion record.

Compiler MUST отклонить profile, если:

- direct component способен выдать action по одному IP/CIDR на shared infrastructure;
- отсутствует positive-domain authorization path;
- clear/reassembled negative SNI не отменяет provisional candidate;
- failure/escalation/route scope шире `ClientKey + SetID + ConfigGen`, когда domain/flow scope доступен;
- profile требует GSO direct для uncertified technique;
- profile пытается поднять Passive RST выше runtime/user maximum;
- negative controls отсутствуют для bundled optimized YouTube pack.

## 6.5. Preview diff редакции 1.2

Preview дополнительно показывает:

```text
effective domain policy
IP match role
negative-SNI override
shared-IP policy
legacy learned-IP role
route/failure scope
GSO policy and required capability
Passive RST maximum and effective runtime mode
required negative controls
last validation generation/hash
```

Изменение любого из этих полей является safety-relevant diff и не скрывается внутри общего «set changed».

# 7. Ownership и provenance

Каждый managed object получает metadata:

```yaml
managed_by: service-profile
service_id: youtube
component_id: video
profile_version: 2026.07.1
profile_source: bundled
compiled_generation: 42
```

Ручные объекты:

```yaml
managed_by: manual
```

## Domain entry states

```text
seed
observed
candidate
confirmed
pinned
excluded
deprecated
```

### seed

Поставляется profile pack.

### observed

Замечен через DNS/QUIC/TCP evidence, но не персистирован как production rule.

### candidate

Предложен profile engine после нескольких согласованных наблюдений.

### confirmed

Прошёл validation policy и разрешён для managed set.

### pinned

Пользователь зафиксировал запись. Profile update не может её удалить или изменить молча.

### excluded

Пользователь исключил запись. Update не может автоматически вернуть её.

### deprecated

Новая версия pack предлагает удалить запись, но удаление проходит через preview diff.

---

# 8. Manual override policy

Профиль не имеет права молча перезаписывать ручную конфигурацию.

Правила:

1. Manual object имеет приоритет ownership.
2. `pinned` сохраняется.
3. `excluded` сохраняется.
4. Изменение managed set вручную создаёт explicit override.
5. Profile update показывает конфликт.
6. Пользователь может:
   - оставить override;
   - принять profile value;
   - отвязать объект от profile;
   - создать fork профиля.
7. Удаление profile не удаляет manual objects.
8. Rollback восстанавливает предыдущую compiled generation.

---

# 9. Runtime isolation

Profile framework не создаёт отдельный service-specific matcher или executor.

## Direct components

Все compiled sets проходят через:

- существующую config validation;
- immutable generation builder;
- обычный classifier;
- source-device policy;
- action planner;
- metrics;
- canary;
- rollback;
- encrypted local secret storage for user-supplied proxy credentials;
- endpoint health and ownership display;
- explicit scope for client/device/sets.


### Direct-component authorization requirements

Для direct-компонента ordinary classifier обязан вернуть `ActionAuthorization` перед любым side effect.

```text
IP/CIDR/port candidate
→ observe/reassemble only

clear SNI / reassembled SNI / eligible source-scoped DNS/QUIC
→ component match
→ policy/confidence/ambiguity checks
→ ActionAuthorization
```

Clear или reassembled hostname другого сервиса является negative evidence и MUST отменять provisional profile candidate. При ambiguity original packet принимается без service action, если более узкая безопасная generic strategy явно не разрешена.

Следующие операции запрещены без authorization:

- fake/split/disorder/TLS mutation;
- original drop/reject;
- QUIC reject/block/fake;
- IPBlockDetect promotion;
- escalation;
- proxy/tunnel route binding;
- Passive RST suppression;
- persistent learned association.

### GSO representation

Service profile видит GSO только через capability result:

```text
packet representation
ActionPlan representation requirement
certified technique support
```

Profile не выбирает queue number, mark или first/secondary pass. Если ActionPlan требует normal TCP и normalizer unavailable, flow fail-open либо использует допустимый accept-only fallback; profile не может заставить raw reinjection GSO buffer.

### Passive RST

Default effective maximum для direct profile:

```text
observe
```

Profile может показывать observation health и требовать negative controls, но не может автоматически включать suppression. Conservative допускается только после отдельной runtime validation и explicit user opt-in; aggressive profile manifest запрещён.

## Router-transport components

Используют только generic transport bindings:

- per-set/per-device scope;
- SO_MARK/rule isolation;
- healthcheck;
- cooldown;
- last-good route;
- no double processing.

## Client-configured components

Не проходят через packet executor. B4:

- диагностирует direct path;
- проверяет configured proxy endpoints;
- формирует setup artifact;
- отображает health;
- не утверждает, что настройки клиента применены, пока нет подтверждения.

Один flow не может одновременно обрабатываться:

```text
packet strategy
+
router transport
+
second service-profile runtime
```

Compiler и config validation обязаны обнаруживать конфликт delivery paths до apply.


---


## 9.1. Scoped state and side effects

Profile/compiler MUST считать частью runtime isolation не только classifier decision, но и всё производное состояние.

Минимальный scope:

```go
type ProfileSideEffectScope struct {
    ClientKey       ClientKey
    FlowKey         FlowKey
    SetID           string
    ComponentID     string
    DomainID        string
    DestinationIP   netip.Addr
    DestinationPort uint16
    L4Proto         uint8
    ConfigGen       uint64
}
```

В зависимости от типа state некоторые поля MAY быть агрегированы, но destination-only ключ для shared Google infrastructure запрещён.

К scope относятся:

- IPBlockDetect verdict/cache;
- escalation;
- RST sent/suppressed bookkeeping;
- Failure Inbox association;
- learned-IP compatibility state;
- route/ipset/proxy binding;
- canary ownership;
- cooldown/last-good route.

Profile uninstall/update/rollback MUST очищать только managed state своей generation и не затрагивать manual или другой service/component state.

## 9.2. Same-client control invariant

Для одного телефона:

```text
YouTube flow authorized
≠ Gmail flow authorized
≠ Google Feed flow authorized
```

Даже при совпадении destination IP, port, resolver answer или CDN ASN. Profile health не может быть `Healthy`, если control flow получил profile ActionToken или route/failure side effect, даже если сам control UI визуально успел загрузиться.

# 10. Discovery integration

Service profile описывает generic objective и probe definitions.

Запрещено:

```go
OptimizeYouTube()
```

Нужно:

```go
RunExperiment(ExperimentDefinition)
```

## Generic objectives

```text
reachability
startup-latency
ui-completion
media-first-byte
media-goodput
stall-free
voice-stability
gateway-stability
transport-connectivity
proxy-handshake
transport-goodput
failover-time
resource-minimum
```

## Component policy

```go
type ComponentOptimizationPolicy struct {
    ComponentID string
    Objective   Objective
    HardGates   []HardGate
    TieBreakers []MetricName
    ProbeIDs    []string
}
```

## YouTube example

```text
api
→ startup-latency

ui
→ ui-completion

video
→ stall-free
→ media-first-byte
→ goodput-p10
→ resource-minimum
```

Optimizer остаётся generic; профиль только задаёт policy.



## Cross-service hard gates для Discovery

Для direct/hybrid packet components candidate немедленно отклоняется при любом событии:

```text
unrelated_control_action_total > 0
same_client_cross_service_evidence_leakage > 0
destination_only_failure_state_detected > 0
destination_only_route_binding_detected > 0
negative_sni_override_failed > 0
gso_mss_decision_mismatch > 0
passive_rst_control_regression > 0
```

Control failure имеет приоритет над улучшением startup/goodput target component. Candidate, который ускоряет YouTube, но ухудшает Gmail или Google Feed, не может стать winner, canary-eligible или last-good.

Discovery profile MAY потребовать RST/GSO shadow observations, но active GSO normalization или RST suppression включаются только отдельным runtime experiment definition и не являются скрытым измерением обычного profile candidate.

## Telegram transport example

```text
direct Telegram DC probe
→ direct path healthy: no transport change
→ timeout/reset/IP-block signature: test configured MTProxy/SOCKS5/tunnel candidates
→ rank by handshake success, latency, stability, media goodput and failover time
```

Для `transport-required` профиля Discovery не запускает fake/split Cartesian matrix как основной путь. Он использует generic transport probes и hard gates:

- endpoint reachable;
- proxy protocol handshake succeeds;
- no DNS or route leak outside selected scope;
- stable reconnect;
- acceptable latency/goodput;
- unrelated clients unaffected.


---

# 11. Domain discovery policy

Dynamic evidence нельзя автоматически превращать в глобальный persistent domain list.

Pipeline:

```text
source-scoped observed evidence
→ candidate association with service/component
→ confidence and ambiguity checks
→ repeated observation
→ optional probe
→ confirmed managed rule
```

Обязательные ограничения:

- client-scoped evidence остаётся client-scoped;
- shared Google/Meta/CDN IP не подтверждает сервис сам по себе;
- clear/reassembled SNI сильнее IP/CIDR;
- разные service components на одном IP не должны перезаписывать друг друга;
- низкая confidence не создаёт persistent rule;
- ECH без внешнего evidence не создаёт hostname;
- temporary DNS/QUIC hints не персистятся как profile data автоматически.
- transport-required profile не должен превращать Telegram DC IP observations в глобальную packet-strategy hostlist;
- IP-block verdict требует отдельного direct/transport comparison и не выводится только из отсутствия SNI;
- dynamic proxy endpoint не становится service seed domain.

---


## 11.1. Negative evidence и shared infrastructure

Для profile-managed domain association действуют дополнительные правила:

1. Clear/reassembled SNI, явно не относящийся к component, отменяет IP/CIDR/port provisional candidate этого flow.
2. Source-scoped DNS/QUIC hint остаётся bounded и не создаёт destination-global profile membership.
3. Один Google IP MAY одновременно иметь кандидаты YouTube, Gmail, Google Feed и другие; это не ошибка store и не повод выбрать последний hostname.
4. Dynamic evidence не может создать persistent IP target для optimized YouTube pack.
5. Failure одного YouTube hostname не превращает весь destination IP в blocked/escalated для профиля.
6. QUIC `FilterQUIC=all` не является authorization для DomainOnly component.
7. При ECH без достаточного scoped evidence profile остаётся unresolved/partial и fail-open.

Profile pack MAY содержать reviewed domain suffix seeds, но broad seeds вроде общих `googleapis.com`, `googleusercontent.com`, Google ASN/CIDR или generic CDN category требуют явного component justification и negative-control validation. По умолчанию такие seeds отклоняются для bundled optimized YouTube pack.

# 12. Beginner UI

Основной экран:

```text
Service Profiles
```

Пример:

```text
YouTube       Healthy
Discord       Not configured
Instagram     Validation required
Twitch        Not installed
Telegram      Transport setup required
```

## Install wizard

```text
1. Выбрать сервис
2. Выбрать устройства
3. Выбрать режим:
   - recommended starter
   - validate locally
   - advanced
4. Preview:
   - создаваемые sets
   - bindings
   - probes
   - conflicts
5. Apply transaction
6. Optional canary
7. Result
```

## Profile detail

```text
YouTube
├── API
│   ├── set
│   ├── strategy
│   ├── health
│   └── last validation
├── UI
└── Video
```

Для transport-required профиля detail показывает другой workflow:

```text
Telegram
├── Direct path: blocked/suspected
├── MTProxy: configured / latency / health
├── SOCKS5: optional
├── Router tunnel: optional
└── Client setup:
    ├── QR/deep link
    └── confirmation status
```

UI не должен показывать для Telegram ложный статус «optimized DPI strategy», если фактически используется client proxy или tunnel.


## Safety и isolation status в UI

Profile detail для direct/hybrid packet component MUST показывать:

```text
effective DomainOnly policy
IP match role: capture-only / explicitly action-eligible
authorization evidence source and confidence
shared-IP ambiguity state
negative-SNI override status
legacy learned-IP role
failure/escalation scope
route/proxy scope
GSO requested/effective mode and technique certification
Passive RST requested maximum/effective mode
incoming visibility and rollback readiness
last same-client control validation
unrelated_control_action_total
```

Beginner UI может сворачивать технические поля, но не имеет права показывать `Healthy`, если:

- Cross-Service Isolation capability отсутствует;
- обязательные negative controls не запускались для текущей generation;
- last validation содержит unrelated action;
- effective DomainOnly откатился в `legacy`/`disabled` без explicit override;
- GSO normalizer или Passive RST mode находится в degraded state.

Advanced UI показывает конкретный flow trace от `CaptureCandidate` до `ActionAuthorization` или причины отказа.

## Advanced link

Каждый component открывает обычный B4 set editor.

Пользователь всегда может увидеть:

- domains;
- IP rules;
- device scope;
- strategy;
- provenance;
- generated diff;
- trace.

---

# 13. Basic/advanced mode

Stage 35 v2.3 уже предусматривает `basic/advanced modes`. Service Profiles используют этот UI primitive, но не меняют основной expert workflow.

## Basic

- Services;
- Devices;
- Health;
- Validate;
- Restore last-good.

## Advanced

- Sets;
- Strategies;
- Discovery;
- Evidence;
- Flows;
- Trace;
- Profile manifests;
- Ownership;
- Compile diff.

Переключение режима не создаёт разные конфигурации. Это два представления одной config generation.

---

# 14. Profile catalog

## Sources

```text
bundled
official-signed
community
local
```

## Bundled

- поставляется с release;
- работает без загрузки каталога;
- минимальный безопасный starter set.

## Official-signed

- обновляется отдельно от binary;
- подписан доверенным ключом;
- имеет version, changelog, compatibility range;
- применяется только после validation и preview.

## Community

- явно помечен;
- не считается доверенным;
- не может включить destructive/full-auto policy без подтверждения;
- проходит ту же schema/config validation.

## Local

- создан пользователем;
- может быть экспортирован;
- не обновляется внешним catalog автоматически.

---

# 15. Security и supply chain

Profile pack не должен содержать исполняемый shell/Go/Lua/JS код.

Разрешён только декларативный data format.

Запрещено в pack:

- произвольные команды;
- пути к произвольным файлам;
- raw firewall snippets;
- внешние executable hooks;
- bundled or catalog-provided user secrets;
- публичные proxy credentials, выдаваемые как доверенные по умолчанию;
- auto-enable unrestricted proxy;
- auto-disable global offload;
- auto-promote destructive strategy;
- auto-route all devices/all traffic through a proxy or tunnel;
- auto-configure a client application without explicit local authorization.

Required:

- canonical serialization;
- content hash;
- signature для official catalog;
- source/revision/license;
- compatibility check;
- size limits;
- count limits;
- regex/domain/endpoint validation;
- preview diff;
- rollback;
- encrypted local secret storage for user-supplied proxy credentials;
- endpoint health and ownership display;
- explicit client/device/set scope;
- secret redaction in logs, export and issue bundles.

---


## 15.1. Capability privilege boundaries

Profile catalog, включая official-signed, не получает право:

- включать global or per-profile `gso_mode=full`;
- назначать queue numbers или marks;
- разрешать uncertified direct GSO mutation;
- включать Passive RST aggressive;
- включать conservative suppression без user/runtime gate;
- ослаблять incoming visibility requirement;
- расширять route/failure state до destination-global;
- отключать negative controls;
- помечать candidate как production-safe при `unrelated_control_action_total > 0`.

Подпись каталога подтверждает происхождение данных, но не отменяет local capability validation.

# 16. Updates

Update pipeline:

```text
fetch metadata
→ verify signature
→ compare compatibility
→ compile candidate generation
→ show diff
→ run validation policy
→ canary if enabled
→ promote
→ preserve previous generation
```

Diff должен показывать:

```text
added sets
removed sets
changed seed rules
changed objectives
changed starter strategies
changed probes
manual conflicts
pinned/excluded preservation
```

Автоматический update не должен запускать тяжёлый Discovery немедленно на всех сервисах.

Допустимо:

- lightweight compatibility check;
- health status;
- queued/manual validation;
- bounded canary.

---


## 16.1. Safety-relevant profile update

Update считается safety-relevant и требует новой validation generation, если изменено хотя бы одно:

```text
domain seeds/patterns/IP ranges
DomainOnly policy
IP match role
negative-SNI/shared-IP policy
QUIC policy
strategy/action class
route/failure scope
GSO policy
Passive RST maximum
negative-control scenarios
required capability versions
```

Старый успешный validation report не переносится на новую safety hash. Automatic update MAY установить metadata/catalog content, но не продвигать такую generation без повторного control validation.

# 17. Initial profile scope

## First production direct-strategy pack

```text
YouTube
```

Class:

```text
direct-strategy
```

Maturity:

```text
optimized
```

при наличии реализованных API/UI/video probes и field evidence.


### Обязательные defaults YouTube pack v1.2

```yaml
classification:
  domain_policy: scoped-hints
  ip_match_role: capture-only
  negative_sni_override: true
  shared_ip_policy: ambiguous-fail-open
  legacy_learned_ip: diagnostic-only
execution:
  passive_rst_policy: observe-max
  gso_policy: inherit
validation:
  required_negative_controls: [gmail, google-feed]
  require_zero_unrelated_actions: true
```

API/UI/video components MAY иметь разные sets и winners, но не могут использовать общий destination-only failure/cache/route state. Broad IP/CIDR targets не входят в safe starter candidate.

Profile maturity `optimized` разрешена только после:

- official YouTube и ReVanced validation;
- same-client Gmail и Google Feed controls;
- shared-IP synthetic fixture;
- GSO/MSS parity, если GSO classify enabled;
- Passive RST observe validation и active-mode rollback proof, если active mode доступен;
- zero unrelated actions across promotion sample.

## Next direct/hybrid packs

```text
Instagram — direct-strategy
Twitch    — direct-strategy
Discord   — hybrid
```

Начинать с `basic` или `structured`.

Discord нельзя считать только доменным профилем, если его voice/UDP component в конкретной среде требует отдельного transport fallback.

## Telegram

```text
Telegram — transport-required
```

Telegram не входит в обычный DPI starter pack.

Профиль Telegram добавляется только после реализации одного из путей:

1. `client-configured` MTProxy/SOCKS5 handoff;
2. generic router-level external tunnel;
3. generic scoped SOCKS fallback, если он корректно поддерживает нужный traffic path.

Maturity сначала:

```text
structured
```

Профиль обязан:

- диагностировать direct path;
- не обещать обход IP-block через fake/split;
- проверять configured transport;
- объяснять, требуется ли действие в клиенте;
- не поставлять случайные публичные proxy credentials;
- не включать global tunnel автоматически.

## Custom templates

```text
custom-domain-group
custom-streaming-service
custom-api-plus-media
custom-transport-required-service
```

Они помогают пользователю создать собственный профиль без написания manifest вручную.


---

# 18. Зависимости от v2.3 и post-v2.3 hardening

Service framework не требует изменения порядка v2.3, но использует его результаты.

## Required before runtime apply

- immutable config generation;
- transactional apply;
- last-good;
- rollback;
- config schema validation;
- set/strategy dry-run.

## Required before automatic local validation

- Discovery sandbox;
- structured ProbeOutcome;
- resource budgets;
- canary.

## Required before optimized YouTube pack

- API/UI/video probes;
- component-specific ranking;
- field trace contract;
- multi-client isolation;
- CDN switch validation.

## Required before beginner UI

- backend profile API;
- ownership metadata;
- compile diff;
- basic/advanced UI foundation.

## Required before transport-required profiles

Для `client-configured`:

- transport healthcheck API;
- local secret storage;
- setup artifact generator;
- explicit user confirmation state.

Для `router-tunnel` / `external-proxy`:

- generic stage 33 transport fallback;
- scoped routing isolation;
- no double processing;
- healthcheck/cooldown;
- transactional last-good route;
- leak/fail-open policy.

Telegram pack не должен блокировать реализацию direct-strategy profile framework.

---


## Required before any optimized direct-strategy runtime apply

Обязательны завершённые и validated:

```text
B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md
CSI-1 → CSI-10
```

Минимально profile framework должен видеть capabilities:

```text
effective-domain-policy
capture-candidate-action-authorization-split
reassembled-sni-authoritative
negative-sni-override
legacy-learned-ip-diagnostic-only
scoped-failure-state
scoped-quic-authorization
scoped-route-binding
same-client-negative-control-validation
```

Если capability отсутствует, bundled optimized YouTube profile не применяется как production candidate. Допустим только preview или explicitly labelled compatibility/manual mode.

## Required before GSO-aware profile execution

Обязательны соответствующие gates:

```text
H1 reassembled-SNI integration
H2 NFQUEUE offload metadata
H3 observe/classify parity
H4 conditional normalizer token
H5 transactional queue topology
```

Profile `gso_policy=inherit` работает при любом effective mode. `normalize-if-required` и `direct-if-certified` доступны только после target-side capability validation. GSO off/observe не должен блокировать обычный profile framework.

## Required before Passive RST exposure

Для UI observation достаточно H6 observe model. Для любого active suppression дополнительно обязательны:

```text
H7 enforcement safety gates
H8 rollback / Failure Inbox / Discovery
H9 API/UI/observability
H10 target validation
```

Profile maximum не может повысить runtime mode. Incomplete incoming visibility всегда понижает effective mode до observe/off согласно runtime contract.

## Required before production promotion of YouTube pack

```text
Cross-Service Isolation release gate
+ GSO/MSS parity for enabled GSO mode
+ Passive RST mode-specific gate
+ Field Test same-client controls
+ transactional rollback proof
```

`multi-client isolation` остаётся обязательной, но не заменяет same-client cross-service isolation.



# 18A. Built-in WARP/MASQUE capability projection

## 18A.1. Canonical transport kind

Встроенный transport имеет единственный canonical identifier:

```text
cloudflare-warp-masque
```

Manifest MUST declare:

```yaml
transport:
  kind: cloudflare-warp-masque
  provider: builtin
  engine: b4-warpd
  protocol: masque-http2
  connect_port: 443
```

Следующие формы запрещены для bundled profile:

```yaml
provider: external-usque
package: usque-keenetic
download_runtime_binary: true
install_command: opkg install usque-keenetic
```

Пользователь устанавливает и обновляет только B4. `b4-warpd` является внутренним crash-isolated helper, а не самостоятельным пользовательским продуктом или dependency.

## 18A.2. Profile authority boundaries

Profile MAY request:

- base WARP transport;
- source-device/service/component scope;
- fail-open or scoped fail-closed within declared product policy;
- maximum allowed camouflage candidate;
- `off`, `sni-cover`, `handshake-desync` or `auto` camouflage policy;
- experimental `require_non_ru`;
- validation profiles and negative controls.

Profile MUST NOT own or create:

- WARP registration/session secret;
- `b4-warpd` process lifecycle;
- TUN or NDM object;
- namespace/veth topology;
- packet marks and route table numbers;
- endpoint variants;
- MASQUE connection;
- `TransportControlAuthorization`;
- camouflage token/cutoff state;
- geo provider lifecycle or attestation cache;
- NAT/MSS owner;
- restart/cooldown state.

These belong to generic B4 runtime and immutable config generation.

## 18A.3. Base WARP manifest

```yaml
components:
  - id: media-via-warp
    delivery: router-tunnel
    managed_set: service-media

    transport:
      kind: cloudflare-warp-masque
      provider: builtin
      mode: base
      ip_families: [ipv4]

      camouflage:
        mode: auto
        maximum_candidate: clienthello-split
        allow_disorder: false

      failure:
        mode: fail-open

    validation:
      required_suites:
        - warp-base
        - warp-camouflage
      require_forwarded_lan_proof: true
```

`mode: base` does not imply non-RU egress and UI MUST NOT present it as a region-changing VPN.

## 18A.4. Experimental non-RU manifest

```yaml
components:
  - id: media-via-observed-nonru
    delivery: router-tunnel
    managed_set: service-media

    transport:
      kind: cloudflare-warp-masque
      provider: builtin
      mode: nested-nonru

      geo:
        require_non_ru: true
        forbidden_countries: [RU]
        attestation_quorum: 2
        max_age_sec: 120
        require_same_country: true
        reject_unknown: true

      failure:
        mode: fail-closed-scoped

    maturity: experimental
```

Compiler MUST reject:

- `maturity: production` for `nested-nonru` without an explicit future normative promotion contract;
- global kill switch as implicit default;
- direct fallback with `require_non_ru: true` and strict policy;
- IPv6 enablement without separate leak/geo proof;
- country selection claims;
- attestation quorum below runtime safety minimum.

## 18A.5. Camouflage policy projection

Conceptual schema:

```yaml
camouflage:
  mode: off | sni-cover | handshake-desync | auto
  cover_sni_source: canonical | builtin-validated | user-explicit
  maximum_candidate: direct | cover-sni | clienthello-split | multisplit | fake-split | preopen | disorder
  allow_disorder: false
  require_endpoint_pin: true
  established_flow_policy: bypass
```

Profile can only lower the maximum capability. It cannot enable a candidate rejected by runtime capability, WARP-C validation or target safety hash.

Mandatory compiler rules:

```text
generic service strategy != WARP control camouflage
ActionAuthorization != TransportControlAuthorization
endpoint IP match alone != camouflage authorization
CONNECT-IP established => established bypass
```

## 18A.6. Beginner UX

Beginner card:

```text
Cloudflare WARP

Назначение:
альтернативный маршрут и обход IP-блокировок

Протокол:
MASQUE HTTP/2 через TCP 443

Состояние:
работает / восстанавливается / отключён / ограничен capability

Маскировка подключения:
Авто / Только SNI / Выкл.

[ ] Требовать наблюдаемый выход не из РФ (экспериментально)
```

When non-RU is enabled:

```text
Наблюдаемый выход: NL
Проверено: 43 секунды назад
Гарантированный регион: нет
При неподтверждённом выходе: выбранный трафик блокируется
```

Forbidden wording:

```text
VPN-страна: Нидерланды
Гарантированная смена региона
Всегда не РФ
```

Advanced UI MUST expose effective instance/backend, W0–W4 health, selected camouflage candidate, cutoff status, endpoint pin status, geo providers/quorum/age, failure policy and last rollback reason without exposing secrets.

Detector-guided recommendation MUST use a separate status from active transport:

```text
Подходящий вариант: WARP — требуется проверка
Проверяется через WARP
WARP проверен для выбранного сервиса
WARP недоступен на этом устройстве/сборке
WARP не помог для выбранной цели
```

The card MUST NOT display `WARP включён`, `WARP решит проблему` or `Recommended` as a production fact before exact target/control validation and a current forwarded-client causal proof.

## 18A.7. Profile safety hash

WARP-aware profile safety hash includes at least:

```text
transport kind/provider/mode
client/component/set scope
failure policy
IP family/DNS policy
camouflage mode and maximum candidate
cover-SNI provenance
required WARP/WARP-C stage versions
nested backend capability
geo quorum/age/forbidden-country policy
forwarded-proof requirement
control/negative scenarios
```

Any change invalidates prior WARP field validation and canary promotion evidence.


# 18B. Silent Path Failure and Scoped Recovery capability projection

## 18B.1. Capability model

Service Profile MAY declare only an upper bound:

```text
disabled
observe
recommend
auto-canary
```

The profile MUST NOT directly enable active recovery. Effective mode is:

```text
min(profile upper bound,
    user/global policy,
    runtime visibility capability,
    current validation/promotion state)
```

`auto-canary` in a manifest means “eligible after promotion”, not “automatically active after installation”.

## 18B.2. Manifest schema

```yaml
components:
  - id: video
    delivery: direct-strategy

    silent_recovery:
      policy: recommend
      success_milestone: media-progress
      long_idle_expected: false
      require_negative_controls: true

      evidence:
        minimum_independent_families: 2
        require_retry_or_application_signal: true
        require_differential_for_active: true

      allowed_bindings:
        - direct:last-good
        - direct:next-validated
        - warp:base

      limits:
        max_attempts_per_scope: 2
        lease_ttl_sec: 300
        cooldown_sec: 120
```

Compiler MUST reject:

- unknown or destination-global binding;
- `warp:base` when built-in WARP capability is absent or forbidden;
- recursive transport binding;
- active policy without rollback target;
- profile threshold weaker than global mandatory safety gate;
- `auto-canary` without required negative controls for shared infrastructure.

## 18B.3. Authority boundaries

Profile owns:

- component success milestone;
- expected long-idle behavior;
- maximum allowed mode;
- ordered allowed binding classes;
- whether same-client controls are mandatory;
- profile-specific stricter time/resource bounds.

Profile does not own:

- packet progress tracker;
- visibility/GSO/PPE gates;
- evidence independence logic;
- suppressor catalog;
- differential probe scheduler;
- recovery lease store;
- false-positive budget;
- runtime marks/routes/TUN lifecycle;
- promotion or rollback authority.

## 18B.4. False-positive-safe beginner UX

Beginner card:

```text
Восстановление при «тихом» зависании

Рекомендуемый режим: Наблюдать

B4 может заметить, что полезная передача остановилась без явной ошибки.
Такое бывает не только из-за DPI, поэтому автоматическое переключение
требует нескольких подтверждений и проверки альтернативного пути.
```

Modes:

```text
Наблюдать
Предлагать переключение
Автоматический canary — доступен после проверки
```

Forbidden wording without causal proof:

```text
РКН заблокировал
DPI подтверждён
автоматически исправлено навсегда
```

UI MUST display:

- effective rather than only configured mode;
- degraded reason;
- last assessment and suppressor reason;
- temporary lease and rollback countdown;
- false-positive rollback action;
- target scope and affected component;
- whether WARP fallback is allowed.

## 18B.5. Recovery binding semantics

```text
direct:last-good
→ previously validated direct binding in the same profile/component scope

direct:next-validated
→ next candidate from Discovery catalog with current safety hash

warp:base
→ built-in base WARP only, subject to WARP base gate and profile authorization

proxy:<id>
→ configured generic transport binding with its own health/leak gates
```

A binding does not become allowed merely because it exists. It must be declared by the component, available in current immutable generation and validated for the target cohort.

## 18B.6. Profile health and promotion

Profile health adds separate fields:

```text
silent_observe_state
silent_recommend_state
silent_auto_canary_state
silent_promoted_cohort_hash
silent_active_lease_count
silent_false_positive_budget_state
```

Overall service health MUST NOT be reported as failed only because optional silent active mode is unavailable. Instead:

```text
target delivery healthy
silent recovery observe-ready
active recovery blocked: incomplete visibility
```

Conversely, target success after an unauthorized recovery cannot produce `Healthy`.

## 18B.7. Cross-service and WARP invariants

For shared Google infrastructure:

```text
YouTube silent suspicion
MUST NOT authorize Gmail/Google Feed recovery
```

For WARP:

```text
direct target silent failure
→ MAY evaluate authorized base-WARP candidate

base-WARP data path silent failure
→ MUST NOT recursively select base WARP
```

When component already requires strict non-RU, every recovery candidate preserves fresh non-RU/DNS/IPv6 gates. Silent recovery cannot weaken geo policy.

# 19. Companion implementation stages

Эти stages не перенумеровывают v2.3.

## SP-1 — Manifest schema and validator

Создать:

```text
serviceprofile/schema
serviceprofile/validate
```

Реализовать:

- schema versions;
- compatibility;
- domains/pattern validation;
- limits;
- provenance;
- canonical hash.

DoD:

- invalid manifest rejected;
- no executable fields;
- deterministic canonicalization;
- fuzz parser;
- migration tests.


### Дополнение SP-1 редакции 1.2

Validator также проверяет:

- `classification` / `execution` / `validation` blocks;
- safe migration defaults;
- prohibition of aggressive Passive RST;
- GSO policy capability bounds;
- broad shared-infrastructure targets;
- mandatory controls for optimized bundled packs;
- minimum route/failure scope;
- safety hash canonicalization.

## SP-2 — Ownership metadata

Добавить:

- managed/manual;
- profile/component/version;
- pinned/excluded;
- override state;
- provenance export.

DoD:

- existing configs migrate as manual;
- no user object becomes managed implicitly;
- round-trip stable.

## SP-3 — Profile compiler

Реализовать deterministic compile в:

- ordinary sets;
- strategy bindings;
- transport bindings;
- probes;
- component policies;
- client setup actions.

DoD:

- same input → same hash;
- no runtime side channel;
- compile conflicts explicit;
- dry-run.


### Дополнение SP-3 редакции 1.2

Compiler формирует `CompiledComponentSafety`, capability requirements и control scenarios. Compile result MUST быть одинаковым для manual и profile-created ordinary objects при одинаковой effective policy, но provenance/profile safety metadata сохраняется отдельно.

## SP-4 — Preview diff and transaction integration

Реализовать:

- create/update/remove diff;
- manual conflict resolution;
- immutable candidate generation;
- apply through v2.3 transaction;
- rollback.

DoD:

- no partial apply;
- previous generation preserved;
- crash-safe state.

## SP-5 — Catalog and trust model

Реализовать:

- bundled;
- official-signed;
- community;
- local;
- signature verification;
- compatibility;
- cache/rollback.

DoD:

- invalid signature rejected;
- offline bundled works;
- community never silently trusted.

## SP-6 — Generic component objectives and delivery modes

Связать service component с generic Discovery:

- startup;
- UI completion;
- media;
- voice/gateway;
- transport connectivity;
- proxy handshake;
- transport goodput;
- failover time;
- resource gates.

Добавить delivery modes:

```text
direct-strategy
external-proxy
router-tunnel
client-configured
hybrid
```

DoD:

- no service-specific branches in optimizer;
- per-component winners;
- no single global score overriding components;
- transport-required component не попадает в packet-strategy matrix по умолчанию;
- compile-time delivery conflict detection.

## SP-7 — Beginner wizard and profile UI

Реализовать:

- service catalog;
- device selection;
- install modes;
- preview;
- apply;
- health;
- component drill-down;
- advanced editor links.

DoD:

- existing manual workflow unchanged;
- profile install reversible;
- UI never hides actual sets.


### Дополнение SP-7 редакции 1.2

UI реализует safety/isolation status, effective policy, authorization trace, capability degradation и last negative-control validation. Beginner view не скрывает degraded/legacy state за общим `Healthy`.

## SP-8 — YouTube profile pack

Содержит:

- API/UI/video components;
- reviewed seed rules;
- generic objectives;
- probes;
- safe starter candidates;
- provenance;
- compatibility.

DoD:

- no hard-coded YouTube branch in core;
- compiled output visible;
- official/ReVanced field validation;
- multi-client isolation;
- CDN switch;
- rollback.


### Дополнение SP-8 редакции 1.2

YouTube pack MUST включать:

- per-component `scoped-hints`/strict effective policy;
- capture-only IP role;
- negative-SNI override;
- shared-IP fail-open ambiguity;
- Gmail/Google Feed same-client control definitions;
- zero-unrelated-action hard gate;
- GSO policy `inherit` by default;
- Passive RST `observe-max` by default;
- reviewed exclusion of broad generic Google domains/IP ranges;
- field report with control-flow authorization audit.

## SP-9 — Additional direct/hybrid starter packs

Начать с Basic/Structured:

- Discord — hybrid;
- Instagram — direct-strategy;
- Twitch — direct-strategy.

DoD каждого pack:

- reviewed seeds;
- no broad unrelated CDN capture;
- declared delivery modes and maturity;
- validation report;
- update owner.

## SP-10 — Transport profile framework

Реализовать:

- `TransportBinding`;
- `ClientSetupAction`;
- direct-path and proxy/tunnel health probes;
- local encrypted secret references;
- setup artifact generation;
- client-confirmation state;
- route/proxy scope;
- conflict prevention with packet strategy.

DoD:

- no service-specific proxy code;
- no global route by default;
- no secret in profile pack/export;
- router transport requires stage 33 capability;
- client-configured mode works without router packet mutation.

## SP-11 — Telegram transport-required pack

Содержит:

- messaging/media components;
- direct Telegram DC connectivity probe;
- MTProxy/SOCKS5 client handoff;
- optional router-tunnel binding;
- latency/stability/failover objectives;
- explicit IP-block verdict limitations.

DoD:

- no fake/split strategy as primary default;
- no claim that local on-router MTProxy alone bypasses blocked DC path;
- configured remote transport health verified;
- QR/deep link generated only from local user configuration;
- unrelated devices and traffic unaffected;
- removal/rollback clean.

## SP-12 — Import/export and profile authoring

Реализовать:

- export profile without secrets;
- fork managed profile;
- local authoring;
- schema lint;
- preview compile;
- provenance report;
- delivery-mode validation.


---


## SP-13 — Cross-service capability projection

Реализовать:

- capability discovery/versioning;
- `CompiledComponentSafety`;
- effective domain policy;
- IP capture-only role;
- negative-control requirements;
- side-effect scope validation;
- migration warnings;
- preview safety diff.

DoD:

- profile cannot authorize action by shared IP alone;
- compiler rejects wider-than-runtime scope;
- old manifests migrate safely;
- manual/profile runtime equivalence retained;
- zero service-specific packet branches.

## SP-14 — GSO/RST profile integration

Реализовать только projection:

- GSO policy upper bound;
- technique certification lookup;
- Passive RST maximum;
- effective/degraded status;
- validation requirements;
- UI and export fields.

DoD:

- no queue/mark ownership in profile code;
- no aggressive RST manifest;
- active modes unavailable without runtime gates;
- profile removal leaves generic runtime intact;
- capability downgrade fails open and invalidates stale validation.

## SP-15 — Same-client control pack definitions

Реализовать declarative control scenarios для YouTube:

```text
gmail-inbox
gmail-message-body
gmail-inline-images
gmail-attachment
google-feed-load
google-feed-refresh
google-article-open
google-feed-images
concurrent-youtube-controls
```

Profile pack хранит scenario IDs и expected network outcomes, но не пользовательское содержимое писем, аккаунтные данные или private URLs.

DoD:

- controller can resolve locally configured packages/scenarios;
- controls are never packet targets;
- control failure blocks promotion;
- reports redact account/content identifiers.



## SP-16 — Built-in WARP transport capability projection

- canonical `cloudflare-warp-masque` kind;
- `provider: builtin` and bundled-engine invariant;
- capability resolver for base, camouflage and nested backend;
- compiler rejection of external installation/download directives;
- immutable scoped transport binding output;
- effective capability/degraded reason projection.

DoD: profile cannot create transport lifecycle objects or bypass runtime WARP safety gates.

## SP-17 — WARP beginner and advanced UX

- base WARP card and status;
- explicit separation from region-changing VPN promise;
- camouflage simple selector;
- experimental `НЕ РФ` opt-in warning;
- observed country, attestation age/quorum and strict failure state;
- W0–W4 health and forwarded-proof visibility;
- secret-safe diagnostics and export.

DoD: novice can configure scoped base WARP without external package installation, while expert can inspect effective objects and evidence.

## SP-18 — WARP camouflage and non-RU policy compiler

- schema in Sections 18A.3–18A.5;
- maximum-candidate upper-bound semantics;
- `TransportControlAuthorization` privilege boundary;
- strict non-RU compile rules;
- outer/inner instance separation;
- IPv6/DNS/leak requirements;
- safety-hash invalidation;
- migration and preview diff.

DoD: invalid combinations are rejected with machine-readable reasons and cannot be hidden by UI defaults.

## SP-19 — WARP profile validation and promotion integration

- invoke FT-M…FT-Q requirements;
- base/camouflage/non-RU verdicts kept separate;
- official YouTube/ReVanced and same-client controls where profile targets YouTube;
- generic TCP/UDP/DNS target probes for other services;
- target-router capability checks;
- rollback and last-good behavior;
- no `production-ready` claim for experimental nested non-RU.

DoD: every compiled WARP profile has exact requirement/test coverage and a promotion state tied to current capability and safety hashes.


## SP-20 — Silent recovery capability projection

- add manifest schema and validator;
- compile effective upper bound without enabling runtime mode;
- expose capability/degraded reason and ownership metadata;
- reject destination-global, recursive and rollback-less bindings.

## SP-21 — False-positive-safe beginner/expert UX

- observe default and truthful wording;
- effective/configured mode separation;
- evidence/suppressor/proof details in expert UI;
- temporary lease and false-positive rollback controls;
- no unsupported DPI/RKN certainty claims.

## SP-22 — Recovery binding compiler and lease integration

- compile ordered allowed bindings;
- bind exact client/service/component/config generation;
- preserve WARP/non-RU and control-flow safety constraints;
- integrate last-good, cooldown, TTL, max attempts and rollback target;
- no profile-owned marks/routes/state machines.

## SP-23 — Silent recovery validation and promotion integration

- map `FT-R`–`FT-V` evidence;
- require `SPF-1`–`SPF-10` coverage for active modes;
- separate observe/recommend/auto-canary/cohort verdicts;
- invalidate promotion on material profile/capability/network change;
- include same-client negative controls and false-positive budget.

# 20. PR decomposition

## Upstream-friendly PR SP-A

```text
Service profile manifest schema + validation
```

Без bundled service data.

## PR SP-B

```text
Managed object ownership/provenance + migration
```

## PR SP-C

```text
Deterministic profile compiler + dry-run diff
```

## PR SP-D

```text
Transactional profile apply through ordinary B4 config
```

## PR SP-E

```text
Optional generic beginner wizard
```

## Separate profile repository / fork PR

```text
Bundled starter profile catalog
```

## Fork-only initial optimized pack

```text
YouTube API/UI/VIDEO profile
```

## Upstream-friendly transport PR SP-F

```text
Generic service delivery modes, transport bindings and client setup artifacts
```

Без Telegram-specific endpoints или credentials.

## Separate transport pack

```text
Telegram transport-required profile
```

Не смешивать Core Fix, profile compiler, transport framework, UI и конкретные service packs в одном PR.

---

# 21. Validation coding-agent

Coding-agent проверяет framework, а не выбирает production strategy вручную.

Обязательные suites:

## Schema

- valid/invalid;
- oversized;
- malicious fields;
- unknown version;
- compatibility.

## Compiler

- deterministic output;
- ID collisions;
- manual conflicts;
- pinned/excluded;
- profile update;
- removal;
- rollback.

## Runtime equivalence

Один и тот же ordinary set, созданный:

```text
manual
vs
compiled profile
```

должен давать одинаковый classifier/executor behavior.

## Multi-client

Профиль не отменяет source-scoped isolation.

## Discovery

- per-component objectives;
- synthetic winner datasets;
- hard gates;
- no global score corruption.

## Transport profiles

- direct path healthy vs blocked;
- MTProxy/SOCKS5 endpoint health;
- invalid secret/auth failure;
- endpoint unreachable;
- failover;
- router tunnel scope;
- DNS/route leak checks;
- client-configured confirmation;
- profile export redacts secrets;
- packet strategy and transport conflict rejected;
- unrelated clients unaffected.


## Cross-service isolation

- same client: YouTube target + Gmail/Google controls;
- shared destination IP synthetic fixtures;
- IP/CIDR produces capture candidate only;
- clear/reassembled non-YouTube SNI revokes YouTube candidate;
- no destination-global block/escalation/route state;
- QUIC action requires positive component authorization;
- `unrelated_control_action_total == 0`.

## GSO/RST capability projection

- GSO off/observe/classify capability combinations;
- profile cannot select unsupported direct technique;
- effective mode downgrade visible;
- Passive RST default observe;
- conservative unavailable without gate;
- aggressive rejected by schema;
- stale validation invalidated on capability/topology change.



## Built-in WARP/MASQUE profiles

- compiler emits only `provider: builtin` transport bindings;
- external package/install/download directive rejected;
- base WARP profile requires forwarded-LAN proof;
- transport control flow cannot inherit service ActionAuthorization;
- camouflage maximum candidate cannot exceed effective runtime capability;
- established MASQUE policy is bypass;
- endpoint pin failure blocks readiness;
- `nested-nonru` remains experimental;
- RU/unknown/stale/conflicting attestation removes strict route;
- strict mode has no direct fallback for selected scope;
- DNS/IPv6 leak requirements enforced;
- base, camouflage and non-RU verdicts shown separately;
- profile exports redact registration/session secrets.


## Silent path recovery profiles

- manifest upper bound cannot bypass global/runtime mode gate;
- `observe` default creates no action or route change;
- active policy without differential proof/rollback target is rejected;
- fast parallel/HLS/prefetch fixtures remain suppressed;
- exact component scope and ConfigGen are preserved;
- `warp:base` is unavailable without WARP base gate;
- recursive WARP candidate is rejected;
- strict non-RU policy cannot be weakened;
- false-positive action rolls back the active lease;
- profile health reports optional capability degradation truthfully.

## UI

- beginner install;
- preview diff;
- cancel;
- rollback;
- advanced visibility.

## Upgrade

- old B4 config unchanged;
- feature disabled by default where required;
- uninstall profile preserves manual data.

---

# 22. Definition of Done

Framework готов, когда:

1. Existing manual config imports without semantic change.
2. Runtime не содержит service-specific branches.
3. Manifest компилируется только в ordinary B4 packet/config objects, generic transport bindings и declarative client setup actions.
4. Compilation deterministic.
5. Managed/manual ownership сохраняется.
6. Pinned/excluded не перезаписываются.
7. Preview diff показывает все изменения.
8. Apply transactional.
9. Rollback восстанавливает предыдущую generation.
10. Profile removal не удаляет manual objects.
11. Catalog trust source виден пользователю.
12. Official signatures проверяются.
13. Community profile не получает скрытых привилегий.
14. Beginner wizard создаёт рабочую конфигурацию.
15. Advanced UI показывает фактические sets/strategies.
16. Generic Discovery получает per-component objectives.
17. API/UI/media могут иметь разных winners.
18. Каждый component явно объявляет delivery mode.
19. Transport-required component не получает packet-desync strategy как primary default.
20. Client-configured transport не обрабатывается packet executor.
21. Router transport использует только generic scoped binding.
22. Profile pack/export не содержит пользовательских proxy secrets.
23. Heavy validation не запускается постоянно.
24. YouTube pack проходит Android/multi-client/CDN validation.
25. Telegram pack проходит direct-vs-transport, failover и scope validation.
26. Coding-agent выдаёт отдельный validation report.

---


### Дополнительный Definition of Done редакции 1.2

27. Optimized direct component получает ActionAuthorization только из eligible positive domain evidence.
28. IP/CIDR/port match для shared infrastructure является capture-only.
29. Clear/reassembled hostname другого сервиса отменяет provisional component candidate.
30. Legacy learned-IP не является authoritative для classifier v2 profile.
31. Failure, escalation, RST bookkeeping и route bindings не destination-global.
32. YouTube pack содержит Gmail и Google Feed same-client controls.
33. `unrelated_control_action_total == 0` для promotion sample.
34. Profile compiler отклоняет aggressive Passive RST и uncertified GSO direct.
35. Capability downgrade отображается и инвалидирует stale safety validation.
36. Profile update safety hash включает domain/GSO/RST/scope/control fields.
37. Beginner UI не показывает `Healthy` при legacy/degraded/unvalidated isolation.
38. Service profile не владеет NFQUEUE topology, marks, GSO tokens или RST baseline.
39. GSO/MSS classification parity доказана для enabled GSO mode.
40. Active Passive RST mode, если доступен, имеет отдельный rollback/control proof.



### Дополнительный Definition of Done редакции 1.3

41. `cloudflare-warp-masque` является canonical built-in transport kind.
42. Ни один bundled profile не требует установки `usque` или `usque-keenetic`.
43. Profile compiler не скачивает WARP engine во время runtime apply.
44. Profile не владеет WARP process/TUN/marks/routes/session/camouflage/geo lifecycle.
45. Base WARP profile требует current forwarded LAN proof before readiness.
46. Ordinary service ActionAuthorization cannot authorize WARP control camouflage.
47. Camouflage policy can only reduce, never elevate, effective WARP-C capability.
48. Established MASQUE policy is immutable bypass in production profile.
49. Endpoint public-key pin is mandatory and cannot be disabled by profile.
50. `nested-nonru` is explicitly experimental and never advertised as selectable guaranteed country.
51. Strict non-RU compile output has scoped fail-closed and no direct selected-scope fallback.
52. RU/unknown/stale/conflicting attestation is represented as unavailable, not healthy.
53. DNS and unvalidated IPv6 cannot silently bypass strict non-RU transport.
54. Beginner UI presents observed country and attestation age, not a configured VPN country.
55. WARP profile safety hash invalidates stale validation after any material transport/camouflage/geo change.
56. Base, camouflage and non-RU readiness have separate verdicts and rollback state.
57. WARP profile export and issue bundle contain no private key, license, access token or complete session config.
58. SP-16…SP-19 have implementation and validation reports with exact FT/IV coverage.


### Дополнительный Definition of Done редакции 1.4

59. Profile schema supports `disabled|observe|recommend|auto-canary` as an upper bound, not direct runtime authority.
60. Default bundled profile policy is `observe` unless a narrower product requirement explicitly disables it.
61. Active recovery cannot compile without exact scope, independent evidence requirements, differential proof and rollback target.
62. Profile cannot own progress, suppressor, lease, false-positive-budget, mark, route or transport lifecycle state.
63. Allowed bindings are ordered, bounded, generation-bound and capability-validated.
64. Destination-global and recursive transport recovery bindings are rejected.
65. YouTube recovery cannot affect Gmail/Google Feed controls on the same client.
66. `warp:base` recovery preserves WARP base gates and never recursively selects itself.
67. Strict non-RU policy is preserved across every recovery candidate.
68. Beginner UI uses uncertainty-aware language and exposes effective/degraded mode.
69. False-positive rollback is directly accessible and revokes the exact lease.
70. `SP-20`–`SP-23` have implementation/validation reports and map to `SPF-1`–`SPF-10`, `FT-R`–`FT-V` and umbrella IV coverage.

# 23. Product decision

Предустановленные профили следует реализовать.

Но их правильное место:

```text
не packet core
не classifier special case
не отдельный routing engine

а:
optional declarative control-plane layer
над обычными sets/strategies/Discovery
и generic scoped transport capabilities
```

Это даёт новичку:

```text
выбрать сервис
→ установить профиль
→ проверить
→ пользоваться
```

и сохраняет для upstream:

```text
generic core
set-oriented architecture
manual compatibility
small reviewable PRs
```

Категории профилей:

```text
YouTube/Instagram/Twitch
→ direct-strategy

Discord
→ hybrid

Telegram
→ transport-required
→ MTProxy/SOCKS5 client setup или external router tunnel
```


---

# 24. Итог редакции 1.2

Service Profiles остаются optional declarative control-plane layer. Редакция 1.2 не переносит service-specific знания в packet core и не дублирует алгоритмы CSI/H addenda. Она делает их capabilities обязательными входами compiler/runtime validation и запрещает считать профиль готовым только потому, что целевой сервис начал работать.

Production-safe profile означает одновременно:

```text
target service works
+ unrelated same-client services remain unaffected
+ every action is authorized
+ every side effect is scoped
+ enabled packet representation is validated
+ active defensive mode has rollback proof
```


---

# 25. Итог редакции 1.3

Service Profiles v1.3 exposes built-in WARP as a generic capability without moving transport lifecycle into profile packs.

Normative product chain:

```text
service evidence
→ ActionAuthorization
→ scoped transport binding
→ generic WARP runtime safety gates
→ forwarded-path proof
→ profile health/promotion verdict
```

For WARP control traffic a separate chain applies:

```text
exact TransportControlAuthorization
→ optional bounded handshake camouflage
→ CONNECT-IP cutoff
→ established bypass
```

The profile can request base WARP, set a camouflage upper bound, or opt into experimental observed non-RU behavior. It cannot create credentials, choose a guaranteed country, weaken endpoint trust, activate an unvalidated capability or convert a missing proof into `Healthy`.


---

# 26. Итог редакции 1.4

Service Profiles v1.4 projects Silent Path Failure as a bounded optional capability, not as a profile-owned detector or router.

Normative chain:

```text
profile component policy upper bound
→ runtime SPF safety gates
→ Field Test differential/control proof
→ exact recovery lease
→ rollback monitor
→ separate mode/cohort verdict
```

The beginner-facing default is `observe`. A profile may declare eligible alternate bindings, including base WARP, but cannot activate them without current runtime validation, exact authorization and a reversible lease.

---

# 27. Detector-guided profile architecture — редакция 1.5

Service Profile Framework не владеет Detector runtime и не дублирует DDI/Discovery. Он объявляет **что пользователь хочет проверить** и **какие component/control роли допустимы**, после чего generic subsystems выполняют диагностику и поиск.

```text
ServiceProfileManifest
→ DetectorTargetPlanSpec
→ TargetPlanCompiler (ABD)
→ BlockingProfile (ABD)
→ NetworkDiagnosticProfile / freshness (DDI)
→ DiscoverySearchPrior (DDI)
→ ordinary adaptive Discovery
→ transactional candidate/canary/rollback
```

Запрещённая цепочка:

```text
profile says "RST/SNI block"
→ profile directly selects strategy
→ production apply
```

## 27.1. Declarative DetectorTargetPlanSpec

Профиль MAY объявлять:

```yaml
components:
  - id: youtube-api
    detector_targets:
      primary:
        - youtubei.googleapis.com
      same_service_controls:
        - www.youtube.com
      same_provider_controls:
        - accounts.google.com
      unrelated_controls:
        - example.org
      protocols: [dns, tcp, tls12, tls13, http, quic]
      detector_mode_upper_bound: quick
```

Compiler MUST:

- нормализовать и дедуплицировать domains;
- связывать target с exact component ID;
- не расширять wildcard в unbounded scan;
- добавлять mandatory controls из trusted profile pack;
- сохранять user custom domains как `manual`/`pinned` ownership;
- запрещать profile pack удалять пользовательские controls;
- ограничивать количество targets/probes declared product budgets;
- не включать скрытые remote endpoints.

## 27.2. Detector policy upper bound

Manifest может задавать только верхнюю границу:

```text
off
quick
standard
deep
```

Фактический режим уменьшается capability/resource/privacy policy. Profile не может:

- отключить clean native baseline;
- снять capture/PPE/GSO visibility gate;
- разрешить high confidence по одному target;
- отключить control probes;
- объявить certificate MITM без verified integrity probe;
- смешать packet и byte thresholds;
- отключить DDI freshness/revalidation;
- убрать full bounded Discovery fallback.

# 28. BlockingProfile и guided-search UX

## 28.1. Beginner presentation

Beginner UI показывает причинную, но осторожную сводку:

```text
Похоже, что:
• UDP/443 к выбранному сервису блокируется
• TLS 1.3 сбрасывается после ClientHello
• DNS-подмена не подтверждена
• контрольные сервисы доступны

Уверенность: высокая
Основание: 3 независимых семейства доказательств
```

UI MUST различать:

```text
наблюдение
гипотеза
подтверждённый профиль сети
результат target validation
production-ready candidate
```

Он не отображает «тип блокировки подтверждён», когда есть contradiction, incomplete visibility, unhealthy controls или stale network context.

## 28.2. Advanced evidence view

Advanced UI показывает:

- target/component role;
- protocol/fingerprint/IP family;
- direct/production path;
- attempt count;
- unique bytes and wire packets;
- TLS/QUIC milestones;
- origin/control suppressors;
- evidence-family independence;
- confidence calculation;
- network fingerprint and age;
- DDI revalidation status;
- suggested dimensions and excluded unsafe shortcuts.

Sensitive target lists and raw evidence export follow privacy policy.

## 28.3. Guided-search preview

Перед запуском пользователь видит:

```text
Обязательные baseline probes: 2
Приоритетные guided candidates: 14
Полный bounded fallback: до 86 candidates
Target controls: 5
Estimated resource/time budget: ...
```

После run UI отображает отдельно:

- guided winner rank;
- full-search fallback used/not used;
- saved probes and wall time;
- final candidate score/quality delta;
- target/control validation;
- canary/promotion status.

Savings не показываются как положительные, если обязательные baselines были пропущены или итоговое качество хуже tolerance.

# 28A. IP-level BlockingProfile → base-WARP recommendation — редакция 1.6

## 28A.1. Product decision

When Detector v2 and ABD/DDI produce fresh, scoped evidence of IP-level path blocking, Beginner UX SHOULD offer **base WARP as a transport candidate to test**.

Normative chain:

```text
fresh BlockingProfile
+ exact service/component/client scope
+ probable/confirmed IP, SYN or CIDR path filtering
+ healthy controls/reference-path evidence
+ WARP capability available
→ show "Проверить через WARP"
→ run scoped target/control canary
→ only after success show "WARP проверен — можно включить"
```

Forbidden chain:

```text
one timeout or destination IP
→ assume IP block
→ enable WARP
```

The recommendation is explanatory UI state. It is not:

```text
ActionAuthorization
TransportAuthorization
route token
promotion decision
non-RU request
camouflage authorization
```

## 28A.2. Recommendation object

```go
type TransportRecommendationState string

const (
    TransportRecommendationNotApplicable      TransportRecommendationState = "not-applicable"
    TransportRecommendationUnavailable        TransportRecommendationState = "unavailable"
    TransportRecommendationEligibleToTest     TransportRecommendationState = "eligible-to-test"
    TransportRecommendationTesting            TransportRecommendationState = "testing"
    TransportRecommendationValidated          TransportRecommendationState = "validated"
    TransportRecommendationRejected           TransportRecommendationState = "rejected"
    TransportRecommendationExpired            TransportRecommendationState = "expired"
    TransportRecommendationBlockedBySafety    TransportRecommendationState = "blocked-by-safety"
)

type TransportRecommendation struct {
    RecommendationID       string
    State                  TransportRecommendationState

    ServiceProfileID       string
    ComponentID            string
    ClientScopeHash        string
    SetID                  string

    BlockingProfileID      string
    BlockingHypothesisID   string
    NetworkContextID       string
    EvidenceRefs           []string
    ContradictionRefs      []string
    Confidence             string
    ReasonCode             string

    TransportKind          string // cloudflare-warp-masque
    TransportMode          string // base only for automatic IP-block recommendation
    FailurePolicyPreview   string

    RequiredCapabilities   []string
    MissingCapabilities    []string
    ValidationPlanID       string
    ValidationResultID     string

    CreatedAt              time.Time
    ExpiresAt              time.Time
}
```

`TransportRecommendation` MUST NOT contain or compile to `ActionAuthorization` or `TransportAuthorization`.

The object expires when any material input changes:

```text
network context
BlockingProfile freshness/confidence
service/component target plan
client scope
ConfigGen
WARP build/capability/safety hash
WARP SessionGen/RouteGen
causal-trace completeness
failure policy
```

## 28A.3. Evidence classes that allow WARP suggestion

Base WARP MAY become `eligible-to-test` when all common gates pass and at least one supported hypothesis exists.

Supported hypotheses:

```text
path_local_syn_filter_probable
path_local_syn_filter_confirmed
service_ip_filter_probable
service_cidr_filter_probable
multi_origin_direct_connect_failure_with_reference_success
shared_transport_path_block_probable
```

Common gates:

```text
BlockingProfile fresh for current NetworkContext
confidence >= configured recommendation threshold
exact service/component scope known
at least two independent evidence families OR differential reference-path proof
same-service and unrelated controls healthy
origin-dead and local-outage suppressors absent
IP family explicit
WARP capability projected by runtime
base WARP allowed by profile/product policy
no cross-service scope expansion
```

High-confidence IP-level evidence MAY include:

- repeated direct SYN/connect failure across multiple service targets;
- exact target success through a healthy reference path;
- direct failure and base-WARP candidate success in a bounded differential probe;
- multiple IPs or origins within the same component failing while controls remain healthy;
- explicit user-pinned IP/CIDR target failing direct and succeeding through an alternate path;
- provider/path evidence showing filtering before TLS/SNI/application milestones.

One of these observations alone is insufficient:

```text
one timeout
one failed IP
one DNS answer
one exception string
one CDN edge
one failed proxy/reference path
one stale profile from another WAN
```

## 28A.4. Cases where WARP is not the primary recommendation

Recommendation compiler MUST prefer the least disruptive causal family:

| BlockingProfile evidence | First recommendation | WARP position |
|---|---|---|
| DNS spoofing/interception only | trusted resolver, system-forward or DoH | not primary; test only if IP path also fails |
| QUIC/UDP 443 blocked, TCP healthy | TCP/TLS fallback | not primary |
| SNI/ClientHello-specific RST | direct split/fake/fingerprint candidates | optional fallback after direct validation |
| TLS fingerprint incompatibility | validated browser/Android ClientHello | optional fallback |
| HTTP redirect/injection | Host/HTTP direct candidates | optional fallback |
| packet-count/byte-window trigger | low-amplification shaping/stream candidate | optional alternate transport |
| local WAN outage/control failure | fix or wait for connectivity | forbidden |
| origin unreachable across independent paths | report origin unavailable | forbidden |
| reference path unhealthy/inconclusive | gather evidence | forbidden |
| shared-CDN IP with ambiguous service ownership | refine target evidence | forbidden for broad route |
| IP/SYN/CIDR path filtering | base WARP differential test | primary transport candidate |

The compiler MUST NOT recommend nested `НЕ РФ` merely because an IP block was found. `nested-nonru` appears only when the user/profile independently declares a geo constraint and all non-RU gates are available.

WARP Transport Camouflage is also separate. Target IP blocking MAY justify testing base WARP, but it does not justify camouflage of the WARP control flow. Camouflage is considered only when the WARP enrollment/MASQUE control path itself shows compatible DPI evidence.

## 28A.5. WARP readiness gates

Before showing an actionable test button, runtime capability projection MUST expose:

```yaml
warp_recommendation:
  transport_kind: cloudflare-warp-masque
  bundled_engine_available: true
  enrollment_supported: true
  base_transport_capable: true
  causal_trace_ready: true
  path_proof_supported: true
  forwarded_binding_correlation: true
  target_canary_supported: true
  current_runtime_state: unconfigured | ready | active | degraded | unavailable
```

UI behavior:

```text
unconfigured + enrollment supported
→ "Настроить WARP и проверить"

ready/active
→ "Проверить через WARP"

degraded/unavailable
→ show reason, no enable button

causal trace/path proof unavailable
→ diagnostic/manual-only, no production recommendation
```

`WARP_CAUSAL_TRACE_READY` is required by the shipped capability before production recommendation. For the current run, required P0 events, current generation and path proof must also be complete.

## 28A.6. Scoped validation plan

Pressing `Проверить через WARP` starts a bounded transaction, not a permanent apply:

```text
1. freeze exact ClientKey/service/component/SetID scope
2. verify fresh direct baseline and BlockingProfile
3. prepare or reuse current base-WARP candidate generation
4. prove WARP L3/router path without promoting service route
5. run exact target probes through base WARP
6. run same-service and unrelated controls
7. run real forwarded Android-client canary where required
8. compare direct vs WARP quality and failure mode
9. rollback all temporary route tokens
10. issue validated/rejected/blocked recommendation state
```

Required comparison:

```text
direct target fails
+ base-WARP target reaches component success milestone
+ controls do not regress
+ WARP path proof belongs to current SessionGen/RouteGen
+ no DNS/IPv6/direct-WAN leak forbidden by policy
→ TransportRecommendationValidated
```

A successful router-origin probe is insufficient. Production enablement requires the applicable forwarded-client proof and current causal chain.

Validation MAY stop early on hard safety failure, but it MUST preserve completed evidence and cleanup temporary state.

## 28A.7. Beginner UX states

### Before validation

```text
Вероятная блокировка по IP

Прямое подключение к выбранному компоненту не проходит,
а контрольные проверки работают. WARP может дать другой сетевой маршрут.

WARP пока не включён. Сначала B4 проверит его только для:
• устройства: Android-main
• сервиса: YouTube
• компонента: video/media

[Проверить через WARP]  [Подробнее]
```

Do not show:

```text
Включить лучший обход
WARP точно исправит проблему
Включить VPN для всего устройства
```

### During validation

```text
Проверяем WARP для YouTube video/media

Прямой путь: не проходит
WARP path: проверяется
Контрольные сервисы: проверяются
Постоянные правила: не изменены
```

### Validated

```text
WARP помог для выбранного сервиса

Цели: 3/3 успешно
Контрольные проверки: без ухудшений
Проверено на устройстве: Android-main
Режим: только выбранный сервис
При сбое WARP: вернуться на прямой путь

[Включить для этого сервиса]  [Оставить выключенным]
```

The enable action is a new explicit transaction that creates ordinary scoped transport authorization under existing WARP/Profile rules. It does not reuse the test token as production authorization.

### Rejected or inconclusive

```text
WARP не подтвердил улучшение

Причина:
• цель не заработала через WARP
или
• ухудшились контрольные проверки
или
• путь WARP не удалось доказать

B4 продолжит обычный guided/full Discovery.
```

## 28A.8. Advanced preview

Advanced UI MUST show:

- recommendation ID/state/expiry;
- service, component, client and SetID scope;
- BlockingProfile/hypothesis IDs;
- direct and reference-path evidence;
- confidence and contradictions;
- selected base-WARP instance and current generation;
- expected failure policy;
- exact target and control probes;
- path-proof and forwarded-client requirements;
- temporary route-token budget;
- rollback target;
- reason when recommendation is unavailable or rejected.

It MUST NOT expose private WARP credentials, raw public IP where redaction applies, full user domain history or secret-bearing trace payloads.

## 28A.9. Failure policy and scope

Default recommended policy for ordinary IP-block bypass:

```yaml
failure:
  mode: fail-open
```

The preview MUST say explicitly:

```text
Если WARP перестанет работать, выбранный сервис вернётся на прямой путь.
```

`fail-closed-scoped` MAY be selected only by explicit profile/user policy. No WARP recommendation may silently create a global kill switch, default route or router-origin route.

Recommended scope is the minimum validated scope:

```text
exact client
+ exact service/component
+ exact managed set/domain authorization
+ current ConfigGen
```

A successful recommendation for one component does not authorize another component or service.

## 28A.10. Interaction with guided Discovery

WARP recommendation is a candidate family within the existing guided/full process:

```text
BlockingProfile indicates IP-level path filtering
→ DDI prioritizes base-WARP transport candidate
→ mandatory direct baseline remains
→ target/control WARP validation runs
→ full bounded fallback remains available
```

Rules:

- WARP does not disable direct strategy candidates unless the planner excludes them for a documented causal reason;
- failed WARP validation returns to ordinary guided/full Discovery;
- a validated direct strategy with equal quality and lower cost MAY rank above WARP;
- a validated WARP route MAY rank above direct packet strategies when IP-level filtering makes those strategies causally inapplicable;
- ranking includes latency, goodput, stability, CPU/RAM and control risk;
- production promotion remains transactional, scoped and reversible.

## 28A.11. Recommendation metrics and hard gates

Bounded metrics:

```text
profile_transport_recommendation_total{transport,reason,state}
profile_warp_recommendation_validation_total{result}
profile_warp_recommendation_duration_seconds
profile_warp_recommendation_control_regression_total
profile_warp_recommendation_expired_total
profile_warp_recommendation_cleanup_failure_total
```

Hard gates:

```text
profile_warp_recommended_without_ip_path_evidence_total == 0
profile_warp_recommended_from_destination_ip_only_total == 0
profile_warp_recommended_for_origin_dead_total == 0
profile_warp_recommended_with_unhealthy_controls_total == 0
profile_warp_recommendation_cross_service_total == 0
profile_warp_recommendation_stale_profile_total == 0
profile_warp_recommendation_without_causal_trace_gate_total == 0
profile_warp_enabled_without_target_canary_total == 0
profile_warp_test_token_reused_as_production_authorization_total == 0
profile_warp_recommendation_ignored_control_regression_total == 0
profile_warp_recommendation_hidden_fail_policy_total == 0
profile_nonru_suggested_without_geo_requirement_total == 0
profile_warp_camouflage_suggested_for_target_ip_block_total == 0
profile_warp_recommendation_cleanup_failure_total == 0
```

## 28A.12. Release verdict

```text
PROFILE_WARP_RECOMMENDATION_READY
```

Requires:

```text
ABD_REFERENCE_PATH_READY
+ ABD_PRODUCTION_READY
+ DDI_PRODUCTION_READY
+ WARP_BASE_READY
+ WARP_CAUSAL_TRACE_READY
+ FT-W…FT-Z detector/guided evidence
+ FT-M/FT-AC/FT-AD WARP path and causal proof
+ Service Profile recommendation UI/transaction tests
+ IV-14/IV-15/IV-17 umbrella PASS
```

`PROFILE_WARP_RECOMMENDATION_READY` authorizes the product feature that offers and validates WARP. It does not authorize any particular user route without a current scoped validation result and explicit product policy/user action.

# 29. Transparent Telegram bridge profile policy

Telegram profile MAY объявить generic transparent bridge preference, но не владеет sockets, deadlines, pending manager или route ladder.

```yaml
transport:
  kind: telegram-transparent-bridge
  transparent:
    enabled: true
    first_byte_policy: bounded-wait
    overflow_policy: worker-failopen
    failopen: true
```

Compiler использует system defaults и capability projection. Expert overrides допускаются только в validated bounds:

```text
soft deadline < hard deadline
max_pending_global bounded
max_pending_per_client bounded
explicit overflow policy
worker/direct fallback capability known
TPROXY recursion guard available
```

Beginner UI не предлагает «просто увеличить timeout». Он показывает:

- ожидает ли bridge первые данные;
- сколько pending connections;
- были ли overflow/fallback;
- какой route выиграл;
- сохранён ли prefix;
- есть ли Android validation;
- degraded/blocked reason.

При `TGB_PRODUCTION_READY != true` profile остаётся disabled, manual-only или clearly experimental в зависимости от product policy.

# 30. Дополнительные Service Profile stages редакции 1.5

## SP-24 — Detector target-plan schema and compiler

- manifest fields для primary/component/control/custom targets;
- ownership, bounds, normalization и preview diff;
- quick/standard/deep upper bound;
- trusted pack controls;
- no hidden remote dependency.

## SP-25 — Detector capability projection and policy validation

- ABD capability matrix;
- clean-path/capture requirements;
- DNS/TLS/QUIC/L4 availability;
- privacy/resource downgrade;
- stale validation invalidation.

## SP-26 — BlockingProfile and evidence UX

- beginner uncertainty language;
- advanced evidence graph;
- profile age/network context;
- contradiction/control visibility;
- redacted export and issue bundle.

## SP-27 — Guided Discovery policy and transaction integration

- DDI profile selection/revalidation;
- guided/full budgets;
- baseline/fallback invariants;
- candidate preview;
- target controls;
- canary/promote/rollback;
- truthful savings report.

## SP-28 — Transparent Telegram bridge policy and UX

- bounded declarative settings;
- capability projection;
- pending/overflow/fallback status;
- secret-safe diagnostics;
- migration from legacy fixed-timeout behavior;
- no profile-owned socket lifecycle.

## SP-29 — Profile-pack validation and release integration

- YouTube/Discord/Instagram/Telegram target plans;
- custom-domain path;
- Field `FT-W…FT-AB` mapping;
- umbrella ABD/DDI/TGB verdict projection;
- downgrade/rollback after network/config/capability change.

## SP-30 — BlockingProfile transport-recommendation compiler

- typed `TransportRecommendation` schema and state machine;
- exact mapping from supported IP/SYN/CIDR hypotheses;
- causal alternative selection for DNS/QUIC/SNI/TLS/HTTP/L4 evidence;
- freshness, confidence, controls and suppressor gates;
- base-WARP-only automatic recommendation;
- no ActionAuthorization/TransportAuthorization output;
- expiry after network/profile/config/capability changes.

DoD: one timeout, one destination IP, unhealthy controls, origin-dead evidence or stale cross-WAN profile cannot produce an actionable WARP recommendation.

## SP-31 — Scoped WARP recommendation UX and validation transaction

- beginner cards for eligible/testing/validated/rejected/unavailable states;
- WARP setup consent/enrollment handoff;
- exact client/service/component preview;
- bounded direct-vs-WARP target/control comparison;
- current WARP causal/path proof requirement;
- forwarded Android canary;
- explicit failure policy and rollback;
- separate test and production authorizations;
- guided/full Discovery fallback after failed WARP validation.

DoD: user can test WARP without changing permanent routing and can enable it only after current scoped validation.

## SP-32 — WARP recommendation release integration

- Field Test mapping to `FT-M`, `FT-W…FT-Z`, `FT-AC…FT-AD`;
- umbrella mapping to `IV-14`, `IV-15`, `IV-17`;
- all recommendation hard gates;
- capability API and profile safety-hash integration;
- downgrade when WARP/ABD/DDI/trace evidence expires;
- release verdict `PROFILE_WARP_RECOMMENDATION_READY`.

DoD: profile packs cannot advertise automatic WARP recommendation until all detector, DDI, WARP path, causal trace and UI transaction gates pass.

# 31. Дополнительный Definition of Done редакции 1.5

71. Every optimized bundled profile declares primary, component and control target roles or explicitly opts out with reason.
72. Custom user domains retain manual/pinned ownership through profile updates.
73. Profile cannot create unbounded wildcard or dynamic infrastructure scans.
74. Detector mode is an upper bound and cannot disable clean baseline or controls.
75. Profile cannot convert Detector hypothesis into ActionAuthorization.
76. Profile cannot directly write a strategy from `BlockingProfile`.
77. BlockingProfile status includes network context, freshness, confidence and contradictions.
78. Beginner UI distinguishes observation, hypothesis, target validation and production readiness.
79. Advanced UI exposes protocol/fingerprint/packet-byte evidence without leaking sensitive data.
80. Guided search preview includes mandatory baselines and full fallback budget.
81. DDI stale/conflicting/cross-WAN profile is rejected or revalidated.
82. Failed guided priors do not suppress full bounded search.
83. Savings report is truthful and quality-aware.
84. Cross-service and same-client control requirements remain mandatory.
85. Telegram profile does not own pending sockets, deadlines or fallback route execution.
86. Zero-byte wait policy is bounded and cannot compile to destructive fixed five-second drop.
87. Pending global/per-client bounds and overflow policy are visible in expert preview.
88. Telegram bridge secrets/prefix payloads are excluded from normal exports.
89. `SP-24`–`SP-29` map to `ABD-1`–`ABD-12`, `DDI-1`–`DDI-10`, `TGB-1`–`TGB-10`, `FT-W`–`FT-AB` and umbrella IV coverage.
90. Profile health is invalidated after material target-plan, detector, network-context, DDI or TGB capability changes.

# 32. Итог редакции 1.5

Service Profiles v1.5 делает идеальный пользовательский сценарий декларативным и безопасным:

```text
выбрать сервис или домены
→ увидеть план диагностики и controls
→ запустить clean Detector v2
→ получить объяснимый BlockingProfile
→ выполнить guided, затем при необходимости full Discovery
→ проверить candidate на Android и controls
→ canary/promote или rollback
```

Для Telegram отдельный profile projection обеспечивает bounded delayed-first-data bridge, но runtime lifecycle остаётся собственностью TGB subsystem.

Профиль ускоряет и упрощает путь пользователя; он не подменяет доказательство, authorization, Discovery или release validation.

# 33. Дополнительный Definition of Done редакции 1.6

91. Fresh probable/confirmed IP, SYN or CIDR path evidence can produce only an `eligible-to-test` base-WARP recommendation.
92. A recommendation never becomes `ActionAuthorization`, `TransportAuthorization` or a route token.
93. One timeout, one IP, one exception, one CDN edge or one failed reference path cannot produce an actionable recommendation.
94. Origin-dead, WAN-outage, unhealthy-control and inconclusive-reference-path states suppress WARP recommendation.
95. DNS-only, QUIC-only, SNI/fingerprint and HTTP-injection profiles prefer their causal direct alternatives before WARP.
96. Automatic recommendation uses base WARP only; nested `НЕ РФ` requires an independent explicit geo constraint.
97. Target IP blocking never authorizes WARP Transport Camouflage.
98. Beginner UI says `Проверить через WARP` before validation and `Включить для этого сервиса` only after scoped success.
99. The WARP test transaction does not alter permanent routing and cleans all temporary tokens/state.
100. Test authorization is never reused as production authorization.
101. Production enablement requires exact target success, healthy controls and applicable forwarded-client causal proof.
102. Router-origin WARP success cannot substitute Android/LAN-client validation.
103. WARP recommendation scope is exact client + service/component + set + ConfigGen and cannot cross services.
104. Default ordinary IP-block recommendation exposes fail-open behavior; fail-closed requires explicit policy.
105. Recommendation expires after network-context, BlockingProfile, WARP generation/capability, target-plan or safety-hash change.
106. Failed or inconclusive WARP validation returns to ordinary guided/full bounded Discovery.
107. A validated lower-cost direct candidate may outrank WARP; ranking remains quality- and risk-aware.
108. Capability projection exposes causal trace/path proof readiness and does not offer production enablement when missing.
109. All 14 recommendation hard gates are registered in Field/Implementation Validation consumers.
110. `PROFILE_WARP_RECOMMENDATION_READY` is required before bundled profiles expose the automatic recommendation feature as production-ready.

# 34. Итог редакции 1.6

Service Profiles v1.6 adds a causal and reversible product path for IP-level blocking:

```text
user selects service/domain
→ Detector v2 proves fresh scoped IP/SYN/CIDR path blocking
→ UI explains why WARP is a plausible alternate route
→ user starts a temporary exact-scope WARP test
→ B4 proves current WARP path and causal trace
→ target succeeds and controls remain healthy
→ real forwarded client canary passes
→ UI offers scoped enablement
→ transactional apply with rollback
```

For other failure classes, the UI presents the corresponding causal family first. WARP remains an alternate transport, not a universal answer to every failure.

The recommendation feature does not weaken the central invariants:

```text
BlockingProfile != authorization
recommendation != route
router-origin success != forwarded proof
base WARP != non-RU
IP block != WARP camouflage authorization
```

