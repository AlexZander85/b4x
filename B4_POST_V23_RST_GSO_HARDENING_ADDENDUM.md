# B4 Post-v2.3 RST/GSO Hardening Addendum

**Версия:** 1.0  
**Дата:** 2026-07-29  
**Статус:** обязательный post-plan companion addendum  
**База:** завершённая реализация `B4_FORK_ARCHITECTURE.md` v2.3 и всех Stage 1–36 `B4_FORK_PATCH_PLAN.md` v2.3  
**Область:** NFQUEUE capture correctness, reassembled-SNI decision integration, NFQUEUE GSO fast path, passive RST injection defense  

---

## 0. Нормативный статус и место в проекте

Этот addendum применяется **поверх уже завершённого патч-плана v2.3**.

Он:

- не переоткрывает и не перенумеровывает Stage 1–36;
- не отменяет ранее пройденные stage gates;
- не превращает исправления в повторную реализацию Core Fix, Productization или Strategy Catalog;
- добавляет отдельный post-plan hardening layer с companion stages `H1–H10`;
- требует малых compatibility/corrective patches в уже существующих runtime-компонентах только там, где найденный gap мешает выполнить новый нормативный контракт;
- должен быть завершён до объявления GSO или активной passive-RST filtering production-ready.

При конфликте требований для подсистем GSO, RST и reassembled-SNI действует следующий порядок приоритета:

```text
B4_FORK_ARCHITECTURE.md v2.4
→ этот addendum
→ B4_FORK_PATCH_PLAN.md v2.3
→ implementation notes и historical documents
```

Исходники и архив из GitHub issue `DanielLavrushin/b4#280` используются только как **read-only reference/proof of concept**. Прямой cherry-pick, blind port или сохранение его фиксированной mark-схемы запрещены без отдельного аудита лицензии, packet semantics и совместимости с текущим форком.

---

# Часть I. Цели и не-цели

## 1. Цели

Форк MUST:

1. сделать complete reassembled ClientHello равноправным источником classifier evidence;
2. гарантировать одинаковый `ClassificationDecision` для одного логического ClientHello независимо от того, получен он одним GSO skb или несколькими MSS-сегментами;
3. использовать `NFQA_CFG_F_GSO` как capability-gated ускоритель capture/classification, а не как замену TCP reassembly;
4. нормализовать GSO skb только когда выбранный `ActionPlan` действительно требует обычных wire-sized TCP packets;
5. исключить двойную классификацию, двойные side effects и повторное применение action при переходе между GSO и normalizer queue;
6. встроить passive RST injection defense в новый TCP FSM;
7. по умолчанию наблюдать подозрительные RST, а не блокировать их;
8. разрешать подавление RST только при полной incoming visibility, точном `FlowKey`, достаточных доказательствах и ограниченном бюджете;
9. автоматически возвращать passive RST mode в `observe` при признаках collateral damage или reconnect regression;
10. сохранить fail-open, bounded memory, transactional lifecycle и source-scoped isolation.

## 2. Не-цели

Этот addendum не должен:

- заменять bounded TCP reassembly режимом GSO;
- включать global GSO в production по умолчанию;
- вводить socket-level GSO как фиктивную per-set опцию;
- применять packet-local strategy непосредственно к GSO skb без доказанной GSO-safety;
- использовать фиксированную служебную mark вроде `0x08000000`;
- блокировать RST только по IPID;
- считать suppressed RST доказательством успешной стратегии;
- автоматически выбирать controlled RST strategy по одному inferred injection hop;
- расширять scope сетов, клиентов или доменов ради прохождения тестов;
- повторно выполнять Stage 1–36.

## 2.1. Связь с завершённым Stage 32

Завершённый Stage 32 `Controlled RST and RST-path diagnostics` сохраняет свой статус и семантику:

- controlled RST injection остаётся explicit outbound strategy/action;
- RST-path diagnostics остаётся heuristic/diagnostic subsystem;
- passive RST injection defense является отдельной inbound validation/suppression subsystem;
- общий код packet parsing, TCP FSM, trace и capability MAY быть расширен совместимыми patches, но Stage 32 не выполняется заново;
- passive detection не разрешает автоматически активировать controlled RST injection, а controlled RST strategy не является доказательством поддельного входящего RST.

Нормативное разделение:

```text
controlled RST injection
→ B4 намеренно создаёт outbound packet по explicit ActionPlan

passive RST injection defense
→ B4 оценивает incoming RST и при достаточных доказательствах может его подавить
```

---

# Часть II. Обязательные архитектурные решения

## 3. ADR-H1 — Reassembly является correctness path

Нормативная схема:

```text
GSO full ClientHello
→ fast path

обычные MSS-сегменты
→ bounded TCP reassembly
→ тот же ClassificationDecision

GSO отсутствует, выключен, truncated или не помог
→ корректность не теряется
```

`NFQA_CFG_F_GSO` MAY уменьшать latency и количество held packets, но MUST NOT быть единственным способом получить clear SNI первого flow.

## 4. ADR-H2 — Complete reassembled SNI становится classifier evidence

После успешной bounded reassembly:

```text
reassemblyResult.Metadata.Complete == true
+ reassemblyResult.Metadata.SNI != ""
+ ECH не скрывает выбранное имя
→ EvidenceReassembledTCPSNI
```

`EvidenceReassembledTCPSNI` MUST:

- участвовать в том же source-scoped set matching, что и packet-local clear SNI;
- иметь тот же или явно определённый эквивалентный priority;
- содержать provenance `reassembled-tcp-sni`;
- быть связано с точным `FlowKey`, `ClientHelloID` и `ConfigGen`;
- проходить TLS version, source-device, IP-family и protocol revalidation;
- не записываться как global learned-IP evidence;
- не становиться positive evidence при conflicting overlap, malformed ClientHello, truncation или ECH ambiguity.

Запрещена модель, в которой reassembly только выставляет `ClearSNI=true`, но hostname продолжает извлекаться исключительно из текущего packet payload.

## 5. ADR-H3 — GSO описывает capture/execution capability, а не домен

Глобальная конфигурация:

```yaml
capture:
  nfqueue:
    gso_mode: off          # off | observe | classify | full
    max_gso_bytes: 32768
    normalize_for_mutation: true
    tcp_only: true
```

Execution policy для strategy/set:

```yaml
execution:
  gso_policy: inherit      # inherit | accept-only | normalize | direct
```

Семантика:

- `off` — NFQUEUE sockets не запрашивают GSO; прежнее поведение;
- `observe` — GSO metadata и shadow decision собираются только в разрешённом diagnostic/canary scope; production action не меняется;
- `classify` — GSO packet может дать authoritative classification; неизменяемый packet принимается напрямую, unsafe mutation идёт через normalizer;
- `full` — direct action над GSO input разрешён только techniques, чья GSO-safety доказана отдельным capability gate.

Defaults:

```text
gso_mode = off
execution.gso_policy = inherit
```

После target validation допустимый рекомендуемый production mode:

```text
gso_mode = classify
```

`full` MUST NOT включаться автоматически, через Discovery winner или migration.

## 6. ADR-H4 — Normalization выполняется только по требованию ActionPlan

Нормативный runtime path:

```text
NFQUEUE GSO classifier
        │
        ├─ non-GSO packet
        │      → обычный runtime
        │
        ├─ GSO + no packet mutation
        │      → NF_ACCEPT unchanged
        │
        ├─ GSO + GSO-safe ActionPlan
        │      → planner строит MTU-bounded writes
        │
        └─ GSO + normal-packet-only technique
               → normalize/requeue
               → executor получает обычные MSS segments
```

Не требуется нормализовать весь traffic non-selected sets. Secondary normalizer path используется только после pure classification/dry-run, когда итоговый plan требует normal packet representation.

## 7. ADR-H5 — Passive RST default observe

```go
type PassiveRSTMode string

const (
    PassiveRSTOff          PassiveRSTMode = "off"
    PassiveRSTObserve      PassiveRSTMode = "observe"
    PassiveRSTConservative PassiveRSTMode = "conservative"
    PassiveRSTAggressive   PassiveRSTMode = "aggressive"
)
```

Default:

```text
passive_rst.mode = observe
```

Ни migration, ни profile compiler, ни Discovery не могут автоматически повысить mode до `aggressive`.

---

# Часть III. Post-plan companion stages

## H1. Reassembled-SNI runtime decision integration

### Реализовать

- новый evidence source `EvidenceReassembledTCPSNI` либо совместимый явно различимый provenance;
- преобразование complete reassembly result в classifier observation;
- единый hostname/set decision path для packet-local и reassembled SNI;
- привязку к `ClientHelloID`, `FlowKey` и immutable config generation;
- release hold после authoritative decision или fail-open abort;
- отсутствие duplicate matcher learning и duplicate trace event.

### Обязательные invariants

```text
один logical ClientHello
→ один ClassificationDecision
→ один ActionToken
```

```text
packet layout changed
→ selected set/action не меняются при одинаковом logical stream
```

### Tests

- ClientHello в 1, 2, 3, 5 сегментах;
- reordered segments;
- exact retransmission;
- identical overlap;
- conflicting overlap;
- SNI во втором сегменте;
- complete ClientHello + trailing record;
- ECH/no clear SNI;
- generation change;
- same destination/two clients;
- parity между GSO full packet и MSS reassembly.

### Коммит

```text
fix(classifier): promote complete reassembled SNI into flow decisions
```

---

## H2. NFQUEUE offload metadata envelope

### Добавить

```go
type OffloadMetadata struct {
    IsGSO               bool
    ChecksumNotReady    bool
    ChecksumNotVerified bool
    PayloadLength       uint32
    OriginalLength      uint32
    Truncated           bool
}
```

Metadata MUST строиться из доступных NFQUEUE attributes, включая:

- `NFQA_SKB_INFO`;
- `NFQA_SKB_GSO`;
- `NFQA_SKB_CSUMNOTREADY`;
- `NFQA_SKB_CSUM_NOTVERIFIED`, если доступно;
- `NFQA_CAP_LEN`;
- фактическую длину copied payload.

### Правила

```text
Truncated
→ never parse as complete ClientHello
→ fail-open / reassembly / diagnostic outcome
```

```text
ChecksumNotReady
→ исходная transport checksum не считается invalid
```

```text
GSO + unsupported mutation
→ action suppress или normalize
```

```text
GSO + no mutation
→ accept unchanged
```

### Capability

Runtime status MUST различать:

```text
unsupported
supported-unvalidated
observe-only
classify-ready
full-action-ready
failed
```

### Коммит

```text
feat(capture): add NFQUEUE GSO and checksum offload metadata
```

---

## H3. GSO observe и classify fast path

### Observe

- разрешён только в diagnostic/candidate/canary scope до завершения normalizer gate;
- shadow decision не меняет production action;
- full GSO payload не сохраняется в public telemetry;
- raw capture подчиняется существующей privacy policy.

### Classify

`gso_mode=classify` разрешён только при **current-generation verdict `GSO_CLASSIFY_READY`** (FB-14 решение 12):

```text
READY → classify разрешён
UNKNOWN/STALE/FAIL → автоматический downgrade в observe
```

`GSO_CLASSIFY_READY` требует:

```text
корректный NFQUEUE/GSO metadata envelope
+ отсутствие truncation/length/checksum ambiguity
+ GSO ↔ equivalent MSS classification parity
+ IPv4/IPv6 coverage
+ retransmission/out-of-order/idempotency tests
+ queue/user drop budgets
+ CPU/RAM/held-packet budgets
+ current visibility proof, когда PPE включён
+ production reachability через реальный packet entry point
```

При `gso_mode=classify`:

- complete GSO ClientHello проходит через тот же classifier API, что reassembled ClientHello;
- no-op/accept/routing verdict может завершиться без secondary queue;
- `ActionPlan` обязан объявить требуемую packet representation;
- неизвестная representation или missing capability приводит к fail-open/suppress, а не direct mutation;
- GSO fast path не создаёт второй `ClientHelloID`.

`classify` разрешает **только classification на представлении GSO**. Он **не разрешает normalization или packet mutation**. Normalization/action дополнительно требуют:

```text
current ActionAuthorization
+ single-use GSOPassToken
+ GSO_RUNTIME_READY
+ strategy compatibility
+ rollback/cleanup readiness
```

> **superseded (FB-14 решение 12):** прежняя формулировка «gso_mode=classify как рекомендуемый production mode» без разрешающего gate заменена verdict-gated моделью настоящего пункта.

### Tests

- GSO full ClientHello 1988 B;
- 4 KiB, 16 KiB и 32 KiB ClientHello fixtures;
- same logical stream GSO/MSS decision parity;
- no-action accept unchanged;
- routing-only path;
- malformed/truncated input;
- config mode transitions.

### Коммит

```text
feat(capture): add capability-gated NFQUEUE GSO classification fast path
```

---

## H4. Conditional GSO normalizer и first-pass token

### Token — canonical `GSOPassToken` (FB-14 решение 4)

Единственный canonical `GSOPassToken` принадлежит GSO/runtime boundary и содержит compact immutable references (крупные mutable `Authorization`/`EffectivePolicy` объекты в token НЕ копируются — они разрешаются по ID/digest в current generation):

```go
type GSOPassToken struct {
    TokenID             string
    FlowKey             classifier.FlowKey
    ClientHelloID       uint64
    ConfigGeneration    uint64
    Decision            classifier.ClassificationDecision
    StrategyID          string
    RequiresAction      bool
    AuthorizationID     string // или AuthorizationDigest
    EffectivePolicyID   string // или EffectivePolicyDigest
    CandidateDisposition string
    CreatedAt           time.Time
    ExpiresAt           time.Time
    ConsumedAt          *time.Time
}
```

Обязательные свойства:

- single-use consume;
- exact generation binding;
- flow/client scope binding;
- TTL/expiry;
- replay rejection;
- no reclassification/re-authorization on secondary pass;
- cleanup при generation retirement;
- bounded memory/cardinality.

Token store MUST быть:

- bounded;
- keyed точным flow/clienthello/generation identity;
- deterministic under retransmission;
- очищаемым по completion, timeout, FIN, RST, shutdown и generation change;
- недоступным между production и candidate/discovery scopes;
- без mutable config pointers.

> **superseded (FB-14):** расширенная схема token с вложенными `ActionAuthorization`/`EffectivePolicy` объектами (бывш. CSI addendum §18) удалена как duplicate schema. CSI ссылается на canonical `GSOPassToken` настоящего пункта.

### First pass

Если требуется normalization, GSO classifier выполняет pure decision/dry-run и MUST NOT до secondary pass:

- повторно обучать matcher;
- записывать production Discovery outcome;
- применять action;
- создавать второй ActionToken;
- фиксировать final connection outcome;
- выполнять irreversible side effects.

### Secondary pass

Secondary worker:

- валидирует token и config generation;
- использует тот же decision и ActionToken identity;
- не повторяет DNS/SNI evidence ingestion;
- не повторяет ClientHello Laboratory capture;
- применяет normal-packet ActionPlan один раз;
- удаляет token после final verdict;
- при token miss/stale выполняет fail-open или безопасный idempotent fallback с явным trace reason.

### Queue transition mechanism

Допустимые кандидаты:

1. userspace verdict `NF_QUEUE_NR(secondaryQueue)`;
2. `NF_REPEAT` + transient mark.

`NF_QUEUE_NR` предпочтителен только если target test доказывает queue-specific normalization на целевом kernel.

`NF_REPEAT` допустим только при:

- mark из общего allocator;
- доказанной очистке mark на всех accept/drop/hold/timeout/shutdown paths;
- loop detection;
- exact firewall ownership;
- отсутствии конфликта с processed, canary, routing, TUN, PPE и user marks.

Фиксированная mark `0x08000000` запрещена.

### Коммит

```text
feat(capture): normalize GSO only for normal-packet action plans
```

---

## H5. Transactional GSO queue topology

Изменение `gso_mode`, queue ranges, worker topology или normalizer mechanism считается runtime topology transaction, а не обычной заменой config pointer.

### Apply order

```text
validate config/marks/queue ranges
→ reserve secondary queues
→ start secondary workers
→ prove owner PID/portid readiness
→ start GSO classifier workers
→ prove readiness
→ atomically install/switch firewall rules
→ drain previous topology
→ commit generation
```

### Rollback

При любой ошибке:

```text
restore previous rules/topology
→ release held packets unchanged
→ invalidate GSO tokens
→ clear owned transient marks/state
→ restore last-good generation
```

### Requirements

- `start + required_queues - 1 <= 65535`;
- no overlap production/candidate/discovery/normalizer queues;
- iptables и nftables parity;
- IPv4/IPv6 explicit capability matrix;
- queue-bypass behavior documented and tested;
- startup window без unbound secondary queue;
- crash/startup reconciliation;
- no global firewall flush;
- worker count and memory budget validated on Keenetic.

### Коммит

```text
feat(runtime): transact NFQUEUE GSO topology and mark lifecycle
```

---

## H6. Passive RST observation model

### State

Passive RST state MUST быть частью/shard-совместимым расширением TCP FSM и хранить только bounded immutable observations:

- exact normalized `FlowKey`;
- config generation;
- SYN/SYN-ACK state;
- server payload progress;
- valid receive/send windows, если наблюдаемы;
- recent server TTL/hop-limit samples;
- TCP option fingerprints;
- RST count/timestamps;
- last route/baseline quality state;
- suppression budget.

### Необходимые сигналы

```text
SYN-ACK seen
server payload progress absent
RST received
```

```text
RST burst in exact FlowKey
```

```text
RST TTL/hop-limit mismatch
against robust server baseline
```

```text
RST SEQ/ACK outside valid receive window
```

```text
TCP option fingerprint mismatch
```

```text
RST without ACK in implausible FSM phase
```

```text
IPID anomaly
→ diagnostic only
```

### Robust TTL/hop baseline

Baseline MUST NOT строиться только по одному первому packet.

Он должен учитывать:

- несколько server observations, когда они доступны;
- median/robust center;
- observed spread;
- configured minimum tolerance;
- freshness;
- route-change/ECMP uncertainty;
- IPv4 TTL и IPv6 hop-limit отдельно;
- baseline quality `none | weak | stable | stale | route-change-suspected`.

Эффективная tolerance должна быть не уже observed spread + safety margin.

При `weak`, `stale` или `route-change-suspected` TTL mismatch не может быть единственным основанием для drop в conservative mode.

### Коммит

```text
feat(tcp): add FSM-aware passive RST observation and evidence model
```

---

## H7. Passive RST decision и enforcement

### Signal classes

**Strong:**

- impossible SEQ/ACK relative to a reliable observed TCP window;
- high-quality TTL/hop baseline mismatch beyond adaptive tolerance;
- pre-server-payload RST in an implausible FSM phase when visibility is complete.

**Corroborating:**

- RST burst;
- TCP options fingerprint mismatch;
- RST without ACK where ACK is expected;
- repeated same injection signature across controlled A/B samples.

**Diagnostic-only:**

- IPID anomaly;
- inferred injection hop;
- one weak TTL sample;
- generic timing correlation without exact flow evidence.

### Conservative mode

```text
один слабый/diagnostic signal
→ trace only
```

```text
один strong + один independent corroborating signal
→ suppress RST, если все safety gates пройдены
```

```text
impossible SEQ/ACK with reliable window
→ suppress RST, если visibility complete и ambiguity отсутствует
```

### Aggressive mode

Допускается suppression по одному strong signal только при:

- explicit operator opt-in;
- exact per-set/per-device scope;
- verified full incoming visibility;
- healthy canary baseline;
- active rollback monitor;
- отсутствии route-change suspicion;
- ограниченном suppression budget.

IPID, inferred hop или один слабый TTL mismatch никогда не достаточны сами по себе.

### Safety gates

- per-set и per-device scope;
- exact `FlowKey`;
- immutable config generation;
- full incoming visibility подтверждена PPE/capture self-test;
- incomplete visibility → effective mode не выше `observe`;
- bounded state и TTL;
- fail-open при ambiguity;
- limit suppressed RST per flow и global rate budget;
- FIN/RST/shutdown/generation cleanup;
- suppression не продлевается sliding TTL бесконечно;
- legitimate closed-port RST без established/SYN-ACK context проходит;
- server RST после confirmed payload progress по умолчанию проходит;
- no suppression for unknown/untracked flow.

### Коммит

```text
feat(tcp): enforce bounded conservative passive RST injection defense
```

---

## H8. Passive RST rollback, Failure Inbox и Discovery

Каждое подозрительное или suppressed RST создаёт structured observation, но не success verdict.

### Failure Inbox

Событие включает:

- redacted client/flow identity;
- set/device scope;
- config generation;
- TCP phase;
- server progress state;
- signal list и strength;
- TTL baseline quality/spread;
- SEQ/ACK validation result;
- option fingerprint result;
- decision `observe | pass | suppress | fail-open`;
- post-decision reconnect/server-progress outcome.

### Discovery

Discovery MAY сравнивать:

```text
direct
production
candidate
candidate + passive RST observe
candidate + conservative suppression
```

Но MUST NOT:

- считать suppression самостоятельной причиной успеха;
- auto-promote aggressive mode;
- смешивать production и sandbox RST state;
- выбирать controlled RST strategy только по inferred path.

### Automatic rollback

Для active suppression runtime должен сравнивать scoped baseline и canary:

- reconnect failures;
- time to SYN-ACK/ServerHello/server payload;
- repeated connection churn;
- no-progress after suppression;
- collateral failures на control domains/services;
- queue drops и router resource pressure.

При hard-gate regression:

```text
conservative/aggressive
→ observe
→ invalidate active suppression generation
→ preserve last-good
→ emit rollback reason
```

Rollback MUST быть scope-limited и transactional.

### Коммит

```text
feat(discovery): integrate passive RST evidence canary and rollback
```

---

## H9. API, schema, UI и observability extension

Поскольку Stage 34–35 уже завершены, этот этап является additive compatibility extension поверх существующих API/UI.

### Config/API

Добавить:

- `capture.nfqueue.gso_mode`;
- `capture.nfqueue.max_gso_bytes`;
- `capture.nfqueue.normalize_for_mutation`;
- `capture.nfqueue.tcp_only`;
- `execution.gso_policy`;
- GSO capability/topology status;
- passive RST mode/scopes/budgets;
- TTL baseline controls;
- rollback thresholds;
- read-only active state и recent decisions.

Requirements:

- schema migration с defaults `gso_mode=off`, `passive_rst.mode=observe`;
- validation queue ranges/mark masks/mode dependencies;
- API version bump или additive versioned fields;
- old configs load unchanged;
- changing GSO topology запускает transaction, а не silent hot pointer update;
- aggressive/full требуют explicit confirmation token;
- import/export не включает raw packets или private ClientHello по умолчанию.

### UI

Advanced UI SHOULD показывать:

- GSO capability и validated level;
- current mode `off/observe/classify/full`;
- packets GSO/normalized/accepted unchanged;
- truncation/checksum-offload warnings;
- normalizer mechanism и queue ranges;
- token misses/loop prevention;
- reassembled-SNI parity status;
- passive RST effective mode и requested mode;
- visibility gate;
- signal breakdown;
- suppression budget;
- reconnect regression/rollback state.

`full` GSO и `aggressive` RST скрыты в advanced mode и сопровождаются явным предупреждением.

### Metrics

Минимум:

```text
classifier_reassembled_sni_total{result,set}
classifier_layout_parity_fail_total{reason}

nfqueue_gso_packets_total{direction,mode}
nfqueue_gso_bytes_total{direction}
nfqueue_gso_truncated_total
nfqueue_gso_csum_not_ready_total
nfqueue_gso_decision_total{path}
nfqueue_gso_normalized_total{mechanism}
nfqueue_gso_action_suppressed_total{reason}
nfqueue_gso_token_miss_total{reason}
nfqueue_gso_transition_total{from,to,result}

passive_rst_observed_total{signal,mode}
passive_rst_decision_total{decision,mode}
passive_rst_suppressed_total{scope,reason}
passive_rst_fail_open_total{reason}
passive_rst_baseline_quality_total{quality}
passive_rst_budget_exhausted_total
passive_rst_rollback_total{reason}
passive_rst_reconnect_regression_total{scope}
```

### Trace

Каждый relevant flow trace должен дополнительно показывать:

```text
offload metadata
GSO mode/capability
payload length vs cap length
checksum state
packet-local vs reassembled SNI provenance
layout parity identity
normalization requirement/mechanism
GSO pass token
secondary queue transition
RST signal set/strength
TTL baseline quality/spread
SEQ/ACK window decision
requested/effective passive RST mode
suppression budget
post-suppression progress or rollback
```

### Коммиты

```text
feat(api): expose NFQUEUE GSO and passive RST hardening controls
```

```text
feat(ui): add advanced GSO and passive RST diagnostics
```

---

## H10. Combined target validation

### GSO kernel/integration matrix

Обязательно проверить:

1. network namespace + veth с реальным GSO skb;
2. ClientHello 1988 B, 4 KiB, 16 KiB, 32 KiB;
3. `NFQA_CAP_LEN` truncation;
4. `NFQA_SKB_CSUMNOTREADY`;
5. unchanged `NF_ACCEPT`;
6. mutation requiring normalization;
7. `NF_REPEAT`/direct queue lifecycle;
8. hold timeout и shutdown с cleanup transit state;
9. queue listener crash;
10. IPv4 и IPv6;
11. iptables и nftables;
12. production/candidate/discovery isolation;
13. PPE visibility;
14. Keenetic CPU/RAM/queue drops;
15. Chrome cold-run A/B;
16. official YouTube и ReVanced;
17. Instagram/Facebook/Cloudflare controls;
18. Discovery reproducibility A/B.

### Passive RST matrix

Обязательно проверить:

- legitimate closed-port RST до SYN-ACK;
- legitimate server RST после SYN-ACK без app payload;
- legitimate RST после server payload progress;
- exact-flow forged pre-response RST;
- multi-RST burst;
- matching TTL и mismatching TTL;
- stable baseline и route-change baseline;
- ECMP/anycast path variation;
- impossible и valid SEQ/ACK;
- TCP option mismatch;
- RST without ACK;
- IPv4 TTL и IPv6 hop-limit;
- incomplete PPE visibility;
- unknown flow;
- budget exhaustion;
- config generation change;
- rollback on reconnect regression;
- Cloudflare reconnect/control scenarios.

### Combined scenarios

- GSO classify + passive RST observe;
- GSO normalize + RST during held first flight;
- GSO token timeout + RST;
- candidate queue + RST suppression isolation;
- PPE deoffload window + GSO;
- hot topology rollback while flows active;
- router restart with stale rules/tokens/marks;
- sustained load and memory pressure.

### Chrome tools

Diagnostic Chrome scripts из issue archive MAY использоваться как L6 workload, но не являются полным proof of correctness, поскольку не гарантируют очистку DNS cache, conntrack и B4 runtime и измеряют browser completion, а не все TCP/TLS milestones.

### Gate

Stage H10 PASS требует:

- real commands и raw result artifacts;
- unit/integration/race/fuzz/benchmark results;
- target Keenetic evidence;
- Android/Chrome field evidence;
- no regression control services;
- no queue leak, stale mark или token leak;
- bounded CPU/RAM;
- rollback proof;
- отсутствие fake PASS.

### Коммит

```text
test(field): validate GSO and passive RST hardening on Keenetic and clients
```

---

# Часть IV. Дополнительные engineering rules

## 8. Representation contract ActionPlan

Каждый TCP `ActionPlan` MUST объявить:

```go
type PacketRepresentation uint8

const (
    RepresentationAny PacketRepresentation = iota
    RepresentationNormalTCP
    RepresentationGSOSafe
)
```

Planner/executor MUST NOT угадывать GSO-safety по названию strategy.

До отдельного доказательства existing split/disorder/fake/raw-reinject techniques считаются `RepresentationNormalTCP`.

## 9. Mark contract

Все transient marks:

- выдаются общим allocator;
- имеют mask/value и owner;
- не пересекаются с packet processed, connmark, canary, sandbox, routing, TUN, PPE или user-reserved masks;
- проверяются при startup и config validation;
- очищаются на каждом terminal verdict и fail-open path;
- не копируются в connmark без explicit contract;
- участвуют в startup reconciliation.

## 10. Hold/replay interaction

Held packet state MUST сохранять сведения, необходимые для корректного final verdict/mark cleanup, либо normalizer design должен исключать transient mark из hold path.

Любой abort:

```text
timeout
pressure
FIN/RST
server progress
shutdown
generation change
queue failure
```

должен release packet unchanged и очистить owned transient state.

## 11. Backpressure

При GSO/normalizer pressure:

1. не создавать новые normalization tokens;
2. не начинать новый hold для GSO flow;
3. suppress unsafe action;
4. accept unchanged/fail-open согласно policy;
5. не повышать passive RST mode;
6. emit metrics и structured diagnostic reason.

## 12. Privacy

- GSO payload не экспортируется автоматически;
- RST flow details редактируются существующей privacy policy;
- raw TTL/SEQ/ACK допустимы локально, но issue bundle по умолчанию sanitized;
- raw ClientHello остаётся opt-in local artifact;
- token и flow IDs в public output должны быть non-reversible/ephemeral.

---

# Часть V. Definition of Done

## 13. Reassembled-SNI DoD

Готово, когда:

1. complete reassembled SNI реально влияет на selected set/action;
2. GSO и MSS layouts дают один decision;
3. один logical ClientHello создаёт один ActionToken;
4. malformed/conflicting/truncated input fail-open;
5. multi-client isolation доказана.

## 14. GSO DoD

Готово, когда:

1. offload metadata полностью доступна runtime;
2. `off` сохраняет прежнее поведение;
3. `classify` доказан на target Keenetic;
4. accept-only GSO packet проходит unchanged;
5. normal-packet action нормализуется без double processing;
6. queue topology применяется transactionally;
7. marks/tokens/holds очищаются на всех paths;
8. IPv4/IPv6 и iptables/nftables имеют честный capability status;
9. no regression control services;
10. `full` остаётся disabled до отдельной GSO-action certification.

## 15. Passive RST DoD

Готово, когда:

1. default mode — `observe`;
2. state встроен в exact-flow TCP FSM;
3. incomplete visibility не допускает active suppression;
4. conservative decision соответствует strong+corroborating matrix;
5. aggressive требует explicit opt-in;
6. legitimate RST scenarios не получают систематический drop;
7. budgets и cleanup доказаны;
8. Failure Inbox/Discovery получают structured evidence;
9. reconnect regression вызывает automatic rollback в `observe`;
10. suppressed RST не записывается как success proof.

## 16. Общий release gate

Addendum считается завершённым только после H1–H10.

До этого UI/API MAY показывать experimental/observe controls, но MUST NOT заявлять:

```text
GSO production-ready
Passive RST protection production-ready
GSO-safe direct actions
```

если соответствующий target capability gate не пройден.

---

# Часть VI. Рекомендуемая последовательность агенту

```text
H1  reassembled-SNI decision integration
H2  offload metadata envelope
H3  GSO observe/classify fast path
H4  conditional normalizer + GSOPassToken
H5  transactional queue topology
H6  passive RST observation model
H7  conservative enforcement
H8  Failure Inbox/Discovery/rollback
H9  API/UI/metrics/trace extension
H10 combined target validation
```

После каждого успешно пройденного companion stage:

- отдельный логический commit или малый commit series;
- полный validation report;
- test/race/fuzz/benchmark evidence, где применимо;
- push в рабочую ветку;
- отсутствие перехода к следующему stage при незакрытом hard gate.

Если target-side проверка невозможна, stage получает `BLOCKED_TARGET_VALIDATION`, а не `PASS`.

---

# 17. Итоговое нормативное решение

```text
v2.3 Stage 1–36 остаются завершёнными.

Этот addendum добавляет post-plan hardening:

reassembled SNI как реальное classifier evidence
+ NFQUEUE GSO как generic classification accelerator
+ reassembly как обязательный correctness path
+ normalization только для ActionPlan, которому она нужна
+ transactional queue/mark/token lifecycle
+ FSM-aware passive RST injection defense
+ observe-by-default и automatic rollback
```

Архив issue `#280` допускается как reference для NFQUEUE flag/attribute и исследовательского A/B, но его fixed mark и двухполосная обработка не являются нормативной архитектурой форка.
