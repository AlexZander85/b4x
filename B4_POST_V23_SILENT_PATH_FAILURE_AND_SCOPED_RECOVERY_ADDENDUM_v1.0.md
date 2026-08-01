# B4 Post-v2.3 Silent Path Failure & Scoped Recovery Addendum

**Версия:** 1.0  
**Дата:** 2026-07-29  
**Статус:** обязательный post-v2.3 companion addendum для обнаружения «тихих» отказов пути и безопасного scoped recovery  
**База:** завершённые `B4_FORK_PATCH_PLAN.md` Stage 1–36, `B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md`, `B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM.md` v1.1, `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md` и `B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md`  
**Область:** passive flow-progress observation, silent path failure suspicion, false-positive suppression, differential proof, bounded strategy/transport recovery, Failure Inbox, canary/promote/rollback, Android/Keenetic validation  
**Главный принцип:** одиночный timeout, stall или повторный ClientHello никогда не является достаточным основанием для автоматического fallback  
**Default:** `observe`  

---

## 0. Нормативный статус и место в проекте

Этот addendum добавляет generic runtime capability:

```text
silent-path-failure-and-scoped-recovery
```

Capability не является отдельной DPI strategy и не считается доказательством вмешательства РКН/ТСПУ.

Нормативное разделение:

```text
flow progress observation
→ фиксирует отсутствие ожидаемого полезного прогресса

silent path suspicion
→ гипотеза о сетевом отказе без явного RST/FIN/TLS Alert

differential proof
→ причинно сравнивает direct/current path с альтернативным candidate path

scoped recovery
→ временно применяет следующий разрешённый strategy/transport только к точному scope
```

Запрещённая формулировка runtime verdict:

```text
rkn_block_confirmed
```

без независимого differential proof.

Допустимые формулировки:

```text
silent_path_failure_suspected
silent_path_failure_correlated
silent_path_failure_differentially_confirmed
recovery_candidate_active
recovery_rolled_back
```

Этот addendum:

- не переоткрывает и не перенумеровывает Stage 1–36;
- не отменяет завершённые CSI, WARP, RST/GSO и PPE gates;
- вводит companion stages `SPF-1`–`SPF-10`;
- использует существующие TCP FSM, reassembly, classifier evidence, `ActionAuthorization`, Discovery, transport binding, canary, last-good и rollback;
- запрещает destination-only failure state;
- запрещает автоматический fallback при incomplete bidirectional visibility;
- требует explicit false-positive suppression evidence;
- запрещает бесконечную rotation кандидатов;
- запрещает recursive transport fallback;
- требует отдельной production promotion для каждого service/component/network cohort;
- требует обновить Field Test, Service Profiles и Implementation Validation после завершения `SPF-10`.

### 0.1. Обязательный порядок реализации

```text
B4_FORK_ARCHITECTURE.md v2.3
→ завершённый B4_FORK_PATCH_PLAN.md Stage 1–36
→ B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md
→ B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM.md v1.1
→ B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md
→ B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md
→ этот addendum SPF-1…SPF-10
→ Field Test Automation update
→ Service Profiles / Beginner UX update
→ Implementation Validation update
→ production promotion
```

Причины такого порядка:

1. CSI задаёт точный scope и запрещает cross-service side effects.
2. WARP предоставляет optional transport recovery target.
3. RST/GSO задаёт корректный bidirectional packet representation и progress accounting.
4. PPE addendum доказывает visibility либо переводит capability в observe-only.
5. Только после этого silent detector может безопасно влиять на runtime routing/strategy.

### 0.2. Приоритет требований

```text
B4_FORK_ARCHITECTURE.md v2.3
→ Cross-Service Isolation Addendum для scope/authorization
→ RST/GSO Addendum для packet representation и visibility
→ WARP Addendum для transport fallback
→ этот addendum для silent failure inference/recovery
→ Field Test / Profiles / Implementation Validation как consumers и release gates
→ read-only references
```

---

# Часть I. Reference design и уроки z2k

## 1. Закреплённый read-only reference

```text
repository: necronicle/z2k
reference commit: 8cffe4e2c9eb27175b4bd55a713d656b5c79f4b2
primary files:
- archive/custom-detectors-rotation/z2k-autocircular.lua
- webpanel/www/app.js
- webpanel/cgi/api.sh
- lib/menu.sh
- tests related to silent fallback / circular rotation
```

Reference используется только для анализа field lessons. Blind port Lua/shell state machine запрещён.

## 2. Что полезного подтверждено в z2k

В z2k `Silent fallback РКН` является explicit opt-in и UI предупреждает о возможных ложных срабатываниях.

В актуальном reference коде:

- repeated TLS ClientHello используется как один из indirect failure signals;
- minimum retry gap был повышен с 2 до 5 секунд после ложных rotations на HLS chunks, prefetch и parallel sub-connections;
- retry window ограничен;
- требуется несколько attempts;
- свежий real-success совместимого QUIC profile временно подавляет TCP silent retry;
- success bypass ограничен временным окном;
- state привязан к profile/host strategy rotation;
- фича включается отдельным flag.

## 3. Что B4 не должен переносить буквально

B4 MUST NOT:

- вращать strategy только по двум ClientHello;
- считать hostname единственным достаточным scope key;
- считать отсутствие incoming Lua callback доказательством DPI;
- использовать один универсальный byte threshold для всех сервисов;
- применять host-wide rotation к shared infrastructure;
- смешивать TCP и QUIC success без service/component authorization;
- сохранять failure verdict вне config generation;
- переключать все flows клиента;
- выдавать «РКН подтверждён» по эвристике;
- активировать recovery без rollback monitor.

B4 использует уроки z2k как negative requirements:

```text
field false positive
→ suppression gate

working parallel path
→ recovery inhibitor

fast retry/prefetch
→ не считать failure

stale retry state
→ expire, не догонять старый counter
```

---

# Часть II. Цели, не-цели и модель риска

## 4. Цели

Форк MUST:

1. наблюдать полезный progress TCP/QUIC flow без packet-local догадок;
2. считать unique sequence-space progress, а не сумму packet lengths;
3. различать handshake silence, early-body silence, midstream stall и throughput collapse;
4. отличать «сервер молчит» от явного RST/FIN/TLS Alert/HTTP error;
5. использовать positive и suppressing evidence;
6. учитывать parallel success того же service/component;
7. учитывать recent success текущей strategy/path;
8. учитывать browser preconnect, cancellation, backgrounding и short-lived flows;
9. требовать complete bidirectional visibility для active mode;
10. выполнять bounded differential probe перед автоматическим recovery;
11. ограничивать recovery точным client/service/component/domain/config scope;
12. использовать только разрешённые next strategy/last-good/transport bindings;
13. не переносить failure state на Gmail/Google Feed или другой flow shared CDN;
14. автоматически rollback при ухудшении controls, reconnect rate, latency или goodput;
15. предоставлять explainable trace, Failure Inbox и issue bundle;
16. по умолчанию работать в `observe`;
17. разрешать active mode только после canary и target-side validation;
18. поддерживать WARP как optional recovery target без рекурсии;
19. fail-open при ambiguity, incomplete visibility или resource pressure;
20. минимизировать ложные срабатывания даже ценой пропуска части real silent failures.

## 5. Не-цели

Этот addendum не должен:

- гарантировать идентификацию конкретного оборудования РКН/ТСПУ;
- считать любой timeout цензурой;
- заменять application health checks;
- лечить origin outage автоматическим DPI strategy;
- лечить DNS failure через packet mutation;
- лечить PMTU/NAT/PPE failure через strategy rotation;
- мигрировать уже установленный TCP flow между paths;
- инжектировать RST клиенту ради принудительного retry по умолчанию;
- блокировать server FIN/RST;
- создавать destination-global blocked cache;
- использовать global per-IP fallback;
- запускать unbounded probes;
- включать WARP глобальным default route;
- автоматически включать experimental `НЕ РФ`;
- использовать silent failure как positive domain evidence;
- расширять profile domains/CIDRs;
- считать один успешный alternate probe вечным доказательством;
- скрывать false-positive rollback из UI/telemetry.

## 6. Основные источники ложных срабатываний

Одинаковый внешне stall может быть вызван:

```text
origin server overload
CDN/WAF/rate limit
HTTP 429/503 без немедленного body
медленным TTFB
длинным server think time
streaming idle interval
HTTP/2 connection reuse
QUIC migration
browser preconnect
prefetch
parallel sub-connections
app background/suspend
Android Doze
Wi-Fi loss/reassociation
WAN packet loss
bufferbloat
PMTU blackhole
NAT timeout
Keenetic PPE/offload visibility gap
NFQUEUE loss
GSO accounting mismatch
router CPU pressure
DNS resolution failure
certificate/auth/application error
user cancellation
server graceful close
```

Поэтому detector обязан сначала искать suppressing evidence, а не только подтверждающие признаки.

---

# Часть III. Термины и нормативные типы

## 7. Silent Path Failure

Состояние, при котором flow не демонстрирует ожидаемого полезного прогресса в пределах adaptive deadline, при этом отсутствует достаточная явная transport/application ошибка.

Это inference, а не факт вмешательства DPI.

## 8. Useful Progress

Useful progress — увеличение подтверждённого unique application byte range либо достижение protocol milestone.

Примеры:

```text
SYN-ACK observed
complete ServerHello observed
first encrypted application record observed
HTTP response headers observed через probe/helper
unique inbound body bytes advanced
media bytes advanced
application milestone advanced
```

Не считается useful progress:

```text
duplicate packet
retransmission того же sequence range
pure ACK
window update без payload
keepalive
повторный ClientHello нового parallel flow
локальный counter без incoming visibility
```

## 9. Suppressing Evidence

Evidence, которое делает silent failure менее вероятным или запрещает active recovery.

Примеры:

```text
fresh success на том же component/path
fresh success совместимого QUIC/TCP flow
HTTP/TLS explicit error
FIN/RST с валидным server provenance
app backgrounded
flow age ниже minimum grace
known preconnect/cancel pattern
resource pressure
PPE visibility incomplete
NFQUEUE drops
GSO parity unknown
ambiguous service classification
```

## 10. Differential Proof

Bounded сравнение двух paths/strategies при максимально одинаковых target parameters:

```text
current path fails to progress
AND candidate path reaches declared milestone
AND controls remain healthy
AND result повторяется в bounded window
```

## 11. Recovery Lease

Временное разрешение применить alternate strategy/transport только к точному scope и только до expiry/validation.

## 12. Нормативные структуры

```go
type SilentFailureClass string

const (
    SilentBeforeServerHello SilentFailureClass = "before-server-hello"
    SilentAfterServerHello  SilentFailureClass = "after-server-hello"
    SilentEarlyBody         SilentFailureClass = "early-body"
    SilentMidstream         SilentFailureClass = "midstream"
    SilentThroughputCollapse SilentFailureClass = "throughput-collapse"
    SilentTransportPath     SilentFailureClass = "transport-path"
)
```

```go
type FlowProgressState struct {
    FlowKey        classifier.FlowKey
    ClientKey      classifier.ClientKey
    SetID          string
    ComponentID    string
    Domain         string
    ConfigGen      uint64
    IPFamily       uint8
    TransportPath  string

    FirstSeenAt            time.Time
    LastOutboundAt         time.Time
    LastInboundAt          time.Time
    LastUniqueInboundAt    time.Time
    LastUniqueOutboundAt   time.Time

    UniqueOutboundBytes    uint64
    UniqueInboundBytes     uint64
    OutboundDataPackets    uint32
    InboundDataPackets     uint32
    RetransmissionCount    uint32

    SynSeen                bool
    SynAckSeen             bool
    ClientHelloComplete    bool
    ServerHelloSeen        bool
    ApplicationDataSeen    bool
    HTTPHeadersSeen        bool
    FINSeen                bool
    RSTSeen                bool
    TLSAlertSeen           bool

    Visibility             VisibilityState
    GSORepresentation      string
    OffloadState           string
    ActionAuthorizationID  string
}
```

```go
type SilentFailureScope struct {
    ClientKey     classifier.ClientKey
    SetID         string
    ComponentID   string
    DomainKey     string
    ConfigGen     uint64
    IPFamily      uint8
    TransportPath string
}
```

`DestinationIP` MAY присутствовать как diagnostic dimension, но MUST NOT быть единственным key.

```go
type SilentFailureEvidence struct {
    Kind        string
    Source      string
    FlowKey     classifier.FlowKey
    Scope       SilentFailureScope
    ObservedAt  time.Time
    ExpiresAt   time.Time
    Weight      int
    IndependentFamily string
    Details     map[string]string
}
```

```go
type SilentFailureAssessment struct {
    Class            SilentFailureClass
    Scope            SilentFailureScope
    Confidence       SilentFailureConfidence
    PositiveEvidence []SilentFailureEvidence
    Suppressors      []SilentFailureEvidence
    DifferentialRunID string
    RecoveryAllowed  bool
    ReasonCode       string
}
```

```go
type ScopedRecoveryLease struct {
    ID              string
    Scope           SilentFailureScope
    FromBindingID   string
    ToBindingID     string
    CandidateGen    uint64
    CreatedAt       time.Time
    ExpiresAt       time.Time
    Attempt         uint8
    MaxAttempts     uint8
    RollbackPolicy  string
    ProofRunID      string
}
```

---

# Часть IV. Архитектура runtime

## 13. Компоненты

```text
Packet observations
→ ProgressObserver
→ UniqueRangeTracker
→ ProtocolMilestoneTracker
→ VisibilityGate
→ SuppressionEvidenceCollector
→ RetryCorrelator
→ BaselineModel
→ SilentFailureClassifier
→ DifferentialProbeController
→ RecoveryPlanner
→ ScopedRecoveryLeaseStore
→ RecoveryValidator
→ RollbackMonitor
→ Failure Inbox / Trace / Metrics
```

### 13.1. ProgressObserver

Принимает только immutable packet/protocol events и не выбирает strategy.

### 13.2. UniqueRangeTracker

Использует TCP sequence arithmetic и bounded interval accounting.

Требования:

- duplicate/retransmitted bytes не увеличивают progress;
- overlap обрабатывается детерминированно;
- sequence wrap тестируется;
- GSO и MSS layouts дают одинаковые unique byte totals;
- per-flow memory bounded;
- state удаляется при FIN/RST/timeout/config expiry.

### 13.3. ProtocolMilestoneTracker

Может фиксировать:

```text
syn
syn_ack
client_hello_complete
server_hello
first_application_data
http_headers (probe/helper only)
first_body_progress
media_progress
fin
rst
tls_alert
```

Packet core не обязан расшифровывать application payload после TLS.

### 13.4. VisibilityGate

Active decision разрешён только если:

```text
incoming_visibility == complete
AND outgoing_visibility == complete
AND queue_drop_state == healthy
AND gso_progress_parity == proven
AND offload_visibility == proven
```

Иначе:

```text
mode_effective = observe
reason = visibility_incomplete
```

### 13.5. SuppressionEvidenceCollector

Работает до classifier action.

Он собирает:

- recent same-scope success;
- recent compatible-protocol success;
- explicit transport/application failure;
- app/device lifecycle markers;
- resource and packet-path degradation;
- classification ambiguity;
- control-flow health;
- user/manual cancellation markers;
- server think-time profile.

### 13.6. BaselineModel

Baseline является optional, bounded и explainable.

Ключ baseline:

```text
client class
+ service/component
+ network fingerprint
+ IP family
+ path/binding
+ config generation family
```

Baseline хранит:

```text
p50/p90/p99 time-to-SYNACK
p50/p90/p99 time-to-ServerHello
p50/p90/p99 time-to-first-unique-inbound
expected inter-progress gaps
normal parallel-flow count
normal retry gap distribution
normal startup bytes
```

Запрещено:

- обучать baseline на уже активном unvalidated recovery;
- смешивать Wi-Fi и WAN fingerprints без revalidation;
- делать unbounded history;
- считать отсутствие данных нулевым baseline;
- использовать baseline как единственное positive evidence.

### 13.7. RetryCorrelator

Повторный ClientHello учитывается только если:

```text
same exact authorized service/component/domain scope
AND previous flow не достиг success milestone
AND gap >= adaptive_min_retry_gap
AND gap <= retry_window
AND retry не объясняется parallel/preconnect pattern
AND нет fresh compatible-path success
```

### 13.8. DifferentialProbeController

Запускает bounded probe только после suspicion и budget check.

Probe MUST:

- использовать exact target/service component;
- сохранять DNS/IP-family constraints либо явно фиксировать различия;
- проверять current и candidate paths;
- не изменять production generation;
- иметь timeout, packet, CPU и attempt budget;
- включать control probe;
- очищать temporary state;
- формировать causal comparison report.

### 13.9. RecoveryPlanner

Не создаёт новый action из destination IP.

Он может выбрать только binding, уже разрешённый profile/config:

```text
next validated direct strategy
last-good direct strategy
base WARP
configured proxy/TUN
safe fail-open
scoped fail-closed (только explicit profile policy)
```

### 13.10. RollbackMonitor

Rollback срабатывает при:

```text
candidate не достиг milestone
control regression
reconnect spike
latency/goodput regression
cross-service action
DNS leak
route recursion
resource budget breach
visibility degradation
user disable
config generation change
```

---

# Часть V. State machine и confidence ladder

## 14. State machine

```text
OBSERVING
  ↓ one anomaly
SUSPECTED
  ↓ suppressors absent + second independent family
CORRELATED
  ↓ bounded differential run started
CORROBORATING
  ↓ current fails + candidate succeeds + controls pass
DIFFERENTIALLY_CONFIRMED
  ↓ recovery policy permits
RECOVERY_CANDIDATE
  ↓ temporary lease installed
RECOVERY_ACTIVE
  ↓ validation window pass
PROMOTABLE
  ↓ explicit canary/promote policy
PROMOTED
```

Failure paths:

```text
any state + suppressor
→ SUPPRESSED

recovery validation fail
→ ROLLED_BACK

visibility lost
→ OBSERVE_ONLY

budget exhausted
→ COOLDOWN

config generation changed
→ EXPIRED
```

## 15. Confidence levels

```go
type SilentFailureConfidence string

const (
    SilentConfidenceNone         SilentFailureConfidence = "none"
    SilentConfidenceSuspicion    SilentFailureConfidence = "suspicion"
    SilentConfidenceCorrelated   SilentFailureConfidence = "correlated"
    SilentConfidenceDifferential SilentFailureConfidence = "differential"
    SilentConfidenceRecurrent    SilentFailureConfidence = "recurrent-validated"
)
```

### 15.1. `suspicion`

Один signal family:

```text
no progress beyond adaptive deadline
OR repeated ClientHello
OR repeated retransmissions
OR early-body stall
```

Разрешено только trace/metrics/Failure Inbox.

### 15.2. `correlated`

Минимум две независимые families, например:

```text
no unique inbound progress
+ client retry
```

или:

```text
no unique inbound progress
+ retransmission burst
```

Разрешено recommendation и differential probe. Auto fallback запрещён.

### 15.3. `differential`

```text
current path fails
+ candidate path succeeds
+ controls pass
+ no suppressors
```

Разрешён temporary scoped recovery lease при policy opt-in.

### 15.4. `recurrent-validated`

Differential result воспроизведён в нескольких bounded runs/periods и recovery стабилен.

Только этот уровень MAY быть promoted как automatic policy для конкретного cohort.

## 16. Независимые evidence families

Чтобы два сигнала считались независимыми, они должны принадлежать разным families:

```text
progress-time
retry/application behavior
transport retransmission
protocol milestone
alternate-path differential
control comparison
historical cohort recurrence
```

Два таймера или два packet counters одной причины не являются независимыми.

---

# Часть VI. False-Positive Control Plane

## 17. Главный safety invariant

```text
single_signal_auto_fallback == forbidden
```

Даже если один signal выглядит сильным.

## 18. Mandatory suppression gates

Active recovery MUST быть запрещён при любом из условий:

### 18.1. Flow слишком молодой

```text
flow_age < minimum_grace
```

Default hard floor:

```text
minimum_grace >= 5s
```

Service profile MAY увеличить grace, но не уменьшить ниже runtime safety floor без explicit experimental override.

### 18.2. Fast parallel-flow pattern

Если новый ClientHello пришёл слишком быстро и соответствует normal parallel/prefetch distribution:

```text
suppress_reason = likely_parallel_or_prefetch
```

### 18.3. Fresh same-scope success

```text
same component/path success within success_bypass_window
→ suppress
```

### 18.4. Fresh compatible-protocol success

Например, TCP retry не должен вращать strategy, если exact same authorized YouTube component недавно успешно передавал media через QUIC.

Требования:

- exact `ClientKey`;
- exact service/component/domain relation;
- explicit compatibility map;
- success должен быть реальным incoming/application progress;
- outgoing QUIC Initial не считается success;
- bypass TTL bounded.

### 18.5. Explicit server/application response

```text
valid FIN
valid RST
TLS Alert
HTTP response/headers через probe/helper
application error milestone
```

Это не silent failure. Может быть другая failure class.

### 18.6. Device/app lifecycle

```text
app backgrounded
screen/device suspended
Doze entered
network switched
user cancelled
```

При отсутствии reliable marker detector остаётся conservative.

### 18.7. Visibility degradation

```text
PPE/offload uncertain
NFQUEUE drops
capture truncation
GSO parity unknown
incoming path incomplete
```

Active action запрещён.

### 18.8. Resource pressure

```text
CPU overload
memory pressure
queue backlog
probe budget exhausted
```

Stall может быть создан самим B4/роутером.

### 18.9. Classification ambiguity

Без final `ActionAuthorization` exact service/component recovery запрещён.

### 18.10. Control failure

Если unrelated control flow одновременно деградирует, вероятнее WAN/router/common-path outage, а не service-specific DPI failure.

## 19. Quarantine-before-action

После correlated suspicion scope попадает в short quarantine state:

```text
CORRELATED
→ wait suppression window
→ collect parallel/control results
→ only then differential probe
```

Default:

```yaml
quarantine:
  min_duration: 2s
  max_duration: 10s
```

Quarantine не блокирует пользовательский трафик и не меняет strategy.

## 20. Per-service adaptive thresholds

Static threshold MAY использоваться как cold-start fallback только в observe mode.

Active mode требует:

```text
validated baseline
OR profile-declared deterministic milestone/deadline
```

Примеры:

```text
API/UI component
→ time-to-first-response milestone

video/media component
→ unique media progress / stall window

game handshake
→ protocol-specific reply milestone

long-lived idle connection
→ detector disabled или app-aware heartbeat
```

## 21. Conservative defaults

```yaml
silent_recovery:
  mode: observe             # off | observe | recommend | auto-canary
  minimum_grace: 5s
  retry_window: 120s
  minimum_independent_families: 2
  require_differential_for_auto: true
  require_complete_visibility: true
  require_action_authorization: true
  require_control_probe: true
  success_bypass_window: 30s
  max_attempts_per_scope: 2
  cooldown: 120s
  lease_ttl: 300s
  fail_on_ambiguity: false
  fail_open_on_detector_error: true
```

`auto-canary` не равен permanent auto promotion.

## 22. False-positive budget

Каждый promoted cohort имеет budget:

```yaml
false_positive_budget:
  max_rollbacks_per_hour: 2
  max_control_regressions: 0
  max_user_reverts_per_day: 1
  max_unconfirmed_recoveries: 1
```

При превышении:

```text
mode_effective = observe
promotion_state = revoked
reason = false_positive_budget_exceeded
```

## 23. User feedback as evidence

Кнопка UI:

```text
«Это было ложное срабатывание»
```

должна:

- rollback exact active lease;
- записать negative outcome;
- увеличить cohort false-positive counter;
- не создавать permanent hardcoded exception автоматически;
- приложить trace IDs;
- перевести policy в observe при budget breach.

---

# Часть VII. Detection contracts

## 24. Handshake silence

### 24.1. Candidate

```text
complete ClientHello observed
+ outgoing path complete
+ no ServerHello/application progress by adaptive deadline
```

### 24.2. Corroboration

Минимум одно:

```text
same-scope retry after minimum gap
retransmission evidence
candidate path differential success
```

### 24.3. Suppressors

```text
fast preconnect/cancel
parallel success
TLS Alert
valid RST/FIN
WAN loss/control failure
visibility incomplete
```

## 25. After-ServerHello silence

```text
ServerHello observed
+ encrypted application data absent
+ no explicit close/error
+ retry or differential evidence
```

Нельзя делать вывод по отсутствию decrypted HTTP, которого роутер не видит.

## 26. Early-body silent drop

```text
some unique inbound application bytes observed
+ progress stopped before component-specific success milestone
+ silence exceeds adaptive gap
+ client/application retries OR alternate path succeeds
```

Static byte threshold допускается только как diagnostic dimension.

## 27. Midstream stall

```text
flow ранее имел useful progress
+ unique inbound bytes перестали увеличиваться
+ no FIN/RST/TLS Alert
+ application requests continuation/retry
+ baseline считает gap аномальным
```

Streaming idle flows и long polling должны быть исключены profile policy.

## 28. Throughput collapse

Низкий throughput сам по себе не является silent failure.

Нужно:

```text
sustained goodput below validated floor
+ packet loss/retransmission context
+ alternate candidate materially better
+ controls unaffected
```

## 29. Transport path silent failure

Для WARP/proxy/TUN:

```text
transport control plane healthy
+ exact forwarded user scope lacks progress
+ direct/control comparison available
```

`TUN exists` или `MASQUE connected` не доказывает user-flow health.

---

# Часть VIII. Scope, authorization и recovery

## 30. Scope invariant

Recovery state MUST включать:

```text
ClientKey
+ SetID
+ ComponentID
+ DomainKey
+ ConfigGen
+ IP family
+ current TransportPath/BindingID
```

Flow-level evidence содержит exact `FlowKey`, но recovery lease применяется к будущим eligible flows exact scope, а не к произвольному destination IP.

## 31. Authorization

Active recovery требует:

```text
valid ActionAuthorization
+ recovery capability allowed by profile/config
+ candidate binding prevalidated
+ exact ConfigGen
```

Silent detector не создаёт domain/service identity.

## 32. Recovery order

Recommended bounded order:

```text
1. current binding retry under same generation
2. next validated direct strategy candidate
3. last-good direct strategy
4. base WARP, если profile разрешает router-tunnel fallback
5. configured proxy/TUN
6. fail-open
7. scoped fail-closed только при explicit strict policy
```

Нельзя автоматически выбирать arbitrary strategy из каталога.

## 33. Existing flows

По умолчанию B4 не мигрирует established TCP flow.

Recovery lease применяется к:

- application retry;
- следующему new flow exact scope;
- explicit test probe.

Controlled RST для ускорения retry запрещён как default и требует отдельной explicit strategy authorization.

## 34. Recovery lease rules

```text
lease TTL bounded
attempt count bounded
candidate generation immutable
rollback target known
control monitor attached
no recursive lease
no cross-generation reuse
```

## 35. Recursive fallback prohibition

```text
direct → base WARP
```

допустимо.

```text
base WARP silent failure → второй base WARP
```

запрещено.

Experimental nested non-RU path является отдельным preconfigured transport, а не automatic recursion.

## 36. WARP interaction

### 36.1. Direct-path failure

B4 MAY открыть temporary base-WARP lease только если:

```text
WARP base L4 forwarded path healthy
profile permits WARP
DNS/IP-family leak policy satisfied
scope exact
candidate probe succeeds
```

### 36.2. WARP-path failure

Fallback:

```text
rollback to last-good direct
OR configured alternate transport
OR scoped fail-closed при strict policy
```

### 36.3. `НЕ РФ`

Silent detector не включает `require_non_ru` самостоятельно.

Если current policy уже требует non-RU:

- recovery candidate также обязан иметь fresh non-RU attestation;
- direct RU/unknown fallback запрещён в strict scope;
- failure отображается как availability loss, а не detector success.

---

# Часть IX. Config, API и UI

## 37. Configuration schema

```yaml
silent_path_failure:
  enabled: true
  mode: observe             # off | observe | recommend | auto-canary

  evidence:
    minimum_independent_families: 2
    require_retry_or_application_signal: true
    require_differential_for_auto: true
    require_control_probe: true

  visibility:
    require_bidirectional: true
    require_gso_parity: true
    require_ppe_proof: true

  timing:
    minimum_grace: 5s
    retry_window: 120s
    success_bypass_window: 30s
    quarantine_min: 2s
    quarantine_max: 10s

  recovery:
    max_attempts_per_scope: 2
    cooldown: 120s
    lease_ttl: 300s
    allow_direct_candidates: true
    allow_warp: false
    allow_proxy: false
    recursive_transport_fallback: false

  safety:
    fail_open_on_ambiguity: true
    fail_open_on_detector_error: true
    auto_disable_on_visibility_loss: true
    auto_disable_on_false_positive_budget: true
```

Per-profile upper bounds:

```yaml
components:
  - id: video
    silent_recovery:
      policy: recommend       # disabled | observe | recommend | auto-canary
      allowed_bindings:
        - direct:last-good
        - warp:base
      success_milestone: media-progress
      long_idle_expected: false
      require_negative_controls: true
```

Profile не может ослабить global safety gates.

## 38. Capabilities API

```http
GET /api/v1/capabilities
```

Добавить:

```text
silent_path_failure_supported
silent_path_failure_version
silent_path_failure_modes
silent_progress_unique_range_accounting
silent_visibility_gate
silent_gso_parity_state
silent_ppe_visibility_state
silent_differential_probe_supported
silent_scoped_recovery_supported
silent_warp_fallback_supported
silent_false_positive_budget_supported
silent_user_revert_supported
```

## 39. Status API

```http
GET /api/v1/silent-path/status
```

Пример:

```json
{
  "configured_mode": "auto-canary",
  "effective_mode": "observe",
  "degraded_reason": "incoming_visibility_incomplete",
  "active_suspicions": 2,
  "active_leases": 0,
  "false_positive_budget": {
    "rollbacks_last_hour": 0,
    "remaining": 2
  }
}
```

## 40. Assessments API

```http
GET /api/v1/silent-path/assessments
GET /api/v1/silent-path/assessments/{id}
```

Response обязан показывать:

- exact scope;
- confidence;
- positive evidence;
- suppressors;
- baseline/deadline;
- visibility state;
- differential run;
- chosen/no recovery reason;
- expiry.

## 41. Recovery API

```http
POST /api/v1/silent-path/assessments/{id}/probe
POST /api/v1/silent-path/assessments/{id}/recover
POST /api/v1/silent-path/leases/{id}/rollback
POST /api/v1/silent-path/leases/{id}/false-positive
```

Mutations требуют:

```text
Idempotency-Key
X-B4-Request-ID
appropriate API scope
```

## 42. Events

```text
silent_observation_started
silent_progress_milestone
silent_suspicion_created
silent_suspicion_suppressed
silent_correlation_reached
silent_differential_started
silent_differential_completed
silent_recovery_lease_created
silent_recovery_activated
silent_recovery_validated
silent_recovery_rolled_back
silent_false_positive_reported
silent_policy_auto_degraded
silent_policy_promotion_revoked
```

Каждый event содержит:

```text
flow/scope pseudonymous IDs
ConfigGen
binding IDs
reason code
visibility state
correlation/proof IDs
```

Secrets и plaintext user content запрещены.

## 43. Beginner UI

Карточка:

```text
Восстановление при «тихом» зависании

Режим:
● Наблюдать
○ Предлагать переключение
○ Автоматический canary

B4 ищет соединения, где полезная передача остановилась
без явной ошибки. Такие признаки могут быть вызваны не только DPI.
Поэтому автоматическое переключение требует повторного подтверждения
и проверки альтернативного пути.
```

Статусы:

```text
Наблюдение
Подозрение — действий нет
Проверяется альтернативный путь
Временно переключено
Стабильно
Откат: вероятное ложное срабатывание
Режим ограничен: неполная видимость
```

Запрещён UI:

```text
РКН заблокировал сайт
```

без differential evidence.

Expert UI показывает evidence/suppressor table и thresholds provenance.

---

# Часть X. Observability и hard gates

## 44. Metrics

```text
b4_silent_assessments_total{class,confidence,outcome}
b4_silent_suppressions_total{reason}
b4_silent_differential_runs_total{outcome}
b4_silent_recovery_leases_total{binding,outcome}
b4_silent_false_positive_total{source}
b4_silent_policy_degrade_total{reason}
b4_silent_unique_progress_bytes_total{direction}
b4_silent_visibility_state{state}
b4_silent_active_scopes
b4_silent_rollbacks_total{reason}
b4_silent_recovery_latency_seconds
```

Labels не должны содержать raw hostname/client MAC/token.

## 45. Mandatory hard gates

```text
silent_failure_action_without_authorization_total == 0
silent_failure_action_with_incomplete_visibility_total == 0
silent_failure_destination_only_state_total == 0
silent_failure_cross_client_action_total == 0
silent_failure_cross_service_action_total == 0
silent_failure_cross_component_action_total == 0
silent_failure_cross_generation_action_total == 0
silent_failure_single_signal_auto_fallback_total == 0
silent_failure_non_independent_evidence_auto_fallback_total == 0
silent_failure_suppressor_ignored_total == 0
silent_failure_fast_parallel_false_positive_total == 0
silent_failure_recent_success_false_positive_total == 0
silent_failure_explicit_server_error_misclassified_total == 0
silent_failure_gso_mss_progress_mismatch_total == 0
silent_failure_ppe_visibility_violation_total == 0
silent_failure_unbounded_probe_total == 0
silent_failure_unbounded_rotation_total == 0
silent_failure_recursive_transport_fallback_total == 0
silent_failure_recovery_without_rollback_target_total == 0
silent_failure_control_regression_promoted_total == 0
silent_failure_false_positive_budget_ignored_total == 0
silent_failure_user_revert_not_rolled_back_total == 0
```

Любое ненулевое значение блокирует production promotion соответствующего mode/cohort.

## 46. Invariants

```text
observe mode never changes packet verdict or route
recommend mode never auto-installs lease
single suspicion never auto-recovers
suppressed assessment never auto-recovers
lease cannot outlive ConfigGen
lease cannot broaden domain/component/client scope
visibility loss revokes active auto mode
false-positive budget breach revokes promotion
```

---

# Часть XI. Tests и validation matrix

## 47. Unit tests

### 47.1. Unique progress

- in-order bytes;
- retransmission;
- duplicate;
- identical overlap;
- conflicting overlap;
- out-of-order;
- sequence wrap;
- GSO vs MSS parity;
- FIN/RST cleanup;
- timeout cleanup.

### 47.2. Evidence independence

- two timers same family do not qualify;
- no-progress + retry qualifies as correlated;
- retransmission + retry without progress-time family remains bounded by policy;
- differential success qualifies only with controls;
- stale evidence expires.

### 47.3. Suppressors

- fresh same-path success;
- compatible QUIC success;
- fast parallel ClientHello;
- preconnect cancellation;
- HTTP/TLS explicit error;
- valid FIN/RST;
- app background marker;
- visibility incomplete;
- queue pressure;
- ambiguity.

### 47.4. Scope

- same destination, different service;
- same phone YouTube vs Gmail;
- same domain, different component;
- different ConfigGen;
- different IP family;
- direct vs WARP binding.

## 48. Property/fuzz tests

- interval tracker bounds;
- evidence serialization;
- state machine transitions;
- timestamp skew;
- timer cancellation;
- config decode/migration;
- malformed events;
- excessive parallel flows;
- random retransmission patterns;
- generation churn.

## 49. Packet-path fixtures

```text
normal fast success
normal slow TTFB
browser preconnect then cancel
parallel HLS chunks
parallel HTTP/2 connections
QUIC success + TCP retries
TCP success + QUIC failure
handshake silent blackhole
early body then silent
midstream stall
valid server RST
valid FIN
TLS Alert
HTTP 429/503 via probe
packet loss/reordering
PMTU blackhole
NAT timeout
PPE hidden incoming
NFQUEUE drop
GSO large skb
Android app background
WAN flap
```

## 50. Differential tests

For each candidate:

```text
current strategy/current path
vs
next strategy
vs
last-good
vs
base WARP (если разрешён)
```

Require:

- same target component;
- same client test role;
- declared DNS/IP-family differences;
- control apps;
- bounded repetition;
- no production promotion.

## 51. Same-client negative controls

Для YouTube profile обязательны:

```text
Gmail
Google app / Discover
```

Hard gate:

```text
unrelated_control_action_total == 0
```

Дополнительно detector обязан доказать, что control stall не был ошибочно использован как evidence YouTube scope.

## 52. Fault injection

Validation controller должен уметь:

```text
drop all incoming after ClientHello
drop incoming after N unique bytes
pause incoming for N seconds
inject duplicate/retransmitted ranges
hide incoming via offload simulation
mark queue as degraded
fail differential candidate
fail control probe
expire lease during validation
change ConfigGen during probe
crash recovery controller
corrupt baseline entry
force false-positive user report
```

Fault injection доступна только test scope.

## 53. Performance budgets

Detector MUST иметь bounded:

- per-flow intervals;
- evidence count;
- assessment TTL;
- baselines;
- concurrent probes;
- active leases;
- event rate.

Recommended initial ceilings:

```yaml
limits:
  max_tracked_flows: 4096
  max_ranges_per_flow: 64
  max_evidence_per_assessment: 32
  max_active_assessments: 256
  max_concurrent_differential_probes: 2
  max_active_recovery_leases: 64
  max_baseline_cohorts: 256
```

Target router validation может уменьшить ceilings.

---

# Часть XII. Реализационные stages

## SPF-1 — Failure taxonomy, threat model и reference freeze

### Задачи

- закрепить z2k reference commit;
- документировать реальные false-positive lessons;
- определить failure classes;
- определить suppressor taxonomy;
- определить normative reason codes;
- добавить feature flag default `observe`/disabled effective action.

### Tests

- schema/reason enum tests;
- no active action in observe;
- reference/provenance audit.

### Deliverable

```text
reports/spf-1-taxonomy.md
```

### Commit

```text
feat(silent): define path-failure taxonomy and safety model
```

## SPF-2 — Unique TCP progress accounting

### Задачи

- реализовать bounded unique sequence range tracker;
- интегрировать TCP FSM;
- обеспечить GSO/MSS parity;
- cleanup lifecycle;
- metrics without raw identifiers.

### Tests

- duplicate/retransmission/overlap/wrap;
- GSO vs MSS;
- race/leak/bounds.

### Deliverable

```text
reports/spf-2-progress-accounting.md
```

### Commit

```text
feat(silent): add bounded unique flow progress accounting
```

## SPF-3 — Protocol milestones и visibility gate

### Задачи

- milestones SYN-ACK/ClientHello/ServerHello/app-data/close;
- capability snapshot;
- PPE/GSO/NFQUEUE integration;
- effective observe-only degradation.

### Tests

- complete/incomplete visibility;
- offload toggle;
- queue drop;
- no active action under degraded state.

### Deliverable

```text
reports/spf-3-visibility.md
```

### Commit

```text
feat(silent): gate active detection on proven visibility
```

## SPF-4 — Suppression evidence и false-positive controls

### Задачи

- fresh success bypass;
- compatible protocol success map;
- fast parallel/preconnect suppression;
- explicit error suppression;
- app/device lifecycle markers;
- resource/control suppressors;
- stale state cleanup.

### Tests

- HLS/prefetch/parallel fixtures;
- QUIC success suppresses compatible TCP retry;
- outgoing-only signal does not count success;
- stale success expires;
- suppression blocks auto action.

### Deliverable

```text
reports/spf-4-false-positive-controls.md
```

### Commit

```text
feat(silent): add mandatory false-positive suppression gates
```

## SPF-5 — Silent failure classifier и adaptive baselines

### Задачи

- implement classes;
- confidence ladder;
- evidence independence;
- adaptive deadlines;
- quarantine-before-action;
- baseline bounds/provenance.

### Tests

- normal slow success;
- handshake/early/midstream failures;
- long idle exclusion;
- one signal stays suspicion;
- two independent families correlate.

### Deliverable

```text
reports/spf-5-classifier.md
```

### Commit

```text
feat(silent): classify silent failures with adaptive evidence
```

## SPF-6 — Differential shadow validation

### Задачи

- current/candidate/control probes;
- budgets;
- causal comparison;
- no production mutation;
- report artifacts;
- cancellation/cleanup.

### Tests

- current fail/candidate pass;
- both fail;
- control fail;
- DNS/IP family mismatch declared;
- probe timeout;
- concurrency budget.

### Deliverable

```text
reports/spf-6-differential.md
```

### Commit

```text
feat(silent): add bounded differential path validation
```

## SPF-7 — Scoped recovery planner и leases

### Задачи

- exact scope key;
- allowed binding graph;
- lease store;
- attempt/cooldown/TTL;
- next-flow semantics;
- no destination-global state;
- no recursive fallback.

### Tests

- cross-client/service/component/generation isolation;
- lease expiry;
- candidate unavailable;
- no arbitrary strategy;
- direct→WARP allowed only by profile;
- WARP→recursive WARP forbidden.

### Deliverable

```text
reports/spf-7-recovery-leases.md
```

### Commit

```text
feat(silent): add scoped bounded recovery leases
```

## SPF-8 — Rollback, false-positive budget и Failure Inbox

### Задачи

- rollback monitor;
- control regression detection;
- user false-positive action;
- budget and auto-revoke;
- Failure Inbox correlation;
- last-good restoration.

### Tests

- candidate failure rollback;
- control regression rollback;
- user revert;
- budget breach → observe;
- crash/restart lease cleanup;
- config generation change.

### Deliverable

```text
reports/spf-8-rollback.md
```

### Commit

```text
feat(silent): enforce rollback and false-positive budgets
```

## SPF-9 — API, UI, Profiles и observability

### Задачи

- capabilities/status/assessment/lease API;
- beginner/expert UI;
- config migration;
- profile upper bounds;
- trace/events/metrics;
- issue bundle redaction.

### Tests

- API schema/idempotency/scopes;
- UI mode/effective-mode distinction;
- no misleading RKN claim;
- profile cannot weaken global gates;
- secrets/content redaction.

### Deliverable

```text
reports/spf-9-product-integration.md
```

### Commit

```text
feat(silent): expose scoped recovery controls and diagnostics
```

## SPF-10 — Router, Android, fault injection и release gate

### Задачи

- Keenetic/PPE validation;
- official YouTube and ReVanced;
- Gmail/Google controls;
- direct strategies and WARP fallback;
- WAN flap/resource pressure;
- long run false-positive measurement;
- validation-of-validation;
- release verdict.

### Tests

Все suites этого addendum плюс target-side canary.

### Required verdicts

```text
silent-observe-ready
silent-recommend-ready
silent-auto-canary-ready
```

Permanent automatic promotion является отдельным cohort result, не global verdict.

### Deliverable

```text
reports/spf-10-release-validation.md
```

### Commit

```text
feat(silent): validate safe silent-path recovery end to end
```

---

# Часть XIII. Promotion policy

## 54. Mode gates

### 54.1. Observe ready

```text
SPF-1…SPF-5 PASS
+ no packet/route side effects
+ resource bounds PASS
```

### 54.2. Recommend ready

```text
observe ready
+ SPF-6 PASS
+ explainable differential reports
+ no automatic lease creation
```

### 54.3. Auto-canary ready

```text
SPF-1…SPF-10 PASS
+ all hard gates zero
+ complete visibility
+ rollback proof
+ same-client controls PASS
+ target router/Android PASS
```

### 54.4. Cohort promoted

```text
recurrent differential proof
+ stable recovery benefit
+ false-positive budget intact
+ no control regression
+ bounded period/canary population
```

## 55. Automatic demotion

Promoted cohort возвращается в observe при:

- WAN fingerprint change;
- B4/engine/config generation change;
- visibility capability change;
- profile update;
- false-positive budget breach;
- repeated rollback;
- user report;
- control regression;
- candidate transport degradation.

---

# Часть XIV. Companion-document synchronization

## 56. Field Test Automation

После `SPF-10` создать следующую редакцию Field Test с suites:

```text
silent-observe
silent-false-positive-controls
silent-differential
silent-scoped-recovery
silent-warp-fallback
silent-long-run
```

## 57. Service Profiles / Beginner UX

Добавить declarative per-component policy:

```text
disabled
observe
recommend
auto-canary
```

и allowed recovery bindings.

## 58. Implementation Validation

Umbrella validation MUST зарегистрировать:

```text
SPF-1…SPF-10
```

и не допускать full PASS, если active silent recovery заявлен, но SPF suites отсутствуют.

## 59. Cross-Service Isolation

Новая редакция CSI не требуется, если runtime использует существующий exact `ActionAuthorization` и scoped binding contract.

---

# Часть XV. Definition of Done

Capability считается реализованной только если:

1. observe mode не меняет runtime verdict/routing;
2. unique progress одинаков для GSO/MSS;
3. active mode невозможен при incomplete visibility;
4. один signal не создаёт fallback;
5. suppressors применяются до recovery;
6. fast parallel/HLS/prefetch fixtures не вращают strategy;
7. fresh compatible success подавляет false retry;
8. differential proof causal и bounded;
9. recovery exact-scope и generation-bound;
10. destination-only state отсутствует;
11. Gmail/Google controls не получают YouTube recovery;
12. WARP fallback не рекурсивен;
13. rollback target всегда определён;
14. false-positive user report немедленно откатывает lease;
15. budget breach автоматически отключает active mode;
16. API/UI показывают suspicion и proof отдельно;
17. issue bundle не содержит secrets/content;
18. все hard gates равны нулю;
19. target router и Android validation пройдены;
20. Field Test, Profiles и umbrella Validation синхронизированы.

---

# Приложение A. Machine-readable acceptance summary

```yaml
addendum: silent-path-failure-and-scoped-recovery
version: 1.0
stages:
  - SPF-1
  - SPF-2
  - SPF-3
  - SPF-4
  - SPF-5
  - SPF-6
  - SPF-7
  - SPF-8
  - SPF-9
  - SPF-10

default_mode: observe

active_requirements:
  complete_bidirectional_visibility: true
  gso_mss_progress_parity: true
  ppe_visibility_proof: true
  action_authorization: true
  minimum_independent_evidence_families: 2
  differential_proof_for_auto: true
  control_probe: true
  rollback_target: true
  false_positive_budget: true

forbidden:
  - single-signal-auto-fallback
  - destination-only-failure-state
  - cross-service-recovery
  - cross-generation-lease
  - unbounded-rotation
  - recursive-transport-fallback
  - misleading-rkn-confirmation

release_verdicts:
  - silent-observe-ready
  - silent-recommend-ready
  - silent-auto-canary-ready
```

# Приложение B. Рекомендуемая структура исходного дерева

```text
src/
├── silentpath/
│   ├── types.go
│   ├── progress.go
│   ├── ranges.go
│   ├── milestones.go
│   ├── visibility.go
│   ├── suppressors.go
│   ├── baseline.go
│   ├── retry.go
│   ├── classifier.go
│   ├── differential.go
│   ├── recovery.go
│   ├── leases.go
│   ├── rollback.go
│   ├── metrics.go
│   └── trace.go
├── api/
│   └── silentpath.go
├── config/
│   └── silentpath.go
└── validation/
    └── silentpath/

tools/
└── validation-controller/
    └── silentpath/
```

# Приложение C. Agent execution contract

Coding-agent обязан для каждого `SPF-*`:

```text
implement
→ run unit/property/component tests
→ run applicable packet-path tests
→ produce stage report
→ verify hard gates
→ commit
→ push current branch
```

Запрещено объединять несколько проваленных stages в один «best effort» commit.

При отсутствии target router/Android доступа stage может получить только:

```text
IMPLEMENTED_NOT_TARGET_VALIDATED
```

но не `PASS` и не production-ready.

