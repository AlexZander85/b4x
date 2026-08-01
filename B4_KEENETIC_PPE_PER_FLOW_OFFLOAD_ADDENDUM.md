# B4 Keenetic MediaTek PPE Per-Flow Offload Exclusion Addendum

**Статус:** нормативное companion-дополнение к `B4_FORK_ARCHITECTURE.md`, `B4_FORK_PATCH_PLAN.md` и `B4_AGENT_PROMPT.md` v2.3  
**Назначение:** реализовать в B4 собственное управление нативным Keenetic MediaTek PPE-механизмом для удержания окна TCP/QUIC-рукопожатия на CPU, не отключая аппаратное ускорение для основного трафика.  
**Порядок выполнения:** документ не перенумеровывает v2.3. На совместимых Keenetic требования этого addendum являются частью Capture Envelope и должны быть выполнены до production-enable hold/reassembly, retransmission-aware Discovery и automatic promotion.  
**Reference:** read-only анализ `necronicle/z2k`, commit `f1f66ffed3d3d53a88957742928447a425d02c79`, прежде всего `files/z2k-ppe-deoffload.sh`.

---

# 0. Решение

B4 не должен глобально отключать аппаратный offload только потому, что установлен на Keenetic MediaTek.

Нужно реализовать:

```text
capability detection
→ native -j PPE per-flow exclusion
→ connskip-bounded CPU handshake window
→ IPv4/IPv6 and TCP/QUIC rule lifecycle
→ real bidirectional visibility self-test
→ runtime safety gate
```

Главная цель:

> первые пакеты нужного соединения, включая повторный/разделённый ClientHello и первые входящие признаки прогресса или неудачи, должны оставаться видимыми CPU/netfilter/NFQUEUE; после окна рукопожатия bulk traffic может снова перейти в аппаратное ускорение.

B4 управляет нативными firmware primitives:

```text
iptables/ip6tables target: PPE
match: connskip
```

B4 **не реализует собственный kernel PPE target** и не копирует firmware code.

---

# 1. Проблема

На части Keenetic с MediaTek аппаратный ускоритель может забрать forwarded flow в hardware path после первых пакетов.

В результате B4 может увидеть:

```text
SYN
первый TCP data packet / первый ClientHello fragment
```

но не увидеть:

```text
следующий ClientHello segment
ClientHello retransmission
ServerHello
ACK progress
RST
QUIC response
```

Для silent-drop блокировок это приводит к ложной картине:

```text
strategy applied
→ no visible failure signal
→ retry/retransmission hidden by offload
→ Discovery/circular logic does not rotate
→ YouTube API/UI/video flow stalls
```

Даже корректный TCP reassembler не помогает, если второй сегмент физически не дошёл до NFQUEUE.

---

# 2. Архитектурные инварианты

1. **Никакого автоматического global offload disable.**
2. Per-flow exclusion применяется только при подтверждённой capability.
3. CPU window ограничен первыми N пакетами соединения.
4. После окна bulk transfer не удерживается на CPU искусственно.
5. Правила применяются только к forwarding path.
6. Правила ограничены нужными транспортами, портами и, где возможно, source scope.
7. IPv4 и IPv6 имеют отдельный capability/status.
8. TCP и QUIC имеют отдельный enable/status.
9. Наличие `PPE` target ещё не означает доказанную видимость — обязателен functional self-test.
10. Неполная видимость запрещает hold/replay и automatic promotion.
11. Ошибка применения правил не должна останавливать весь B4: режим деградирует в fail-open/observe-only.
12. B4 удаляет только собственные правила и chains.
13. Повторный apply идемпотентен и не создаёт дубликаты.
14. NDM firewall regeneration не должен незаметно удалить защиту.
15. UI/API не имеют права показывать `PASS`, пока не выполнен реальный self-test.

---

# 3. Конфигурационная модель

Существующий ADR-001 `capture.offload_policy` сохраняется:

```yaml
capture:
  offload_policy: detect   # detect | exclude | disable-global

  ppe:
    tcp_enabled: true
    quic_enabled: true

    tcp_ports:
      - 80
      - 443
      - 2053
      - 2083
      - 2087
      - 2096
      - 8443

    udp_ports:
      - 443

    connskip_packets: 30

    ipv4: auto             # auto | on | off
    ipv6: auto             # auto | on | off

    source_scope: managed-devices
    reassert_interval_sec: 55

    self_test:
      mode: startup-and-change
      controlled_endpoint: ""
      timeout_ms: 5000
```

## 3.1. Политики

### `detect`

B4:

- определяет наличие firmware capabilities;
- не устанавливает exclusion rules;
- показывает риск и результат пассивной проверки;
- не утверждает, что packet visibility полная.

### `exclude`

B4:

- устанавливает per-flow PPE exclusion;
- выполняет self-test;
- разрешает visibility-dependent функции только после успешного результата.

### `disable-global`

Отдельный advanced/debug режим:

- никогда не включается автоматически;
- требует явного предупреждения;
- не является нормальной production-конфигурацией;
- используется только когда per-flow механизм недоступен и оператор осознанно принимает потерю throughput.

## 3.2. User-facing toggle

Основной UI toggle:

```text
Аппаратный offload: per-flow исключение
```

Соответствие:

```text
OFF → offload_policy=detect
ON  → offload_policy=exclude
```

`disable-global` доступен только в Advanced.

## 3.3. Port scope

Значения по умолчанию повторяют типичные B4 bypass ports, но effective port set должен компилироваться как:

```text
configured PPE ports
∩
ports used by enabled B4 packet-inspection sets
```

При невозможности безопасно вычислить intersection допускается explicit configured port list.

Нельзя динамически ограничить правило hostname-ом до ClientHello: hostname ещё неизвестен в момент, когда firmware принимает решение об offload. Поэтому минимальная достижимая область:

```text
forwarded flow
+ protocol
+ destination port
+ optional source device/interface scope
+ first N packets
```

---

# 4. Capability detection

Создать пакет:

```text
src/capture/ppe
```

или эквивалентный generic capture adapter.

## 4.1. Capability states

```go
type PPECapabilityState string

const (
    PPEUnknown     PPECapabilityState = "unknown"
    PPEUnsupported PPECapabilityState = "unsupported"
    PPEPartial     PPECapabilityState = "partial"
    PPESupported   PPECapabilityState = "supported"
    PPEBroken      PPECapabilityState = "broken"
)
```

## 4.2. Проверки

B4 обязан проверить:

### Kernel target

IPv4:

```text
/proc/net/ip_tables_targets contains exact line PPE
```

IPv6:

```text
/proc/net/ip6_tables_targets contains exact line PPE
```

### `connskip` match

Проверка должна быть функциональной, а не только поиском файла:

```text
создать временную private chain
→ попытаться добавить rule с -m connskip --connskip 1
→ удалить chain
```

### Tables/chains

- `mangle` доступна;
- `PREROUTING` доступна;
- `FORWARD` доступна;
- iptables/ip6tables backend совместим с firmware target.

### Lock support

Предпочитать:

```text
iptables -w
ip6tables -w
```

с fallback только при доказанной совместимости.

### Privileges

Недостаточные права должны давать:

```text
state=unsupported-or-permission-denied
```

а не silent success.

## 4.3. Не полагаться только на модель роутера

Нельзя считать PPE доступным только потому, что:

```text
SoC vendor = MediaTek
или
router model in hard-coded list
```

Модель может использоваться как diagnostic metadata, но решение принимается по реальным capabilities.

---

# 5. Firewall rule model

B4 создаёт собственные chains:

```text
B4_PPE_PRE
B4_PPE_FWD
```

и ровно по одному owned jump:

```text
mangle/PREROUTING → B4_PPE_PRE
mangle/FORWARD    → B4_PPE_FWD
```

Каждое правило содержит comment/provenance:

```text
b4:ppe:v1:tcp
b4:ppe:v1:quic
```

## 5.1. TCP rule

Концептуально:

```bash
-p tcp \
-m multiport --dports <effective_tcp_ports> \
-m connskip --connskip <N> \
-j PPE
```

## 5.2. QUIC rule

Концептуально:

```bash
-p udp \
-m multiport --dports <effective_udp_ports> \
-m connskip --connskip <N> \
-j PPE
```

## 5.3. Source scope

При `source_scope=managed-devices` compiler добавляет до transport match:

```text
source ipset / interface match / device policy match
```

только если scope можно определить до первого payload packet.

Запрещено создавать широкое правило `all LAN traffic → PPE` без отображения этого факта в UI.

## 5.4. IPv4/IPv6

- IPv4 является отдельным apply gate.
- IPv6 best-effort только при `auto`.
- При `ipv6=on` отсутствие target является apply error.
- Частичный статус отображается явно:

```text
IPv4: active
IPv6: unsupported
```

## 5.5. Rule order

Правила должны срабатывать:

- до hardware binder;
- до возврата в fast path;
- без обхода B4 NFQUEUE rules;
- без конфликтов с B4 processed-packet mark;
- без сохранения processed packet mark в CONNMARK.

Порядок подтверждается router integration test, а не только статическим `iptables-save`.

---

# 6. Lifecycle и NDM regeneration

## 6.1. Apply

Pipeline:

```text
detect capabilities
→ compile desired rules
→ validate conflicts
→ create/update private chains
→ install jumps
→ verify exact rules
→ run visibility self-test
→ publish status
```

## 6.2. Idempotency

Повторный apply:

- не увеличивает число jumps;
- не создаёт duplicate rules;
- обновляет port/window config атомарно;
- сохраняет previous working generation до завершения проверки.

## 6.3. NDM table regeneration

Keenetic может пересоздавать netfilter tables.

B4 должен поддержать минимум один нативный устойчивый механизм:

```text
NDM netfilter hook
или
event-driven firewall reapply
```

Периодический assert допускается только как safety net.

После regeneration:

```text
rules missing
→ reapply
→ verify
→ rerun lightweight visibility check
```

## 6.4. Shutdown/uninstall

B4 удаляет:

- owned rules;
- owned jumps;
- owned chains;
- transient self-test chains.

Не удаляет firmware/other application rules.

## 6.5. Crash recovery

При запуске:

- найти stale B4 chains;
- reconcile desired state;
- удалить orphan duplicate rules;
- не считать stale rule доказательством успешного current apply.

---

# 7. Bidirectional Visibility Self-Test

Capability detection без functional self-test недостаточен.

Создать:

```text
CaptureVisibilitySelfTest
```

## 7.1. Уровни

### Level 0 — static capability

Проверяет target/match/tables/rules.

Результат:

```text
capability_only
```

Не разрешает automatic promotion.

### Level 1 — passive live observation

На реальном новом flow фиксирует:

- первый outgoing payload;
- последующие outgoing payload/retransmit;
- incoming SYN-ACK/ACK/ServerHello/RST/QUIC response;
- NFQUEUE direction counters.

Результат полезен, но не доказывает offload defect, если peer просто не ответил.

### Level 2 — controlled functional A/B

Нормативный production gate.

Нужны:

```text
dedicated test client or validation namespace
+ controlled remote endpoint
+ unique source port/session marker
```

Test controller создаёт предсказуемый flow:

1. новый TCP connection;
2. ClientHello, намеренно разделённый минимум на два TCP sequence ranges;
3. optional same-seq retransmission;
4. endpoint возвращает deterministic ServerHello/ACK/progress;
5. отдельная QUIC probe отправляет Initial и получает deterministic response.

Проверяется видимость:

```text
outgoing first fragment
outgoing second fragment
outgoing retransmission
incoming progress packet
flow direction correlation
```

## 7.2. A/B protocol

Для одного test scope:

```text
A: exclusion temporarily absent for dedicated flow
B: exclusion active for dedicated flow
```

Менять production rules для всех клиентов запрещено.

Допустимые способы изоляции:

- dedicated source device;
- temporary source ipset;
- dedicated source port range;
- validation namespace/interface;
- sandbox connmark.

## 7.3. Result model

```go
type CaptureVisibilityResult struct {
    RunID string

    Capability PPECapabilityState
    Policy     string

    IPv4Active bool
    IPv6Active bool
    TCPActive  bool
    QUICActive bool

    OutgoingFirstPayloadSeen bool
    OutgoingSecondRangeSeen  bool
    OutgoingRetransSeen      bool
    IncomingProgressSeen     bool

    TCPBidirectionalComplete  bool
    QUICBidirectionalComplete bool

    RuleCountersBefore map[string]uint64
    RuleCountersAfter  map[string]uint64

    OffloadSuspected bool
    FailureStage     string
    Evidence         []string
}
```

## 7.4. Verdicts

```text
PASS
PASS_WITH_LIMITATIONS
FAIL
UNSUPPORTED
INCONCLUSIVE
```

`INCONCLUSIVE` нельзя преобразовывать в PASS.

## 7.5. False-positive protection

Self-test не должен считать отсутствие ответа доказательством offload.

`offload_suspected=true` разрешено только при сочетании:

```text
controlled endpoint healthy
+ client emitted expected packets
+ B4 saw first packet
+ later expected packet absent
+ exclusion A/B changes visibility
```

---

# 8. Runtime safety gate

Создать:

```go
type CaptureVisibilityMode string

const (
    VisibilityComplete       CaptureVisibilityMode = "complete"
    VisibilityOutgoingOnly   CaptureVisibilityMode = "outgoing-only"
    VisibilityUnknown        CaptureVisibilityMode = "unknown"
    VisibilityIncomplete     CaptureVisibilityMode = "incomplete"
)
```

## 8.1. Complete

Разрешены:

- bounded ClientHello hold;
- reassembly;
- retransmission idempotency;
- automatic Discovery;
- canary/promotion при выполнении остальных gates.

## 8.2. Outgoing-only / unknown

Разрешены:

- observe;
- stateless safe mutation;
- fail-open.

Запрещены:

- hold, зависящий от следующего сегмента;
- ACK-dependent replay decisions;
- automatic claim that strategy failed/succeeded;
- promotion на основании неполного trace.

## 8.3. Incomplete

B4 обязан:

```text
release held packets fail-open
disable repeated hold for affected flow
mark flow observe-only
emit capture_visibility_incomplete
```

## 8.4. Runtime degradation

Если после успешного startup self-test B4 обнаруживает:

- исчезновение PPE rules;
- sudden loss of incoming visibility;
- NDM regeneration;
- rule counter anomaly;

он переводит capability в degraded и блокирует новые visibility-dependent actions до revalidation.

---

# 9. API

Добавить generic endpoints:

```text
GET  /api/v1/capture/offload/capabilities
GET  /api/v1/capture/offload/status
POST /api/v1/capture/offload/apply
POST /api/v1/capture/offload/remove
POST /api/v1/capture/offload/self-test
GET  /api/v1/capture/offload/self-test/{run_id}
```

## 9.1. Capabilities response

```json
{
  "platform": "keenetic",
  "soc_family": "mediatek",
  "ppe_target_ipv4": true,
  "ppe_target_ipv6": true,
  "connskip_ipv4": true,
  "connskip_ipv6": true,
  "policy": "exclude",
  "supported": true
}
```

## 9.2. Status response

```json
{
  "desired": "exclude",
  "effective": "exclude",
  "rules_present": true,
  "tcp_window_active": true,
  "quic_window_active": true,
  "connskip_packets": 30,
  "visibility": "complete",
  "last_self_test": {
    "verdict": "PASS",
    "run_id": "ppe-..."
  }
}
```

## 9.3. Mutation safety

Mutating requests требуют:

- authorization;
- idempotency key;
- config generation precondition;
- audit event;
- rollback on failed verify/self-test.

---

# 10. UI

В разделе Capture/Advanced:

```text
Аппаратный offload: per-flow исключение
```

Описание:

> На совместимых Keenetic с MediaTek аппаратный ускоритель может увести соединение в hardware path после первых пакетов. Тогда B4 не видит повторный или разделённый ClientHello, входящий ответ и RST, из-за чего подбор стратегии может залипнуть. Опция удерживает только окно рукопожатия нужных TCP/QUIC-портов на CPU через нативные firmware-механизмы PPE + connskip. Основной трафик после окна снова может ускоряться аппаратно.

## 10.1. States

```text
Не поддерживается
Обнаружено, не включено
Правила применены, проверка не выполнена
Проверка выполняется
Работает
Работает частично
Видимость неполная
Ошибка применения
```

## 10.2. UI fields

Показывать:

- capability IPv4/IPv6;
- TCP/QUIC;
- port scope;
- connskip window;
- source scope;
- rule presence;
- last self-test;
- last regeneration/reapply;
- current runtime safety mode.

## 10.3. Actions

```text
Включить
Выключить
Проверить видимость
Показать правила
Скачать диагностический отчёт
```

Нельзя показывать `Работает`, основываясь только на наличии iptables rule.

---

# 11. Observability

## 11.1. Events

```text
ppe_capability_detected
ppe_capability_unsupported
ppe_rules_compiled
ppe_rules_applied
ppe_rules_removed
ppe_rules_missing
ppe_rules_reasserted
ppe_self_test_started
ppe_self_test_packet_seen
ppe_self_test_passed
ppe_self_test_inconclusive
ppe_self_test_failed
capture_visibility_degraded
visibility_dependent_features_disabled
```

## 11.2. Metrics

```text
b4_ppe_supported
b4_ppe_rules_present
b4_ppe_rule_reapply_total
b4_ppe_self_test_total{verdict}
b4_ppe_self_test_duration_ms
b4_capture_outgoing_visibility
b4_capture_incoming_visibility
b4_capture_visibility_degrade_total
b4_hold_disabled_visibility_total
```

## 11.3. Diagnostic bundle

Включить:

- platform/kernel metadata;
- target/match detection;
- redacted `iptables-save` fragments;
- desired/effective policy;
- rule counters;
- self-test timeline;
- NFQUEUE direction counters;
- offload/visibility verdict;
- reason why hold/Discovery is enabled or disabled.

Не включать пользовательские payload/secrets без явного debug consent.

---

# 12. Реализационные этапы

Этапы не перенумеровывают v2.3.

## PPE-1 — Audit и capability model

- изучить текущий B4 firewall lifecycle;
- определить NDM regeneration hooks;
- реализовать capability DTO;
- никаких rule mutations.

**DoD:**

- real router report;
- unsupported platform report;
- no false supported state.

## PPE-2 — Rule compiler

- private chains;
- TCP/QUIC rules;
- source scope;
- IPv4/IPv6;
- deterministic desired-state hash.

**DoD:**

- golden `iptables-restore` fixtures;
- no duplicate jumps;
- config validation.

## PPE-3 — Transactional apply/remove

- xtables lock;
- apply;
- exact verify;
- rollback;
- cleanup.

**DoD:**

- interrupted apply test;
- duplicate cleanup test;
- previous generation restored after failure.

## PPE-4 — NDM resilience

- event hook;
- periodic safety assert;
- stale state reconciliation.

**DoD:**

- simulated table wipe;
- rules restored once;
- no reapply storm.

## PPE-5 — Static/passive diagnostics

- capability endpoint;
- rule counters;
- passive visibility state.

**DoD:**

- cannot emit PASS without functional test.

## PPE-6 — Controlled bidirectional self-test

- test controller;
- controlled endpoint protocol;
- split ClientHello;
- retransmission;
- incoming progress;
- QUIC probe;
- isolated A/B.

**DoD:**

- real MediaTek Keenetic evidence bundle;
- unsupported router gives UNSUPPORTED;
- dead endpoint gives INCONCLUSIVE, not FAIL/PASS.

## PPE-7 — Runtime safety gate

- wire visibility state into:
  - hold;
  - reassembly;
  - ActionToken ACK logic;
  - Discovery;
  - canary/promotion.

**DoD:**

- removing rule during test disables dependent features;
- all held packets released fail-open;
- no repeated hold loop.

## PPE-8 — API/UI/productization

- authenticated API;
- UI toggle/status;
- issue bundle;
- docs/migration.

**DoD:**

- beginner-safe wording;
- advanced controls;
- rollback from UI;
- no claim of global offload disable.

---

# 13. Tests

## 13.1. Unit

- capability parsing;
- deterministic rule compilation;
- port set intersection;
- source scope;
- IPv4/IPv6 partial capability;
- result verdict state machine.

## 13.2. Component

- fake iptables runner;
- lock contention;
- missing PPE target;
- missing connskip;
- apply verification failure;
- duplicate cleanup;
- rollback.

## 13.3. Network namespace

Обычный CI kernel может не иметь Keenetic `PPE` target.

Разрешён test adapter:

```text
mock target / injected command runner
```

для lifecycle tests.

Но mock не заменяет router acceptance.

## 13.4. Real Keenetic MediaTek

Обязательная матрица:

```text
IPv4 TCP/443
IPv6 TCP/443 where supported
IPv4 UDP/443
IPv6 UDP/443 where supported
split ClientHello
same-seq retransmission
incoming ServerHello/progress
RST
silent-drop controlled case
NDM table regeneration
service restart
router reboot
```

## 13.5. Negative

- unsupported Keenetic;
- non-Keenetic Linux;
- target exists but connskip absent;
- IPv4 only;
- permission denied;
- iptables lock busy;
- self-test endpoint unreachable;
- source device offline;
- rule removed during hold;
- config generation changes during self-test.

## 13.6. Performance

Измерить:

- CPU during handshake burst;
- CPU during sustained video;
- goodput before/after;
- number of CPU-retained packets;
- PPE/flow counters for unrelated traffic.

Acceptance:

```text
handshake visibility restored
+
unrelated bulk traffic remains accelerated
+
sustained YouTube goodput does not regress beyond declared budget
```

---

# 14. Production acceptance criteria

Функция считается готовой только когда:

1. `PPE` и `connskip` обнаруживаются функционально.
2. Rules ограничены protocol/port/window/scope.
3. Apply/remove/reapply идемпотентны.
4. IPv4/IPv6 status раздельный.
5. TCP/QUIC status раздельный.
6. NDM regeneration не оставляет B4 без правил незаметно.
7. Controlled test видит второй ClientHello range.
8. Controlled test видит incoming progress.
9. A/B подтверждает, что exclusion меняет visibility на affected router.
10. Inconclusive result не считается PASS.
11. Incomplete visibility отключает hold/replay/autopromotion.
12. Held packets выпускаются fail-open.
13. Bulk video после handshake не удерживается постоянно на CPU.
14. Unrelated LAN traffic не теряет аппаратное ускорение.
15. UI объясняет effective scope.
16. Diagnostic bundle позволяет доказать каждый verdict.
17. Реальный Keenetic/MediaTek report приложен к stage gate.
18. Никакой hard-coded PASS отсутствует.

---

# 15. PR decomposition

## PR PPE-A

```text
capture/ppe capability model and read-only diagnostics
```

## PR PPE-B

```text
deterministic private-chain rule compiler
```

## PR PPE-C

```text
transactional apply/remove and NDM resilience
```

## PR PPE-D

```text
controlled bidirectional visibility self-test
```

## PR PPE-E

```text
runtime safety gate for hold/reassembly/Discovery
```

## PR PPE-F

```text
API, UI and diagnostic bundle
```

Не смешивать эту работу в одном commit с:

- новым fake strategy;
- service profile pack;
- optimizer scoring changes;
- unrelated UI redesign.

---

# 16. Инструкция coding-agent

До начала реализации агент обязан предоставить:

```text
PPE_IMPLEMENTATION_AUDIT.md
```

с:

- фактическим B4 firewall path;
- current offload behavior;
- NDM hooks;
- raw sender/marks interaction;
- выбранным chain order;
- target router capabilities;
- рисками.

После каждого `PPE-*` этапа:

```text
PPE_STAGE_N_IMPLEMENTATION_REPORT.md
PPE_STAGE_N_VALIDATION_REPORT.md
```

Verdict:

```text
PASS
PASS_WITH_LIMITATIONS
FAIL
```

`PASS_WITH_LIMITATIONS` не разрешает automatic promotion, если ограничение касается incoming visibility.

---

# 17. Итоговая модель

```text
Keenetic MediaTek capability
→ native PPE/connskip exclusion
→ first-N handshake packets stay on CPU
→ NFQUEUE sees split/retransmitted ClientHello and incoming progress
→ B4 classifier/reassembly/Discovery receives complete evidence
→ bulk flow returns to hardware acceleration
```

Это обязательное capture-layer исправление для совместимых Keenetic, а не новая DPI-стратегия.
