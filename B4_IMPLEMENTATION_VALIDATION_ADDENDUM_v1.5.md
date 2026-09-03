# B4 Implementation Validation Addendum

**Статус:** нормативное umbrella-дополнение к `B4_FORK_ARCHITECTURE.md`, `B4_AGENT_PROMPT.md`, завершённому `B4_FORK_PATCH_PLAN.md` v2.3 и post-v2.3 companion addenda  
**Редакция:** 1.5 — полностью сохраняет редакции 1.1–1.4; синхронизирует umbrella validation с WARP/MASQUE v1.2 и Field Test v1.5, регистрирует causal trace schemas/gates, stages `FT-AC`–`FT-AE`, новый `IV-17` и release verdict `WARP_CAUSAL_TRACE_READY`  
**Назначение:** определить, как coding-agent должен автоматически проверять, что все реализованные нововведения форка, включая built-in WARP/MASQUE v1.2, WARP+WARP/`НЕ РФ` causal transport trace, Silent Path Failure/Scoped Recovery, Detector v2, DDI-guided strategy search и Transparent Telegram Bridge, работают в соответствии с архитектурой, addendum-контрактами и acceptance criteria.  
**Важно:** этот документ не поручает coding-agent подбирать production-стратегии обхода YouTube. Подбор, сравнение и promotion стратегий является обязанностью встроенной утилиты Discovery/Optimizer форка.

Нормативная последовательность для реализации и проверки:

```text
B4_FORK_ARCHITECTURE.md v2.4
→ завершённый B4_FORK_PATCH_PLAN.md Stage 1–36
→ завершённый B4_KEENETIC_PPE_PER_FLOW_OFFLOAD_ADDENDUM.md
→ B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md
→ B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM.md v1.2
→ B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md
→ B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM.md v1.0
→ B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM.md v1.2
→ B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM.md v1.0
→ B4_FIELD_TEST_AUTOMATION_ADDENDUM v1.5
→ B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM v1.6
→ B4_IMPLEMENTATION_VALIDATION_ADDENDUM v1.5
```

Этот документ проверяет также собственную реализацию: suite registry, API/CLI contract, verdict aggregation, полноту артефактов и невозможность ложного `PASS`.

---

# 1. Разделение ответственности

## 1.1. Coding-agent

Coding-agent обязан проверять:

- корректность реализации каждого этапа патч-плана;
- соблюдение архитектурных инвариантов;
- отсутствие регрессий B4;
- корректность packet path;
- корректность classifier/evidence/confidence;
- TCP FSM;
- ClientHello reassembly;
- hold/replay и fail-open;
- retransmission idempotency;
- action planner/executor;
- capture envelope и processed marks;
- offload diagnostics;
- API contracts;
- Discovery sandbox isolation;
- strategy optimizer как программную подсистему;
- canary/promote/rollback;
- observability и issue bundles;
- реальные end-to-end сценарии на роутере и Android-устройстве;
- unique bidirectional progress, silent-failure suppressors and causal differential proof;
- exact scoped recovery leases, false-positive budgets and rollback behavior;
- Detector v2 target plans, clean-path evidence, controls, confidence and immutable `BlockingProfile`;
- DDI context/freshness/revalidation and guided/full Discovery A/B semantics;
- transparent Telegram bridge pending budgets, prefix preservation, fallback ladder and Android lifecycle;
- WARP generation-aware event ordering, route/path proof and trace/runtime consistency;
- exact forwarded Android binding correlation;
- nested WARP parent/child dependency, geo-provider/quorum and non-RU route-gate consistency;
- DNS/IPv6 observed path and generation-owned cleanup closure.

Coding-agent проверяет, что механизм выбора стратегии работает правильно, но не выполняет роль постоянного production-оптимизатора.

## 1.2. Встроенная утилита B4

Discovery/Optimizer форка отвечает за:

- генерацию candidate variants;
- запуск production-safe probes;
- сравнение API/UI/VIDEO результатов;
- оценку startup latency, goodput, stalls и overhead;
- исключение кандидатов по hard gates;
- ранжирование;
- canary;
- promote;
- rollback;
- last-good;
- периодическую или ручную переоценку при изменении сети.

## 1.3. Пользователь

Пользователь не должен вручную перебирать параметры стратегий.

Роль пользователя:

- предоставить тестовый роутер и Android-устройство;
- один раз настроить API/ADB доступ;
- при необходимости разрешить canary/full-auto;
- подтвердить спорные пользовательские milestones, если нет Android Test Companion;
- предоставить issue bundle при ошибке.

---

# 2. Главная цель автоматического тестирования агентом

Агент должен доказать:

```text
реализованная функция существует
→ вызывается через реальный runtime path
→ корректно работает на позитивных и негативных сценариях
→ корректно деградирует при ошибках
→ не ломает другие flows/клиентов
→ соблюдает memory/time/packet budgets
→ диагностируется через trace/metrics/API
```

Недостаточно:

```text
код компилируется
или
один unit test проходит
или
YouTube один раз открылся
```

---

# 3. Уровни проверки

Каждое нововведение должно пройти применимые уровни.

## L0 — Static audit

- код соответствует архитектуре;
- нет stale config pointers;
- нет unbounded collections;
- нет goroutine per packet;
- нет скрытых global caches;
- ошибки и timeout paths освобождают state;
- license/provenance соблюдены;
- config migration определена.

## L1 — Unit tests

- pure policy;
- parsers;
- RangeSet;
- sequence arithmetic;
- FSM transitions;
- marker resolution;
- ActionToken rules;
- scoring;
- rollback decision;
- config validation.

## L2 — Property/fuzz tests

- DNS parser;
- TLS parser;
- QUIC parser;
- TCP ranges/reassembly;
- marker resolver;
- packet builder;
- config decoder;
- event serializer.

## L3 — Component integration

- classifier + HintStore;
- DNS → evidence;
- QUIC → evidence;
- reassembly → classifier;
- classifier → action planner;
- planner → executor;
- executor → trace;
- transactional config → runtime generation.

## L4 — Packet-path integration

Через network namespaces, veth, NFQUEUE, pcap fixtures или test backend:

- NF_ACCEPT/NF_DROP;
- delayed verdict;
- raw packet send;
- processed-mark bypass;
- checksums;
- sequence numbers;
- packet order;
- retransmissions;
- IPv4/IPv6;
- FIN/RST cleanup.

## L5 — Router integration

На целевом Keenetic/Entware:

- iptables/nftables rules;
- NFQUEUE owner/readiness;
- mark collision;
- capture envelope;
- offload visibility;
- restart;
- crash cleanup;
- resource budgets.

## L6 — Real Android E2E

На реальном телефоне:

- официальный YouTube;
- ReVanced;
- split ClientHello;
- ECH;
- QUIC→TCP;
- cold start;
- CDN switch;
- multiple clients;
- restart/no ARP MAC;
- long playback.

## L7 — Fault injection

- dropped second ClientHello segment;
- delayed segment;
- duplicate NFQUEUE delivery;
- raw send error;
- queue drop;
- conflicting overlap;
- memory pressure;
- daemon crash;
- config apply failure;
- canary failure;
- unavailable DNS evidence;
- offload bypass.

---

# 4. Агентский Validation Controller

Coding-agent должен использовать отдельный локальный инструмент:

```text
tools/validation-controller
```

Он не является production Discovery/Optimizer.

Назначение:

- развернуть build;
- вызвать test APIs;
- управлять ADB;
- запускать детерминированные acceptance scenarios;
- внедрять faults;
- собирать traces/pcaps/metrics;
- сравнивать фактический результат с expected invariant;
- формировать validation report.

CLI:

```text
b4-validate preflight
b4-validate stage STAGE_ID
b4-validate subsystem classifier
b4-validate subsystem reassembly
b4-validate subsystem executor
b4-validate subsystem discovery
b4-validate router
b4-validate android --app official
b4-validate android --app revanced
b4-validate full
b4-validate export RUN_ID
```

---

# 5. API для проверки реализации

API может использовать те же внутренние runtime-компоненты, но test endpoints должны быть отделены от production optimizer endpoints.

Base:

```text
/api/v1/validation
```

## 5.1. Capabilities

```http
GET /api/v1/validation/capabilities
```

Проверяет:

- build/commit;
- schema;
- enabled feature flags;
- kernel capabilities;
- queue readiness;
- mark configuration;
- offload visibility;
- supported tests;
- resource limits.

## 5.2. Запуск validation suite

```http
POST /api/v1/validation/runs
```

```json
{
  "suite": "core-fix",
  "target_client_id": "android-main",
  "fault_profile": "none",
  "trace_level": "detailed",
  "promotion_allowed": false
}
```

## 5.3. Статус

```http
GET /api/v1/validation/runs/{run_id}
```

## 5.4. Events

```http
GET /api/v1/validation/runs/{run_id}/events
Accept: text/event-stream
```

## 5.5. Cancel

```http
POST /api/v1/validation/runs/{run_id}/cancel
```

## 5.6. Report

```http
GET /api/v1/validation/runs/{run_id}/report
```

Formats:

```text
application/json
text/markdown
application/zip
```

## 5.7. Fault injection

```http
POST /api/v1/validation/faults
```

Примеры:

```json
{
  "scope": "next-matching-flow",
  "fault": "delay-clienthello-segment",
  "parameters": {
    "segment_index": 2,
    "delay_ms": 300
  }
}
```

Fault injection MUST быть:

- выключена в production default;
- доступна только с отдельным API scope;
- ограничена выбранным client/flow/test session;
- автоматически очищаться после run;
- запрещена для обычных LAN-клиентов.

---

# 6. Validation Suite: Core Classifier

## Проверки

### Source isolation

```text
CLIENT_A DNS/QUIC evidence → CLIENT_A flow
CLIENT_B same destination IP → no inherited evidence
```

### Multiple candidates

```text
same client + same IP + same SetID hosts → resolved
same client + same IP + different SetID hosts → ambiguous
clear SNI → resolves ambiguity
```

### Confidence

- destructive action blocked below threshold;
- clear/reassembled SNI strongest;
- DNS/QUIC ordering;
- legacy global IP remains low priority;
- confidence does not silently replace policy priority.

### Config generation

- evidence survives only through revalidation;
- stale SetID is rejected/rematched;
- hot apply does not retain pointer to removed config.

### DomainOnly strict

Принимает:

```text
clear packet-local SNI
complete reassembled SNI
explicit static hostname match
```

Не принимает:

```text
source-scoped DNS hint
source-scoped QUIC hint
unrelated client hint
port-only
IP/CIDR-only match
legacy global IP
```

### DomainOnly scoped-hints

Принимает всё, что разрешено `strict`, а также:

```text
fresh source-scoped DNS A/AAAA/HTTPS evidence
fresh source-scoped QUIC SNI evidence
```

при обязательной revalidation по:

```text
ClientKey
destination/protocol
SetID/component
TTL
config generation
ambiguity state
```

Clear или reassembled hostname другого сервиса является negative evidence и обязан отменять provisional IP/port candidate. Shared IP/CIDR не может сам по себе выдавать ActionAuthorization.

## Acceptance

- deterministic decisions;
- every decision has phase/source/confidence/reason;
- no cross-client leakage;
- bounded store;
- fake clock tests;
- race tests.

---

# 7. Validation Suite: TCP FSM and Clean SYN

## Scenarios

```text
clean SYN + generic combo → NF_ACCEPT
clean SYN + fake SNI → NF_ACCEPT
explicit SynFake → expected injection
SYN-ACK → FSM progress
ACK-only → no TLS action
FIN/RST → cleanup
server progress → mutation window closed
```

## Acceptance

- no generic raw reinjection of clean SYN;
- no fake data before valid state;
- no state leak after close;
- incoming/server progress visible;
- trace matches actual packet order.

---

# 8. Validation Suite: ClientHello Reassembly

## Fixtures

- complete single packet;
- `1396 + remainder`;
- three segments;
- out-of-order;
- duplicate;
- retransmission;
- identical overlap;
- conflicting overlap;
- sequence wrap;
- coalesced TLS records;
- ECH;
- FIN/RST mid-reassembly;
- timeout;
- memory limit;
- packet limit.

## Hold/replay

- confident DNS/QUIC flow does not hold unnecessarily;
- partial flow is held;
- completion produces correct logical ClientHello;
- hard timeout releases unchanged;
- fail-open order is original arrival order;
- same flow does not enter repeated hold loop;
- offload-incomplete environment disables hold mode.

## Acceptance

- no lost packet;
- no oversized reconstructed TCP packet;
- no indefinite verdict;
- memory/time bounded;
- expected timeout behavior;
- pcap output matches trace.

---

# 9. Validation Suite: Action Planner and Executor

## Planner

- absolute positions;
- semantic positions;
- marker errors without clear SNI;
- duplicate normalization;
- range ordering;
- IPv4/IPv6;
- MTU validation.

## Executor

- packet checksum;
- TCP seq/ack/options;
- send order;
- processed mark;
- no re-entry;
- partial raw-send failure;
- cancellation;
- action budget;
- fail-open invalid plan.

## Existing B4 techniques

Each existing technique migrated to planner MUST have equivalence tests:

```text
old expected semantic behavior
vs
new action plan/executor behavior
```

Byte-for-byte packet equivalence is required only where architecture expects it. Otherwise compare endpoint logical stream and intended DPI-visible order.

---

# 10. Validation Suite: Retransmission Idempotency

## Scenarios

### Original accepted

```text
fake sent + original NF_ACCEPT
→ retransmission NF_ACCEPT
→ fake action suppressed
```

### Original replaced

```text
original NF_DROP
→ real plan sent raw
→ retransmission
→ no repeated fake storm
→ bounded real-only replay according to policy
```

### ACK progress

```text
server ACK covers range
→ duplicate retransmission suppressed/dropped
```

### ACK visibility uncertain

```text
offload/incoming visibility incomplete
→ do not blindly drop legitimate retransmission
→ fail-open according to policy
```

## Acceptance

- one logical fake action per ClientHello;
- bounded real replay;
- no packet storm;
- trace exposes suppression reason;
- ActionToken expires and cleans correctly.

---

# 11. Validation Suite: Kernel Capture Envelope

## Checks

- mark namespace conflict detection;
- processed packet bypass;
- managed connection mark;
- first-N outgoing visibility;
- first-N incoming visibility;
- SYN-ACK visibility;
- FIN/RST visibility;
- queue owner readiness;
- stale chain cleanup;
- daemon restart;
- router reboot;
- flow offload self-check.

## Fault cases

- second ClientHello segment bypasses NFQUEUE;
- ServerHello bypasses NFQUEUE;
- processed packet is requeued;
- queue unavailable;
- mark collides with Keenetic policy.

## Acceptance

- capability status is explicit;
- unsafe hold/replay is disabled automatically;
- production traffic fails open;
- no recursive packet injection;
- cleanup is idempotent.

---

# 12. Validation Suite: Observability

Каждое ключевое событие должно быть одновременно проверено по:

1. фактическому packet/runtime behavior;
2. structured event;
3. metric counter;
4. session/issue bundle.

Обязательные consistency assertions:

```text
injected packet count in trace
=
raw sender calls
=
metric delta
```

```text
classification decision in trace
=
set/action actually used
```

```text
reassembly complete
=
parser received expected complete bytes
```

```text
rollback event
=
previous generation active
```

Проверить:

- event sequence gaps;
- trace drops;
- monotonic timestamps;
- redaction;
- no raw ClientHello by default;
- pcap optional and bounded;
- schema versioning;
- backward-compatible report reader.

---

# 13. Validation Suite: Discovery/Optimizer Utility

Здесь coding-agent не подбирает технику вручную. Он тестирует алгоритм утилиты.

## 13.1. Synthetic deterministic datasets

Подать в optimizer заранее заданные результаты.

Пример:

```text
Candidate A:
success 100%
startup 400 ms
goodput 15 Mbit/s
no stalls

Candidate B:
success 80%
startup 200 ms
goodput 50 Mbit/s
one stall
```

Expected:

```text
A ranks above B because B fails hard gates
```

Другой пример:

```text
A and B equal startup
B has higher p10 goodput and equal overhead
→ B wins VIDEO
```

## 13.2. Separate API/UI/VIDEO rank

Проверить, что:

- API winner может отличаться от VIDEO winner;
- один global score не перезаписывает per-service results;
- strategy chains корректно составляются по set/service.

## 13.3. Adaptive search

Проверить:

- полный Cartesian product не запускается без необходимости;
- shadow probes запускаются только при нужном failure signature;
- resolver/IP-family/TLS-profile axes добавляются по policy;
- resource budget соблюдается.

## 13.4. Statistical behavior

- 3-run shortlist;
- 5-run validation;
- 10-run promotion;
- A/B interleaving;
- median/max for small samples;
- p90/p95 only when sample count allows;
- tie handling;
- noisy/outlier dataset.

## 13.5. Safety

- no auto promote in report-only;
- canary-auto cannot affect unrelated client;
- rollback on hard gate;
- last-good preserved;
- cooldown prevents flapping;
- config generation transactions.

---

# 14. Validation Suite: Discovery Sandbox

## Scenarios

```text
baseline-none
baseline-production
candidate
```

Проверить:

- production B4 does not process baseline-none;
- production B4 does not double-process candidate flow;
- candidate queue isolated;
- source-port/connmark isolation;
- queue collision detection;
- worker crash cleanup;
- router restart cleanup;
- cancellation;
- concurrent normal client unaffected.

---

# 15. Validation Suite: Real Android E2E

Coding-agent может использовать API + ADB для проверки работоспособности нововведений.

Он не выбирает production strategy вручную. Для теста используются:

- known-good test profile;
- known-bad profile;
- no-op/baseline profile;
- deterministic fixture strategy;
- candidate, выбранный встроенной утилитой.

## Required runs

### Official YouTube

- five cold starts;
- QUIC enabled + B4 Reject;
- QUIC disabled;
- video start;
- CDN switch;
- long playback.

### ReVanced

- spoof streams off;
- spoof streams on;
- five cold starts;
- video playback.

### Multi-client

- target phone;
- second LAN client using shared Google/CDN IP;
- verify evidence and strategy isolation.

### Router lifecycle

- B4 restart;
- no MAC yet in ARP;
- Wi-Fi reconnect;
- config hot apply;
- rollback.

## What agent verifies

- first flow correctly classified;
- split/ECH handled according to evidence;
- no multi-minute retry;
- action applied once;
- no packet storm;
- trace explains outcome;
- no NFQUEUE drops;
- bounded resources;
- utility receives valid measurements.

The agent does not claim that the test profile is globally optimal.

---

# 16. Known-good and known-bad test profiles

Для deterministic E2E нужны специальные validation profiles.

## No-op

```text
classify only
no packet mutation
```

## Known-good local fixture

Работает на controlled test endpoint or replay harness, а не обязательно у ISP.

Проверяет:

- fake/split/action path;
- server progress;
- retransmission handling;
- metrics.

## Known-bad

Преднамеренно вызывает:

- invalid action plan;
- low-confidence block;
- timeout/fail-open;
- sandbox failure;
- rollback.

## Production candidate

Выбирается Discovery/Optimizer утилитой и используется только для проверки полного lifecycle:

```text
discover
→ candidate
→ canary
→ measure
→ promote/rollback
```

---

# 17. Controlled Test Endpoint

Чтобы агент мог проверять transport correctness независимо от текущего DPI провайдера, рекомендуется test server.

Возможности:

- записывает полученный TCP stream;
- логирует segmentation/order as observed;
- возвращает controlled TLS/HTTP responses;
- может delay/drop/reset;
- поддерживает IPv4/IPv6;
- выдаёт correlation ID;
- не требует доступа к production secrets.

Это позволяет доказать:

- endpoint получил исходный logical stream;
- disorder/split не повредил данные;
- replay корректен;
- first-flight mutation остановлена;
- checksums/sequence valid.

ISP/YouTube E2E остаётся отдельным уровнем L6.

---

# 18. Stage Completion Gate

Этап патч-плана считается завершённым только при наличии:

```text
STAGE_N_IMPLEMENTATION_REPORT.md
STAGE_N_VALIDATION_REPORT.md
```

Validation report:

```markdown
# Stage N Validation

## Build/commit/config
## Applicable levels L0-L7
## Test suites executed
## Expected invariants
## Actual results
## Trace/metric consistency
## Resource bounds
## Fault injection results
## Router results
## Android results, if applicable
## Known limitations
## PASS / PASS-WITH-LIMITATIONS / FAIL
```

`PASS-WITH-LIMITATIONS` допустим только когда limitation:

- не нарушает MUST-инвариант;
- явно gated feature flag;
- не включён production default;
- имеет follow-up issue.

---

# 19. Full Validation Run

Команда:

```text
b4-validate full
```

Должна выполнять:

```text
static audit
→ unit/race/fuzz
→ component integration
→ packet-path integration
→ router preflight
→ kernel capture validation
→ Android E2E
→ Discovery/Optimizer algorithm tests
→ sandbox tests
→ canary/rollback test
→ observability consistency
→ final bundle
```

Output:

```text
validation-results/<run-id>/
├── RUN_MANIFEST.json
├── FULL_VALIDATION_REPORT.md
├── SUBSYSTEM_MATRIX.json
├── test-results/
├── traces/
├── pcaps/
├── router-diagnostics/
├── android-diagnostics/
├── fault-injection/
└── issue-bundles/
```

---

# 20. API permissions

Validation API scopes:

```text
validation:read
validation:run
validation:fault
validation:router
validation:android
capture:pcap
capture:clienthello
strategy:canary-test
strategy:rollback-test
```

Coding-agent MUST NOT receive `strategy:promote` by default.

Это технически закрепляет разделение:

```text
agent validates implementation
utility selects/promotes production strategies
```

---

# 21. Acceptance criteria документа

1. Coding-agent может автоматически проверить каждый реализованный subsystem.
2. Реальный packet path проверяется, а не только pure functions.
3. Router/Keenetic behavior проверяется отдельно.
4. Android E2E запускается через API + ADB.
5. Discovery/Optimizer проверяется на synthetic и real inputs.
6. Agent не выполняет ручной подбор стратегий.
7. Production strategy promotion остаётся обязанностью utility.
8. Fault injection безопасна и scoped.
9. Trace/metrics сверяются с фактическим behavior.
10. Каждый этап получает отдельный validation verdict.
11. Full validation создаёт воспроизводимый bundle.
12. PASS невозможен при нарушении MUST-инварианта.

---

# 22. Итог

Coding-agent должен выступать как:

```text
implementation verifier
integration test runner
fault-injection operator
router/device E2E validator
report generator
```

Он не должен выступать как:

```text
production strategy tuner
постоянный YouTube optimizer
автоматический selector вместо встроенной утилиты
```

Встроенная B4 Discovery/Optimizer utility подбирает и применяет стратегии. Coding-agent доказывает, что эта утилита и все нижележащие механизмы реализованы и работают правильно.

---

# 23. Нормативная интеграция редакции 1.1

Редакция 1.1 не отменяет и не сокращает существующие разделы 1–22. Она расширяет их до umbrella validation contract для всех завершённых и companion-подсистем.

Правило применимости:

```text
implemented and enabled capability
→ MUST execute applicable suites

implemented but disabled-by-default capability
→ MUST execute unit/component/fault suites
→ target active-mode suite MAY be BLOCKED_CAPABILITY

not implemented capability
→ FAIL for stage/addendum declared complete
→ NOT_APPLICABLE only when capability is explicitly outside declared build scope
```

Ни один `NOT_RUN`, `SKIPPED`, `BLOCKED_CAPABILITY` или `BLOCKED_TARGET_VALIDATION` не преобразуется в `PASS`.

## 23.1. Источники требований

> **superseded (FB-14 решение 7):** настоящий раздел больше НЕ является самостоятельным Exact Source-Stage Registry. Единственный canonical registry — machine-readable **Exact Source-Stage Registry** (FB-33), который включает все действующие требования и acceptance criteria: ARCH v2.4, PLAN Stage 1–36, CSI-1…CSI-10, H1…H10, PPE-1…PPE-8, FT-A…FT-L + FT-AC…FT-AE + FT-MON-A…J, SP-1…SP-15 + SP-20…SP-23 + SP-30…SP-32, IV-1…IV-17, MON-1…MON-12. Перечисленные ниже списки — только generated views с явным фильтром (например, `view=v1.5-added`).

Validation Controller обязан построить machine-readable registry требований из canonical Exact Source-Stage Registry (см. FB-33):

```text
ARCH-v2.4
PLAN-v2.3 Stage 1–36
CSI-1…CSI-10
H1…H10
PPE-1…PPE-8
FT-A…FT-L
SP-1…SP-15
IV-1…IV-12
```

Каждое нормативное требование получает:

```go
type RequirementRecord struct {
    RequirementID   string
    SourceDocument  string
    SourceSection   string
    Level           RequirementLevel
    Capability      string
    TestIDs         []string
    EvidenceKinds   []EvidenceKind
    Blocking        bool
    FeatureGate     string
}
```

Запрещены:

- нормативный `MUST` без `TestID`;
- `TestID` без requirement source;
- stage `PASS` без полного blocking requirement coverage;
- ручная правка итогового verdict без audit event;
- скрытое исключение suite из `full` profile.

## 23.2. Verdict model

Допустимые terminal verdicts:

```text
PASS
PASS_WITH_LIMITATIONS
FAIL
ERROR
BLOCKED_CAPABILITY
BLOCKED_TARGET_VALIDATION
NOT_APPLICABLE
CANCELLED
```

`PASS_WITH_LIMITATIONS` допустим только для non-blocking требования, когда:

- production default остаётся безопасным;
- limitation описана;
- feature flag выключает непроверенный path;
- follow-up issue зарегистрирован;
- отсутствует нарушение архитектурного MUST.

Aggregation:

```text
any blocking FAIL/ERROR
→ subsystem FAIL

any required BLOCKED_TARGET_VALIDATION
→ subsystem BLOCKED_TARGET_VALIDATION
→ release gate не пройден

any required BLOCKED_CAPABILITY for enabled capability
→ subsystem FAIL

all blocking requirements PASS
+ only approved non-blocking limitations
→ PASS_WITH_LIMITATIONS

all requirements PASS
→ PASS
```

---

# 24. Расширенные уровни проверки

Существующие L0–L7 сохраняются.

## L8 — Contract, migration and release validation

- public API/schema backward compatibility;
- config migration from every supported prior schema;
- feature-flag default safety;
- capability downgrade behavior;
- report/schema reader compatibility;
- service-profile compile equivalence;
- release-gate aggregation;
- clean install, upgrade, downgrade and uninstall;
- reboot/crash persistence;
- validation-of-validation meta-tests.

Каждый production-ready subsystem должен иметь минимум:

```text
L0 static
+ L1 unit
+ L3 component
+ L4 packet/runtime integration where applicable
+ L5 target router where applicable
+ L7 fault injection
+ L8 contract/release validation
```

Packet-path capability без L4 не может быть `PASS`. Keenetic-specific capability без L5 не может быть `PASS`. Android-specific production claim без L6 получает `BLOCKED_TARGET_VALIDATION`.

---

# 25. Coverage registry завершённого Patch Plan Stage 1–36

Ниже указан минимальный обязательный mapping. Controller хранит его также в `VALIDATION_COVERAGE_REGISTRY.json`.

| Stage | Обязательное покрытие | Blocking evidence |
|---:|---|---|
| 1 | baseline audit, stale paths, dependency/provenance map | audit report + unresolved-risk list |
| 2 | TLS/DNS/TCP/Android fixtures, fixture hashes, malformed corpus | fixture manifest + parser/fuzz results |
| 3 | schema/version scaffolding, defaults, migration/round-trip | config compatibility report |
| 4 | capture envelope, processed provenance mark, readiness/offload self-check | namespace/target-router packet proof |
| 5 | phase/evidence/confidence policy | deterministic decision vectors |
| 6 | ClientKey identity, ARP/MAC absence, IP reuse, IPv4/IPv6 | source-isolation tests |
| 7 | clean SYN pass, TCP FSM, cleanup | packet trace and state-leak checks |
| 8 | bounded HostHintStore, TTL, ambiguity, config revalidation | fake-clock/race/bounds tests |
| 9 | DNS record parser, CNAME/A/AAAA/HTTPS/NXDOMAIN/SERVFAIL | corpus/fuzz/property tests |
| 10 | DoH/system DNS first-flow evidence, cache/provider failover | resolver integration matrix |
| 11 | QUIC evidence to TCP handoff | source-scoped handoff fixtures |
| 12 | NFQ decision order, DomainOnly modes, trace reasons | strict/scoped-hints/legacy/disabled matrix |
| 13 | structured TLS parser, ECH metadata, incomplete records | parser/fuzz fixtures |
| 14 | observe reassembly, overlap/retransmission/wrap/bounds | reassembly corpus + race tests |
| 15 | ECH-aware policy and safe ambiguity | ECH positive/negative vectors |
| 16 | auto hold/replay, preconditions, fail-open, Keenetic guard | namespace + incomplete-visibility faults |
| 17 | stream offsets, semantic markers, normalized ranges | planner property tests |
| 18 | first-flight-only, retransmission idempotency | duplicate/retry packet proof |
| 19 | executor checksums/order/mark/failure cleanup | raw-send fault matrix |
| 20 | metrics/trace/issue bundle v2 | behavior/event/metric consistency |
| 21 | isolated Experiment Sandbox | queue/mark/worker isolation proof |
| 22 | Structured ProbeOutcome/layered verdict/body policy | deterministic probe datasets |
| 23 | adaptive matrix/shadow probes/scoring | search-budget and ranking tests |
| 24 | Failure Candidate Inbox | dedupe/TTL/scope/promotion-safety tests |
| 25 | Android ClientHello capture | bounded privacy-safe capture proof |
| 26 | Fake Profile Compiler | deterministic compile/size/provenance tests |
| 27 | transactional apply/last-good/canary/rollback | crash/power-failure/reboot tests |
| 28 | marker multisplit/multidisorder | planner/executor equivalence matrix |
| 29 | hostfakesplit | precondition/negative marker tests |
| 30 | fake payload catalog/selection | bounded catalog and no unsafe auto-promote |
| 31 | fakedsplit/fakeddisorder/TLS record split | endpoint logical-stream proof |
| 32 | controlled outbound RST and diagnostics | FSM/budget/scope/cleanup tests |
| 33 | confidence-based TUN/SOCKS fallback | scoped route/failover/leak matrix |
| 34 | backend config/API | schema/auth/idempotency/concurrency tests |
| 35 | UI | effective-state, warnings, rollback and accessibility smoke |
| 36 | controlled router/Android validation | target report with no hard-gate failures |

Stage coverage is not satisfied by a later E2E alone. Each stage must retain its own lower-level deterministic tests and evidence.

---

# 26. Validation Suite: Cross-Service Scope Isolation

Suite ID:

```text
cross-service-isolation
```

## 26.1. Candidate/authorization split

Scenarios:

```text
shared Google IP + port 443
→ CaptureCandidate may exist
→ ActionAuthorization must not exist

clear youtube SNI
→ authorize matching YouTube component

clear gmail/google-feed SNI
→ revoke provisional YouTube candidate
→ no YouTube action or side effect

ambiguous DNS/QUIC hints
→ fail-open / observe-only
```

Assertions:

- candidate creation does not mutate packet;
- ActionToken requires authorization ID;
- action executor rejects candidate-only plan;
- stale authorization is rejected after config generation change;
- negative evidence has deterministic precedence;
- `legacy` mode is visible and cannot masquerade as isolated production mode.

## 26.2. Reassembled SNI authoritative path

- split ClientHello hostname becomes matcher input;
- packet-local incomplete parser result cannot override complete reassembly;
- clear/reassembled non-target SNI cancels IP candidate;
- reassembly timeout releases unchanged;
- decision trace identifies `packet-sni` vs `reassembled-sni`;
- one logical flow receives one final authorization.

## 26.3. Scoped state

Validate keys and cleanup for:

```text
IPBlockDetect
escalation
outbound controlled-RST bookkeeping
passive-RST suppression state
Failure Inbox
route binding
proxy fallback binding
learned evidence
```

Minimum key dimensions:

```text
ClientKey
FlowKey or destination/protocol
SetID/component
DomainHash or evidence association
ConfigGen
TTL/epoch
```

A destination-only `IP:port` persistent verdict is a hard failure for DomainOnly/service-profile paths.

## 26.4. QUIC authorization

- `FilterQUIC=all` cannot authorize from static/shared IP alone;
- source-scoped QUIC SNI may authorize only in `scoped-hints`;
- contradictory TCP SNI revokes prior provisional QUIC association;
- QUIC reject/fallback action is scoped to authorized component and client;
- UDP state cannot contaminate later unrelated TCP flow.

## 26.5. Same-client negative controls

Required Android controls:

```text
Gmail inbox headers
Gmail message body
inline images
attachment metadata/download smoke
Google app/Discover feed initial load
feed refresh
card/article open
image load
```

Run with:

- YouTube profile disabled;
- YouTube profile enabled;
- active YouTube playback;
- QUIC enabled/rejected/disabled;
- IPv4 and IPv6 where available;
- hot apply and rollback;
- after failure/escalation/RST observations;
- shared destination IP fixtures.

Hard gate:

```text
unrelated_control_action_total == 0
```

No control flow may receive YouTube ActionAuthorization, ActionToken, packet mutation, QUIC reject, block verdict, escalation, route/proxy binding or RST suppression.

---

# 27. Validation Suite: NFQUEUE GSO and Representation Parity

Suite ID:

```text
gso-hardening
```

## 27.1. Metadata envelope

Validate parsing and propagation of:

```text
NFQA_SKB_INFO
NFQA_CAP_LEN
payload length vs original length
checksum-not-ready state
GSO flag
queue ID
packet provenance
```

Truncation, missing attributes or unsupported kernel capability must produce explicit downgrade, never silent direct mutation.

## 27.2. Classification parity

Equivalent logical ClientHello inputs:

```text
single GSO skb
2 MSS segments
N MSS segments
out-of-order MSS
retransmitted segment
coalesced TLS records
```

must produce the same:

```text
SetID/component
EvidenceSource
DomainPolicy decision
ActionAuthorization result
ActionPlan semantics
```

for sizes at least:

```text
1988 bytes
4 KiB
16 KiB
32 KiB
configured maximum
```

## 27.3. Direct action eligibility

Each technique declares representation support:

```go
type RepresentationRequirement string

const (
    RepAnyLogicalStream RepresentationRequirement = "any-logical-stream"
    RepMSSPackets       RepresentationRequirement = "mss-packets"
    RepOriginalPacket   RepresentationRequirement = "original-packet"
)
```

Planner/executor must reject direct GSO action when technique capability is absent. Classification acceleration must remain available independently from mutation eligibility.

## 27.4. Conditional normalizer

Validate:

- normalization requested only by ActionPlan;
- primary queue creates one `GSOPassToken`;
- secondary pass consumes it once;
- duplicate, expired or foreign token is rejected/fail-open;
- no classifier/evidence side effects run twice;
- no fixed mark collides with existing `ProcessedBit` or Keenetic policy marks;
- token state is bounded and cleaned on timeout, rollback, crash and shutdown;
- normalizer queue unavailable causes transactional rollback or safe fail-open;
- no raw reinjection of oversized skb without preserved semantics.

## 27.5. Transactional topology

Test apply/rollback across:

```text
old queue owner active
new primary queue ready
new secondary queue ready
rules switched atomically
old owner drained
```

Faults at every transition must leave either previous complete topology or fail-open disabled topology, never half-applied processing.

## 27.6. Resource/performance

Measure:

- classification latency GSO vs MSS;
- CPU and allocations per logical ClientHello;
- token store high-water mark;
- queue drop and user drop;
- duplicate processing count;
- normalizer amplification;
- maximum bounded memory under adversarial GSO inputs.

---

# 28. Validation Suite: Passive RST Observation and Defense

Suite ID:

```text
passive-rst-defense
```

Outbound Controlled RST from Stage 32 and inbound Passive RST defense are separate suites and separate state machines.

## 28.1. Observe mode

Default mode:

```text
observe
```

Assertions:

- incoming RST verdict is unchanged;
- TTL/hop, sequence/ack validity, timing and FSM context recorded;
- baseline updates are robust against outliers;
- no single observation becomes block proof;
- incomplete incoming visibility is explicit;
- metrics/trace do not claim suppression.

## 28.2. Conservative enforcement

Requires:

```text
complete incoming visibility
stable baseline
high suspicion score
valid flow/FSM context
remaining suppression budget
automatic rollback monitor
explicit feature enable
```

Test legitimate RST, forged-like RST, delayed RST, duplicate RST, NAT/reconnect, path change and IPv4/IPv6.

## 28.3. Aggressive mode

- disabled by default;
- unavailable to service-profile/catalog automatic privilege elevation;
- explicit operator opt-in;
- isolated target validation;
- stricter budget and short expiry;
- forced rollback on reconnect regression.

## 28.4. Rollback and contamination controls

- reconnect failure threshold downgrades to `observe`;
- suppression state cannot cross client/domain/set/config generation;
- control services never inherit YouTube RST defense state;
- suppressed RST is not counted as successful target progress;
- crash/restart clears unsafe ephemeral suppression state;
- Failure Inbox receives structured but non-authoritative evidence.

---

# 29. Validation Suite: DNS, DoH and Resolver Semantics

Suite ID:

```text
dns-resolver
```

## 29.1. Record correctness

Required records/statuses:

```text
A
AAAA
CNAME chain
HTTPS/SVCB where supported
NXDOMAIN
NODATA
SERVFAIL
REFUSED
timeout
malformed/truncated response
```

Validate compression pointers, loops, bounds, duplicate records, TTL=0, large TTL clamp and mixed-family answers.

## 29.2. System-forward and DoH

- system-forward preserves expected resolver semantics;
- DoH request/response path is bounded and cancellable;
- provider failover is deterministic;
- no recursive interception loop;
- bootstrap resolution policy is explicit;
- cache keys include query name/type/class and relevant resolver generation;
- negative caching follows configured bounds;
- provider change invalidates incompatible cache state;
- DNS failure does not silently create hostname evidence.

## 29.3. Evidence integration

- evidence remains source-scoped;
- CNAME association records provenance;
- A/AAAA expiration uses absolute TTL, not lookup refresh;
- DNS answer for shared IP may create candidates, not global service authorization;
- stale config SetID is revalidated;
- ECH first flow behavior matches `strict`/`scoped-hints` policy;
- privacy/redaction excludes full client query logs by default.

## 29.4. Fault/performance

Inject provider timeout, partial response, malformed CNAME, cache corruption, clock jump and concurrent identical queries. Verify singleflight/bounded concurrency where implemented, failover cooldown and no goroutine/cache leak.

---

# 30. Validation Suite: UDP Forwarding, NAT and QUIC Runtime

Suite ID:

```text
udp-nat-quic
```

## 30.1. UDP forwarding/NAT table

- flow key includes source/destination addresses, ports, family and protocol;
- return packets map to correct client;
- idle timeout and explicit cleanup are bounded;
- port reuse does not inherit stale service state;
- concurrent clients to same destination remain isolated;
- checksum handling correct for IPv4/IPv6;
- fragmented/oversized datagrams follow documented policy;
- daemon restart does not leave persistent broken binding.

## 30.2. QUIC modes

Validate:

```text
allow
block/reject
fallback-to-TCP
observe
safe tested mutation modes, if implemented
```

Assertions:

- block/reject only after authorized policy;
- fallback does not become global destination rule;
- Initial parsing bounded/fuzzed;
- version negotiation/Retry/unknown version fail safely;
- connection IDs do not cause cross-client association;
- QUIC-to-TCP evidence handoff expires and revalidates;
- no UDP packet storm or retry loop;
- disabling QUIC restores baseline without restart where transactional config supports it.

## 30.3. Faults

- dropped Initial;
- reordered datagrams;
- duplicate Initial;
- NAT rebinding;
- address family switch;
- parser error;
- queue drop;
- hot apply during active UDP flow;
- rollback during fallback.

---

# 31. Validation Suite: IPv4/IPv6 and Address-Family Parity

Suite ID:

```text
ip-family-parity
```

All applicable classifier, DNS, TCP, UDP, QUIC, routing, SOCKS/TUN and observability suites run for IPv4 and IPv6.

Required checks:

- canonical address representation;
- no IPv4-mapped IPv6 key collision;
- correct pseudoheader checksums;
- extension-header policy and bounds;
- fragmentation policy;
- route/rule family parity;
- per-family mark/queue topology;
- DNS A vs AAAA evidence isolation;
- Happy Eyeballs concurrent family behavior;
- family failover does not inherit stale ActionToken/block/escalation state;
- issue bundle identifies actual family.

A subsystem advertised as dual-stack cannot receive `PASS` when only IPv4 packet-path tests were executed.

---

# 32. Validation Suite: Strategy Catalog and Controlled Outbound RST

Suite ID:

```text
strategy-catalog
```

## 32.1. Generic requirements

Every strategy technique must declare:

```text
preconditions
supported families
supported packet representations
maximum packet amplification
first-flight/FSM window
failure mode
rollback/fail-open behavior
observability fields
```

## 32.2. Split/disorder/fake families

For multisplit, multidisorder, hostfakesplit, fakedsplit, fakeddisorder and TLS-record split:

- semantic markers resolve to valid stream offsets;
- duplicate/overlapping ranges normalize deterministically;
- endpoint receives intact logical stream;
- DPI-visible order matches intended plan;
- no action after server progress/window close;
- retransmissions do not repeat fake storm;
- MTU, IPv4/IPv6 and GSO representation requirements enforced;
- invalid marker fails open.

## 32.3. Fake payload catalog

- canonical payload hash/provenance;
- bounded sizes/counts;
- captured profiles redact/private-store raw data;
- malformed profile rejected;
- catalog update transaction/rollback;
- auto-selection respects confidence and promotion policy;
- no payload from another service/component is silently reused without compatibility proof.

## 32.4. Controlled outbound RST

- valid FSM and authorization required;
- sequence/ack/checksum correct;
- one bounded injection per token/policy;
- no control-service contamination;
- no conflict with Passive RST defense state;
- incomplete visibility disables unsafe follow-up assumptions;
- trace distinguishes `outbound-controlled-rst` from `inbound-passive-rst`.

---

# 33. Validation Suite: Confidence-Based TUN/SOCKS/Transport Fallback

Suite ID:

```text
transport-fallback
```

## 33.1. Selection policy

- fallback starts only at configured confidence/failure policy;
- direct strategy and transport path cannot both process one flow;
- client/set/component scope explicit;
- route binding has config generation and expiry;
- shared destination does not route unrelated service/client;
- fail-open/leak policy explicit.

## 33.2. SOCKS5

Test:

- no-auth and authenticated handshake where supported;
- domain-name, IPv4 and IPv6 address types;
- connect success/refusal/timeout;
- partial handshake and malformed reply;
- credential redaction;
- endpoint health/cooldown/failover;
- TCP half-close and reconnect;
- DNS resolution ownership and leak behavior.

## 33.3. TUN/router tunnel

- route/rule/mark isolation;
- selected devices/sets only;
- IPv4/IPv6 parity;
- MTU/MSS handling;
- DNS path according to policy;
- crash/restart cleanup;
- tunnel endpoint failure and rollback;
- no loop into B4 packet strategy;
- no global default-route takeover unless explicitly configured and separately validated.

## 33.4. Client-configured transport

For service profiles using client handoff:

- B4 creates only declarative setup artifact;
- no false claim that client applied settings;
- QR/deep link contains only local user configuration;
- secrets absent from logs/export;
- confirmation state explicit;
- packet executor remains uninvolved.

---

# 34. Validation Suite: Transactional Runtime, Hot Apply and Lifecycle

Suite ID:

```text
transactional-runtime
```

Validate transactions spanning:

```text
config snapshot
classifier/evidence generation
NFQUEUE owner/topology
marks/firewall rules
PPE connskip rules
route/proxy bindings
service profile compiled objects
last-good metadata
```

## 34.1. Atomicity

Fault injection at every apply phase:

- validation failure before side effects;
- queue owner not ready;
- firewall rule failure;
- route rule failure;
- persistence failure;
- daemon crash before/after commit point;
- UI/API client retry with same Idempotency-Key;
- concurrent apply conflict.

Expected:

```text
old complete generation
or
new complete generation
```

Never mixed generations.

## 34.2. Active-flow behavior

- existing flow keeps compatible immutable snapshot or safely revalidates;
- no dangling pointer to removed set/strategy;
- held packets release on rollback;
- GSO tokens and ActionTokens invalidate by generation;
- routes/cache/escalation cannot survive incompatible generation;
- telemetry labels correct generation.

## 34.3. Last-good/canary/rollback

- last-good written only after required gates;
- canary scope deterministic;
- hard failure triggers rollback once;
- rollback itself is health-checked;
- cooldown prevents flapping;
- reboot restores committed generation, not half-applied candidate;
- rollback restores Gmail/Google controls and target baseline.

---

# 35. Validation Suite: Keenetic MediaTek PPE Per-Flow Offload Exclusion

Suite ID:

```text
keenetic-ppe
```

## 35.1. Capability detection

Validate actual target capabilities, not model-name assumptions:

- kernel target presence;
- `connskip` match/target semantics;
- required tables/chains;
- lock/privilege support;
- IPv4/IPv6 support;
- NDM regeneration behavior;
- capability states and reasons in API/UI.

## 35.2. Rule compiler and scope

- source client/device scope;
- TCP and QUIC port scope;
- exact chain/rule ordering;
- no global offload disable in `detect`/`exclude`;
- deterministic generated comments/ownership;
- mark namespace compatibility;
- idempotent apply/remove;
- no unrelated client exclusion.

## 35.3. Bidirectional visibility self-test

Run Level 0 static, Level 1 passive live observation and Level 2 controlled A/B where safe.

Verify:

```text
first-N outgoing packets visible
SYN-ACK/server progress visible
FIN/RST visible
second ClientHello segment visible
processed packet bypass intact
```

Verdicts:

```text
complete
outgoing-only
incomplete
unknown
```

must drive runtime safety gates. Incomplete/unknown visibility forbids hold/replay, unsafe retransmission suppression, active Passive RST defense and capability-dependent promotion.

## 35.4. Lifecycle

- NDM table regeneration recovery;
- daemon restart and router reboot;
- stale rule cleanup;
- uninstall cleanup;
- concurrent firewall mutation lock behavior;
- failed apply rollback;
- no automatic `disable-global` without explicit operator action.

## 35.5. Performance

Measure CPU during bounded handshake exclusion and after flow eligibility for offload. Prove that exclusion is per-flow/bounded and unrelated bulk flows retain expected offload behavior.

---

# 36. Validation Suite: Service Profiles and Beginner UX

Suite ID:

```text
service-profiles
```

## 36.1. Schema/compiler

- manifest version/limits/provenance/signature;
- deterministic canonical compile hash;
- no executable fields;
- ownership managed/manual/pinned/excluded;
- compile to ordinary sets/strategies/probes/scoped transport bindings/client actions;
- no runtime service-specific branch;
- conflicts and delivery-mode exclusivity;
- import/export without secrets;
- update/rollback/removal preserving manual objects.

## 36.2. Domain and capability policy projection

For optimized direct components:

- effective `domain_policy` explicit;
- shared IP/CIDR/port is capture-only;
- `negative_sni_override=true` where required;
- legacy/degraded isolation prevents `Healthy` production status;
- profile cannot own NFQUEUE topology, marks, GSO tokens or RST baseline;
- uncertified GSO direct technique rejected;
- aggressive Passive RST request rejected;
- capability downgrade invalidates prior safety hash.

## 36.3. YouTube pack

Required component separation:

```text
api
ui
video
```

Validate official YouTube and ReVanced, per-component objectives/winners, CDN switch, rollback, multi-client and same-client Gmail/Google controls.

## 36.4. Additional profiles

- direct/hybrid profile cannot broadly capture unrelated CDN;
- Discord hybrid delivery conflict tests;
- Telegram transport-required profile does not claim fake/split as primary IP-block solution;
- client-configured MTProxy/SOCKS setup artifact/confirmation/security;
- router tunnel scope/leak/failover;
- beginner wizard preview shows actual compiled objects and risks.

## 36.5. UI

Basic and Advanced views are two representations of one config generation. Validate effective policy, evidence, authorization, degraded capability, last validation, rollback and advanced drill-down.

---

# 37. Validation Suite: Field Test Automation and Trace Contract

Suite ID:

```text
field-test-automation
```

This suite validates the implementation of `B4_FIELD_TEST_AUTOMATION_ADDENDUM`, not a single strategy candidate.

## 37.1. Router TestSession API

- capabilities complete and truthful;
- session create/status/events/stop/report;
- Idempotency-Key and request correlation;
- cancellation and timeout cleanup;
- report formats JSON/Markdown/ZIP;
- no promotion scope by default;
- concurrent session/resource limits.

## 37.2. Local controller/ADB

- loopback binding;
- device/package preflight;
- force-stop-only default;
- official/ReVanced lifecycle;
- target/control role distinction;
- clock correlation;
- disconnect/reconnect behavior;
- secrets and device identifiers redacted.

## 37.3. Control Scenario Driver

- Gmail and Google app scenarios emit success/failure without collecting message/feed contents;
- inferred vs measured markers explicit;
- baseline-none, baseline-production and candidate ordering;
- concurrent target/control sequence;
- authorization auditor joins flow events to control role;
- any unrelated action is hard failure.

## 37.4. GSO/RST adapters

- representation parity report;
- normalizer lifecycle report;
- Passive RST observe/safety report;
- capability-dependent runs return correct blocked verdict;
- reports bind build/config/capability/topology/safety hashes.

## 37.5. Optimizer/canary contract

- separate API/UI/VIDEO ranking;
- adaptive matrix, not unconditional Cartesian product;
- A/B interleaving;
- sample-count statistics;
- report-only default;
- canary rollback on target, control, resource, GSO or RST hard gate;
- stale field report invalidated after relevant hash change.

---

# 38. Validation Suite: Validation-of-Validation

Suite ID:

```text
implementation-validation-meta
```

Это обязательная проверка реализации самого этого addendum.

## 38.1. Requirement registry completeness

Controller должен сгенерировать:

```text
VALIDATION_REQUIREMENTS.json
VALIDATION_TEST_REGISTRY.json
VALIDATION_COVERAGE_MATRIX.json
VALIDATION_ORPHANS.json
```

Hard gates:

```text
blocking_requirements_without_tests == 0
tests_without_requirement_source == 0
completed_stages_without_validation_report == 0
duplicate_requirement_ids == 0
duplicate_test_ids == 0
```

## 38.2. Suite discovery and CLI/API parity

For every suite advertised by API:

- CLI can list it;
- CLI and API resolve the same canonical suite ID/version;
- capability prerequisites match;
- default `full` profile includes it when applicable;
- unknown suite/version rejected;
- schema documents required parameters;
- dry-run returns planned tests without mutation.

## 38.3. Verdict aggregation meta-tests

Synthetic child results must prove:

```text
one blocking FAIL cannot be masked by many PASS
ERROR cannot become PASS_WITH_LIMITATIONS
BLOCKED_TARGET_VALIDATION blocks release
BLOCKED_CAPABILITY for enabled feature is FAIL
NOT_APPLICABLE requires declared scope reason
cancelled run cannot emit PASS
missing artifact cannot emit PASS
```

Mutation tests intentionally invert aggregator conditions; meta-suite must detect every injected false-pass mutation.

## 38.4. Evidence integrity

Each test result contains:

```text
test ID
requirement IDs
build commit
config generation
capability snapshot hash
start/end monotonic timestamps
commands/inputs
expected invariant
actual assertion
artifact references
verdict/reason
```

Validate artifact hashes, missing/truncated files, duplicate event sequence, corrupted JSONL, report reader compatibility and deterministic summary regeneration.

## 38.5. Reproducibility

- same fixture/config/build produces same deterministic assertions;
- nondeterministic fields excluded from content hash;
- random/fuzz seed recorded;
- target-dependent variance represented as measured data, not hidden;
- rerun command generated;
- environment and tool versions recorded;
- partial rerun links to parent full run without overwriting it.

## 38.6. Safety of validation infrastructure

- fault injection disabled by default;
- all faults scoped to session/client/flow and auto-expire;
- controller cannot mutate ordinary clients outside allowlist;
- validation queue/marks cannot collide with production topology;
- cancellation/crash cleans faults, queues, routes and captures;
- pcap/ClientHello permissions explicit;
- privacy redaction tested with seeded secrets/message-like content;
- no validation endpoint grants production `strategy:promote` by default.

## 38.7. False-negative controls

The meta-suite includes known broken fixtures:

- cross-client hint leak;
- destination-only block cache;
- invalid TCP checksum;
- duplicate action side effect;
- GSO/MSS decision mismatch;
- leaked GSOPassToken;
- RST suppression under incomplete visibility;
- global PPE disable;
- route leak;
- rollback no-op;
- control flow receiving YouTube token;
- missing trace event with metric increment.

Every seeded defect must cause expected suite failure. A validator that passes a known-broken fixture fails meta-validation.

---



# 38A. Validation Suite: Built-in WARP/MASQUE Transport v1.2

This suite is blocking for every WARP capability claim. It validates the actual bundled subsystem, not presence of an external package or a mocked interface.

## 38A.1. Requirement domains

Registry MUST contain source requirement IDs for:

```text
WARP-1…WARP-12
WARP-C1…WARP-C10
FT-M…FT-Q
FT-AC…FT-AE
SP-16…SP-19
WARP_CAUSAL_TRACE_READY
```

Requirement categories:

- reference/source/license/supply chain;
- bundled build and packaging;
- secrets and enrollment;
- structured IPC/supervision;
- TUN/NDM/address/MTU lifecycle;
- socket marks and recursion protection;
- scoped PBR/NAT/MSS/DNS;
- W0–W4 liveness and self-heal;
- nested backend and non-RU geo gate;
- transport-control identity;
- enrollment/cover-SNI/handshake camouflage;
- CONNECT-IP cutoff and established bypass;
- candidate scoring and stability promotion;
- outer/inner isolation;
- Passive RST observation/defense;
- API/UI/telemetry/profile/field integration;
- target router/Android/fault/performance evidence;
- generation-aware trace envelope and event durability;
- route/path proof with counter deltas;
- forwarded Android binding correlation;
- nested parent/child dependency graph;
- provider-level geo/quorum and DNS/IPv6 path proof;
- resource ownership and cleanup closure;
- validation-of-observability mutants.

## 38A.2. L0 — Static, provenance and packaging

Required checks:

- exact upstream `usque` source commit;
- exact B4 patch-set hash;
- MIT license notice and source provenance;
- reproducible per-architecture build;
- binary/manifest/SBOM hashes;
- one B4 install package contains `b4-warpd`;
- no mandatory external `usque`/`usque-keenetic` opkg dependency;
- no runtime `latest` download path;
- no hardcoded enrollment proxy credentials;
- no `insecure` production flag;
- no secret-bearing sample committed;
- config/schema migration and rollback defined.

Mutation fixtures MUST detect:

```text
floating main/latest reference
missing license
wrong-architecture artifact
unverified download
external package dependency
secret in log/export
insecure TLS enabled
```

## 38A.3. L1/L2 — Unit, property and fuzz

At minimum:

- engine manifest and architecture resolver;
- session parser with confidential-field redaction;
- interface identity/ownership and assigned address selection;
- MarkAllocator/table/rule allocation;
- WARP state machines and generation transitions;
- IPC framing/version/auth/event ordering;
- reconnect/cooldown/budget arithmetic including clock skew;
- endpoint variant TTL/rollback;
- W0–W4 verdict aggregation;
- geo quorum/age/RU/unknown/conflict logic;
- strict fail-closed policy;
- camouflage envelope, packet/byte/time budgets and cutoff;
- candidate lexicographic scoring;
- outer/inner authorization and token isolation;
- report redaction;
- `TransportTraceEnvelope` schema/version/order/generation invariants;
- trace-derived state reducer and runtime-state comparator;
- `TransportPathProof`, `TunnelDependencyLink`, geo quorum, DNS/IP-family and cleanup ledgers.

Fuzz targets include config/session/IPC/event/geo responses, malformed lifecycle ordering, sequence gaps, generation churn, duplicate/reordered required events and ownership-ledger corruption.

## 38A.4. L3/L4 — Component and packet-path integration

Use fake MASQUE server, namespaces/veth, deterministic packet fixtures and fault injection.

Required scenarios:

```text
CONNECT-IP 200
CONNECT-IP non-200
TLS/pin mismatch
TCP connect timeout/reset
connected then data path dead
idle wake and reconnect
connect/disconnect/cutoff event loss/reorder/duplicate
TUN packet pump read/write failure
MTU boundary and oversize packet
outer control direct route
inner control route through base WARP
route recursion attempt
service strategy attempts to match WARP endpoint
camouflage exact authorization
camouflage destination-only rejection
ClientHello mutation then cutoff
post-cutoff packet mutation attempt
old-generation masque_connected after reconnect
route exists without packet/byte counter delta
router-origin success substituted for forwarded success
inner parent-generation mismatch
geo quorum without provider events
DNS/IPv6 config intent without observed path
cleanup incomplete after crash/rollback
```

Packet/runtime evidence MUST prove established encrypted MASQUE payload is not modified. Trace evidence MUST independently reconstruct the same effective state as runtime/API.

## 38A.5. L5 — Keenetic target integration

On each claimed target class:

- Entware/B4 package install/upgrade/remove;
- no separate WARP package installation;
- TUN availability and stable ownership;
- assigned WARP address, `/32`, MTU 1280 and link state;
- NDM command read-back and iproute2 fallback behavior;
- flash-save budget;
- PBR mark/rule/table coexistence;
- PPE/offload visibility and exclusion where required;
- NAT/MSS single-owner proof;
- forwarded TCP/UDP/DNS path;
- firewall reload, WAN flap, idle, reboot and daemon crash;
- cleanup with no stale rule/route/interface/process;
- resource budgets for base and nested modes separately;
- current route/rule/table/interface/namespace counter proof;
- required-event durability and trace/runtime state consistency;
- generation-owned cleanup ledger after crash, rollback and uninstall.

Router-origin W3 proof cannot substitute for forwarded W4 proof. W4 additionally requires exact Android/LAN binding correlation and current `TransportPathProof`.

## 38A.6. L6 — Android and real-service E2E

Applicable profiles run:

- official YouTube;
- ReVanced;
- Gmail and Google Feed same-client controls;
- multi-client isolation;
- TCP and UDP/game-style generic probes;
- base WARP off/on comparison;
- camouflage C0/C1 and selected candidate comparison;
- nested non-RU positive and unavailable cases where the network exposes them.

No target-side non-RU availability is required for a safety PASS; however production availability claim requires observed target evidence. A missing target path yields `BLOCKED_TARGET_VALIDATION`.

Every WARP Android E2E report MUST contain `TestSessionID → ClientKey → component → BindingID → RouteTokenID → PathProofID → current SessionGen → application milestone`, including same-client controls.

## 38A.7. L7 — Fault injection

Blocking fault fixtures:

- missing/corrupt/wrong-architecture engine;
- invalid or truncated session;
- registration rate-limit/timeout;
- endpoint blocked or pin mismatch;
- stale TUN/NDM object and foreign interface;
- NDM false-success;
- MTU drift;
- route/mark collision;
- missing/double NAT;
- full/read-only state filesystem;
- supervisor/helper crash and orphan;
- rapid WAN flaps;
- lost cutoff event;
- namespace unavailable;
- inner session loss;
- geo provider timeout, RU, unknown, stale, conflicting and malicious fixtures;
- DNS/direct-IP/IPv6 leak;
- rollback failure injection;
- missing/reordered/duplicate required WARP events;
- old-generation event accepted by current state;
- trace buffer/storage pressure and required-event drop;
- trace/runtime state mismatch;
- stale parent route token and direct inner-control leak;
- geo route gate inconsistent with provider events;
- public-IP change without attestation refresh;
- orphan namespace/veth/rule/NAT/mark/token and foreign-resource removal.

Recovery MUST remain bounded. Restart, enrollment, endpoint and candidate retry storms are blocking failures.

## 38A.8. L8 — Contract, migration and release

Validate:

- WARP API/schema/CLI/UI parity;
- v1.0→v1.1→v1.2 configuration compatibility;
- Field Test v1.5 contract including `FT-AC…FT-AE`;
- Service Profiles v1.6 compiler and UI;
- validation registry coverage;
- report/artifact completeness;
- secret-safe export;
- capability/version/safety-hash invalidation;
- separate base/camouflage/non-RU verdicts;
- rollback and uninstall behavior;
- no false production-ready claim;
- `WARP_CAUSAL_TRACE_READY` aggregation and blocked semantics;
- complete required-event/artifact set and trace schema hash;
- independent validation-of-observability mutants.

## 38A.9. Mandatory WARP v1.2 hard gates

```text
warp_secret_leak_total == 0
warp_foreign_interface_modified_total == 0
warp_recursive_control_route_total == 0
warp_mark_collision_total == 0
warp_route_without_liveness_total == 0
warp_destination_set_partial_apply_total == 0
warp_unbounded_restart_total == 0
warp_unbounded_registration_total == 0
warp_unrelated_control_action_total == 0
warp_rollback_failure_total == 0
nonru_route_active_without_fresh_attestation == 0
nonru_route_active_while_any_provider_ru == 0
nonru_route_active_with_provider_disagreement == 0
nonru_route_active_with_direct_dns == 0
nonru_route_active_with_unvalidated_ipv6 == 0
nonru_route_active_after_attestation_expiry == 0
nonru_strict_direct_fallback_total == 0
nonru_identity_creation_budget_exceeded == 0
masque_camouflage_without_control_authorization_total == 0
masque_camouflage_destination_only_authorization_total == 0
masque_established_payload_mutation_total == 0
masque_camouflage_cutoff_failure_total == 0
masque_control_route_recursion_total == 0
masque_camouflage_cross_instance_total == 0
masque_strategy_promoted_without_forwarded_probe_total == 0
masque_strategy_promoted_without_stability_window_total == 0
masque_insecure_tls_total == 0
masque_endpoint_pin_failure_accepted_total == 0
masque_unbounded_candidate_retry_total == 0
masque_rst_suppression_without_exact_authorization_total == 0
warp_route_promoted_without_path_proof_event_total == 0
warp_forwarded_success_without_binding_trace_total == 0
warp_direct_fallback_without_trace_total == 0
warp_nested_missing_parent_link_total == 0
warp_nested_parent_generation_mismatch_total == 0
warp_nested_control_direct_leak_total == 0
warp_nested_route_active_without_parent_health_total == 0
warp_nested_stale_parent_token_total == 0
warp_geo_attestation_without_route_counter_delta_total == 0
warp_geo_quorum_without_provider_events_total == 0
warp_geo_route_gate_state_mismatch_total == 0
warp_nonru_revocation_exceeded_deadline_total == 0
warp_nonru_public_ip_change_without_refresh_total == 0
warp_dns_path_unproven_total == 0
warp_ipv6_path_unproven_total == 0
warp_connect_ip_event_wrong_generation_total == 0
warp_post_cutoff_mutation_total == 0
warp_cleanup_incomplete_total == 0
warp_owned_resource_leak_total == 0
warp_foreign_resource_removed_total == 0
warp_trace_secret_leak_total == 0
warp_trace_required_event_missing_total == 0
warp_trace_dropped_required_event_total == 0
warp_trace_event_order_violation_total == 0
warp_trace_generation_mismatch_total == 0
warp_trace_state_mismatch_total == 0
```

A not-run, skipped, unsupported or artifact-missing hard gate is not zero and cannot be aggregated as `PASS`.

`WARP_CAUSAL_TRACE_READY` — **узкий composable verdict** (FB-14 решение 9). Подтверждает только полную причинную связь:

```text
TransportAuthorization
→ BindingID
→ RouteTokenID
→ route/rule/mark ownership
→ socket/TUN/MASQUE path
→ target flow
→ required control flows
→ cleanup/rollback events
```

Обязательные условия:

```text
все required events присутствуют
+ ordering непротиворечив
+ IDs и ConfigGeneration согласованы
+ trace-derived state совпадает с runtime/API state
+ target и controls различимы
+ route/path counters подтверждают выбранный path
+ cleanup/rollback закрывает все owned resources
+ missing/skipped/unknown/stale evidence не считается PASS
```

Nested WARP, geo/non-RU, camouflage и Android field validation **не входят автоматически** в causal-trace verdict; они имеют отдельные verdicts (`WARP_BASE_TRANSPORT_READY`, `WARP_CAMOUFLAGE_READY`, `WARP_NESTED_READY`, `WARP_NON_RU_READY`, `WARP_ANDROID_VALIDATED`, `WARP_PRODUCTION_READY`). `WARP_PRODUCTION_READY` агрегирует только применимые verdicts для заявленного release scope.

> **superseded (FB-14 решение 9):** прежний расширенный состав (FT-AC…FT-AE + Android correlation + nested/geo/DNS/IPv6 consistency) заменён узким causal-trace составом настоящего пункта.

# 38B. Validation Suite: Silent Path Failure and Scoped Recovery v1.0

## 38B.1. Requirement domains

Umbrella registry MUST cover:

```text
SPF-1…SPF-10
FT-R…FT-V
SP-20…SP-23
```

Requirement groups:

- unique bidirectional TCP progress;
- protocol milestones and visibility gate;
- independent evidence correlation;
- false-positive suppression;
- adaptive baselines;
- bounded differential proof;
- exact scoped recovery leases;
- WARP/proxy recovery constraints;
- rollback and false-positive budget;
- API/UI/telemetry/privacy;
- target and long-run validation.

## 38B.2. L0 — Static and contract audit

Validate:

- no destination-global silent failure/recovery maps;
- no raw config pointers in long-lived assessment/lease state;
- all collections, timers and probes are bounded;
- observe path cannot invoke planner/executor/routing mutation;
- profile policy is an upper bound, not runtime privilege;
- no service-specific branches in generic detector core;
- no unsupported `RKN/DPI confirmed` UI strings;
- privacy-safe labels and exports.

## 38B.3. L1/L2 — Unit, property and fuzz

Mandatory:

- TCP sequence/range unique progress including wrap/overlap/retransmission;
- GSO/MSS representation parity;
- evidence-family independence and duplicate-source rejection;
- deterministic suppressor precedence;
- baseline/deadline/expiry fake-clock tests;
- assessment/lease state-machine property tests;
- API/event/config decoder fuzz;
- scope/generation mutation tests.

## 38B.4. L3/L4 — Component and packet-path integration

Scenarios:

- handshake, early-body and midstream silence;
- repeated ClientHello without server progress;
- explicit FIN/RST/TLS Alert/application error;
- HLS/DASH parallel connections and prefetch;
- fresh compatible QUIC/TCP success bypass;
- NFQUEUE drop/pressure and incomplete incoming visibility;
- PPE visibility loss and recovery;
- bounded current/candidate differential A/B;
- exact lease installation, expiry and rollback;
- no packet mutation caused by observe-only assessment.

## 38B.5. L5 — Keenetic target integration

Validate on target:

- incoming capture envelope and PPE exclusion proof;
- GSO/MSS progress parity under real offload conditions;
- bounded CPU/RAM/state on mixed TCP/QUIC traffic;
- reboot, firewall reload, WAN flap and config hot apply;
- stale assessment/lease cleanup;
- direct and optional base-WARP candidate routing;
- no recursive transport fallback.

## 38B.6. L6 — Android and same-client controls

Required target scenarios:

- official YouTube and ReVanced cold/warm start;
- HLS/DASH segment bursts and CDN changes;
- Gmail and Google app/Discover concurrent controls;
- background/foreground and Doze;
- Wi-Fi/WAN transition;
- real target stall fixture or controlled impairment;
- user false-positive rollback action.

## 38B.7. L7 — Fault injection

Inject:

- lost incoming observation;
- duplicate/reordered packets;
- fake retry signal;
- both paths fail / both paths pass;
- candidate probe timeout;
- rollback target disappears;
- control regression after lease activation;
- false-positive budget exhaustion;
- clock skew/expiry race;
- WARP unavailable or strict non-RU attestation lost.

Every fault MUST produce bounded degradation, rollback or a non-PASS verdict.

## 38B.8. L8 — Validation-of-validation

Seed mutants that:

- allow single-signal fallback;
- ignore one mandatory suppressor;
- count retransmissions as progress;
- accept incomplete visibility;
- use destination-only recovery state;
- skip control probes;
- allow recursive WARP fallback;
- omit rollback target;
- suppress false-positive budget;
- aggregate observe readiness into active PASS.

Meta-suite MUST detect every mutant.

## 38B.9. Mandatory Silent Path hard gates

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

Any non-zero hard gate blocks the applicable active claim. Observe readiness may remain independently valid only when the violation cannot affect observation correctness and is explicitly scoped; all observation-integrity violations block even observe readiness.

# 39. Validation API и CLI редакции 1.3

## 39.1. CLI

Existing commands remain. Add:

```text
b4-validate list
b4-validate plan full
b4-validate requirement REQUIREMENT_ID
b4-validate stage 1..36
b4-validate companion CSI-1
b4-validate companion H1
b4-validate companion PPE-1
b4-validate companion FT-A
b4-validate companion SP-1
b4-validate subsystem dns
b4-validate subsystem udp-nat-quic
b4-validate subsystem transport-fallback
b4-validate subsystem keenetic-ppe
b4-validate subsystem cross-service-isolation
b4-validate subsystem gso-hardening
b4-validate subsystem passive-rst-defense
b4-validate subsystem service-profiles
b4-validate subsystem field-test-automation
b4-validate meta
b4-validate full --profile release
b4-validate reproduce RUN_ID TEST_ID
```

## 39.2. Capabilities response

`GET /api/v1/validation/capabilities` additionally returns:

```text
validation_schema_version
suite_registry_version
requirement_registry_hash
supported_suite_ids
supported_fault_ids
available_target_adapters
cross_service_isolation_version
domain_policy_modes
reassembled_sni_authoritative
nfqueue_gso_supported
nfqueue_gso_mode
normalizer_queue_ready
passive_rst_supported
passive_rst_effective_mode
ppe_connskip_capability
incoming_visibility_verdict
service_profile_schema_versions
field_test_contract_version
```

Capabilities must reflect effective runtime state, not configured intent only.


### Silent Path Failure capability projection редакции 1.3

Validation capabilities MUST add:

```text
silent_path_failure_supported
silent_path_failure_version
silent_path_failure_modes
silent_progress_unique_range_accounting
silent_protocol_milestones_supported
silent_visibility_gate
silent_gso_parity_state
silent_ppe_visibility_state
silent_suppression_catalog_version
silent_differential_probe_supported
silent_scoped_recovery_supported
silent_warp_fallback_supported
silent_false_positive_budget_supported
silent_user_revert_supported
silent_active_mode_promotion_state
silent_target_validation_hash
```

A planned active suite MUST be `BLOCKED_CAPABILITY` when any required state is absent, stale, degraded or inconsistent. It cannot be omitted or downgraded to a strategy failure.

## 39.3. Run request

Example:

```json
{
  "suite": "full",
  "profile": "release",
  "target_client_id": "android-main",
  "control_roles": ["gmail", "google-feed"],
  "fault_profile": "none",
  "trace_level": "detailed",
  "required_capabilities": [],
  "promotion_allowed": false,
  "expected_build_commit": "...",
  "expected_config_generation": 418
}
```

## 39.4. Planned tests endpoint

```http
POST /api/v1/validation/plan
```

Returns without mutation:

- resolved requirements;
- test IDs;
- skipped/not-applicable reasons;
- capability prerequisites;
- estimated resource profile;
- target requirements;
- expected artifacts.

## 39.5. Coverage endpoints

```http
GET /api/v1/validation/requirements
GET /api/v1/validation/tests
GET /api/v1/validation/coverage
GET /api/v1/validation/runs/{run_id}/coverage
```

## 39.6. Run event extensions

```text
requirement_started
requirement_satisfied
requirement_failed
suite_blocked_capability
suite_blocked_target
artifact_created
artifact_hash_verified
verdict_aggregated
false_pass_guard_triggered
cleanup_started
cleanup_completed
```

---

# 40. Full Validation Run редакции 1.3

`b4-validate full --profile release` выполняет:

```text
manifest/requirement registry validation
→ static audit and generated-code checks
→ build, vet, unit, race, fuzz, property tests
→ config/schema/migration compatibility
→ classifier/evidence/DomainOnly suites
→ DNS/DoH resolver suites
→ TCP FSM/reassembly/hold-replay suites
→ planner/executor/strategy catalog suites
→ retransmission and controlled outbound RST suites
→ UDP/NAT/QUIC suites
→ IPv4/IPv6 parity
→ capture envelope and PPE visibility suites
→ GSO metadata/parity/normalizer/topology suites
→ Passive RST observe/enforcement/rollback suites
→ transactional runtime/hot apply/last-good suites
→ Discovery/Optimizer/Sandbox/Failure Inbox suites
→ transport fallback and route-leak suites
→ backend API/auth/idempotency/UI smoke
→ service-profile compiler/catalog/UX suites
→ field-test automation contract suites
→ router target lifecycle
→ Android target + same-client controls
→ canary/rollback test
→ observability consistency
→ validation-of-validation meta-suite
→ release gate aggregation
→ final reproducible bundle
```

## 40.1. Profiles

```text
quick
component
router
android
fault
release
```

`quick` is never sufficient for production release. `release` includes all applicable blocking suites.

## 40.2. Run ordering and cleanup

- destructive/fault suites run only after baseline and readiness;
- control baselines collected before candidate mutation;
- rollback tested before canary;
- GSO/Passive RST active modes run only after observe/parity gates;
- faults and temporary topology cleaned between suites;
- final cleanup verification runs even after failure/cancel;
- early hard failure may stop dependent suites but report them as blocked, not passed.

## 40.3. Expanded output

```text
validation-results/<run-id>/
├── RUN_MANIFEST.json
├── FULL_VALIDATION_REPORT.md
├── RELEASE_GATE_REPORT.md
├── SUBSYSTEM_MATRIX.json
├── STAGE_1_36_MATRIX.json
├── COMPANION_STAGE_MATRIX.json
├── VALIDATION_REQUIREMENTS.json
├── VALIDATION_TEST_REGISTRY.json
├── VALIDATION_COVERAGE_MATRIX.json
├── VALIDATION_ORPHANS.json
├── CAPABILITY_SNAPSHOT.json
├── CONFIG_MIGRATION_REPORT.md
├── CROSS_SERVICE_ISOLATION_REPORT.md
├── DNS_DOH_VALIDATION_REPORT.md
├── UDP_NAT_QUIC_VALIDATION_REPORT.md
├── IP_FAMILY_PARITY_REPORT.md
├── TRANSPORT_FALLBACK_VALIDATION_REPORT.md
├── PPE_VALIDATION_REPORT.md
├── GSO_PARITY_REPORT.md
├── GSO_NORMALIZER_LIFECYCLE_REPORT.md
├── PASSIVE_RST_VALIDATION_REPORT.md
├── SERVICE_PROFILE_VALIDATION_REPORT.md
├── FIELD_TEST_CONTRACT_VALIDATION_REPORT.md
├── VALIDATOR_META_REPORT.md
├── test-results/
├── traces/
├── pcaps/
├── router-diagnostics/
├── android-diagnostics/
├── fault-injection/
├── migrations/
├── coverage/
└── issue-bundles/
```

---

# 41. Companion-stage coverage matrix

## 41.1. Cross-Service Isolation

| Stage | Required validation |
|---|---|
| CSI-1 | schema/migration/effective-policy trace |
| CSI-2 | candidate/authorization separation and executor rejection |
| CSI-3 | reassembled-SNI authoritative matcher path |
| CSI-4 | negative evidence revocation and ambiguity fail-open |
| CSI-5 | legacy learned-IP non-authoritative behavior/migration |
| CSI-6 | scoped block/escalation/RST state and cleanup |
| CSI-7 | domain-authorized QUIC matrix |
| CSI-8 | scoped route/proxy side effects and leak tests |
| CSI-9 | API/UI/metrics/trace consistency |
| CSI-10 | Gmail/Google negative controls and rollout gate |

## 41.2. RST/GSO Hardening

| Stage | Required validation |
|---|---|
| H1 | reassembled-SNI runtime decision parity |
| H2 | NFQUEUE offload metadata/truncation/checksum envelope |
| H3 | GSO observe/classify parity and bounds |
| H4 | conditional normalizer and single-use token |
| H5 | transactional queue topology/rollback |
| H6 | Passive RST observe/baseline model |
| H7 | conservative enforcement, budgets and legitimate RST controls |
| H8 | Failure Inbox/Discovery/reconnect rollback |
| H9 | API/schema/UI/metrics/trace compatibility |
| H10 | target combined GSO/RST/control validation |

## 41.3. Keenetic PPE

| Stage | Required validation |
|---|---|
| PPE-1 | actual capability audit/model |
| PPE-2 | deterministic scoped rule compiler |
| PPE-3 | transactional apply/remove |
| PPE-4 | NDM regeneration/restart resilience |
| PPE-5 | static/passive visibility diagnostics |
| PPE-6 | controlled bidirectional A/B self-test |
| PPE-7 | runtime safety degradation gates |
| PPE-8 | API/UI/observability/productization |

## 41.4. Field Test Automation

| Stage | Required validation |
|---|---|
| FT-A | TestSession/trace schema and reader compatibility |
| FT-B | router test/discovery API/auth/idempotency |
| FT-C | local controller/ADB/clock/result storage |
| FT-D | official/ReVanced lifecycle automation |
| FT-E | companion markers/privacy/source accuracy |
| FT-F | adaptive optimizer/hard gates/statistics |
| FT-G | canary modes/rollback/permission boundaries |
| FT-H | Gmail/Google same-client automation |
| FT-I | authorization/scoped-state auditor |
| FT-J | GSO parity/normalizer lifecycle |
| FT-K | Passive RST safety/reconnect rollback |
| FT-L | unified production promotion gate |

## 41.5. Service Profiles

| Stage | Required validation |
|---|---|
| SP-1 | schema/limits/provenance/fuzz/migration |
| SP-2 | ownership/pinned/excluded/round-trip |
| SP-3 | deterministic compile/equivalence/conflicts |
| SP-4 | preview/transaction/crash rollback |
| SP-5 | catalog signature/trust/offline/cache |
| SP-6 | generic objectives/delivery modes/no global score |
| SP-7 | beginner UI/preview/actual-object visibility |
| SP-8 | YouTube pack target/control/CDN/rollback |
| SP-9 | additional pack isolation and maturity |
| SP-10 | generic transport framework/security/scope |
| SP-11 | Telegram transport-required correctness |
| SP-12 | import/export/authoring/redaction |
| SP-13 | cross-service capability projection |
| SP-14 | GSO/RST capability privilege boundaries |
| SP-15 | same-client control pack definitions |

---



## 41.6. Built-in WARP/MASQUE v1.2

| Stage | Mandatory coverage |
|---|---|
| WARP-1 | pinned references, license, threat model, forbidden dependencies |
| WARP-2 | reproducible bundled build, package, manifest, SBOM, architecture matrix |
| WARP-3 | secret store, enrollment, migration, redaction, bounded retry |
| WARP-4 | structured IPC, supervisor ownership, generation-aware trace envelope, event durability and crash cleanup |
| WARP-5 | TUN/NDM identity, assigned address, MTU, read-back, foreign-interface safety |
| WARP-6 | socket marks, direct control route, recursion/collision prevention |
| WARP-7 | scoped PBR, atomic sets, NAT/MSS/DNS and leak prevention |
| WARP-8 | W0–W4 liveness, idle/wake, self-heal, fail-open/fail-closed, rollback |
| WARP-9 | isolated inner backend, parent/child dependency graph, namespace/fallback capability, resource ownership and bounds |
| WARP-10 | provider-level geo evidence, quorum, route-counter proof, RU/unknown/stale/conflict/direct/DNS/IPv6 gates |
| WARP-11 | API/UI/Field Test/Service Profile integration, trace export and migration |
| WARP-12 | target router/Android/fault/performance, causal trace and release evidence |
| WARP-C1 | exact transport-control identity and authorization |
| WARP-C2 | enrollment camouflage and no credential/proxy leakage |
| WARP-C3 | cover-SNI provenance and endpoint trust/pinning |
| WARP-C4 | handshake-only strategy adapter and representation correctness |
| WARP-C5 | CONNECT-IP cutoff, budgets and established bypass |
| WARP-C6 | candidate scoring, least-aggressive promotion and invalidation |
| WARP-C7 | outer/inner authorization/mark/token/cutoff and generation isolation |
| WARP-C8 | Passive RST observe, exact enforcement, budget and rollback |
| WARP-C9 | API/UI/telemetry/causal trace diagnostics and secret-safe export |
| WARP-C10 | target validation, event-order/path-proof mutants, hard gates and production claim policy |

## 41.7. Field Test Automation v1.5 WARP additions

| Stage | Mandatory coverage |
|---|---|
| FT-M | base lifecycle, W0–W4 and forwarded path |
| FT-N | camouflage catalog/authorization/cutoff/stability |
| FT-O | nested non-RU safety and attestation |
| FT-P | WARP fault/leak/performance matrix |
| FT-Q | separate base/camouflage/non-RU promotion verdicts and causal-trace dependency |
| FT-AC | trace envelope, required-event completeness, event order and runtime consistency |
| FT-AD | route/path proof and forwarded Android binding correlation |
| FT-AE | nested dependency, geo quorum, DNS/IPv6 path and cleanup ownership |

## 41.8. Service Profiles additions (SP-16…SP-19; введены v1.5, действуют в v1.6)

> **FB-14 решение 8:** заголовок обновлён — SP-16…SP-19 остаются действующими в Service Profiles v1.6; версия «v1.5» в названии — исторический контекст введения (non-normative).

| Stage | Mandatory coverage |
|---|---|
| SP-16 | canonical built-in WARP capability projection |
| SP-17 | beginner/advanced UX and truthful status wording |
| SP-18 | camouflage/non-RU compiler and privilege boundaries |
| SP-19 | field-validation/promotion/rollback integration |


## 41.9. Silent Path Failure and Scoped Recovery v1.0

| Stage | Mandatory coverage |
|---|---|
| SPF-1 | taxonomy, threat model, z2k reference freeze, false-positive priority |
| SPF-2 | unique TCP progress, retransmission/overlap/wrap/GSO parity |
| SPF-3 | protocol milestones, incoming visibility and mode degradation |
| SPF-4 | suppression catalog, benign parallel patterns and recent-success bypass |
| SPF-5 | classifier, evidence independence, adaptive baselines and expiry |
| SPF-6 | bounded differential causal proof and control comparison |
| SPF-7 | exact scoped planner, leases, candidates, TTL/cooldown/max attempts |
| SPF-8 | rollback, user false-positive, budget and automatic demotion |
| SPF-9 | API/UI/profiles/events/metrics/privacy and truthful wording |
| SPF-10 | Keenetic/Android/fault/long-run/release validation |

### Field Test Automation v1.3 additions

| Stage | Mandatory coverage |
|---|---|
| FT-R | observe path, unique progress and representation parity |
| FT-S | mandatory false-positive suppressor fixtures |
| FT-T | bounded differential causal proof |
| FT-U | exact scoped recovery, WARP constraints and rollback |
| FT-V | long-run, false-positive budget and mode/cohort promotion |

### Service Profiles v1.4 additions

| Stage | Mandatory coverage |
|---|---|
| SP-20 | capability projection and manifest upper-bound semantics |
| SP-21 | truthful beginner/expert UX and false-positive rollback |
| SP-22 | allowed recovery binding compiler and lease integration |
| SP-23 | FT/IV promotion, invalidation and separate verdicts |

# 42. Release and production gates

## 42.1. Core release gate

Required:

- Stage 1–27 and 34–36 applicable blocking requirements pass;
- no unresolved mark/queue/routing collision;
- rollback verified;
- no cross-client or same-client cross-service leakage;
- resource budgets respected;
- trace/metric/runtime consistency;
- validator meta-suite pass.

## 42.2. Optional strategy gate

For Stage 28–32 technique:

- explicit technique capability tests pass;
- representation requirements enforced;
- endpoint logical stream preserved;
- bounded amplification/idempotency;
- target validation where production claim is made.

## 42.3. Transport gate

Stage 33 or transport profile cannot be production-ready until scoped route/leak/failover/cleanup tests pass for declared families and client scope.

## 42.4. GSO gate

No `GSO production-ready` claim until H1–H5, H9 and applicable H10 tests pass. Observe/classify and direct-action readiness are separate capability claims.

## 42.5. Passive RST gate

- observe may be production default after observation correctness;
- conservative requires complete visibility, target safety, budget and rollback proof;
- aggressive remains explicit experimental opt-in unless separately approved by all blocking gates.

## 42.6. Service-profile gate

Optimized YouTube profile requires:

```text
CSI pass
+ effective scoped-hints/strict policy proof
+ same-client Gmail/Google controls
+ GSO parity for enabled mode
+ Passive RST safety for enabled mode
+ rollback proof
+ field-test contract pass
```

## 42.7. Blocked target behavior

When target router/Android validation is unavailable:

```text
BLOCKED_TARGET_VALIDATION
```

not `PASS`, not `PASS_WITH_LIMITATIONS`. Code may be committed behind disabled/experimental capability only when no production-ready claim is made.

---



## 42.8. Built-in WARP base gate

`cloudflare-warp-masque/base` can be production-ready only when:

```text
WARP-1…WARP-8 PASS
+ WARP-11…WARP-12 applicable base scope PASS
+ W0–W4 PASS
+ scoped routing/NAT/MSS/DNS PASS
+ crash/reboot/firewall/WAN recovery PASS
+ secrets/supply-chain PASS
+ zero blocking WARP hard gates
```

A router-origin-only probe or external package installation cannot satisfy this gate.

For WARP v1.2 the base production claim additionally requires `WARP_CAUSAL_TRACE_READY`; connectivity without current path proof or binding correlation is `BLOCKED_TRACE_COMPLETENESS`.

## 42.9. WARP Transport Camouflage gate

Production-ready camouflage requires:

```text
base WARP gate PASS
+ WARP-C1…WARP-C10 PASS
+ exact transport-control authorization
+ endpoint trust/pin PASS
+ deterministic cutoff PASS
+ established payload mutation total == 0
+ least-aggressive stability promotion PASS
+ target-router validation
```

If unavailable, base WARP MAY remain production-ready with effective camouflage `off`, explicitly reported as a limitation. When camouflage is enabled, the release gate also requires authorization-to-cutoff causal trace and `warp_post_cutoff_mutation_total == 0`.

## 42.10. Experimental non-RU gate

The feature may be exposed as `experimental-available` only when nested safety, strict leak protection and truthful UI tests pass.

It MUST NOT receive a `production regional VPN`, `selectable country` or `guaranteed non-RU availability` claim.

Runtime route authorization still requires fresh per-session attestation. Target inability to obtain non-RU egress is an availability result, not permission to weaken safety gates. A non-RU claim additionally requires current parent/child dependency, per-provider geo events, route-counter proof, DNS/IPv6 observed path and gate/runtime consistency.


## 42.11. Silent observe and recommend gates

`SILENT_OBSERVE_READY` requires:

```text
SPF-1…SPF-5 applicable observation scope PASS
+ unique progress/GSO parity PASS
+ visibility and suppression correctness PASS
+ observe changes no verdict/routing/state
+ zero observation-integrity hard-gate violations
```

`SILENT_RECOMMEND_READY` additionally requires:

```text
SPF-6 differential proof PASS
+ bounded candidate comparison
+ target/control evidence
+ truthful recommendation UI/API
```

A recommendation is not a recovery authorization.

## 42.12. Silent auto-canary and cohort promotion gates

`SILENT_AUTO_CANARY_READY` requires:

```text
SPF-1…SPF-10 PASS
+ FT-R…FT-V PASS
+ applicable SP-20…SP-23 PASS
+ complete bidirectional/PPE/GSO visibility
+ two independent evidence families
+ mandatory suppressors PASS
+ causal differential proof
+ exact ActionAuthorization and ConfigGen
+ rollback target/lease/budget PASS
+ same-client controls PASS
+ zero blocking Silent Path hard gates
```

`SILENT_COHORT_PROMOTED` additionally requires target-specific long-run evidence, fresh safety hash and false-positive rate within the approved budget.

Promotion is revoked on:

- visibility/capability degradation;
- material WAN/profile/config/strategy/transport change;
- control regression;
- user false-positive report;
- budget breach;
- missing or stale validation evidence.

Silent active readiness is independent from base service/profile/WARP readiness. Failure of optional active recovery cannot be hidden inside an overall service PASS, and cannot incorrectly fail an otherwise healthy base path.

# 43. Stage completion artifacts редакции 1.3

For every original or companion stage:

```text
<STAGE>_IMPLEMENTATION_REPORT.md
<STAGE>_VALIDATION_REPORT.md
<STAGE>_TEST_RESULTS.json
<STAGE>_REQUIREMENT_COVERAGE.json
```

Validation report adds:

```markdown
## Source requirement IDs
## Build/commit/config/capability hashes
## Applicable L0–L8 levels
## Tests planned/executed/not applicable/blocked
## Positive scenarios
## Negative scenarios
## Fault injection
## Packet/runtime evidence
## Trace/metric/API consistency
## Resource bounds
## Migration/compatibility
## Target router/Android results
## Cleanup verification
## Known limitations
## Reproduction commands
## PASS / PASS_WITH_LIMITATIONS / FAIL / BLOCKED_*
```

A report without exact commands/results and linked machine-readable test output is incomplete.

---

# 44. Companion implementation stages этого addendum

These stages do not renumber Patch Plan Stage 1–36.

## IV-1 — Requirement and suite registry

- parse/maintain canonical requirement IDs;
- registry schema/version/hash;
- stage/addendum coverage mapping;
- orphan detection;
- deterministic export.

DoD: no blocking orphan requirement for declared complete scope.

## IV-2 — Verdict engine and false-pass guards

- terminal verdict model;
- aggregation rules;
- dependency blocking;
- limitation policy;
- synthetic and mutation tests.

DoD: every seeded false-pass mutation is detected.

## IV-3 — Validation API/CLI contract v1.3

- list/plan/run/status/events/cancel/report;
- requirement/test/coverage endpoints;
- schema/idempotency/auth;
- CLI/API parity;
- dry-run.

## IV-4 — Stage 1–36 suite completion

Implement missing deterministic suites and stage matrix; do not use Stage 36 E2E as substitute for earlier unit/component tests.

## IV-5 — DNS/UDP/QUIC/IP-family suites

Implement Sections 29–31 with fixtures, fuzz, namespace and target evidence.

## IV-6 — Transport, built-in WARP and transactional lifecycle suites

Implement Sections 33–34 and 38A base scope, including route leak, SOCKS/TUN, WARP-1…WARP-12, forwarded-path proof, crash/hot-apply/rollback.

## IV-7 — PPE target suite

Implement Section 35 and map PPE-1…PPE-8.

## IV-8 — CSI/GSO/RST/WARP-camouflage unified safety suites

Implement Sections 26–28 and 38A camouflage/non-RU scope with same-client controls, representation parity, topology, authorization, cutoff, geo/leak budgets and rollback. Map WARP-C1…WARP-C10.

## IV-9 — Service Profile conformance suite

Implement Section 36 plus WARP-aware profile requirements and map SP-1…SP-19.

## IV-10 — Field Test contract conformance suite

Implement Section 37 plus WARP Field Test additions and map FT-A…FT-AE.

## IV-11 — Validation infrastructure meta-suite

Implement Section 38: completeness, aggregation, evidence integrity, reproducibility, safety and known-broken fixtures.

## IV-12 — Full WARP-aware release orchestration

Implement Section 40 ordering, WARP base/camouflage/non-RU/causal-trace separate verdicts, final cleanup, release gate report and complete bundle. Full WARP claim requires `WARP_CAUSAL_TRACE_READY`. A missing WARP report blocks only claims whose declared release scope includes WARP, but cannot be silently omitted from a full-fork claim.

After every successful IV stage:

- implementation commit;
- validation report;
- exact commands/results;
- push to working branch;
- no next stage while a blocking gate is unresolved.

---


## IV-13 — Silent Path Failure false-positive and scoped-recovery suite

- register `SPF-1…SPF-10`, `FT-R…FT-V` and `SP-20…SP-23`;
- implement Section 38B L0–L8 suites;
- validate exact hard-gate names and mutant detection;
- produce separate observe/recommend/auto-canary/cohort verdicts;
- integrate same-client controls, WARP recursion guard and false-positive rollback;
- update full-run ordering, cleanup and release bundle.

DoD: no full-fork PASS while declared Silent Path scope has an orphan stage, missing suite, stale target evidence, skipped suppressor, absent rollback proof or collapsed optimistic verdict.

# 45. Расширенные acceptance criteria редакции 1.3

> **superseded (FB-14 решение 6):** ручные totals в заголовках и списках (включая «77», «86», «146») не являются нормативной истиной. Единственный источник — machine-readable **Exact Source-Stage Registry** (FB-33): `criteria_total = count(valid canonical registry entries)`. Total в заголовках, summary, reports и UI генерируется автоматически; CI падает при `declared_total != computed_total`. До исправления registry финальная validation считается `BLOCKED`. Исторические counts допустимы только в changelog с явной версией.

К исходным criteria 1–12 добавляются:

13. Every Stage 1–36 has explicit requirement-to-test coverage.
14. Every CSI/H/PPE/FT/SP companion stage has explicit coverage and verdict.
15. DomainOnly `strict` and `scoped-hints` semantics match Architecture v2.4.
16. Shared IP/CIDR/port alone never authorizes a DomainOnly service action.
17. Clear/reassembled non-target SNI revokes provisional target candidate.
18. `unrelated_control_action_total == 0` for required Gmail/Google controls.
19. Reassembled SNI is exercised through the real matcher/authorization path.
20. Destination-only persistent block/escalation/route state is detected as failure.
21. DNS/DoH A/AAAA/CNAME/negative/cache/failover paths are validated.
22. UDP forwarding and NAT flow table are stable, bounded and source-isolated.
23. QUIC allow/reject/fallback and evidence handoff are authorized and bounded.
24. IPv4/IPv6 parity is proven for every advertised dual-stack subsystem.
25. Every strategy catalog technique has planner/executor/endpoint/fault tests.
26. Controlled outbound RST and inbound Passive RST are distinguished and separately validated.
27. SOCKS/TUN/transport fallback has scope, leak, failover and cleanup proof.
28. Transactional hot apply never produces mixed runtime generations.
29. Last-good/canary/rollback survive crash/reboot and restore control baselines.
30. Keenetic PPE capability and per-flow exclusion are validated on actual target when claimed.
31. Incomplete offload visibility automatically disables unsafe dependent features.
32. GSO and MSS representations produce equivalent classification/authorization semantics.
33. Normalizer token/topology lifecycle is bounded, single-pass and transactional.
34. Passive RST observe changes no verdict; active modes require visibility/budget/rollback proof.
35. Service Profile compiler is deterministic and cannot elevate GSO/RST privileges.
36. Optimized YouTube profile passes official/ReVanced, multi-client, same-client control and CDN tests.
37. Field Test Automation API/controller/control/auditor reports satisfy its contract.
38. Validation Controller itself passes requirement completeness and false-pass meta-tests.
39. Missing required target validation yields `BLOCKED_TARGET_VALIDATION`, never `PASS`.
40. A cancelled, errored, artifact-incomplete or cleanup-incomplete run cannot emit `PASS`.
41. Full release bundle is reproducible and privacy-safe.
42. Production-ready claim is impossible while any blocking requirement is unresolved.

---



### Дополнительные acceptance criteria редакции 1.2

43. Every WARP-1…WARP-12 and WARP-C1…WARP-C10 stage has explicit requirement-to-test coverage and verdict.
44. Every FT-M…FT-Q and SP-16…SP-19 stage has explicit coverage and verdict.
45. Bundled WARP provenance, license, source/patch/binary hashes and SBOM are validated.
46. A full B4 install needs no external `usque` or `usque-keenetic` package.
47. Runtime download or floating latest engine cannot pass release validation.
48. WARP secrets never appear in logs, telemetry, profile export, issue bundle or test artifact.
49. WARP route activation requires current forwarded LAN W4 proof, not only process/TUN/router probe.
50. Outer control route cannot recurse through WARP; inner control route cannot silently go direct.
51. Service ActionAuthorization and TransportControlAuthorization are validated as separate privilege domains.
52. Destination IP alone never authorizes WARP camouflage.
53. Endpoint public-key pin failure and insecure TLS are blocking failures.
54. Camouflage modifies only authorized SYN/ClientHello window and always reaches cutoff or bounded fail-safe.
55. Established MASQUE payload mutation is a blocking zero-tolerance failure.
56. Candidate promotion requires forwarded proof, stability window and least-aggressive winner policy.
57. Outer/inner instance state, marks, tokens and cutoff events are isolated.
58. Strict non-RU route is impossible for RU, unknown, stale, conflicting or path-unproven attestation.
59. Strict non-RU selected scope cannot fall back directly.
60. DNS/direct-IP/unvalidated-IPv6 leak fixtures are blocking for strict non-RU.
61. Non-RU UI and reports use observed/time-bounded wording and make no country availability guarantee.
62. Restart/enrollment/endpoint/candidate recovery loops are bounded under fault and clock-skew fixtures.
63. Base and nested resource/performance results are separate and target-specific.
64. Missing WARP target evidence yields `BLOCKED_TARGET_VALIDATION` for the corresponding capability claim.
65. Base, camouflage and non-RU verdicts are independent; success of one cannot mask failure or non-execution of another.
66. Validator meta-suite detects removal/skip/forced-zero of every WARP hard gate.
67. Full release bundle contains WARP coverage, tests, traces, target evidence, cleanup and privacy proof when WARP is in declared scope.


### Дополнительные acceptance criteria редакции 1.3

68. Every SPF-1…SPF-10, FT-R…FT-V and SP-20…SP-23 stage has explicit requirement-to-test coverage and verdict.
69. Observe path is proven non-mutating for packet verdict, route, strategy, transport and persistent failure state.
70. TCP progress accounting is unique-range based and equivalent for GSO/MSS layouts.
71. Single-signal and duplicate evidence cannot authorize active fallback.
72. Every mandatory suppressor has positive, negative and mutation tests.
73. Fast parallel/HLS/prefetch/preconnect and recent-compatible-success fixtures produce zero active recovery.
74. Incomplete bidirectional/PPE/GSO visibility blocks active modes and yields an explicit degraded verdict.
75. Explicit server close/error conditions are not classified as silent DPI failure.
76. Differential proof is bounded, causal and includes same-client controls.
77. Recovery is exact client/service/component/config-generation scoped and destination-global state remains zero.
78. Every lease has a valid rollback target, TTL, cooldown, max-attempt budget and cleanup proof.
79. WARP fallback is profile-authorized, base-gate validated and non-recursive.
80. Strict non-RU policy cannot be weakened by silent recovery.
81. Control regression, user false-positive report or budget breach triggers deterministic rollback/demotion.
82. UI/API/report wording distinguishes suspicion, proof, recommendation, temporary recovery and promotion.
83. Observe, recommend, auto-canary and cohort claims are separate terminal verdicts.
84. Missing target/long-run evidence yields `BLOCKED_TARGET_VALIDATION`, never active PASS.
85. Validator meta-suite detects every seeded omission/forced-zero/bypass of Silent Path hard gates and suppressors.
86. Full release bundle includes assessment, suppressor, differential, lease, rollback, control and privacy evidence for declared Silent Path scope.

# 46. Итог редакции 1.1

Coding-agent доказывает не только наличие кода, но полную цепочку:

```text
normative requirement
→ registered test
→ real implementation path
→ positive/negative/fault execution
→ packet/runtime evidence
→ trace/metric/API consistency
→ resource and lifecycle bounds
→ target validation where required
→ deterministic verdict
→ reproducible artifact
```

Umbrella validation считается корректной только при одновременном выполнении:

```text
all implemented functions covered
+ all service/client scopes isolated
+ all packet representations validated
+ all active defenses safely gated
+ all transactions recoverable
+ all claims backed by target evidence
+ validator cannot issue a false PASS
```

Встроенная Discovery/Optimizer utility по-прежнему выбирает и применяет production strategies. Coding-agent и `b4-validate` проверяют, что utility, packet engine, control plane, profiles, target integration и сама validation infrastructure реализованы согласно нормативным контрактам.



---

# 47. Итог редакции 1.2

Implementation Validation v1.2 closes the umbrella coverage gap created by the built-in WARP/MASQUE subsystem.

A WARP-related claim now requires the complete chain:

```text
pinned source and bundled artifact
→ secret-safe enrollment
→ supervised instance and exact TUN ownership
→ non-recursive control socket path
→ scoped PBR/NAT/MSS/DNS
→ W0–W4 proof
→ optional exact camouflage authorization and cutoff
→ optional nested geo/leak gate
→ fault/rollback/cleanup
→ target evidence
→ deterministic separate verdict
```

Validation MUST preserve three independent claims:

```text
base WARP production-ready
WARP camouflage production-ready or disabled/blocked
observed non-RU experimental-available or unavailable/blocked
```

No aggregation rule may collapse them into one optimistic `WARP PASS`.


---

# 48. Итог редакции 1.3

Implementation Validation v1.3 prevents the new silent-path capability from turning a weak heuristic into an optimistic full-fork PASS.

Active recovery claim requires:

```text
correct unique observation
→ complete visibility
→ suppression of benign patterns
→ independent evidence correlation
→ bounded causal differential proof
→ exact reversible lease
→ target/control success
→ false-positive budget
→ target-specific promotion verdict
```

The validator preserves four independent claims:

```text
silent observe ready
silent recommend ready
silent auto-canary ready
silent cohort promoted
```

No aggregation rule may infer a later claim from an earlier one or from a single successful fallback.

---

# 49. Umbrella coverage Detector v2 / DDI / TGB — редакция 1.4

Implementation Validation v1.4 регистрирует как first-class normative requirements:

```text
ABD-1…ABD-12
DDI-1…DDI-10
TGB-1…TGB-10
FT-W…FT-AB
SP-24…SP-29
```

Registry MUST хранить для каждого requirement:

- source document/version/hash;
- implementation owner;
- dependencies and capability gates;
- applicable L0–L8 suites;
- target/control requirements;
- hard-gate metrics;
- release verdicts;
- cleanup and rollback evidence;
- blocked reasons;
- provenance/license obligations.

`ABD`, `DDI` и `TGB` не сворачиваются в один общий «detector PASS».

## 49.1. Ownership boundaries

Validator доказывает:

```text
ABD owns:
  TargetPlan + probe evidence + EvidenceGraph + BlockingProfile

DDI owns:
  network envelope + freshness + revalidation + search priors

Discovery owns:
  candidate generation + baselines + execution + scoring + full fallback

TGB owns:
  pending first-data lifecycle + bridge outcome + prefix handoff + route ladder

Service Profiles own:
  declarative intent and capability upper bounds only
```

Наличие второго competing optimizer/profile compiler, прямой strategy write из Detector или profile-owned bridge socket state является архитектурным FAIL.

# 50. L0–L8 validation model редакции 1.5

## 50.1. L0 — Static/provenance audit

Проверяется:

- pinned reference commits and license registry;
- clean-room/adaptation notes;
- no hidden runtime download/dependency;
- bounded target/dynamic-control configuration;
- immutable profile structures;
- no ActionAuthorization in Detector output;
- no fixed destructive five-second zero-byte branch;
- no ambiguous bridge bool contract;
- no unbounded pending map/goroutine lifecycle.

## 50.2. L1 — Unit tests

Минимум:

- TargetPlan validation/normalization/ownership;
- network fingerprint and expiry;
- DNS differential rules;
- TLS/HTTP staged/integrity/fingerprint rules;
- QUIC milestone classifier;
- wire-packet/unique-byte accounting;
- EvidenceGraph independence/contradictions/confidence;
- BlockingProfile immutability;
- DDI adapter and deterministic merge;
- bridge state transitions, deadlines, outcomes and route policy.

## 50.3. L2 — Property/fuzz tests

Минимум:

- arbitrary duplicate/contradictory evidence never raises invalid confidence;
- packet segmentation/GSO representation preserves logical packet/byte result;
- random malformed DNS/TLS/QUIC evidence cannot panic or authorize action;
- target-plan bounds hold under wildcard/Unicode/duplicate input;
- prefix handoff preserves arbitrary byte sequence exactly once;
- reload/cancel races leave no pending state;
- deterministic seed yields deterministic guided plan.

## 50.4. L3 — Component integration

- Detector API v2 → suite → persistence;
- native-direct mark/rule isolation;
- dynamic controls cache/provider;
- BlockingProfile → NetworkDiagnosticProfile envelope;
- DDI revalidation → Discovery request;
- guided plan → ordinary sandbox executor;
- TPROXY listener → TGB state manager → fallback worker/direct.

## 50.5. L4 — Network laboratory

Fault injection covers:

```text
DNS spoof/NXDOMAIN/empty/DoH block
SYN drop/RST/FIN/timeout
TLS alert/spoof/MITM/origin error
HTTP block page/legitimate redirect/server limit
QUIC UDP drop/VN/Retry/handshake stall
packet-count trigger
byte-count trigger
GSO representation
unhealthy controls
stale/cross-WAN profile
Telegram 0/partial/full delayed prefix
primary/fallback failure and recursion attempt
```

## 50.6. L5 — Keenetic target

- NFQUEUE/PPE/GSO visibility proof;
- clean native path without production self-interference;
- bounded CPU/RAM/socket impact;
- real WAN context switching;
- exact TPROXY original destination;
- bridge pending stress and cleanup;
- router restart/hot apply/rollback.

## 50.7. L6 — Android and application controls

- user-selected YouTube/Telegram/other service targets;
- same-client service controls;
- guided/full A/B;
- Telegram preconnect/delayed first data;
- explicit MTProto proxy control;
- background/foreground/network switch;
- no collateral strategy/route mutation.

## 50.8. L7 — Fault and rollback

- corrupted/stale profile;
- failed fast revalidation;
- guided winner regression;
- target/control regression;
- TGB pending overflow;
- upstream WS/DC failure;
- config reload and shutdown;
- last-good restoration and zero leaked state.

## 50.9. L8 — Validation-of-validation

Meta-suite MUST seed at least:

- removed clean-baseline check;
- single-probe high-confidence bug;
- disabled control precedence;
- packet/byte conflation;
- skipped baseline/full fallback;
- forced optimistic savings;
- zero-byte destructive handled result;
- prefix byte loss/duplication;
- unbounded pending limit;
- suppressed issue verdict blocker.

Каждая mutation обязана изменить итоговый verdict на `FAIL`/`BLOCKED`, а не остаться незамеченной.

## 50.10. WARP v1.2 causal-trace application

Across L0–L8 the umbrella model additionally requires:

```text
L0 — trace schema/source/hash and privacy contract
L1 — envelope/order/generation/path/dependency reducers
L2 — sequence, generation, ownership and cardinality properties/fuzz
L3 — b4-warpd IPC → RouteManager → trace store → status reducer
L4 — old/reordered/missing events, counter/path and nested leak fixtures
L5 — real Keenetic route counters, namespace and cleanup ownership
L6 — real Android binding-to-milestone causal chain
L7 — reconnect/revocation/rollback/storage-pressure behavior
L8 — validation-of-observability mutants and forced-zero detection
```

No lower layer can substitute for a missing higher-layer proof. In particular, valid IPC framing does not prove route use, and route use does not prove the Android application milestone.

# 51. Mandatory hard gates редакции 1.5

Umbrella validator регистрирует и проверяет полный набор hard gates из всех применимых source addenda:

```text
detector_single_probe_confirmed_total == 0
detector_exception_string_only_confirmed_total == 0
detector_static_target_only_high_confidence_total == 0
detector_self_interference_total == 0
detector_native_path_unproven_total == 0
detector_capture_invalid_packet_verdict_total == 0
detector_control_failure_ignored_total == 0
detector_duplicate_evidence_confidence_increase_total == 0
detector_cross_component_evidence_merge_total == 0
detector_cross_generation_evidence_merge_total == 0
detector_unbounded_dynamic_scan_total == 0
detector_resource_budget_bypass_total == 0
detector_sensitive_export_total == 0
detector_dns_single_resolver_spoof_confirmed_total == 0
detector_dns_cdn_variance_misclassified_total == 0
detector_unverified_mitm_verdict_total == 0
detector_tls_availability_integrity_conflation_total == 0
detector_tls_fingerprint_unlabeled_total == 0
detector_quic_single_target_global_udp_verdict_total == 0
detector_quic_tcp_evidence_conflation_total == 0
detector_valid_application_error_dpi_total == 0
detector_packet_threshold_reported_as_byte_threshold_total == 0
detector_byte_threshold_reported_as_packet_threshold_total == 0
detector_gso_skb_count_as_wire_packet_total == 0
detector_single_origin_l4_budget_confirmed_total == 0
detector_server_header_limit_dpi_total == 0
detector_retransmission_counted_as_progress_total == 0
detector_l4_threshold_without_controls_total == 0
blocking_profile_without_target_plan_total == 0
blocking_profile_without_network_context_total == 0
blocking_profile_without_provenance_total == 0
blocking_profile_mutated_after_compile_total == 0
blocking_profile_high_confidence_with_contradiction_total == 0
blocking_profile_direct_action_authorization_total == 0
blocking_profile_direct_production_write_total == 0
guided_search_skipped_baseline_total == 0
guided_search_disabled_full_fallback_total == 0
guided_search_profile_overrode_current_baseline_total == 0
guided_search_target_unvalidated_promotion_total == 0
guided_search_cross_service_action_total == 0
guided_search_white_sni_direct_promotion_total == 0
guided_search_false_savings_report_total == 0
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
warp_secret_leak_total == 0
warp_foreign_interface_modified_total == 0
warp_recursive_control_route_total == 0
warp_mark_collision_total == 0
warp_route_without_liveness_total == 0
warp_destination_set_partial_apply_total == 0
warp_unbounded_restart_total == 0
warp_unbounded_registration_total == 0
warp_unrelated_control_action_total == 0
warp_rollback_failure_total == 0
nonru_route_active_without_fresh_attestation == 0
nonru_route_active_while_any_provider_ru == 0
nonru_route_active_with_provider_disagreement == 0
nonru_route_active_with_direct_dns == 0
nonru_route_active_with_unvalidated_ipv6 == 0
nonru_route_active_after_attestation_expiry == 0
nonru_strict_direct_fallback_total == 0
nonru_identity_creation_budget_exceeded == 0
masque_camouflage_without_control_authorization_total == 0
masque_camouflage_destination_only_authorization_total == 0
masque_established_payload_mutation_total == 0
masque_camouflage_cutoff_failure_total == 0
masque_control_route_recursion_total == 0
masque_camouflage_cross_instance_total == 0
masque_strategy_promoted_without_forwarded_probe_total == 0
masque_strategy_promoted_without_stability_window_total == 0
masque_insecure_tls_total == 0
masque_endpoint_pin_failure_accepted_total == 0
masque_unbounded_candidate_retry_total == 0
masque_rst_suppression_without_exact_authorization_total == 0
warp_route_promoted_without_path_proof_event_total == 0
warp_forwarded_success_without_binding_trace_total == 0
warp_direct_fallback_without_trace_total == 0
warp_nested_missing_parent_link_total == 0
warp_nested_parent_generation_mismatch_total == 0
warp_nested_control_direct_leak_total == 0
warp_nested_route_active_without_parent_health_total == 0
warp_nested_stale_parent_token_total == 0
warp_geo_attestation_without_route_counter_delta_total == 0
warp_geo_quorum_without_provider_events_total == 0
warp_geo_route_gate_state_mismatch_total == 0
warp_nonru_revocation_exceeded_deadline_total == 0
warp_nonru_public_ip_change_without_refresh_total == 0
warp_dns_path_unproven_total == 0
warp_ipv6_path_unproven_total == 0
warp_connect_ip_event_wrong_generation_total == 0
warp_post_cutoff_mutation_total == 0
warp_cleanup_incomplete_total == 0
warp_owned_resource_leak_total == 0
warp_foreign_resource_removed_total == 0
warp_trace_secret_leak_total == 0
warp_trace_required_event_missing_total == 0
warp_trace_dropped_required_event_total == 0
warp_trace_event_order_violation_total == 0
warp_trace_generation_mismatch_total == 0
warp_trace_state_mismatch_total == 0
```

Требования к registry:

1. gate имеет owner stage и test producer;
2. отсутствующий metric не трактуется как zero;
3. unsupported gate получает `NOT_APPLICABLE` только с machine-checkable capability reason;
4. target-required gate без target evidence даёт `BLOCKED_TARGET_VALIDATION`;
5. seeded forced-zero mutation обнаруживается validation-of-validation;
6. aggregate full-fork PASS запрещён при FAIL/BLOCKED required gate.

# 52. Release verdict registry редакции 1.5

Validator сохраняет отдельные terminal/intermediate verdicts:

```text
ABD_TARGET_PLAN_READY
ABD_CLEAN_BASELINE_READY
ABD_DNS_EVIDENCE_READY
ABD_TLS_HTTP_EVIDENCE_READY
ABD_QUIC_EVIDENCE_READY
ABD_L4_PROFILER_READY
ABD_DYNAMIC_CONTROLS_READY
ABD_EVIDENCE_GRAPH_READY
ABD_BLOCKING_PROFILE_READY
ABD_DDI_ADAPTER_READY
ABD_ROUTER_VALIDATED
ABD_ANDROID_VALIDATED
ABD_PRODUCTION_READY
DETECTOR_GUIDED_STRATEGY_SEARCH_READY
DDI_SCHEMA_READY
DDI_REVALIDATION_READY
DDI_HINT_PLANNER_READY
DDI_TARGET_VALIDATED
DDI_PRODUCTION_READY
TGB_STATE_MACHINE_READY
TGB_PENDING_BUDGET_READY
TGB_PREFIX_HANDOFF_READY
TGB_ANDROID_VALIDATED
TGB_PRODUCTION_READY
ISSUE_278_RESOLVED
ISSUE_277_RESOLVED
WARP_BASE_READY
WARP_CAMOUFLAGE_READY
WARP_NON_RU_SAFETY_READY
WARP_CAUSAL_TRACE_READY
```

Дополнительные правила:

- `ABD_PRODUCTION_READY` требует все ABD evidence/profile stages и companion coverage;
- `DDI_PRODUCTION_READY` требует freshness/revalidation, baselines, full fallback и target A/B;
- `DETECTOR_GUIDED_STRATEGY_SEARCH_READY` требует одновременно ABD и DDI production readiness;
- `ISSUE_278_RESOLVED` требует измеренного real integration/search impact, не только API field;
- `TGB_PRODUCTION_READY` требует state/resource/prefix/route/target proof;
- `ISSUE_277_RESOLVED` требует delayed-first-byte Android/controlled reproduction и нулевой destructive drop;
- ни один issue verdict не выводится из compilation/unit tests alone;
- `WARP_CAUSAL_TRACE_READY` — узкий causal-trace verdict по FB-14 решение 9 (полный перечень условий см. §38A): required-event set, ordering, ID/generation consistency, trace/runtime parity, target/controls distinction, route/path counters, cleanup closure; missing/skipped/unknown/stale evidence не считается PASS. Nested/non-RU/camouflage/Android имеют отдельные verdicts;
- WARP base, camouflage, non-RU и causal-trace verdicts не выводятся транзитивно друг из друга.

## 52.1. Blocked verdicts

Используются как минимум:

```text
BLOCKED_CLEAN_BASELINE
BLOCKED_CAPTURE_VISIBILITY
BLOCKED_DYNAMIC_CONTROLS
BLOCKED_NETWORK_CONTEXT
BLOCKED_PROFILE_REVALIDATION
BLOCKED_TARGET_VALIDATION
BLOCKED_ANDROID_VALIDATION
BLOCKED_TPROXY_CAPABILITY
BLOCKED_RESOURCE_BUDGET
BLOCKED_LONG_RUN
BLOCKED_TRACE_SCHEMA
BLOCKED_TRACE_COMPLETENESS
BLOCKED_TRACE_TARGET_VALIDATION
BLOCKED_TRACE_RUNTIME_MISMATCH
```

Blocked verdict не является PASS_WITH_LIMITATIONS для production claim.

# 53. Validation API/CLI delta v1.5

## 53.1. CLI

```text
b4-validate list --capability detector-v2
b4-validate list --capability detector-guided-discovery
b4-validate list --capability telegram-transparent-bridge
b4-validate run --profile detector-quick
b4-validate run --profile detector-deep
b4-validate run --profile guided-search-ab
b4-validate run --profile telegram-bridge-android
b4-validate run --profile warp-causal-trace
b4-validate run --profile warp-nested-nonru-trace
b4-validate run --profile full-b4x
b4-validate explain --verdict ISSUE_278_RESOLVED
b4-validate explain --verdict ISSUE_277_RESOLVED
```

## 53.2. Capabilities response

Capabilities MUST expose separately:

```yaml
detector_v2:
  target_plan: true
  clean_native_path: true
  dns: true
  tls_http_fingerprints: true
  quic: true
  l4_packet_profiler: true
  l4_byte_profiler: true
  dynamic_controls: true
  blocking_profile: true

ddi:
  schema: true
  network_context: true
  fast_revalidation: true
  deterministic_priors: true
  full_fallback: true
  guided_ab: true
warp_causal_trace:
  schema_version: 1
  required_event_set: true
  event_order_validation: true
  path_counter_proof: true
  forwarded_binding_correlation: true
  nested_dependency_graph: true
  geo_quorum_trace: true
  dns_ipv6_path_trace: true
  cleanup_ownership: true
  target_validated: false

tgb:
  structured_outcome: true
  delayed_first_data: true
  bounded_pending: true
  prefix_handoff: true
  non_recursive_fallback: true
  android_validated: false
```

`android_validated`, target evidence age and network-context hash are runtime evidence, not compile-time constants.

## 53.3. Full run ordering

```text
static/provenance
→ unit/property/fuzz
→ synthetic network lab
→ clean router baseline
→ WARP trace schema/event-order synthetic suite
→ WARP route/path and forwarded-client proof
→ WARP nested/geo/DNS/IPv6/cleanup proof
→ ABD target/evidence/profile
→ DDI envelope/revalidation
→ guided/full A/B
→ service/control Android validation
→ TGB synthetic/stress
→ TGB Keenetic/Android
→ rollback/cleanup
→ validation-of-validation
→ independent release verdict aggregation
```

# 54. Companion coverage matrix редакции 1.5

| Source stages | Field coverage | Service Profile coverage | Umbrella suite |
|---|---|---|---|
| `ABD-1…ABD-3` | `FT-W` | `SP-24…SP-25` | `IV-14` |
| `ABD-4…ABD-8` | `FT-X…FT-Y` | `SP-25…SP-26` | `IV-14` |
| `ABD-9…ABD-10` | `FT-Y` | `SP-26` | `IV-14` |
| `ABD-11…ABD-12` | `FT-Z…FT-AB` | `SP-27…SP-29` | `IV-15` |
| `DDI-1…DDI-5` | `FT-Z` | `SP-27` | `IV-15` |
| `DDI-6…DDI-10` | `FT-Z…FT-AB` | `SP-27…SP-29` | `IV-15` |
| `TGB-1…TGB-6` | `FT-AA` | `SP-28` | `IV-16` |
| `TGB-7…TGB-10` | `FT-AA…FT-AB` | `SP-28…SP-29` | `IV-16` |
| `WARP-1…WARP-8` | `FT-M`, `FT-AC…FT-AD` | `SP-16…SP-19` | `IV-6`, `IV-17` |
| `WARP-9…WARP-10` | `FT-O`, `FT-AE` | `SP-18…SP-19` | `IV-8`, `IV-17` |
| `WARP-C1…WARP-C10` | `FT-N…FT-Q`, `FT-AC…FT-AE` | `SP-18…SP-19` | `IV-8`, `IV-12`, `IV-17` |
| `WARP_CAUSAL_TRACE_READY` | `FT-AC…FT-AE` | diagnostics projection only | `IV-17` |

No source stage may reach PASS with an empty Field/Profile/Umbrella coverage cell unless explicitly `NOT_APPLICABLE` with normative justification.

# 55. Additional implementation stages этого addendum

## IV-14 — Adaptive Blocking Detector conformance suite

- registers `ABD-1…ABD-12`;
- implements L0–L8 detector tests;
- verifies reference/provenance registry;
- validates target plan, clean path, multi-protocol evidence, dynamic controls, EvidenceGraph and BlockingProfile;
- issues ABD intermediate/production verdicts.

## IV-15 — DDI and guided-search causal suite

- registers `DDI-1…DDI-10`;
- validates envelope/freshness/revalidation;
- proves deterministic priors, mandatory baselines and full fallback;
- executes target guided/full A/B;
- verifies truthful savings and target/control quality;
- issues DDI, detector-guided and issue #278 verdicts.

## IV-16 — Transparent Telegram bridge lifecycle suite

- registers `TGB-1…TGB-10`;
- validates structured outcomes and delayed-first-data FSM;
- verifies pending budgets and prefix exactness;
- executes TPROXY/fallback/stress/reload/shutdown suites;
- runs Keenetic/Android issue reproduction and explicit proxy control;
- issues TGB and issue #277 verdicts.



## IV-17 — WARP causal tracing and validation-of-observability suite

- registers WARP v1.2 trace requirements, `FT-AC…FT-AE` and all causal trace hard gates;
- validates `TransportTraceEnvelope` schema, boot/process/session generation and monotonic event ordering;
- independently derives WARP state from events and compares it with runtime/API state;
- proves route/path ownership with packet/byte counter deltas;
- proves forwarded Android `TestSessionID → BindingID → RouteTokenID → SessionGen → milestone` chain;
- validates nested parent/child generation, current parent health and route-token invalidation;
- recomputes geo quorum from provider events and compares it with the kernel non-RU gate;
- validates observed DNS/IPv6 paths and strict-scope revocation timing;
- validates camouflage authorization-to-cutoff chain and zero post-cutoff mutation;
- validates cleanup ownership closure and foreign-resource preservation;
- injects missing/reordered/duplicate/old-generation events, storage pressure, trace/runtime mismatch, stale tokens and orphan resources;
- issues `WARP_CAUSAL_TRACE_READY` only after synthetic, Keenetic and Android evidence pass.

Required artifacts:

```text
IV-17_WARP_TRACE_SCHEMA_REPORT.md
IV-17_WARP_EVENT_ORDER_RESULTS.json
IV-17_WARP_PATH_PROOF_RESULTS.json
IV-17_WARP_ANDROID_CAUSAL_CHAIN.json
IV-17_WARP_NESTED_GEO_DNS_IPV6_RESULTS.json
IV-17_WARP_CLEANUP_LEDGER.json
IV-17_VALIDATION_OF_OBSERVABILITY_MUTANTS.json
```

DoD: full WARP/fork PASS is impossible while a required event, current-generation path proof, Android correlation, nested dependency, geo/DNS/IPv6 proof or cleanup terminal record is missing, stale, contradictory or accepted only through forced-zero metrics.

# 56. Expanded acceptance criteria редакции 1.5

87. Every `ABD`, `DDI`, `TGB`, `FT-W…FT-AB` and `SP-24…SP-29` requirement has explicit registry coverage and verdict.
88. Source addendum version/hash is present in every corresponding stage report.
89. Current B4 detector regression fixtures remain green before Detector v2 claims.
90. Target plan roles and bounds are machine-validated.
91. Native direct baseline is proven uncontaminated by B4X production actions.
92. Single probe, exception string or static endpoint cannot produce confirmed/high confidence alone.
93. Availability and certificate integrity are validated separately.
94. TLS/QUIC fingerprint identity is present in evidence and reports.
95. Packet and byte thresholds remain separate through API, profile, priors and UI.
96. GSO/wire packet accounting parity is demonstrated.
97. Controls and contradictions dominate optimistic evidence.
98. BlockingProfile is immutable, provenance-bearing and non-authoritative for actions.
99. Cross-WAN/stale/conflicting profiles cannot guide without revalidation.
100. Guided search preserves mandatory baselines and full fallback.
101. A/B report includes probes, time, winner rank, score/quality and controls.
102. Target-unvalidated guided candidate cannot be promoted.
103. DDI/ABD cannot bypass CSI, SPF, WARP or ActionAuthorization gates.
104. Zero-byte Telegram soft timeout never becomes destructive handled success.
105. Every prefix byte is handed off exactly once.
106. Pending global/per-client limits and overflow behavior are stress-proven.
107. TPROXY route recursion and wrong original destination remain zero.
108. Reload/shutdown leave zero pending socket/goroutine state.
109. Android delayed-first-byte and explicit proxy control evidence are included.
110. `ISSUE_278_RESOLVED` and `ISSUE_277_RESOLVED` are separately justified.
111. Missing real router/Android/A-B evidence yields explicit BLOCKED verdict.
112. Meta-validation detects seeded bypass of each new gate family.
113. Full-fork release aggregation cannot hide blocked optional claims as production-ready.
114. Release bundle contains privacy-safe target plan, evidence, profile, priors, A/B, bridge lifecycle, cleanup and verdict artifacts.


115. WARP v1.2 source version/hash is registered in every WARP/FT/IV stage report.
116. `FT-AC…FT-AE` and `IV-17` have non-empty requirement, test-producer, artifact and verdict mappings.
117. Required WARP event schema includes boot/process/config/route/session generation and monotonic sequence.
118. Old-generation, duplicate and reordered events cannot advance current runtime state.
119. Trace-derived and runtime/API WARP state must match or release is blocked.
120. Required-event loss or storage-pressure drop is blocking and externally visible.
121. Route/rule/table existence cannot replace packet/byte counter-delta proof.
122. W4 requires exact forwarded Android/LAN binding correlation.
123. Router-origin health probe cannot satisfy forwarded-client causal proof.
124. Direct fallback and route revocation have explicit causal events and bounded timing.
125. Inner WARP depends on current healthy base generation and current parent route token.
126. Parent reconnect invalidates child dependency and strict nested route until revalidated.
127. Inner control direct leak, recursion or stale parent token is a blocking failure.
128. Geo quorum is independently recomputed from per-provider results.
129. Geo route gate state matches provider/quorum evidence and current kernel routing.
130. Public-IP, session, DNS path or IPv6 policy changes invalidate stale attestation.
131. DNS path is observed, not inferred solely from configured resolver.
132. IPv6 strict-scope state is observed disabled or separately validated.
133. Camouflage trace proves exact authorization, candidate actions, CONNECT-IP and cutoff.
134. Established MASQUE payload has zero post-cutoff mutation.
135. Cleanup ledger covers all generation-owned processes, interfaces, namespaces, routes, NAT/MSS, marks, listeners and tokens.
136. Foreign resource removal is detected as failure.
137. Crash/restart/rollback/uninstall leave no owned-resource leaks.
138. Trace exports are secret-safe and metrics labels remain bounded-cardinality.
139. Base, camouflage, non-RU and causal trace verdicts are separately aggregated.
140. `WARP_CAUSAL_TRACE_READY` cannot be inferred from connectivity or zero legacy counters.
141. Missing real Keenetic path-counter proof yields `BLOCKED_TRACE_TARGET_VALIDATION`.
142. Missing real Android causal chain yields `BLOCKED_TRACE_TARGET_VALIDATION`.
143. Trace schema incompatibility yields `BLOCKED_TRACE_SCHEMA`.
144. Trace/runtime disagreement yields `BLOCKED_TRACE_RUNTIME_MISMATCH`.
145. Validation-of-validation catches forced-zero, skipped producer and omitted artifact for every causal gate family.
146. Full-fork production PASS requires `WARP_CAUSAL_TRACE_READY` whenever WARP is included in declared scope.

# 57. Итог редакции 1.5

Implementation Validation v1.5 preserves Detector v2, Detector-Guided Discovery and Telegram Bridge Hardening coverage and closes the observability gap introduced by WARP/MASQUE v1.2.

A detector-guided production claim now requires:

```text
clean direct baseline
→ bounded target plan
→ independent multi-protocol evidence
→ healthy controls and suppressors
→ immutable BlockingProfile
→ DDI context/freshness/revalidation
→ deterministic guided priors
→ unchanged baselines and full fallback
→ target/control A/B validation
→ canary/promote/rollback
```

A transparent Telegram bridge claim requires:

```text
structured outcome
→ bounded delayed-first-data state
→ exact prefix preservation
→ non-recursive route ladder
→ resource/cleanup proof
→ Keenetic and Android validation
```

No validator may infer `ISSUE_278_RESOLVED` from a new API field or `ISSUE_277_RESOLVED` from a larger timeout.


# 58. Exact source-stage registry редакции 1.5

```text
ABD-1
ABD-2
ABD-3
ABD-4
ABD-5
ABD-6
ABD-7
ABD-8
ABD-9
ABD-10
ABD-11
ABD-12
DDI-1
DDI-2
DDI-3
DDI-4
DDI-5
DDI-6
DDI-7
DDI-8
DDI-9
DDI-10
TGB-1
TGB-2
TGB-3
TGB-4
TGB-5
TGB-6
TGB-7
TGB-8
TGB-9
TGB-10
WARP-1
WARP-2
WARP-3
WARP-4
WARP-5
WARP-6
WARP-7
WARP-8
WARP-9
WARP-10
WARP-11
WARP-12
WARP-C1
WARP-C2
WARP-C3
WARP-C4
WARP-C5
WARP-C6
WARP-C7
WARP-C8
WARP-C9
WARP-C10
FT-AC
FT-AD
FT-AE
IV-17
```



# 59. WARP v1.2 causal trace source binding

```text
file: B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md
sha256: 87c909d59e9cad9ad70c224f81a4af08e3fb578288ae451f49f8a10451f8ed3d
field contract: B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md
umbrella stage: IV-17
release verdict: WARP_CAUSAL_TRACE_READY
```

Final invariant:

```text
WARP production claim
= base/camouflage/non-RU applicable gates
+ complete generation-aware event chain
+ current route/path counter proof
+ forwarded Android binding correlation
+ nested parent/child and geo/DNS/IPv6 consistency
+ cleanup ownership closure
+ validation-of-observability mutants
```
