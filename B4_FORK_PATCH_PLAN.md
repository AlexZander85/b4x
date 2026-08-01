# Патч-план B4 Flow Classifier v2.3

**База:** B4 `1.73.0`, commit `7160ee8f066bbbed1c713b4d0114db4e8acbc882`  
**Архитектурный источник истины:** `B4_FORK_ARCHITECTURE.md` редакции 2.3  
**Статус:** последовательный implementation plan для coding-агента  

Этот план заменяет редакции 2.0–2.2 и отдельный файл предлагаемых дополнений 2.3.

---

## 0. Область работ

### Уровень A — Core Fix, обязательно

- capture envelope и processed mark;
- clean SYN invariant;
- TCP FSM;
- classification phase/evidence/confidence;
- source-scoped HostHintStore;
- DNS→first-flow;
- QUIC→TCP handoff;
- DomainOnly v2;
- TLS metadata;
- bounded TCP ClientHello reassembly;
- ECH-aware evidence policy;
- sequence-aware action planner;
- first-flight/retransmission idempotency;
- metrics/trace/fail-open.

### Уровень B — Productization, обязательно до production rollout

- isolated Discovery sandbox;
- baseline-none/production/candidate;
- structured ProbeOutcome/verdicts;
- adaptive matrix and shadow probes;
- Passive Failure Candidate Inbox;
- Real ClientHello Laboratory;
- fake-profile compiler;
- transactional apply;
- last-good/canary/cooldown/rollback;
- config/UI/privacy.

### Уровень C — Strategy Catalog, после A и B

- marker-based multisplit/multidisorder;
- hostfakesplit;
- fake payload catalogs;
- fakedsplit/fakeddisorder;
- TLS record split;
- controlled RST injection;
- confidence-based TUN/SOCKS fallback.

Запрещено реализовывать Level C как способ обойти незавершённый classifier/reassembly.

---

# Часть I. Инженерные правила

## 1. Общие правила

1. Один этап — один логически изолированный commit или малый commit series.
2. Перед изменением integration path сделать audit фактической кодовой базы.
3. Новые режимы вводить через feature flags и observe-only.
4. Ошибки parser/reassembly/action должны быть fail-open.
5. Не хранить mutable config pointers в flow/hint state.
6. Не расширять scope сетов/Google CIDR ради прохождения теста.
7. Не смешивать production traffic и Discovery traffic.
8. Не считать один успешный HTTP status достаточным доказательством.
9. Не копировать reference code без license review.
10. Любая destructive technique требует confidence threshold, preconditions и budget.
11. Любой hold path имеет release/timeout/shutdown cleanup.
12. Любой generated packet получает processed provenance mark.

## 2. Обязательные deliverables каждого этапа

- код;
- unit/integration tests;
- trace/metrics, если этап меняет runtime behavior;
- config migration/defaults;
- краткое design note в commit/PR;
- benchmark или memory bound для hot path;
- rollback/disable path.

---

# Часть II. Audit и fixtures

## Этап 1. Baseline implementation audit

### Сделать

Зафиксировать фактический путь:

```text
iptables/nftables/NFQUEUE
→ nfq handler
→ packet parsing
→ set matching
→ learned IP
→ strategy selection
→ drop/inject/raw send
→ response handling
```

### Проверить

- где чистый SYN попадает в generic injection;
- где назначается/теряется mark;
- какие первые incoming/outgoing packets попадают в queue;
- как работают IPv4/IPv6;
- где hardware offload влияет на visibility;
- как DoH/system DNS вызывают matcher;
- какой lifetime learned cache;
- где config pointers сохраняются;
- как shutdown/restart очищает state;
- какие UI/API config schemas существуют.

### Выход

`docs/audit/b4-1.73-flow-path.md` с call graph, рисками и точками патча.

### Коммит

```text
docs(audit): map B4 packet classification and injection paths
```

---

## Этап 2. Regression fixtures

### TLS fixtures

- complete clear-SNI ClientHello;
- split `1396 + remainder`;
- 2/3/5 segment split;
- out-of-order;
- exact retransmission;
- identical overlap;
- conflicting overlap;
- ECH/no clear SNI;
- multiple TLS records;
- trailing/coalesced data;
- malformed nested lengths;
- large `1.7–2.0 KiB` ClientHello;
- TLS 1.2 compact;
- TLS 1.3 standard/large.

### DNS fixtures

- A/AAAA;
- multiple answers;
- CNAME chain;
- TTL zero/large;
- HTTPS/SVCB with/without ECHConfig;
- NXDOMAIN/SERVFAIL;
- DoH redirect response;
- two clients querying same shared IP for different domains.

### TCP fixtures

- clean SYN;
- SYN with explicit SynFake;
- SYN-ACK;
- FIN/RST;
- TFO payload;
- sequence wrap;
- retransmission after action;
- ServerHello progress.

### Android fixtures

Sanitized packets/metadata from real traces:

- YouTube API;
- YouTube UI;
- two `googlevideo` CDN flows;
- first flow unclassified, later clear-SNI flow;
- QUIC→TCP fallback;
- ECH outer ClientHello.

### Коммит

```text
test(fixtures): add Android DNS TLS QUIC and TCP regression corpus
```

---

## Этап 3. Config/version scaffolding

### Добавить

- schema version for classifier v2.3;
- immutable runtime generation ID;
- feature flags with compatibility defaults;
- config validation hooks;
- test clock and interfaces.

### Defaults

```text
classifier_v2 = observe/off by build phase
DomainOnly = legacy
reassembly = off/observe
hold_replay = off
new strategies = disabled
```

### Коммит

```text
feat(config): add classifier v2 generation and feature flag scaffolding
```

---

# Часть III. Kernel capture correctness

## Этап 4. Capture Envelope и processed provenance mark

### Создать

```text
src/capture/envelope.go
src/capture/marks.go
src/capture/readiness.go
src/capture/offload_check.go
```

### Реализовать

- first-N outgoing packets;
- first-N incoming packets;
- explicit SYN-ACK/FIN/RST queue rules;
- QUIC Initial visibility;
- IPv4/IPv6;
- processed mark bypass;
- queue-bypass policy;
- production/candidate queue separation.

### Mark contract

Все raw-sent/injected/replayed packets получают один reserved mark. Firewall rules исключают его до NFQUEUE.

### Readiness

Проверять queue number и owner PID/portid через procfs. Fixed sleep — только timeout backoff, не proof of readiness.

### Offload self-check

- test flow seen outgoing;
- reply visibility;
- queue counters;
- explicit `flow_offload_bypass_suspected`.

### Tests

- rules generation snapshots;
- marked packet bypass;
- queue owner mismatch;
- cleanup idempotency;
- IPv4/IPv6;
- mocked procfs.

### Коммит

```text
feat(capture): define NFQUEUE envelope marks readiness and offload diagnostics
```

---

# Часть IV. Classification state и TCP lifecycle

## Этап 5. ClassificationPhase, Evidence и Confidence

### Создать

```text
src/classifier/types.go
src/classifier/phase.go
src/classifier/evidence.go
src/classifier/policy.go
```

### Типы

Реализовать архитектурные:

- `ClassificationPhase`;
- `EvidenceSource`;
- `Evidence`;
- `ClassificationDecision`;
- `ConfidenceThresholds`.

### Требования

- все candidates доступны trace;
- selected evidence отделён от candidate set;
- confidence deterministic;
- policy pure/testable;
- no final unknown on first incomplete packet;
- set lookup revalidates source-device/protocol/config generation.

### Tests

- source priority;
- freshness;
- ambiguity;
- conflict clear SNI vs DNS;
- legacy fallback;
- destructive threshold.

### Коммит

```text
feat(classifier): add phased multi-evidence decisions with confidence
```

---

## Этап 6. Client identity

### Реализовать

`ClientKey` с IP/MAC/ifindex/VLAN и quality state.

### Требования

- IP-only temporary identity;
- late ARP enrichment;
- no cross-VLAN merge;
- bounded identity cache;
- source-device matcher compatibility;
- trace reason when MAC unresolved.

### Tests

- cold ARP start;
- late MAC;
- DHCP/IP reuse;
- guest network;
- missing ARP.

### Коммит

```text
feat(classifier): add resilient source client identity resolution
```

---

## Этап 7. Clean SYN pass и TCP FSM skeleton

### Реализовать

- normalized `FlowKey`;
- `TCPFlowPhase`;
- transition function;
- FIN/RST cleanup;
- ServerProgress state;
- clean SYN guard before generic TLS injection.

### Инвариант

```text
SYN + no payload + no explicit SYN technique → NF_ACCEPT
```

### Не делать пока

- hold/replay;
- new split strategy;
- fake profile changes.

### Tests

- clean SYN with fake-SNI set;
- SynFake allowed;
- TCPMD5 explicit path;
- SYN retransmission;
- SYN-ACK;
- TFO;
- FIN/RST;
- config generation change.

### Коммит

```text
fix(tcp): pass clean SYN and introduce explicit flow state machine
```

---

# Часть V. Source-scoped DNS/QUIC evidence

## Этап 8. Bounded HostHintStore

### Реализовать

- `HintKey(client,destination,protocol)`;
- multiple candidates;
- absolute expiry;
- per-client/global limits;
- deterministic eviction;
- config generation revalidation;
- metrics.

### API

```go
Observe(observation Evidence) error
Lookup(client ClientKey, dst netip.Addr, proto uint8) []Evidence
InvalidateGeneration(gen uint64)
DeleteClient(client ClientKey)
GC(now time.Time)
```

### Tests

- same IP/two clients;
- same client/multiple domains;
- TTL not sliding;
- eviction;
- stale set removal;
- race tests.

### Коммит

```text
feat(classifier): add bounded source-scoped host hint store
```

---

## Этап 9. Structured DNS records parser

### Создать/расширить

- DNS observation model;
- A/AAAA/CNAME parser;
- HTTPS/SVCB/ECHConfig metadata;
- RCODE/TTL;
- resolver ID;
- transaction/client context.

### Requirements

- bounds checks;
- pointer loop protection;
- no panic;
- malformed response no positive hint;
- CNAME canonical chain;
- multiple answer support;
- fuzzing.

### Коммит

```text
feat(dns): parse structured answers TTL CNAME HTTPS and ECH metadata
```

---

## Этап 10. DNS → first-flow integration

### DoH path

После успешного resolver response создавать hints до возврата ответа клиенту.

### System DNS path

Парсить visible responses и привязывать к query/client transaction.

### Set resolution

Hostname разрешается в один или несколько matching sets с учётом source device.

### Negative responses

NXDOMAIN/SERVFAIL создают diagnostic outcome, но не positive hint.

### Integration tests

- DNS answer затем immediate TCP SYN/ClientHello;
- ECH ClientHello first flow;
- multiple clients;
- CNAME googlevideo;
- A/AAAA;
- set hot reload;
- resolver failover.

### Коммит

```text
feat(classifier): correlate DNS answers with each client first flow
```

---

## Этап 11. QUIC → TCP handoff

### Реализовать

- parse QUIC Initial SNI;
- create UDP evidence;
- mirror bounded TCP hint;
- then execute configured allow/reject/mutate;
- no global IP overwrite.

### Tests

- QUIC parse then reject then TCP same IP;
- two clients/shared IP;
- malformed QUIC;
- ECH/unknown QUIC metadata;
- TTL expiry;
- QUIC disabled app path.

### Коммит

```text
feat(classifier): hand off source-scoped QUIC identity to TCP fallback
```

---

## Этап 12. NFQ decision integration и DomainOnly v2

### Decision order

Использовать policy из architecture, не ad-hoc condition chain.

### DomainOnly modes

- strict;
- scoped-hints;
- legacy;
- disabled.

### Compatibility

Existing boolean config migrates to equivalent legacy mode.

### Trace

Показывать:

```text
all evidence
selected source/confidence
DomainOnly mode/result
set/strategy
```

### Коммит

```text
feat(nfq): integrate classifier decisions and scoped DomainOnly semantics
```

---

# Часть VI. TLS metadata и reassembly

## Этап 13. Structured TLS metadata parser

### Возвращать

- complete/incomplete;
- exact record need;
- SNI;
- ALPN;
- supported versions;
- ECH presence/outer name;
- ClientHello size;
- record/trailing data count;
- parse error.

### Requirements

- no allocation proportional to attacker length before cap;
- nested length validation;
- multiple records;
- fuzz tests;
- backward wrapper for legacy callers.

### Коммит

```text
feat(tls): expose bounded ClientHello metadata including ECH state
```

---

## Этап 14. Observe-only TCP reassembly

### Создать

```text
src/classifier/tcp_ranges.go
src/classifier/tcp_reassembly.go
```

### Реализовать

- RangeSet;
- base sequence;
- exact record length;
- out-of-order;
- retransmission;
- identical/conflicting overlap;
- multiple records/trailing data;
- timeout/FIN/RST/generation abort;
- memory budgets.

### Режим

Observe-only: не задерживать original packets и не менять action.

### Metrics

complete/abort reason/bytes/time/segments.

### Tests

Весь TLS fixture corpus, race, benchmark, fuzz.

### Коммит

```text
feat(tcp): observe bounded out-of-order TLS ClientHello reassembly
```

---

## Этап 15. ECH-aware evidence policy

### Реализовать

- ECH metadata feeds decision;
- no final unknown on ECH;
- scoped DNS/QUIC lookup;
- host-marker techniques marked unavailable without clear host;
- contradiction/confirmation handling;
- confidence update.

### Tests

- ECH + fresh DNS one candidate;
- ECH + ambiguous shared IP;
- ECH + QUIC hint;
- stale hint;
- clear SNI contradiction;
- strict DomainOnly.

### Коммит

```text
feat(classifier): resolve ECH flows through scoped corroborated evidence
```

---

## Этап 16. Auto hold/replay

### Preconditions

Observe reassembly must be stable and benchmarked.

### Modes

- off;
- observe;
- auto;
- always debug.

### Auto policy

Hold only when:

- first payload looks like incomplete ClientHello;
- current decision below needed threshold;
- memory/queue budgets available;
- flow not in ServerProgress/closed;
- target policy allows hold.

### Abort paths

- timeout;
- malformed/conflicting overlap;
- FIN/RST;
- shutdown;
- pressure;
- generation change.

Все abort paths release unchanged.

### Keenetic guard

Default timeout/budgets validated on target router.

### Коммит

```text
feat(tcp): add bounded fail-open ClientHello hold and replay
```

---

# Часть VII. Action planner и executor

## Этап 17. Stream-offset и semantic-marker planner

### Создать

```text
src/action/stream_map.go
src/action/markers.go
src/action/planner.go
src/action/packet_builder.go
```

### Типы

- `StreamRange`;
- `PacketSpan`;
- `LogicalMarker`;
- `SplitPosition`;
- `PlannedWrite`;
- `ActionPlan`.

### Markers

Минимум:

- ClientHello start/end;
- SNI extension start;
- host start/end;
- SLD middle.

### Requirements

- dry-run;
- marker unavailable on ECH/no host;
- exact stream→TCP sequence mapping;
- MTU awareness;
- valid checksums/lengths;
- processed mark;
- no arbitrary in-place rewrite of retransmission.

### Initial scope

Перевести существующие B4 fake/split/combo actions на planner без добавления новых techniques.

### Коммит

```text
refactor(tcp): plan packet actions from logical stream offsets and markers
```

---

## Этап 18. First-flight-only и retransmission idempotency

### Реализовать

`ActionTokenStore` с config generation.

### Rules

- one action per logical ClientHello;
- retransmission suppressed;
- partial overlap suppressed;
- new flow allowed;
- ServerProgress closes mutation window;
- rollback invalidates candidate tokens;
- budget checked before send.

### Tests

- exact retransmit;
- reordered retransmit;
- timeout/retry;
- duplicate NFQUEUE delivery;
- config hot apply;
- process mark bypass;
- packet amplification cap.

### Коммит

```text
fix(tcp): make first-flight actions retransmission idempotent
```

---

## Этап 19. Executor fail-safe hardening

### Реализовать

- centralized packet builder;
- checksum/length validation;
- raw send error handling;
- mark verification;
- action budget enforcement;
- partial send handling;
- cleanup on cancellation;
- fail-open when plan invalid.

### Tests

- injected packet re-entry;
- raw send failure;
- invalid MTU;
- IPv4/IPv6;
- TCP options;
- max writes/bytes/delay.

### Коммит

```text
fix(action): enforce packet provenance budgets and fail-open execution
```

---

# Часть VIII. Observability

## Этап 20. Metrics, trace и issue bundle v2

### Добавить

Все обязательные metrics из architecture:

- classifier/evidence/confidence;
- capture/queue/offload;
- FSM/reassembly;
- action/token/amplification;
- ECH fallback;
- Discovery outcomes.

### Trace schema

Structured JSON plus human-readable trace.

### Issue bundle

Содержит по умолчанию:

- versions/commit/config hash;
- redacted client/flow IDs;
- relevant DNS/QUIC/TLS evidence;
- FSM/action timeline;
- queue/offload status;
- ProbeOutcome;
- no raw ClientHello unless explicit.

### Коммит

```text
feat(observability): expose classifier capture action and discovery diagnostics
```

---

# Часть IX. Discovery v2.3

## Этап 21. Isolated Experiment Sandbox

### Реализовать

- baseline-none;
- baseline-production;
- candidate;
- dedicated queue;
- source-port range;
- connmark exclusion;
- processed mark;
- queue owner readiness;
- logs;
- cancellation;
- crash/reboot cleanup.

### Invariants

- production B4 не обрабатывает baseline-none/candidate flow;
- candidate не влияет на обычных клиентов;
- cleanup idempotent;
- stale chain/process detected at startup.

### Tests

- concurrent workers;
- process crash;
- queue collision;
- cancellation;
- router restart simulation;
- production service remains active.

### Коммит

```text
feat(discovery): add isolated baseline and candidate NFQUEUE sandboxes
```

---

## Этап 22. Structured ProbeOutcome и layered verdict

### Реализовать

- L4 connect/reset/drop;
- TLS ServerHello/Alert/other;
- HTTP status;
- TTFB;
- body bytes;
- exact failure offset;
- throughput;
- retransmissions/flow retries;
- amplification/CPU;
- DiagnosticVerdict.

### Body policy

- success threshold > typical 16 KiB cutoff;
- configurable read cap;
- exact offset persisted;
- near-16k is classifier label, not hard-coded success logic.

### Tests

- reset before TLS;
- TLS Alert;
- body 8/16/32/128 KiB;
- midstream reset;
- stall;
- slow but valid;
- HTTP error with body.

### Коммит

```text
feat(discovery): classify layered transport TLS body and throughput outcomes
```

---

## Этап 23. Adaptive matrix and shadow probes

### Variant dimensions

- strategy;
- fake profile;
- fake SNI;
- resolver;
- IP family;
- TLS profile;
- target profile.

### Search policy

- baseline first;
- vary one dimension at a time;
- bounded concurrency;
- early stop;
- no full Cartesian explosion;
- deterministic seed/reproducibility.

### Shadow probes

При failure сравнить bounded alternatives:

- TLS12/TLS13;
- IPv4/IPv6;
- system DNS/DoH;
- standard/large CH;
- direct/proxy if configured.

### Targets

API/UI/video/body/throughput/CDN switch/cold start/resume.

### Scoring

Success/stability/body/throughput minus latency/retries/amplification/CPU/collateral.

### Коммит

```text
feat(discovery): add adaptive causal matrix and shadow diagnostics
```

---

## Этап 24. Passive Failure Candidate Inbox

### Inputs

- conntrack `UNREPLIED`/`SYN_SENT`;
- classifier ambiguity;
- reassembly abort;
- repeated flow retry;
- queue drops;
- offload suspicion;
- probe failure.

### Model/UI API

Implement `FailureCandidate` with source-scoped DNS/QUIC candidates and suggested actions.

### Actions

- trace;
- pcap;
- ClientHello capture;
- isolated Discovery;
- issue bundle;
- scoped canary.

### Safety

No automatic destructive action from inbox signal alone.

### Tests

- hardware offload stale counters;
- two clients same destination;
- SYN_SENT aging;
- dedup/expiry;
- evidence update after DNS.

### Коммит

```text
feat(diagnostics): add per-client failing flow candidate inbox
```

---

# Часть X. Real ClientHello Laboratory

## Этап 25. Real Android ClientHello capture

### Реализовать

- selected client/IP/MAC filter;
- bounded capture duration;
- TCP/443 IPv4/IPv6;
- reuse production reassembly/parser;
- candidate list;
- metadata/hash/provenance;
- privacy redaction;
- local retention.

### Важно

Не использовать упрощённый contiguous-only pcap reassembly как production implementation.

### Tests

- two-segment Android hello;
- out-of-order/retransmit;
- multiple simultaneous flows;
- ECH;
- no traffic;
- malformed capture;
- privacy export.

### Коммит

```text
feat(lab): capture and validate real client TLS ClientHello profiles
```

---

## Этап 26. Fake Profile Compiler

### Modes

- raw-captured;
- compact-compatible;
- fingerprint-preserving;
- single-packet-safe;
- multi-packet-fake disabled initially.

### Реализовать

- structural SNI replacement;
- extension policy;
- nested length recalculation;
- ALPN/version validation;
- IPv4/IPv6 MTU estimator;
- change report;
- immutable source artifact;
- SHA/provenance;
- validation API.

### Safety

Compiled profile не становится active автоматически.

### Tests

- shorter/longer SNI;
- extension removal;
- 1500 MTU;
- IPv6 overhead;
- invalid source;
- deterministic seed;
- reparse compiled output.

### Коммит

```text
feat(lab): compile validated MTU-aware fake ClientHello profiles
```

---

# Часть XI. Runtime control plane

## Этап 27. Transactional apply, last-good, canary and rollback

### Transaction

```text
validate
→ build immutable generation
→ allocate runtime
→ queue readiness
→ canary probes
→ atomic promote
→ drain previous
```

### Last-good

Persist schema/config/strategy/set hashes and validation summary, not live flows/hints.

### Canary

- client group;
- set;
- new-flow percentage;
- duration;
- minimum samples;
- explicit stop conditions.

### Cooldown

Scoped by set/client/protocol/candidate generation.

### Rollback

- atomic generation restore;
- state/token cleanup;
- candidate worker shutdown;
- reason/metrics/history.

### Tests

- validation failure;
- queue readiness failure;
- partial canary failure;
- crash during promote;
- rollback with held flows;
- anti-flapping.

### Коммит

```text
feat(runtime): add transactional canary promote last-good and rollback
```

---

# Часть XII. Optional Strategy Catalog

Этапы 28–32 выполняются только после Core Fix и Productization DoD.

## Этап 28. Marker-based multisplit/multidisorder

### Реализовать

- semantic/absolute positions;
- forward/reverse/custom order;
- stream-preserving sequence mapping;
- first-flight token;
- amplification cap;
- dry-run.

### Initial candidates

Read-only catalog from zapret2/Flowseal concepts:

- split at 1;
- around SNI extension;
- host start/end;
- SLD middle;
- small multi-position variants.

### Tests

2/3/5 segments, MTU, retransmission, API/UI/video.

### Коммит

```text
feat(strategy): add bounded marker-based multisplit and multidisorder
```

---

## Этап 29. Hostfakesplit

### Preconditions

- complete clear/reassembled SNI;
- host markers;
- established FSM;
- confidence threshold;
- first-flight token;
- ECH/no host unavailable.

### Requirements

- structural replacement validation;
- endpoint sees original logical stream;
- explicit fake/real order;
- per-strategy budget;
- no universal default.

### Коммит

```text
feat(strategy): add confidence-gated hostfakesplit
```

---

## Этап 30. Fake payload catalog and bounded auto-selection

### Catalog

- generated neutral valid TLS;
- Google-like candidates;
- Android-captured compiled candidates;
- QUIC Initial candidates;
- license/provenance metadata.

### Discovery

Compare profile separately from transport technique.

### Promotion

Only after multiple target profiles/samples and canary.

### Коммит

```text
feat(discovery): manage provenanced fake payload profiles and selection
```

---

## Этап 31. Fakedsplit/fakeddisorder and TLS record split

### Preconditions

- stable planner;
- tokens;
- budgets;
- fake profiles;
- Discovery/canary.

### Fake-mix requirements

- declarative writes;
- no retransmission repeat;
- endpoint original stream;
- kill switch;
- high confidence only.

### TLS record split requirements

- valid TLS records;
- preserve handshake/trailing records;
- separate technique;
- marker-based boundaries;
- no non-ClientHello mutation.

### Коммит

```text
feat(strategy): add bounded fake-mix and explicit TLS record split
```

---

## Этап 32. Controlled RST and RST-path diagnostics

### Runtime RST

Только где packet path корректен и explicit strategy configured.

### Diagnostic path

- TCP SYN traceroute;
- observed RST TTL/IPID/flags;
- direct/candidate comparison;
- heuristic label only.

### Safety

Не auto-select strategy solely from inferred injection hop.

### Коммит

```text
feat(diagnostics): add controlled RST strategy and heuristic path analysis
```

---

# Часть XIII. Optional transport fallback

## Этап 33. Confidence-based TUN/SOCKS fallback

### Policy

```text
resolved/high confidence → native B4 action
ambiguous/unknown        → direct/generic/proxy by scoped config
```

### Requirements

- per-set/per-device;
- SO_MARK/rule isolation;
- no double processing;
- pooling;
- healthcheck;
- cooldown/last-good route;
- UDP idle bounds;
- capability matrix;
- telemetry.

### References

wstunnel lifecycle/pooling; existing SOCKS/TUN implementation patterns. No direct blind port.

### Коммит

```text
feat(routing): add scoped confidence-based proxy fallback
```

---

# Часть XIV. Backend config and UI

## Этап 34. Backend config/API

### Добавить

- classifier/evidence thresholds;
- hint store limits;
- DomainOnly modes;
- capture envelope/marks;
- reassembly/hold limits;
- action budgets;
- Discovery variants/sandbox;
- failure inbox;
- ClientHello profiles/compiler;
- transactional apply/canary;
- optional strategies/fallback;
- retention/privacy.

### Requirements

- schema migration;
- validation;
- safe defaults;
- API versioning;
- import/export without raw private artifacts by default.

### Коммит

```text
feat(api): expose classifier discovery lab and runtime control configuration
```

---

## Этап 35. UI

### Экраны

- classifier status/evidence;
- capture envelope/offload;
- active flows/FSM/reassembly;
- set/strategy dry-run;
- Discovery baselines/results/verdicts;
- Failure Inbox;
- ClientHello capture/compiler;
- candidate canary/promote/rollback;
- last-good/history.

### UX

- basic/advanced modes;
- warnings for destructive/high-amplification techniques;
- explicit privacy prompt for raw export;
- no automatic production apply after test.

### Коммит

```text
feat(ui): add classifier diagnostics discovery lab and rollback workflows
```

---

# Часть XV. Field validation

## Этап 36. Controlled router validation

### Test preparation

- watchdog/discovery noise disabled unless under test;
- target phone identity present;
- other YouTube clients idle;
- clean B4 restart;
- queue/offload self-check passes;
- known config generation.

### Android scenarios

1. official YouTube cold start;
2. ReVanced cold start;
3. API/UI load;
4. first video CDN;
5. CDN switch;
6. playback stall/resume;
7. background/foreground;
8. QUIC enabled + B4 parse/reject;
9. app QUIC disabled;
10. ECH/split ClientHello;
11. second client simultaneous lookup;
12. IPv4/IPv6;
13. DoH/system DNS;
14. hot apply/canary/rollback.

### Success metrics

- time DNS→first classified flow;
- time app start→UI usable;
- time video start→stable playback;
- unclassified first flows;
- SYN retries;
- reassembly completion;
- evidence source/confidence;
- actions per logical ClientHello;
- body/throughput;
- queue drops;
- CPU/memory;
- collateral failures.

### Acceptance

Must satisfy architecture Core/Productization DoD on target router.

### Коммит

```text
test(field): validate Android YouTube first-flow classification on Keenetic
```

---

# Часть XVI. PR decomposition

## PR A1 — Audit and fixtures

Этапы 1–3.

## PR A2 — Capture correctness

Этап 4.

## PR B — Evidence classifier

Этапы 5–6, 8–12.

## PR C — TCP lifecycle and observe reassembly

Этапы 7, 13–15.

## PR D — Hold/replay

Этап 16.

## PR E — Action correctness

Этапы 17–19.

## PR F1 — Observability and sandbox

Этапы 20–21.

## PR F2 — Causal Discovery

Этапы 22–23.

## PR F3 — Failure Inbox

Этап 24.

## PR F4 — ClientHello Laboratory

Этапы 25–26.

## PR F5 — Transactional runtime

Этап 27.

## PR G1–G5 — Optional strategies

Этапы 28–32.

## PR H — Transport fallback

Этап 33.

## PR I — API/UI and field validation

Этапы 34–36.

PR boundaries MAY split further, но нельзя объединять Core Fix с большим UI/strategy PR.

---

# Часть XVII. Gates

## Gate 1 — начать hold/replay

Только после:

- capture envelope verified;
- observe reassembly stable;
- memory benchmark;
- all release paths tested.

## Gate 2 — начать planner mutation

Только после:

- decision/evidence integrated;
- clean SYN fixed;
- FSM stable;
- ActionToken tests.

## Gate 3 — начать optional strategies

Только после:

- Core Fix DoD;
- structured Discovery;
- canary/rollback;
- amplification metrics.

## Gate 4 — production rollout

Только после:

- field matrix;
- no cross-client leakage;
- first-flow classification success;
- resource budget;
- documented rollback.

---

# Часть XVIII. Reference repositories для агента

## Обязательные

- B4 base repository;
- zapret2;
- z2k;
- nDPI;
- SpoofDPI;
- DPIBreak;
- SNI-Spoofing;
- GreenTunnel;
- nfqws2-keenetic;
- nfqws2-keenetic-strategy-selector;
- YT-DPI.

## Рекомендуемые для optional/catalog/control plane

- Flowseal/zapret-discord-youtube;
- zapret-gui;
- wstunnel;
- ранее проанализированные NoDPI/GreenTunnel/SNI-Spoofing и другие references по конкретному этапу.

## Правила использования

- references read-only by default;
- сначала сформулировать invariant/interface, затем clean-room implementation;
- прямое копирование только после license/provenance review;
- непонятная лицензия → не копировать;
- binary blobs не включать без provenance.

---

# Часть XIX. Definition of Done

## Core Fix

- clean SYN accepted without explicit SYN technique;
- capture envelope and marks verified;
- source-scoped DNS/QUIC first-flow classification;
- multi-evidence phase/confidence;
- bounded split ClientHello reassembly;
- ECH fallback;
- stream-offset planner;
- retransmission idempotency;
- fail-open and metrics.

## Productization

- isolated baselines;
- structured causal outcomes;
- adaptive matrix/shadow probes;
- failure inbox;
- real ClientHello lab/compiler;
- transactional canary/promote/rollback;
- privacy-safe issue bundle;
- field validation.

## Optional strategy

- preconditions;
- budgets;
- dry-run;
- idempotency;
- Discovery proof;
- canary rollback;
- no collateral expansion.

---

# Часть XX. Итоговая инструкция агенту

Работать строго по порядку stages и gates. Не пытаться «починить YouTube» добавлением очередной fake/split комбинации до завершения classification/capture/TCP lifecycle.

Основной критерий успеха:

```text
первый flow реального Android-клиента
→ правильно классифицирован
→ action применён один раз
→ ответ сервера виден
→ API/UI/video стабильно проходят
→ причина любого сбоя объяснима trace/ProbeOutcome
```
