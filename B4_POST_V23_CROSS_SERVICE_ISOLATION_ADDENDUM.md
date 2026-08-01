# B4 Post-v2.3 Cross-Service Scope Isolation Addendum

**Версия:** 1.0  
**Дата:** 2026-07-29  
**Статус:** обязательный post-plan corrective/hardening addendum  
**База:** завершённая реализация `B4_FORK_ARCHITECTURE.md` v2.3 и всех Stage 1–36 `B4_FORK_PATCH_PLAN.md` v2.3  
**Порядок применения:** после завершённого v2.3 patch plan, **до** `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md`  
**Область:** DomainOnly v2, cross-service isolation, shared-IP ambiguity, reassembled-SNI authorization, QUIC gating, failure/escalation caches, routing scope, Gmail/Google negative-control validation

---

## 0. Нормативный статус и место в проекте

Этот addendum применяется **поверх уже завершённых Stage 1–36**.

Он:

- не переоткрывает и не перенумеровывает Stage 1–36;
- не отменяет ранее пройденные stage gates;
- добавляет отдельный post-plan corrective layer с companion stages `CSI-1`–`CSI-10`;
- устраняет обнаруженные после реализации пути cross-service collateral damage;
- обязателен до включения активных режимов GSO, passive RST suppression, автоматической promotion или широкого production rollout YouTube-профилей;
- разрешает малые compatibility patches в существующих компонентах, но не допускает возврат к ad-hoc packet matching;
- требует сохранить загрузку legacy-конфигов, но запрещает незаметно трактовать legacy semantics как production-safe DomainOnly.

Порядок выполнения документов:

```text
B4_FORK_ARCHITECTURE.md v2.4
→ завершённый B4_FORK_PATCH_PLAN.md v2.3 (Stage 1–36)
→ B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md
→ B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md
→ target field validation / production promotion
```

При пересечении требований действует приоритет:

```text
B4_FORK_ARCHITECTURE.md v2.4
→ этот addendum для scope/DomainOnly/cross-service semantics
→ RST/GSO hardening addendum для GSO и passive RST specifics
→ implementation notes и historical documents
```

### 0.1. Почему source-scoped isolation недостаточно

Gmail, Google app/Discover и YouTube работают на **одном телефоне**. Поэтому изоляция только по `ClientKey` решает cross-client leakage, но не решает cross-service leakage внутри одного клиента.

Обязательная формула:

```text
точный ClientKey
+ точный FlowKey
+ domain/service evidence
+ config generation
+ action authorization
```

Ни destination IP, ни порт `443`, ни принадлежность Google ASN/CDN, ни прежний YouTube-flow того же телефона не являются достаточным доказательством, что новый flow относится к YouTube.

---

# Часть I. Полевая проблема и модель риска

## 1. Наблюдаемый симптом

При включённых YouTube sets на целевом Android-устройстве:

- заголовки писем Gmail могут приходить;
- тело письма, изображения или другие части сообщения могут не загружаться;
- лента новостей в Google app может не загружаться;
- отключение YouTube sets восстанавливает поведение.

Этот симптом MUST рассматриваться как возможное cross-service воздействие, пока trace не доказал иную причину.

Возможные пути:

```text
shared Google IP/CIDR
→ преждевременный YouTube set match
→ YouTube mutation/reject/route
→ Gmail или Google Feed flow повреждён
```

```text
YouTube failure/IPBlockDetect
→ destination-only blocked cache IP:443
→ другой Google hostname на том же IP:443
→ cached RST/drop
```

```text
YouTube clear SNI learned as IP→set
→ legacy learned-IP reused для другого Google flow
→ strategy применяется до реального SNI
```

```text
UDP/QUIC static-IP match
→ FilterQUIC=all
→ QUIC action без подтверждения YouTube hostname
```

## 2. Verified implementation gaps на текущей post-Stage-36 ветке

На ветке `agent/classifier-v2.3-capture-envelope` при подготовке addendum подтверждены следующие integration gaps.

### 2.1. Global DomainOnly default остаётся legacy

`src/config/types.go`:

```go
DefaultClassifierConfig.DomainOnlyMode = DomainOnlyLegacy
```

`src/nfq/classifier_decision.go` разрешает packet path без v2.3 gate, когда effective mode равен `legacy`.

Следствие: видимый per-set boolean `Targets.DomainOnly` не гарантирует новую строгую semantics при legacy global mode.

### 2.2. IP candidate появляется до clear SNI

`src/nfq/handler.go` сначала выполняет:

```go
matcher.MatchIPWithSource(pkt.dst, pkt.srcMac)
```

и только позднее packet-local TLS parser пытается получить SNI.

Это допустимо только как **capture candidate**, но не как разрешение применить domain-scoped YouTube action.

### 2.3. Reassembled SNI не является authoritative hostname в основном matcher path

`handleTCPPacket` получает:

```go
reassemblyResult = w.observeTCPReassembly(...)
```

но основной hostname всё ещё извлекается из текущего payload:

```go
host, tlsVersion, _ = sni.ParseTLSClientHelloSNI(payload)
```

Complete reassembled SNI MUST стать полноценным evidence и уметь отменять provisional IP match.

### 2.4. Legacy learned-IP является destination-global

`src/sni/suffixset.go` хранит legacy association приблизительно как:

```text
destination IP → domain + *SetConfig
```

с длительным/sliding lifetime и без `ClientKey`, `FlowKey` и immutable config snapshot.

### 2.5. IPBlockDetect cache имеет слишком широкий ключ

Текущий TCP path использует:

```go
dstIPPort := fmt.Sprintf("%s:%d", pkt.dstStr, dport)
```

Такой ключ не содержит client, hostname, set, evidence source или config generation.

### 2.6. UDP/QUIC path допускает IP match раньше QUIC SNI

Static/learned IP может назначить set до QUIC SNI. `FilterQUIC=all` затем способен разрешить action по факту IP/port candidate.

### 2.7. Routing side effects могут пережить packet decision

Даже если packet classifier позднее стал точнее, destination-only ipset/route/proxy binding может продолжить направлять unrelated Google traffic по YouTube path.

Эти findings являются основанием для corrective stages ниже.

---

# Часть II. Цели и не-цели

## 3. Цели

Форк MUST:

1. гарантировать, что YouTube set не воздействует на Gmail, Google app/Discover и другой non-YouTube traffic того же устройства;
2. разделить причину захвата packet и разрешение применить action;
3. сделать per-set DomainOnly policy явной и вычислять effective policy детерминированно;
4. сделать clear/reassembled SNI сильным positive и negative evidence;
5. считать shared IP/CIDR только provisional candidate для domain-scoped set;
6. запретить QUIC reject/mutation по одному IP match для DomainOnly set;
7. убрать destination-global learned-IP из authoritative v2 path;
8. сделать block/escalation/RST/failure state client/domain/set/generation scoped;
9. запретить destination-only routing side effects для domain-scoped shared endpoints;
10. добавить Gmail и Google Feed как обязательные negative controls;
11. fail-open при ambiguity, incomplete visibility и недостатке evidence;
12. передавать cross-service violations в Failure Inbox и Discovery без автоматического расширения domain list.

## 4. Не-цели

Этот addendum не должен:

- добавлять Gmail- или Google-specific branches в packet core;
- hard-code домены приложений вместо evidence pipeline;
- решать проблему расширением Google CIDR/ASN;
- считать весь Google traffic YouTube traffic;
- отключать QUIC глобально как постоянный workaround;
- выключать Gmail/Google tests ради успешного YouTube validation;
- превращать DNS observation в глобальный persistent IP rule;
- применять strategy по одному destination IP для DomainOnly set;
- сохранять `*SetConfig` в long-lived flow/cache state;
- считать отсутствие SNI доказательством YouTube;
- повторно выполнять Stage 1–36.

---

# Часть III. Нормативная decision model

## 5. ADR-CSI-1 — CaptureCandidate не равен ActionAuthorization

Ввести явное разделение:

```go
type CaptureCandidate struct {
    FlowKey        classifier.FlowKey
    Client         classifier.ClientKey
    CandidateSetID string
    Source         classifier.EvidenceSource
    DestinationIP netip.Addr
    DestinationPort uint16
    L4Proto        uint8
    ConfigGen      uint64
    Reason         string
}
```

```go
type ActionAuthorization struct {
    FlowKey        classifier.FlowKey
    SetID          string
    Domain         string
    EvidenceSource classifier.EvidenceSource
    Confidence     uint8
    DomainPolicy   DomainPolicy
    ConfigGen      uint64
    Final          bool
    ExpiresAt      time.Time
}
```

Нормативно:

```text
IP/CIDR/port/geosite match
→ MAY создать CaptureCandidate
→ MUST NOT сам по себе создать ActionAuthorization для DomainOnly set
```

```text
clear SNI / complete reassembled SNI
→ MAY создать authoritative ActionAuthorization
```

```text
fresh source-scoped DNS/QUIC evidence
→ MAY создать ActionAuthorization только в scoped-hints policy
```

`ActionPlan` для domain-scoped set MUST ссылаться на валидный `ActionAuthorization` той же:

- `FlowKey`;
- `SetID`;
- `ConfigGen`;
- client identity;
- protocol/port scope.

## 6. ADR-CSI-2 — Effective per-set DomainOnly policy

Добавить явную policy:

```go
type DomainPolicy string

const (
    DomainPolicyInherit     DomainPolicy = "inherit"
    DomainPolicyStrict      DomainPolicy = "strict"
    DomainPolicyScopedHints DomainPolicy = "scoped-hints"
    DomainPolicyLegacy      DomainPolicy = "legacy"
    DomainPolicyDisabled    DomainPolicy = "disabled"
)
```

Per-set config:

```yaml
targets:
  domain_only: true
  domain_policy: scoped-hints
```

Effective policy:

```text
explicit set.domain_policy
→ global classifier.domain_only_mode, если inherit
→ legacy compatibility mapping только если config действительно legacy
```

Правила:

- managed/compiled YouTube API/UI/VIDEO sets MUST использовать `scoped-hints`, если нет отдельно доказанной причины для `strict`;
- `strict` разрешает только clear SNI, reassembled SNI и explicit static hostname;
- `scoped-hints` дополнительно разрешает свежие source-scoped DNS/QUIC evidence;
- `legacy` загружается для совместимости, но MUST быть виден как unsafe compatibility mode;
- `disabled` разрешает IP/CIDR fallback и не должен использоваться для shared Google YouTube sets без отдельного manual opt-in;
- profile compiler и Discovery MUST NOT генерировать `legacy`;
- migration MUST NOT молча подписывать legacy config как `scoped-hints` или `strict`.

### 6.1. Legacy safety validation

Legacy config MUST продолжать загружаться. Однако transactional apply MUST отклонять или требовать explicit unsafe override, если одновременно выполняются условия:

```text
DomainOnly=true
+ effective policy=legacy
+ set содержит IP/CIDR/geosite/geoip/port fallback
+ strategy может mutate/drop/reject/route/proxy
```

Machine-readable reason:

```text
unsafe_legacy_domain_scope
```

UI MUST предлагать безопасную миграцию на `scoped-hints` или `strict`, показывая diff.

## 7. ADR-CSI-3 — Positive и negative domain evidence

Clear/reassembled hostname выполняет две функции:

1. подтверждает подходящий set;
2. отменяет несовместимые provisional candidates.

Нормативная схема:

```text
shared IP → provisional YouTube candidate
clear/reassembled SNI = YouTube hostname
→ authorize YouTube set
```

```text
shared IP → provisional YouTube candidate
clear/reassembled SNI = Gmail/Google Feed/другой hostname
→ revoke YouTube candidate
→ accept direct либо evaluate другой eligible set
```

```text
shared IP → несколько eligible sets одинаковой силы
→ ambiguous
→ no domain-scoped mutation
→ NF_ACCEPT / configured safe fallback
```

Нужно ввести explicit negative evidence/result:

```go
type CandidateDisposition string

const (
    CandidateEligible      CandidateDisposition = "eligible"
    CandidateContradicted  CandidateDisposition = "contradicted"
    CandidateAmbiguous     CandidateDisposition = "ambiguous"
    CandidateInsufficient  CandidateDisposition = "insufficient"
)
```

Запрещено оставлять ранее выбранный IP-set активным после появления clear/reassembled SNI, которое не принадлежит этому set.

## 8. ADR-CSI-4 — Reassembled SNI является authoritative evidence

После complete bounded reassembly:

```text
Metadata.Complete=true
+ Metadata.SNI!=""
+ no conflicting overlap
+ hostname допустим по ECH policy
→ EvidenceReassembledSNI
```

`EvidenceReassembledSNI` MUST:

- пройти `MatchSNIWithSourceTLS` или единый v2 matcher;
- участвовать в той же decision policy, что packet-local SNI;
- отменять provisional static-IP/learned-IP/port candidates;
- быть привязано к exact `FlowKey`, `ClientHelloID`, `ConfigGen`;
- не создавать global IP learning;
- производить не более одного final `ClassificationDecision` и одного `ActionToken` на logical first flight.

Если packet-local SNI и reassembled SNI противоречат друг другу:

```text
trace conflict
→ suppress mutation
→ fail-open
→ Failure Inbox
```

### 8.1. Связь с последующим RST/GSO addendum

После выполнения `CSI-4` stage `H1 Reassembled-SNI runtime decision integration` из `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md` трактуется как:

- verification данного контракта;
- parity между GSO и MSS layouts;
- integration с GSO first-pass token;
- отсутствие duplicate classification.

Он не должен повторно реализовывать параллельный matcher path.

## 9. ADR-CSI-5 — Incomplete evidence не разрешает destructive action

Для DomainOnly set:

```text
ClientHello incomplete
+ нет достаточного source-scoped hint
→ no ActionAuthorization
```

Если capture visibility и hold capability полны:

```text
bounded hold
→ wait reassembly/evidence
→ authorize либо release unchanged
```

Если visibility incomplete, queue pressure или timeout:

```text
NF_ACCEPT unchanged
→ flow observe-only
```

Нельзя применять YouTube mutation «на всякий случай» к shared Google IP.

---

# Часть IV. State и side-effect isolation

## 10. ADR-CSI-6 — Legacy learned-IP не authoritative в classifier v2

В v2 runtime legacy learned-IP может иметь только один из статусов:

```text
diagnostic
или
low-confidence provisional capture candidate
```

Он MUST NOT:

- создавать final `ActionAuthorization`;
- разрешать destructive mutation;
- разрешать QUIC reject;
- создавать global route/ipset entry;
- перезаписывать source-scoped DNS/QUIC candidates;
- продлевать DNS validity sliding lookup-ами;
- хранить `*SetConfig`.

Новая запись:

```go
type ScopedLearnedObservation struct {
    Client        classifier.ClientKey
    DestinationIP netip.Addr
    L4Proto       uint8
    Domain        string
    SetID         string
    Source        classifier.EvidenceSource
    Confidence    uint8
    CreatedAt     time.Time
    ExpiresAt     time.Time
    ConfigGen     uint64
}
```

TTL абсолютный:

```text
ExpiresAt = min(source validity, configured cap)
```

Lookup не продлевает evidence validity.

## 11. ADR-CSI-7 — Failure, block и escalation state имеют полный scope

Заменить destination-only ключи.

Минимальная модель:

```go
type ScopedFailureKey struct {
    Client          classifier.ClientKey
    DestinationIP   netip.Addr
    DestinationPort uint16
    L4Proto         uint8
    SetID           string
    DomainKey       string
    ConfigGen       uint64
}
```

Для exact-flow state использовать полный `FlowKey`.

### 11.1. IPBlockDetect

Для DomainOnly set persistent blocked verdict разрешён только когда:

- есть eligible domain evidence;
- set final/authorized;
- failure относится к тому же client/domain/set;
- ambiguity отсутствует;
- config generation совпадает;
- TTL bounded;
- direct/candidate comparison не противоречит verdict.

Запрещено:

```text
IP:443 → blocked для всех доменов/клиентов
```

Если domain неизвестен или shared IP ambiguous:

```text
не создавать reusable blocked cache
→ Failure Inbox candidate only
```

### 11.2. Escalation

Escalation key MUST включать:

```text
ClientKey + DomainKey + SetID + ConfigGen
```

Escalation, полученная на YouTube hostname, не применяется к другому hostname того же destination IP.

### 11.3. RST sent/suppressed state

RST bookkeeping MUST быть exact-FlowKey scoped. Passive RST addendum обязан использовать эту модель, а не destination-global cache.

### 11.4. Failure Inbox

Добавить signals:

```text
cross_service_scope_violation
provisional_set_revoked_by_sni
shared_ip_ambiguous
unsafe_legacy_domain_scope
blocked_cache_scope_rejected
route_scope_rejected
quic_action_scope_rejected
```

Событие не расширяет domain list автоматически.

## 12. ADR-CSI-8 — QUIC action требует service authorization

Для DomainOnly set static IP/CIDR, learned IP или port match может только включить parsing/capture.

Нормативно:

```text
IP candidate + QUIC SNI YouTube
→ authorize YouTube QUIC action
```

```text
IP candidate + source-scoped DNS/QUIC hint YouTube
→ authorize только в scoped-hints и при threshold
```

```text
IP candidate + QUIC SNI другого сервиса
→ revoke YouTube candidate
→ no YouTube action
```

```text
IP candidate + malformed/unknown QUIC
→ fail-open для DomainOnly set
```

`FilterQUIC=all` MUST означать:

```text
all QUIC packets уже авторизованного set/flow
```

а не:

```text
all QUIC packets к IP, который когда-либо совпал с set
```

Для explicit non-domain global block set с `DomainPolicyDisabled` сохраняется отдельная configured semantics.

## 13. ADR-CSI-9 — Routing и proxy side effects не могут быть destination-global

Для DomainOnly/shared-IP set запрещено создавать destination-only persistent route/ipset binding без source и decision scope.

Допустимые механизмы:

- exact-flow/connmark после authoritative decision;
- source-device + destination + bounded lifetime, если платформа действительно поддерживает такой match;
- per-client nftables set/map;
- userspace proxy handoff, привязанный к final `ActionAuthorization`;
- no route fallback, если platform capability недостаточна.

Недопустимо:

```text
YouTube SNI на 1.2.3.4
→ добавить 1.2.3.4 в глобальный YouTube route ipset
→ весь Gmail/Google traffic к 1.2.3.4 идёт тем же путём
```

Routing binding MUST хранить:

```text
owner/set ID
client scope
config generation
provenance
timeout
transaction ID
```

Rollback/shutdown MUST удалять только owned bindings.

---

# Часть V. Post-plan companion stages

## CSI-1. Effective domain-policy schema и migration guard

### Реализовать

- `DomainPolicy` per set;
- deterministic effective-policy resolution;
- compatibility parser старого `Targets.DomainOnly`;
- `unsafe_legacy_domain_scope` validation;
- config diff/migration preview;
- profile compiler prohibition для `legacy`;
- explicit unsafe override только для advanced/manual config.

### Tests

- old config loads;
- absent field;
- explicit inherit/strict/scoped-hints/legacy/disabled;
- DomainOnly false;
- legacy + IP + destructive strategy rejected;
- safe manual observe-only legacy accepted with warning;
- hot apply/reload preserves effective policy.

### Коммит

```text
feat(config): add effective per-set domain policy and legacy scope guard
```

---

## CSI-2. CaptureCandidate / ActionAuthorization split

### Реализовать

- typed provisional candidates;
- typed action authorization;
- planner requires authorization for DomainOnly set;
- no direct action from static IP/port/geosite candidate;
- immutable SetID/config generation references;
- exact FlowKey binding;
- dry-run reason codes.

### Tests

- static IP creates candidate but no action;
- clear SNI authorizes;
- DNS scoped hint authorizes only scoped-hints;
- stale hint rejected;
- config generation mismatch rejected;
- candidate cannot be reused by another flow/client.

### Коммит

```text
refactor(classifier): separate capture candidates from action authorization
```

---

## CSI-3. Reassembled-SNI authoritative integration

### Реализовать

- convert complete reassembly metadata to `EvidenceReassembledSNI`;
- single matcher path for packet-local/reassembled SNI;
- candidate revocation;
- hold release after final decision;
- one decision/token per logical ClientHello;
- conflicting overlap fail-open;
- no global learned-IP side effect.

### Tests

- 1/2/3/5 segments;
- SNI entirely in later segment;
- retransmission/out-of-order;
- identical/conflicting overlap;
- ECH;
- packet-local vs reassembled parity;
- shared Google IP with YouTube vs non-YouTube SNI;
- two concurrent flows same client/IP, different hostnames.

### Коммит

```text
fix(nfq): authorize domain sets from complete reassembled SNI
```

---

## CSI-4. Negative evidence and provisional-match revocation

### Реализовать

- explicit contradicted disposition;
- clear/reassembled non-matching SNI revokes IP/port candidate;
- eligible other set may replace provisional set;
- ambiguity suppresses mutation;
- trace records candidate lifecycle;
- no previously selected set survives contradiction.

### Tests

```text
YouTube IP candidate + Gmail SNI → no YouTube action
YouTube IP candidate + Google Feed SNI → no YouTube action
YouTube IP candidate + YouTube SNI → expected action
same IP + equal set candidates → ambiguous/fail-open
```

### Коммит

```text
fix(classifier): revoke provisional service matches on contradictory hostname evidence
```

---

## CSI-5. Remove authoritative legacy learned-IP path

### Реализовать

- v2 learned observations source-scoped and immutable;
- absolute expiry;
- no `*SetConfig` in cache;
- no action authorization from legacy learned IP;
- no global route learning;
- migration/cleanup of transferred legacy entries;
- metrics for rejected legacy reuse.

### Tests

- one YouTube observation does not affect Gmail flow to same IP;
- same client and two clients;
- expiry does not slide;
- removed set/config generation invalidates observation;
- legacy cache transfer cannot resurrect deleted/moved set.

### Коммит

```text
fix(classifier): demote legacy learned IP to scoped provisional evidence
```

---

## CSI-6. Scope IPBlockDetect, escalation and RST bookkeeping

### Реализовать

- `ScopedFailureKey`;
- exact FlowKey RST state;
- client/domain/set/config scoped block cache;
- no cache on unknown/ambiguous domain;
- scoped escalation;
- bounded TTL/entry budgets;
- cleanup on FIN/RST/generation/rollback;
- Failure Inbox events for rejected broad cache writes.

### Tests

- YouTube failure cache cannot hit Gmail same IP:443;
- domain A block does not block domain B;
- client A block does not block client B;
- config generation change invalidates entries;
- IPv4/IPv6;
- race/GC/budget;
- reconnect recovery.

### Коммит

```text
fix(nfq): scope block escalation and RST state by client domain and generation
```

---

## CSI-7. Domain-authorized QUIC gating

### Реализовать

- static IP only enables QUIC inspection;
- `FilterQUIC=all` applies only after set authorization;
- QUIC SNI contradiction revokes candidate;
- malformed/unknown QUIC fail-open for DomainOnly;
- scoped DNS/QUIC hint thresholds;
- no legacy learned-IP QUIC action;
- same authorization token used by reject/mutate/fallback.

### Tests

- YouTube QUIC SNI;
- Gmail/Google Feed QUIC on shared IP;
- ECH/unknown QUIC;
- malformed Initial;
- QUIC→TCP handoff;
- QUIC enabled/disabled app paths;
- UDP port-only global set unaffected when DomainPolicyDisabled.

### Коммит

```text
fix(quic): require domain authorization before service-scoped UDP actions
```

---

## CSI-8. Scoped routing/proxy side effects

### Реализовать

- reject destination-only route learning for DomainOnly/shared-IP set;
- flow/client-scoped connmark/routing binding;
- capability check and fail-open when platform cannot isolate;
- transactional ownership/provenance;
- bounded timeout;
- cleanup/rollback/restart reconciliation;
- no double processing with packet executor.

### Tests

- YouTube route does not capture Gmail same IP;
- two clients same IP destination;
- hot apply and rollback;
- worker crash/restart;
- iptables/nftables where supported;
- TUN/SOCKS fallback scope;
- queue/route marks do not collide.

### Коммит

```text
fix(routing): bind domain-scoped routes to authorized client flows
```

---

## CSI-9. Observability, API and UI corrective patch

### Trace MUST показывать

```text
all capture candidates
candidate source and scope
provisional set
positive and negative evidence
candidate disposition
selected effective domain policy
ActionAuthorization ID
revocation reason
block/escalation key scope
route binding scope
final set/action or fail-open reason
config generation
```

### Метрики

```text
cross_service_candidate_total{source,set}
cross_service_candidate_revoked_total{reason}
cross_service_ambiguous_total{reason}
domain_authorization_total{policy,source,result}
legacy_scope_rejected_total{path}
blocked_cache_write_total{result,reason}
route_binding_total{result,scope}
quic_scope_rejected_total{reason}
unrelated_control_action_total{service,set}
```

Последняя метрика должна оставаться `0` в acceptance suite.

### API/UI

- effective policy per set;
- unsafe legacy warning;
- provisional vs authorized state;
- cross-service violation events;
- scoped cache/route diagnostics;
- migration preview;
- negative-control validation result;
- no raw private hostname export by default.

### Коммит

```text
feat(observability): expose domain authorization and cross-service isolation state
```

---

## CSI-10. Gmail/Google negative-control validation and rollout gate

### Synthetic integration matrix

1. same client, same destination IP, YouTube hostname then unrelated hostname;
2. same client, concurrent YouTube and unrelated Google flows;
3. two clients, shared IP;
4. static IP/CIDR candidate before SNI;
5. split/reordered ClientHello;
6. ECH + scoped DNS/QUIC;
7. legacy learned-IP present;
8. IPBlockDetect hit before unrelated flow;
9. escalation before unrelated flow;
10. QUIC `FilterQUIC=all`;
11. route/proxy binding;
12. hot apply and rollback;
13. IPv4/IPv6;
14. queue pressure/incomplete PPE visibility.

### Target Android field matrix

Сценарии выполняются на том же телефоне, для которого включены YouTube sets.

#### Baseline A — YouTube sets disabled

- Gmail sync/list headers;
- open multiple email bodies;
- load inline images;
- open attachment or external content where test account permits;
- Google app feed initial load;
- feed refresh;
- open feed card/article/image;
- record TCP/QUIC/DNS traces and user-visible timings.

#### Candidate B — YouTube sets enabled

Повторить тот же сценарий без изменения других параметров.

#### Concurrent C

- start official YouTube or ReVanced playback;
- одновременно refresh Gmail body/content;
- одновременно refresh Google feed;
- trigger CDN switch/background/foreground;
- verify no non-YouTube flow gets YouTube authorization/token/route/cache.

#### Failure contamination D

- искусственно или контролируемо получить YouTube candidate failure;
- проверить IPBlockDetect/escalation/RST state;
- сразу открыть Gmail body и Google feed;
- подтвердить отсутствие reuse broad state.

### Actual-domain capture rule

Нельзя hard-code предположительный список Gmail/Google Feed доменов как единственное доказательство. Test controller должен:

- записать фактически наблюдаемые DNS/SNI/QUIC domains целевого устройства;
- redacted-сопоставить flow с app/test milestone;
- проверить, какой set/action был выбран;
- сохранить domain hashes/provenance в report;
- не добавлять наблюдаемые unrelated domains в YouTube profile автоматически.

### Hard gates

Production promotion запрещена, если хотя бы один unrelated control flow получил:

```text
YouTube ActionAuthorization
YouTube ActionToken
YouTube packet mutation
YouTube QUIC reject
YouTube IPBlockDetect hit
YouTube escalation
YouTube route/proxy binding
YouTube passive-RST suppression policy
```

Обязательные результаты:

```text
unrelated_control_action_total = 0
cross-service cache reuse = 0
cross-service route reuse = 0
Gmail body/content success не хуже baseline за допустимым budget
Google feed success не хуже baseline за допустимым budget
YouTube expected API/UI/video flows сохраняют целевую работоспособность
```

### Rollout

Порядок:

```text
unit/integration
→ namespace/kernel tests
→ observe-only target traces
→ one-device canary
→ concurrent negative controls
→ failure-contamination tests
→ bounded cohort
→ production promotion
```

Любой hard-gate failure:

```text
automatic rollback
→ disable candidate generation
→ preserve report/Failure Inbox
→ no automatic widening of domains/IPs
```

### Коммит

```text
test(field): gate YouTube rollout on Gmail and Google cross-service isolation
```

---

# Часть VI. Required invariants

## 14. Classifier invariants

```text
shared destination IP != service identity
```

```text
same client != same service
```

```text
capture candidate != action authorization
```

```text
non-matching clear/reassembled SNI revokes provisional domain set
```

```text
ambiguous domain-scoped flow → no destructive mutation
```

```text
one logical first flight → one final decision → one ActionToken
```

## 15. State invariants

```text
no long-lived mutable *SetConfig pointers
```

```text
no destination-only blocked cache for DomainOnly/shared-IP flows
```

```text
no destination-only route binding for DomainOnly/shared-IP flows
```

```text
lookup does not extend evidence validity
```

```text
config generation change revalidates or removes all scoped state
```

## 16. Fail-open invariants

При:

- incomplete ClientHello;
- conflicting overlap;
- unknown/malformed QUIC;
- source identity uncertainty;
- PPE/capture visibility incomplete;
- queue pressure;
- ambiguous shared IP;
- stale/missing hint;
- unsupported platform routing isolation;

должно выполняться:

```text
no YouTube action
→ NF_ACCEPT unchanged или безопасный explicitly configured fallback
→ structured trace/metric
```

---

# Часть VII. Совместимость с RST/GSO hardening

## 17. Обязательная последовательность

`B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md` начинается только после прохождения `CSI-1`–`CSI-10` либо после документированного доказательства эквивалентной реализации.

> **FB-14 решение 5 (уточнение):** данный порядок является **release sequencing** (последовательностью реализации/валидации документов), а не runtime dependency chain. Runtime-цепочки определяются плоскостями по SPF §0.1 (data plane / diagnostic-control plane / transport escalation). Универсальная линейная цепочка WARP→RST/GSO→PPE→SPF не существует.

Причины:

- GSO ускоряет раннюю классификацию, но не должен ускорять неправильный IP-based action;
- GSO first-pass token обязан переносить `ActionAuthorization`, effective domain policy и candidate disposition;
- normalizer worker не должен повторно расширять set scope;
- passive RST suppression должен использовать exact FlowKey и scoped failure state;
- reconnect rollback monitor должен отличать YouTube flow от Gmail/Google flow;
- reassembled-SNI integration должна быть исправлена до GSO parity tests.

## 18. GSOPassToken reference

CSI использует **canonical `GSOPassToken`** из `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md` (H4, FB-14 решение 4). Отдельная CSI-owned token schema не существует.

Canonical token содержит compact immutable references (TokenID, FlowKey, ClientHelloID, ConfigGeneration, Decision, StrategyID, RequiresAction, AuthorizationID/Digest, EffectivePolicyID/Digest, CandidateDisposition, CreatedAt, ExpiresAt, ConsumedAt) и обладает single-use consume, exact generation binding, flow/client scope binding, TTL/expiry, replay rejection и cleanup при generation retirement.

> **superseded (FB-14):** прежняя расширенная schema с вложенными `Authorization ActionAuthorization` и `EffectivePolicy DomainPolicy` объектами удалена как duplicate canonical schema. `Authorization`/`EffectivePolicy` разрешаются по immutable ID/digest в current generation и в token не копируются.

Secondary worker MUST NOT:

- повторно выбирать set по IP;
- повторно применять legacy learned-IP;
- создавать broad block/route state;
- игнорировать negative hostname evidence;
- менять `Authorization.SetID` без нового authoritative evidence и нового token.

## 19. Passive RST integration

Passive RST subsystem MUST:

- работать только по exact FlowKey;
- наследовать final authorized set/domain scope;
- не подавлять RST unrelated Google flow из-за YouTube history;
- передавать suspected event в scoped Failure Inbox;
- rollback при росте reconnect failures отдельно по service/control cohorts.

---

# Часть VIII. Definition of Done

## 20. Functional DoD

Addendum завершён, когда:

1. per-set effective DomainPolicy реализована;
2. legacy config загружается, но unsafe scope не маскируется;
3. static IP/CIDR/port candidate не разрешает DomainOnly action;
4. complete reassembled SNI участвует в основном matcher path;
5. contradictory hostname отменяет provisional YouTube set;
6. ambiguity fail-open;
7. legacy learned-IP не authoritative в v2;
8. IPBlockDetect/escalation/RST state scoped;
9. QUIC action требует domain authorization;
10. routing/proxy bindings не destination-global для DomainOnly/shared-IP;
11. trace показывает candidate→authorization lifecycle;
12. Gmail и Google Feed negative controls автоматизированы;
13. concurrent YouTube/Gmail/Google scenarios проходят;
14. rollback очищает caches/routes/tokens;
15. subsequent RST/GSO hardening использует этот authorization contract.

## 21. Acceptance DoD

На целевом Keenetic и Android-устройстве:

```text
YouTube sets enabled
+ official YouTube/ReVanced usable
+ Gmail headers and bodies/content usable
+ Google app feed usable
+ no unrelated flow receives YouTube action/state
```

Обязательное машинно проверяемое условие:

```text
unrelated_control_action_total == 0
```

Нельзя закрывать addendum только ручным утверждением «визуально работает» без flow-level trace и config generation correlation.

## 22. Resource DoD

- bounded candidate/auth/cache entries;
- no goroutine per packet;
- no global lock during parse/raw send;
- no unbounded domain strings in public metrics;
- route/cache cleanup deterministic;
- target CPU/RAM/queue-drop regression within approved budget;
- negative-control tests не требуют постоянного heavy capture в production.

---

# Часть IX. Deliverables для coding-agent

## 23. Обязательные артефакты

Для каждого `CSI-*` stage:

1. implementation commit;
2. unit/integration tests;
3. implementation report;
4. validation report;
5. migration/compatibility note;
6. resource/bounds note;
7. known limitations;
8. exact commands/results;
9. branch push после успешного gate.

Итоговые документы:

```text
docs/reports/cross-service/CSI_IMPLEMENTATION_REPORT.md
docs/reports/cross-service/CSI_VALIDATION_REPORT.md
docs/validation/gmail-google-negative-controls.md
docs/runtime/domain-authorization-contract.md
```

## 24. Запрещённые shortcuts

Coding-agent не должен:

- просто удалить IP ranges без понимания decision path;
- добавить Gmail domains в allowlist как основное исправление;
- отключить QUIC глобально;
- отключить IPBlockDetect без scoped replacement;
- считать `Targets.DomainOnly=true` достаточным без effective policy trace;
- использовать GSO как workaround для неправильного classifier order;
- расширять YouTube domains по наблюдениям Gmail/Google;
- пропускать target negative-control tests;
- объявлять success по одним unit tests;
- делать broad iptables/nftables ACCEPT rule для всего Google traffic.

---

# 25. Итоговое архитектурное решение

Целевая формула:

```text
shared IP/CIDR/port
→ capture candidate only

clear/reassembled SNI
или допустимый source-scoped DNS/QUIC hint
→ service-scoped ActionAuthorization

contradictory hostname
→ revoke provisional YouTube candidate

ambiguous/incomplete visibility
→ fail-open

failure/block/escalation/route/RST state
→ exact client/flow/domain/set/config scope
```

Главный acceptance result:

```text
YouTube optimization improves YouTube
without changing Gmail, Google Feed or unrelated traffic behavior.
```

До выполнения этого addendum YouTube profile нельзя считать production-isolated, даже если собственные YouTube probes проходят успешно.
