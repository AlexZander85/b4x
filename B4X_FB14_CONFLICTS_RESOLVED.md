# FB-14 — 14 междокументных противоречий: исправленные решения владельца

**Статус:** все 14 конфликтов закрыты владельцем для последующего внесения в canonical normative documents.

**Дата решения:** 31.07.2026.

**Назначение:** этот файл является временным authoritative conflict-resolution record для задачи FB-14. Он не заменяет архитектуру, patch plan и addenda. До финальной верификации каждое решение ниже должно быть перенесено в соответствующие нормативные документы, а конфликтующие формулировки — удалены, объединены либо явно помечены `superseded`.

---

## 0. Принципы разрешения конфликтов

При внесении решений соблюдать следующий порядок:

1. **Безопасность и корректность runtime выше удобства формулировки.** Нельзя выбирать норму, создающую silent drop, broad scope, второй source of truth, stale authorization, mixed generation или ложный readiness verdict.
2. **Архитектура v2.4 задаёт системные границы**, но не отменяет необходимость здравого инженерного решения, если companion-документы противоречат друг другу или неполны.
3. **Один semantic object — один canonical owner и один canonical schema.** Допускаются только компактные ссылки/ID/digest на объекты другого owner, но не дублирование их содержимого и lifecycle.
4. **Data plane, control plane и transport escalation не сводятся к одной линейной цепочке.** Для каждой плоскости фиксируется отдельный порядок зависимостей и runtime flow.
5. **Provisional evidence не является production authorization.** DNS/QUIC hints, passive observations, detector hypotheses и test eligibility не могут сами по себе разрешать destructive packet action, route mutation или production promotion.
6. **Readiness доказывается реальным production call chain и evidence.** Наличие типа, schema, helper, теста или Markdown-отчёта без runtime wiring не считается реализацией.
7. **Количество критериев, stages и gates не дублируется вручную.** Оно вычисляется из единого machine-readable registry и проверяется CI.
8. **Unknown, skipped, missing или stale evidence никогда не агрегируется в PASS.**

---

## 1. Сводка решений

| № | Тема | Решение владельца | Обязательное действие |
|---:|---|---|---|
| 1 | DDI-4 ownership evidence → BlockingProfile | Compiler принадлежит ABD; DDI хранит, валидирует и доставляет immutable profile | Удалить DDI-owned compiler semantics |
| 2 | ~~ADR-WARP 1..7 vs changelog 1..6~~ | СНЯТ: changelog-секции в WARP v1.2 не существует (ложное срабатывание) | Правок не требуется; нормативны ADR-WARP-1…7 |
| 3 | Legacy `/api/watchdog/*` | Event-driven cutover; mutating API отключается при authoritative Monitoring | Исключить два mutating source of truth |
| 4 | Два `GSOPassToken` | Один компактный canonical token с immutable IDs/digests | Удалить второй schema/type |
| 5 | WARP/RST-GSO/PPE/SPF order | Не одна цепочка; отдельно data plane, control plane и transport escalation | Переписать конфликтующие dependency diagrams |
| 6 | IV: 77/86/другие counts | Count вычисляется только из canonical registry | Удалить ручные totals из prose |
| 7 | Устаревший IV registry | Один Exact Source-Stage Registry | Генерация cross-reference и CI consistency check |
| 8 | Ссылки на старые версии | Все ссылки на актуальные версии | Historical refs только в changelog/migration |
| 9 | `WARP_CAUSAL_TRACE_READY` | Узкий causal-trace verdict; optional capabilities имеют отдельные verdicts | Не смешивать base trace с nested/non-RU/Android |
| 10 | Unhealthy controls vs SP-30 | Обе нормы объединяются; unhealthy/inconclusive всегда блокируют action | Единственная causal decision matrix |
| 11 | 16 KiB | Default bounded reassembly budget, не универсальный protocol threshold | Configurable bound + global budgets + matrix tests |
| 12 | `gso_mode=classify` | Отдельный readiness gate; classify не разрешает mutation | Downgrade в observe при unknown/fail |
| 13 | `scoped-hints` vs `strict` | Hints — provisional/correlation evidence; destructive authorization требует authoritative identity | Запрет hint-only ActionAuthorization |
| 14 | Telegram zero-byte close | Soft timeout паркует; hard timeout завершает только observable cleanup path | Запрет fixed-5s silent handled/drop |

---

## 2. Решения по конфликтам

### 1. DDI-4: владелец компиляции raw evidence → `BlockingProfile`

**Конфликт:** ABD v1.2 делегирует компиляцию ABD, тогда как DDI/TGB местами описывает compiler как deliverable DDI.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

ABD является единственным владельцем цепочки:

```text
raw active/passive evidence
→ normalized evidence graph
→ failure attribution
→ blocking hypotheses
→ immutable BlockingProfile
```

DDI не реализует второй compiler и не меняет semantics `BlockingProfile`. DDI владеет только:

```text
profile envelope/version
freshness и expiry
NetworkContextID/ConfigGeneration compatibility
persistence
revalidation
selection
delivery в guided Discovery
```

DDI может отклонить stale/incompatible profile, но не перекомпилирует evidence и не повышает confidence.

**Обязательные правки:**

- заменить DDI-owned compiler wording на consumer/integration contract;
- запретить duplicate `BlockingProfile` schemas;
- добавить static ownership check и production reachability test `ABD output → DDI store → Discovery input`.

---

### 2. ADR-WARP: семь или шесть решений

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

СНЯТ (ложное срабатывание): changelog-секции в WARP addendum v1.2 не существует (grep «changelog» — 0 совпадений); утверждение «changelog v1.2 говорит 1..6» (findings_draft.md:45) ошибочно. Нормативны `ADR-WARP-1`…`ADR-WARP-7`, включая geo-attestation ADR (строки 398-1454). Правок не требуется.

Changelog не является источником, способным отменить ADR.

---

### 3. Срок жизни legacy `/api/watchdog/*`

**Конфликт:** Monitoring должен стать единственным source of truth, но календарный deadline legacy API отсутствует.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Cutover является **событийным**, а не привязанным к произвольной дате.

#### До authoritative cutover

Legacy endpoint может существовать только в shadow/read-only compatibility режиме и не имеет права:

- менять config;
- создавать sets;
- запускать direct Discovery apply;
- владеть scheduler/state;
- выполнять promotion/rollback.

#### Условие cutover

Cutover выполняется после одновременного прохождения:

```text
Monitoring shadow parity
+ scheduler readiness
+ ABD/DDI integration readiness
+ transactional apply path readiness
+ rollback readiness
+ API migration tests
```

#### После cutover

- любые legacy `POST/PUT/PATCH/DELETE /api/watchdog/*` возвращают `410 Gone` или стабильную migration error;
- read-only GET alias разрешён максимум один совместимый minor release;
- read-only alias читает Monitoring state и не хранит собственный state;
- затем маршруты полностью удаляются;
- одновременно никогда не допускаются два mutating sources of truth.

`MON_PRODUCTION_READY` запрещён, если хотя бы один legacy mutating path достижим из production router.

---

### 4. `GSOPassToken`: два определения

**Конфликт:** RST/GSO содержит базовый token, CSI — расширенный token с authorization/policy semantics.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Должен существовать один canonical `GSOPassToken`, принадлежащий GSO/runtime boundary, с compact immutable references:

```text
GSOPassToken {
    TokenID
    FlowKey
    ClientHelloID
    ConfigGeneration
    Decision
    StrategyID
    RequiresAction
    AuthorizationID или AuthorizationDigest
    EffectivePolicyID или EffectivePolicyDigest
    CandidateDisposition
    CreatedAt
    ExpiresAt
    ConsumedAt
}
```

В token **не копируются** крупные mutable `Authorization` и `EffectivePolicy` objects. Они разрешаются по immutable ID/digest в current generation.

Обязательные свойства:

- single-use consume;
- exact generation binding;
- flow/client scope binding;
- TTL/expiry;
- replay rejection;
- no reclassification/re-authorization on secondary pass;
- cleanup при generation retirement;
- bounded memory/cardinality.

RST/GSO и CSI должны ссылаться на один schema/type. Второе определение удалить.

---

### 5. Порядок WARP, RST/GSO, PPE и SPF

**Конфликт:** документы пытаются задать одну линейную цепочку, хотя подсистемы относятся к разным плоскостям.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Универсальная цепочка `WARP → RST/GSO → PPE → SPF` отклонена.

#### 5.1. Data plane для обычного router flow

```text
PPE capability/visibility decision
→ capture path (NFQUEUE/TUN/TPROXY)
→ GSO/GRO representation handling при необходимости
→ packet parsing и flow identity
→ CSI-scoped classification
→ authorized RST/packet action при наличии gate
→ TCP/TLS/application progress observation
→ SPF observation
```

Пояснения:

- PPE определяет, видит ли B4X необходимые пакеты; при необходимости flow временно исключается из offload.
- GSO — packet representation concern, а не доменная policy.
- RST action возможен только после classification/authorization; passive RST observation может происходить в ходе progress tracking.
- SPF зависит от достаточной visibility, но не требует физического наличия PPE на платформах без PPE.

#### 5.2. Diagnostic/control plane

```text
SPF и Continuous Monitoring
→ MonitorAssessment
→ ABD diagnostics
→ BlockingProfile
→ DDI-guided Discovery
→ mandatory baselines/controls
→ scoped canary
→ transactional promotion или rollback
```

#### 5.3. Transport escalation

```text
подтверждённая scoped failure
+ healthy controls
+ valid TransportAuthorization
→ optional scoped WARP/MASQUE binding
→ route/path proof
→ progress observation через SPF/MON
```

WARP не является глобальным prerequisite SPF. SPF обязан наблюдать progress как direct path, так и уже авторизованный WARP path.

`require_ppe_proof=true` применяется только когда:

- PPE capability заявлена/включена; и
- решение зависит от bidirectional packet visibility.

Отсутствие PPE на неподдерживаемой платформе переводит proof requirement на эквивалентный capture path, а не блокирует SPF целиком.

---

### 6. IV v1.5: 77, 86 или другое число критериев

**Конфликт:** prose содержит несколько ручных totals, которые расходятся с фактическим registry.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Ни `77`, ни `86`, ни любое другое вручную записанное число не является самостоятельной нормативной истиной.

Единственный source of truth — machine-readable **Exact Source-Stage Registry**.

```text
criteria_total = count(valid canonical registry entries)
```

Требования:

- total в заголовках, summary, reports и UI генерируется автоматически;
- каждый registry entry имеет unique ID, source document, source hash, stage, category и applicability;
- CI падает при duplicate ID, orphan ID, missing source, missing stage или `declared_total != computed_total`;
- исторические counts допустимы только в changelog с явной версией;
- до исправления registry финальная validation считается `BLOCKED`, а не PASS.

---

### 7. IV §23.1: устаревший registry

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Создать один canonical machine-readable Exact Source-Stage Registry, включающий все действующие requirements и acceptance criteria, в том числе поздние IV, FT и SP additions.

§23.1 должен быть:

- удалён как независимый source of truth; либо
- генерироваться автоматически из canonical registry.

Обязательный validator проверяет:

```text
unique IDs
complete document coverage
valid source hashes
stage coverage
no orphan requirements
no duplicate semantics under different IDs
no missing verdict dependency
```

---

### 8. Ссылки на старые версии документов

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Все normative cross-references обновляются до актуальных версий:

- Architecture v2.4;
- WARP/MASQUE v1.2;
- Service Profiles v1.6;
- ABD v1.2;
- DDI/TGB v1.0;
- Silent Path v1.0;
- Field Test v1.5;
- Implementation Validation v1.5.

Historical versions разрешены только в changelog и migration notes и должны быть явно помечены `historical/non-normative`.

CI должен обнаруживать stale normative references.

---

### 9. `WARP_CAUSAL_TRACE_READY`: состав условий

**Конфликт:** WARP v1.2 и IV v1.5 смешивают causal trace с расширенными readiness capabilities.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

`WARP_CAUSAL_TRACE_READY` является **узким composable verdict**, подтверждающим только полную причинную связь:

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

- все required events присутствуют;
- ordering непротиворечив;
- IDs и ConfigGeneration согласованы;
- trace-derived state совпадает с runtime/API state;
- target и controls различимы;
- route/path counters подтверждают выбранный path;
- cleanup/rollback закрывает все owned resources;
- missing/skipped/unknown/stale evidence не считается PASS.

Отдельные verdicts:

```text
WARP_BASE_TRANSPORT_READY
WARP_CAMOUFLAGE_READY
WARP_NESTED_READY
WARP_NON_RU_READY
WARP_ANDROID_VALIDATED
WARP_PRODUCTION_READY
```

Nested WARP, geo/non-RU, camouflage и Android field validation **не входят автоматически** в causal-trace verdict. `WARP_PRODUCTION_READY` агрегирует только применимые verdicts для заявленного release scope.

---

### 10. §28A.4: unhealthy controls против SP-30 DoD

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Обе нормы сохраняются и объединяются в одну canonical causal decision matrix. SP-30 не отменяет базовый запрет §28A.4.

При любом из условий:

```text
unhealthy controls
origin dead/unreachable
reference path unhealthy или inconclusive
stale/cross-network/cross-generation evidence
visibility unknown
scope ambiguity
```

результат может быть только:

```text
blocked-by-safety
rejected
inconclusive
```

Запрещены:

- `eligible-to-test` при unhealthy controls;
- `ActionAuthorization`;
- `TransportAuthorization`;
- production apply/promotion.

Fresh scoped evidence при здоровых controls может дать `eligible-to-test`, но это только разрешение на bounded diagnostic/canary, не production action.

---

### 11. Порог 16 KiB

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

`16 KiB` — безопасный default memory budget `max_reassembly_bytes_per_flow` для Keenetic/OpenWrt-class targets, а не универсальная граница ClientHello, DPI или application data.

Допускается configurable повышение, например до `32 KiB` или другого validated maximum, только при одновременных bounds:

- per-flow;
- per-client;
- global memory;
- segment count;
- timeout;
- concurrent reassemblies.

При превышении configured bound:

```text
explicit bounded abort
+ metric/event
+ safe fail-open/ambiguity result
```

Запрещён ложный `complete` verdict.

Validation matrix должна включать small, boundary, above-boundary и configured-maximum cases, включая fragmented/out-of-order/retransmission layouts.

---

### 12. Gate для `gso_mode=classify`

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Вводится отдельный current-generation verdict `GSO_CLASSIFY_READY`.

Он требует:

- корректный NFQUEUE/GSO metadata envelope;
- отсутствие truncation/length/checksum ambiguity;
- GSO ↔ equivalent MSS classification parity;
- IPv4/IPv6 coverage;
- retransmission/out-of-order/idempotency tests;
- queue/user drop budgets;
- CPU/RAM/held-packet budgets;
- current visibility proof, когда PPE включён;
- production reachability через реальный packet entry point.

Поведение:

```text
READY → classify разрешён
UNKNOWN/STALE/FAIL → автоматический downgrade в observe
```

`classify` разрешает только classification на представлении GSO. Он **не разрешает normalization или packet mutation**.

Normalization/action дополнительно требуют:

```text
current ActionAuthorization
+ single-use GSOPassToken
+ GSO_RUNTIME_READY
+ strategy compatibility
+ rollback/cleanup readiness
```

---

### 13. `scoped-hints` против `strict`

**Конфликт:** документы не разделяют identity/correlation hints и destructive authorization.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

#### `strict`

Используется для destructive/production authorization и требует authoritative target identity:

- clear SNI;
- complete reassembled SNI;
- explicit static exact target;
- иной эквивалентный strong identity proof, если он отдельно формализован.

#### `scoped-hints`

Свежие DNS/QUIC hints допускаются для:

- capture candidate selection;
- flow correlation;
- provisional classification;
- diagnostics;
- candidate generation/ranking;
- bounded test eligibility.

Они должны быть exact-scoped по применимым:

```text
ClientKey/FlowKey
ServiceProfileID/SetID
ComponentID/TargetRole
destination + protocol
NetworkContextID
ConfigGeneration
TTL/freshness
```

Обязательны ambiguity handling, contradiction handling и negative-SNI revocation.

**Критическая граница:** DNS/QUIC hint сам по себе никогда не создаёт destructive `ActionAuthorization`, WARP `TransportAuthorization`, production route binding или promotion.

IP/CIDR/port остаются capture-only hints в обоих режимах.

Managed profile может использовать `scoped-hints` для first-flow/ECH/QUIC coverage, но переход к destructive action требует дополнительного authoritative/differential proof согласно Action Planner policy.

User override может ужесточить policy, но не ослабить minimum safety policy profile/runtime.

---

### 14. Telegram zero-byte close

**Конфликт:** одна формулировка допускает `idle_preconnect_expired`, другая запрещает silent fixed-5s drop.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Разделить soft и hard deadline.

#### Soft deadline

```text
zero bytes
→ не closed
→ не handled/claimed
→ park в bounded PendingHandshakeManager
```

Первый байт до hard deadline возвращает connection в normal handshake classification с сохранением prefix и без duplication/loss.

#### Hard deadline

Zero-byte connection может быть завершено только как observable:

```text
idle_preconnect_expired
+ explicit metric/event
+ reason
+ correct socket cleanup
+ pending-budget release
```

Это не `unsupported MTProto`, не successful handle и не silent drop.

Запрещено:

```text
fixed 5-second deadline
→ head == 0
→ handled=true
→ nil connection
```

Field proof должен включать delayed-first-byte > 5 s, partial prefix, client close, cancellation, reload/shutdown и pending-budget exhaustion.

---

## 3. Обязательные действия coding-agent после FB-14

1. Внести решения в canonical normative documents; не ограничиваться этим файлом.
2. Для каждого конфликта указать изменённые документы, sections и hashes.
3. Удалить либо пометить `superseded` конфликтующие schemas, verdicts, diagrams и prose.
4. Не создавать новые параллельные compatibility schemas без migration owner и removal deadline.
5. Обновить Architecture v2.4 cross-references и dependency diagrams там, где решение уточняет межсистемную границу.
6. Обновить Exact Source-Stage Registry и генерируемые counts.
7. Обновить Field Test/Implementation Validation gates, verdict dependencies и false-PASS resistance.
8. Добавить static checks:
   - duplicate type/schema/verdict;
   - stale version reference;
   - unreachable stage deliverable;
   - config/API field without production consumer;
   - gate without producer/consumer;
   - registry count mismatch.
9. Для каждого поведенческого решения добавить production-root integration test, а не только standalone unit test.
10. Повторно выполнить полный read-only requirement extraction и conflict scan после документальных правок.
11. Финальная code verification разрешена только после фиксации новых normative hashes.

---

## 4. Acceptance criteria закрытия FB-14

FB-14 считается закрытым только если одновременно:

```text
14/14 owner decisions перенесены в canonical documents
+ 0 активных противоречащих normative definitions
+ 0 duplicate canonical schemas
+ 0 stale normative version references
+ registry consistency PASS
+ production reachability requirements добавлены
+ validation/field gates обновлены
+ новый independent conflict scan не находит эти 14 конфликтов
```

Само наличие этого файла не является закрытием FB-14.

---

# 5. FB-18A — постатейная сверка Architecture v2.4 ↔ Implementation Validation v1.5
**Статус:** выполнена статическая двусторонняя сверка consolidated architecture clauses `ARCH-106…ARCH-145` с полным текстом `B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md`.

**Проверенные документы** (хэши пересчитаны 01.08.2026 после FB-14, commit `026ea485`):

```text
B4_FORK_ARCHITECTURE_v2.4.md
sha256: 6df1c1a245158addd7837296c3e927a714970bb761e3f1e7e68064fbecbdc73b
(до FB-14: 815d1069d210e95bbc38fbdda68b93d1ffb106a7ceecfa46c9056fc868cb5e0f)

B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md
sha256: aae0c3e63fb1c2b1fd2fdaa3f9b27662132521cd50a8862240c3f0eea60484b5
(до FB-14: b5ee991995b4a56674204da6e0645245adcc7d01ad53b3baabe6e889af9961b7)
```

**Важно:** число `40` подтверждено для consolidated architecture clauses `§106…§145`. Число `39` для IV не является воспроизводимым canonical total: IV v1.5 одновременно содержит старые и новые suites, stages `IV-1…IV-17`, acceptance criteria до `146` и неполный delta-registry в §58. До создания единого generated registry любые ручные totals считаются informational, а не нормативными.

Эта сверка проверяет **наличие и семантическую согласованность validation contract**, но не доказывает реализацию кода или активность gates.
## 5.1. Сводка результата
| Статус | Количество |
|---|---:|
| `MAPPED` | 23 |
| `PARTIAL` | 9 |
| `MISSING` | 5 |
| `SEMANTIC_MISMATCH` | 3 |
| **Всего ARCH clauses** | **40** |

Следовательно, финальная verification остаётся заблокированной: `17` из `40` consolidated architecture clauses не имеют полного непротиворечивого IV contract.
## 5.2. Полная ARCH → IV crosswalk
| ARCH | Требование | IV coverage | Статус | Решение/обязательная правка |
|---:|---|---|---|---|
| 106 | Effective domain policy | §26.1, §36.2, AC 15–17 | `MAPPED` | Сохранить FB-14 решения для strict/scoped-hints; обновить stale ссылку AC-15 на Architecture v2.4. |
| 107 | Candidate and authorization split | §26.1–26.2, AC 16–19, hard gates | `MAPPED` | Обязать integration test проходить через реальный matcher/authorization path. |
| 108 | Scoped side effects | §26.3–26.4, AC 20/23, CSI gates | `MAPPED` | Проверять полные keys во всех maps/caches/routes, а не только classifier. |
| 109 | Cross-service negative controls | §26.5, §36.3, §42.6, AC 18/36 | `MAPPED` | Same-client controls должны быть release-blocking. |
| 110 | Reassembly correctness path | §26.2, §27.2, AC 19/32 | `MAPPED` | Подтвердить real production reachability reassembled SNI → authorization. |
| 111 | GSO capability model | §27.1–27.6, §42.4, AC 32–33 | `MAPPED` | Сохранить раздельные observe/classify/action verdicts. |
| 112 | Transactional topology | §27.5, §34.1, AC 28/33 | `MAPPED` | Mixed generation и temporary token/queue leaks остаются blocking. |
| 113 | Passive RST | §28.1–28.4, §42.5, AC 26/34 | `MAPPED` | Observe и active modes агрегировать раздельно. |
| 114 | PPE policy | §35.1–35.5, AC 30–31 | `MAPPED` | Default exclude и возврат established flows в offload должны иметь target evidence. |
| 115 | PPE capability and self-test | §35.1/35.3, AC 30–31 | `MAPPED` | Model name не является evidence; dependent active modes требуют current complete visibility. |
| 116 | PPE lifecycle | §35.2–35.4 | `MAPPED` | Добавить foreign-resource and NDM-regeneration proof в release bundle. |
| 117 | Useful progress | §38B.3–38B.6, §42.11, AC 70 | `MAPPED` | Unique-range semantics и GSO/MSS parity обязательны. |
| 118 | Suppressors and differential proof | §38B.2–38B.8, AC 72–76 | `MAPPED` | Каждый suppressor должен иметь positive/negative/mutation test. |
| 119 | Recovery planner | §38B.4–38B.8, §42.12, AC 78–81 | `MAPPED` | Lease scope/TTL/generation/rollback target и no-recursion release-blocking. |
| 120 | Monitoring evolutionary replacement | Нет отдельной suite/stage/registry coverage | `MISSING` | Добавить IV-18 и MON-1…MON-12; проверить strangler cutover и удаление direct apply. |
| 121 | Monitor model | Нет MonitorService/MonitorAssessment contract tests | `MISSING` | Зарегистрировать schemas, full scope key, independent health/diagnostic axes и persistence lifecycle. |
| 122 | Temporal evidence | Нет temporal bucket/recurrence/decay/independence suite | `MISSING` | Добавить bounded temporal/recovery/source-independence tests и demand intake budgets. |
| 123 | Trigger planner | Нет MON→ABD trigger/suppressor/budget gates | `MISSING` | Добавить quick/deep trigger matrix, WAN/visibility/resource suppressors и запрет direct profile/config creation. |
| 124 | Authoritative active diagnosis | §49–§51, IV-14, AC 90–97 | `MAPPED` | Overlay не может удалить mandatory controls/baselines. |
| 125 | Resolution and address outcomes | DNS differential покрыт общо; exact-vs-independent/per-address contract не формализован | `PARTIAL` | Добавить два раздельных experiment types и outcome для каждого A/AAAA; first success не скрывает siblings. |
| 126 | Evidence authority and attribution | AC 92/97/98 частично; authority enum и attribution separation отсутствуют | `PARTIAL` | Валидировать passive/provisional/authoritative/android authority и отдельные ProbeFailureCode/Attribution/Hypothesis/Recommendation. |
| 127 | Stage-aware observers | Observer capability contract отсутствует | `MISSING` | Добавить capability-declared observers; unavailable=no opinion; higher-layer verdict требует соответствующей capability. |
| 128 | BlockingProfile and DDI | §49.1, IV-15, AC 98–100 | `MAPPED` | Согласовать ownership с FB-14 п.1; DDI не компилирует raw evidence. |
| 129 | Guided search | §50.3–50.7, IV-15, AC 100–102 | `MAPPED` | Mandatory baselines/full fallback/controls не могут быть удалены prior-ом. |
| 130 | Transport candidates | §33 и IV-15 покрывают transport/prior общо, но causal family mapping отсутствует | `PARTIAL` | Добавить normative failure-family→candidate-family matrix и запрет broad WARP escalation по DNS/QUIC-only hints. |
| 131 | Telegram bridge | IV-16, §50, §51, AC 104–109 | `MAPPED` | PASS только через TPROXY listener production path и field evidence, не standalone helpers. |
| 132 | Base WARP architecture | §38A, §42.8, IV-17 | `MAPPED` | Bundled/pinned implementation и no runtime download остаются blocking. |
| 133 | WARP scope and path proof | §38A, IV-17, AC 121–124 | `MAPPED` | Route existence не заменяет counter/binding/application proof. |
| 134 | WARP camouflage | §42.9, IV-17, AC 133–134 | `MAPPED` | Отдельная authorization и cutoff; zero established-payload mutation. |
| 135 | Nested WARP and non-RU | §42.10, IV-17, AC 125–132 | `MAPPED` | Отдельный optional verdict, fresh parent/geo/DNS/IPv6 proof. |
| 136 | Causal observability and cleanup | IV-17/§52 требуют causal verdict, но состав смешан с optional nested/non-RU/Android | `SEMANTIC_MISMATCH` | Применить FB-14 п.9: узкий composable causal verdict; optional capability verdicts отдельно. |
| 137 | Declarative Service Profiles | §36.1, §41.5 | `MAPPED` | Compiler только в ordinary B4 objects; preserve manual/pinned/excluded. |
| 138 | Capability projection | §36.2, SP-13/16/20 частично; MON/ABD/canary и полный v1.6 projection не покрыты | `PARTIAL` | Добавить projection всех readiness verdicts и test, что profile может только сузить capability. |
| 139 | Beginner recommendations | §36.5/§41 частично; eligible-to-test→validated state machine и SP-30…32 отсутствуют | `PARTIAL` | Зарегистрировать SP-30…SP-32 и проверить fresh BlockingProfile, controls, causal readiness, Android/path proof, explicit geo requirement. |
| 140 | Profile release rule | §42.6 и SP-19/23 частично | `PARTIAL` | Добавить единый gate: target + unrelated controls + exact scope + current representation/transport proof + rollback readiness. |
| 141 | Capability dependency graph | §53.3 full-run ordering ставит WARP до ABD и полностью пропускает MON | `SEMANTIC_MISMATCH` | Разделить execution scheduling и verdict dependencies; aggregation обязана следовать ARCH graph, TGB может идти параллельно. |
| 142 | Principal verdicts | §52 содержит только часть и иные имена; MON/PPE/CSI/GSO/SPF/profile verdicts отсутствуют | `SEMANTIC_MISMATCH` | Создать canonical verdict registry с alias mapping и dependency expressions для всех ARCH principal verdicts. |
| 143 | Global hard-gate classes | §51 содержит metrics, но нет полной class mapping и MON gate family | `PARTIAL` | Каждый gate: global class + owner + runtime producer + verdict consumer + reset semantics + mutant; FB-03 prerequisite. |
| 144 | Recommended file order (глава XXXVII «Consolidated Implementation Order»; секция — порядок чтения файлов, не implementation-order требование) | §25/§41/§54/§58 частично; §58 «Exact registry» содержит только delta subset | `PARTIAL` | Уточнить маппинг: §144 — file order, а не validation requirement; consolidation registry решается FB-33. |
| 145 | No flag-day migration | L8 содержит общую migration проверку, но нет MON strangler/direct-apply reachability и общих cutover invariants | `PARTIAL` | Добавить per-subsystem shadow/canary/cutover/rollback tests и reverse-reachability legacy paths после cutover. |

## 5.3. Новые подтверждённые расхождения и решения владельца

### FB18-01 — отсутствует umbrella validation Continuous Monitoring

**Расхождение:** Architecture `§120…§123` требует strangler migration, canonical monitor model, temporal evidence и bounded trigger planner. IV v1.5 не регистрирует `MON-1…MON-12`, не имеет отдельной Monitoring suite, Monitoring hard-gate family или `MON_PRODUCTION_READY`.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Добавить самостоятельный stage:

```text
IV-18 — Continuous Monitoring conformance and Watchdog cutover suite
```

Он обязан:

- зарегистрировать `MON-1…MON-12`;
- зарегистрировать `FT-MON-A…FT-MON-J`;
- валидировать ObservationBus, subjects, resolution snapshots, temporal buckets, independence, contradictions, decay, recovery и source health;
- проверить quick/deep trigger budgets и suppressors;
- доказать production chain `MON → ABD → DDI/Discovery`;
- доказать отсутствие `passive observation → direct config mutation`;
- выполнить reverse-reachability audit legacy Watchdog routes/callers;
- блокировать `MON_PRODUCTION_READY`, пока legacy mutating path достижим;
- иметь target, restart, storage-pressure, privacy и validation-of-validation evidence.

---

### FB18-02 — неполный contract resolution/address outcomes

**Расхождение:** Architecture `§125` различает client-observed exact endpoint и independent-current-resolution experiment, требует отдельный outcome для каждого A/AAAA address и запрещает скрывать failures первым success. IV содержит общие DNS differential checks, но не фиксирует этот contract.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Добавить machine-readable experiment kind:

```text
client_observed_exact_endpoint
independent_current_resolution
```

Для каждого terminal A/AAAA address обязательны:

```text
address
family
resolution provenance
selected/not-selected
DNS/TCP/TLS/HTTP/QUIC outcomes
latency
failure attribution
evidence refs
```

Aggregation не имеет права сворачивать sibling failures после первого success. Missing per-address evidence блокирует `ABD_CLIENT_RESOLUTION_READY`.

---

### FB18-03 — не формализованы evidence authority и stage-aware observers

**Расхождение:** Architecture `§126…§127` требует уровни authority, раздельные failure/attribution/hypothesis/recommendation и capability-aware observers. IV не содержит полного observer capability contract.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

IV должен явно тестировать:

```text
passive-monitoring
provisional-fast
authoritative-abd
android-canary
```

и раздельные поля:

```text
ProbeFailureCode
FailureAttribution
BlockingHypothesis
Recommendation
```

Каждый observer публикует capabilities. `observer unavailable` означает `NO_OPINION`, а не failure. TCP/TLS-only observer не может подтвердить HTTP/body hypothesis. Exact-endpoint и independent-resolution observations нельзя смешивать.

Добавить отдельные readiness verdicts:

```text
ABD_CLIENT_RESOLUTION_READY
ABD_MULTI_VANTAGE_READY
```

---

### FB18-04 — отсутствует causal mapping failure family → transport candidate family

**Расхождение:** Architecture `§130` задаёт разные candidate families для IP/SYN/CIDR, DNS, QUIC, SNI/fingerprint и threshold failures. IV проверяет guided priors и transport fallback, но не фиксирует эту причинную матрицу.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Добавить normative matrix:

```text
hypothesis/evidence family
→ eligible candidate families
→ forbidden candidate families
→ mandatory narrower families
→ prerequisites
→ controls
→ target validation
```

Base WARP/SOCKS/TUN допускаются только как scoped `eligible-to-test` для совместимой failure family. DNS-only, QUIC-only или provisional hint не может напрямую авторизовать broad transport escalation.

---

### FB18-05 — неполное покрытие Service Profiles v1.6

**Расхождение:** Architecture `§138…§140` требует projection verdicts всех subsystems, beginner recommendation state machine и строгий profile release rule. IV покрывает ранние SP stages, но не регистрирует `SP-30…SP-32` и не валидирует полный v1.6 recommendation contract.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Добавить в IV registry и suites:

```text
SP-30 — BlockingProfile transport-recommendation compiler
SP-31 — Scoped WARP recommendation UX and validation transaction
SP-32 — WARP recommendation release integration
```

Profile projection должен читать current verdicts classifier/GSO/PPE/SPF/MON/ABD/DDI/WARP/canary и может только сузить capability.

Обязательная recommendation state machine:

```text
not-applicable
unavailable
eligible-to-test
testing
validated
rejected
expired
blocked-by-safety
```

Promotion требует target success, same-client controls, exact side-effect scope, current representation/transport/path proof и rollback readiness.

---

### FB18-06 — run ordering не совпадает с capability dependency graph

**Расхождение:** Architecture `§141` требует `MON → ABD → DDI → canary → WARP recommendation`, тогда как IV §53.3 ставит WARP suites до ABD и полностью пропускает MON.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Разделить:

1. **physical test execution scheduling** — независимые безопасные suites могут выполняться параллельно;
2. **verdict dependency aggregation** — обязана строго следовать Architecture dependency graph.

Canonical dependency expression:

```text
Classifier/Capture
→ CSI + GSO/RST + PPE visibility
→ Progress/SPF
→ MON
→ ABD
→ DDI/Guided Discovery
→ scoped canary/runtime control
→ base WARP causal readiness where selected
→ Service Profile recommendation readiness
```

TGB может выполняться параллельно после своих capture/routing prerequisites. Никакая ранняя WARP suite не удовлетворяет отсутствующий MON/ABD/DDI dependency.

---

### FB18-07 — principal verdict registry неполон и использует несовместимые имена

**Расхождение:** Architecture `§142` перечисляет principal verdicts, но IV §52 содержит только ABD/DDI/TGB/WARP subset. Отсутствуют CSI/GSO/PPE/SPF/MON/profile verdicts; часть имён расходится (`GUIDED_DISCOVERY_READY` vs `DETECTOR_GUIDED_STRATEGY_SEARCH_READY`, `TELEGRAM_BRIDGE_PRODUCTION_READY` vs `TGB_PRODUCTION_READY`).

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Создать один canonical verdict registry с:

```text
canonical name
aliases
owner stage
dependency expression
required gates
required target evidence
blocked variants
expiry/invalidation rules
```

Все principal verdicts Architecture должны иметь запись либо explicit supersession mapping. Alias не создаёт второй state store. API/UI/reports используют canonical name и могут отображать legacy alias только как compatibility metadata.

---

### FB18-08 — hard gates не сведены в global classes и не доказана их активность

**Расхождение:** IV §51 перечисляет множество metrics, Architecture `§143` определяет global hard-gate classes. Между ними нет полной machine-readable mapping; Monitoring gates отсутствуют. Само наличие metric name не доказывает runtime producer/consumer.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Каждый hard gate получает:

```text
GateID
GlobalGateClass
OwnerStage
RuntimeProducer
VerdictConsumer
PromotionBlocker
ResetSemantics
Applicability
TestProducer
MutationTest
Artifact
```

Missing metric не трактуется как zero. Forced-zero, skipped producer и unconsumed gate обязаны обнаруживаться meta-suite.

`FB-03` является обязательным prerequisite executable crosswalk. Пока runtime producer/consumer не доказаны:

```text
status = BLOCKED_BY_FB03
```

а не PASS.

---

### FB18-09 — IV §58 ошибочно называется Exact registry, но содержит только delta subset

**Расхождение:** текущий §58 перечисляет ABD/DDI/TGB/WARP и несколько поздних FT/IV IDs, но не включает Patch Plan, CSI, GSO/RST, PPE, SPF, MON, полный SP/FT и `IV-1…IV-16`. Он не может быть единственным Exact Source-Stage Registry.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

§58 должен быть заменён generated registry всех действующих нормативных документов:

```text
RequirementID
SourceDocument
SourceVersion
SourceSHA256
Section
Stage
Category
Dependencies
Suites
Gates
Verdicts
Applicability
```

Delta registries разрешены только как generated views с явным фильтром, например `view=v1.5-added`. Полный registry обязан включать `MON-1…MON-12`, `FT-MON-A…J`, `SP-30…SP-32` и новый `IV-18`.

Все totals вычисляются из registry. Заявленные `39`, `77`, `86` и другие ручные counts не используются для release decisions.

---

### FB18-10 — no-flag-day migration недостаточно проверяется

**Расхождение:** IV L8 содержит общую migration validation, но Architecture `§145` требует observe/shadow/canary/cutover для каждой крупной subsystem и отключение unsafe legacy direct paths до production readiness.

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

Для каждой крупной subsystem обязательна migration matrix:

```text
legacy
shadow
parity
canary
cutover
legacy mutation disabled
rollback
removal
```

Validation должна доказывать:

- production-root reachability нового path;
- отсутствие production callers старого mutating path;
- restart/reboot не возвращает legacy source of truth;
- API compatibility adapter не хранит собственный state;
- rollback возвращает целостную old generation;
- cutover имеет explicit gate и audit event.

Compilation, standalone helper tests и Markdown reports не являются migration proof.

---

### FB18-11 — порядок выполнения FB-задач

**РЕШЕНИЕ ВЛАДЕЛЬЦА:**

```text
FB-14 canonical document edits
→ FB-18A static crosswalk
→ FB-03 active gate implementation
→ IV-18/MON and other new normative fixes
→ FB-18B executable production crosswalk
→ updated FB backlog
→ remaining implementation fixes
→ full IV/FT execution
→ final independent audit
```

Не допускается завершить все старые `FB-01…FB-27`, а затем впервые выполнять crosswalk: это создаёт повторный цикл и может закрепить реализацию под неполный validation contract.

---

## 5.4. Обязательный FB-18B executable crosswalk

После документальных правок и FB-03 для каждой строки `ARCH-106…ARCH-145` требуется доказать:

```text
ARCH requirement
→ IV requirement
→ registered suite
→ production root
→ full call chain
→ runtime side effect
→ active gate producer
→ verdict consumer
→ cleanup/rollback
→ evidence artifact
```

Статусы:

```text
PASS
FAIL
BLOCKED_BY_CAPABILITY
BLOCKED_BY_TARGET
BLOCKED_BY_FB03
NOT_APPLICABLE
```

`MAPPED` из FB-18A не является runtime PASS.

---

## 5.5. Новый блокирующий verdict

До завершения FB-18B:

```text
FINAL_VERIFICATION_BLOCKED
reason:
  ARCH_IV_TRACEABILITY_INCOMPLETE
  ACTIVE_GATE_COVERAGE_INCOMPLETE
  MONITORING_VALIDATION_MISSING
  CANONICAL_REGISTRY_INCOMPLETE
```

Ни один общий `B4X_ARCHITECTURE_COMPLIANT`, `FULL_FORK_PASS` или production-ready claim недопустим.

## 6. Обновлённые acceptance criteria после FB-18A

Предыдущие критерии раздела 4 сохраняются, но недостаточны для начала финальной verification.

Финальная verification разрешена только если:

```text
FB-14 decisions merged into canonical documents
+ FB-18A crosswalk discrepancies resolved
+ IV-18/MON coverage implemented
+ canonical registry complete
+ principal verdict registry reconciled
+ every hard gate has active producer and consumer
+ FB-03 PASS
+ FB-18B executable crosswalk complete
+ no MISSING/PARTIAL/SEMANTIC_MISMATCH for applicable ARCH-106…145
```
