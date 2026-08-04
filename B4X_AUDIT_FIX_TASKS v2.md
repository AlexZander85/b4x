# B4X — ЗАДАНИЕ НА ИСПРАВЛЕНИЕ ПО ИТОГАМ АУДИТА

**Репозиторий:** AlexZander85/b4x, ветка `agent/classifier-v2.3-capture-envelope`  
**База:** B4 1.73.0 (commit `7160ee8f...`); аудит выполнялся на рабочем дереве HEAD `49a73e17...` + 33 untracked, без доступного `.git` metadata  
**Дата аудита:** 31.07.2026  
**Вердикт аудита:** `B4X_NOT_COMPLIANT`  
**Редакция задания:** remediation revision 2 — синхронизирована с `B4X_FB14_CONFLICTS_RESOLVED.md` и статическим crosswalk `B4X_FB18_ARCH_IV_CROSSWALK.json`  
**Назначение:** исправить подтверждённые нарушения, подключить декларативные подсистемы к production call chain, восстановить executable validation и только после этого повторно пройти независимый аудит.

**Обязательные источники при работе:**

- `artifacts/audit/B4X_AUDIT_VERDICT.md`;
- `artifacts/audit/B4X_FIX_BACKLOG.md`;
- `artifacts/audit/B4X_FINDINGS_CATALOG.md`;
- `artifacts/audit/hard_gates_audit.md`;
- `artifacts/audit/warp_audit.md`;
- `artifacts/audit/mon_abd_ddi_audit.md`;
- `artifacts/audit/csi_ppe_rstgso_audit.md`;
- `artifacts/audit/sp_ft_spf_audit.md`;
- `artifacts/audit/patch_plan_audit.md`;
- `artifacts/audit/patch_plan_quality.md`;
- `artifacts/audit/test_quality_audit.md`;
- `artifacts/audit/req_index_part1.md`, `req_index_part2.md`, `req_index_part3.md`;
- `artifacts/audit/findings_draft.md`;
- `artifacts/audit/reachability/**`;
- `B4X_FB14_CONFLICTS_RESOLVED.md` — authoritative owner decisions до переноса в canonical documents;
- `B4X_FB18_ARCH_IV_CROSSWALK.json` — machine-readable результат FB-18A.

**Нормативный приоритет при расхождении:**

```text
безопасность и фактическая runtime-корректность
→ B4X_FB14_CONFLICTS_RESOLVED.md owner decisions
→ B4_FORK_ARCHITECTURE_v2.4.md
→ актуальные companion addenda
→ B4_FORK_PATCH_PLAN.md
→ Implementation Validation / Field Test contracts
→ audit findings и remediation guidance
```

Audit finding устанавливает наличие проблемы, но не имеет права отменять более безопасное owner decision или создавать новый небезопасный runtime contract.

---

## СТАТУС ВЫПОЛНЕНИЯ (синхронизировано с Beads, 03.08.2026)

| FB | Статус | Подтверждение |
|---:|---|---|
| FB-01 | ВЫПОЛНЕНА | Beads b4x-end, closed 03.08; тест уже использует &cfg, vet + test + -race PASS |
| FB-02 | поставка 04.08 (частично) | WARP base-transport lifecycle runtime (controller loop: enrollment/restart/apply-route/control/rollback, bounded 3/64, mark ownership, atomic destination set, causal-trace redaction) + 10 verified §72 hard-gate producers (negative fixtures) + registry 283 gates / 45 applicable (10 warp; FB-29/30 producers re-declared в генераторе, yaml↔gen.go синхронизированы; mon_production_ready сохранён через EXTRA_GATES) + meta/applicable 35→45 + matrix (45 verified / 238 missing) + интеграция в main (SetWarpRuntime); full CI PASS; commits 790c8f6f + 26d8a139; Beads b4x-jjh. 04.08 (part 2, SPF): + 22 verified §45 SPF producers (src/silentpath/hard_gate_producers.go lifecycle guards: authorization/visibility/cross-*/correlation/recovery/rollback) + negative fixtures + registry/applicable 45→67 + matrix (67 verified / 216 missing); commits fed07a5d + 5ed181ea. 04.08 (part 2, DDI/TGB): + 24 verified §32/§33 producers (14 discovery guards src/discovery/hard_gate_producers.go: context/revalidation/WAN/hint/target/promotion; 10 bridge guards src/mtproto/hard_gate_producers.go: pending/prefix/route/failure/shutdown) + negative fixtures + registry/applicable 67→91 + matrix (91 verified / 192 missing); Beads b4x-61d |
| FB-03 | поставка 04.08 (частично) | b4-validate CLI (list / plan full / full --profile release / requirement / meta) + узкий causal verdict (10 warp base_transport gates, FB-14 п.9) + meta-suite в CLI + FB03_GATE_PRODUCER_CONSUMER_MATRIX.json (283: 35 verified / 248 missing); runtime producers WARP/SPF/FT/MON — совместно с FB-02/07/27/28; Beads b4x-q58 |
| FB-04 | открыта | — |
| FB-05 | открыта | — |
| FB-06 | ВЫПОЛНЕНА | Beads b4x-4xq, closed 03.08; release.yml: vet + -race + fuzz smoke (27 целей), найден и исправлен int-overflow в readCountryCode |
| FB-07 | открыта | — |
| FB-08 | выполнена | — |
| FB-09 | ВЫПОЛНЕНА | Beads b4x-0to, closed 03.08; tcp_hold_worker.go releaseTCPHoldOnFlowTermination + 3 теста |
| FB-10 | ВЫПОЛНЕНА | Beads b4x-bed, closed 02.08; commit e23ba6ab |
| FB-11 | открыта | — |
| FB-12 | ВЫПОЛНЕНА | Beads b4x-1lb, closed 02.08; commit 5bb47b13 |
| FB-13 | ВЫПОЛНЕНА | Beads b4x-abc, closed 03.08; session_test.go + тест сериализации |
| FB-14 | ВЫПОЛНЕНА | Beads b4x-lv0, closed 04.08; commits 026ea485 (14/14 решений) + 8f9b6b94 (FB-18A пересчёт хэшей); верификация 04.08 — remediation report |
| FB-15 | ВЫПОЛНЕНА | Beads b4x-1yk, closed 03.08; build: swagger gen-defaults build-ui, pnpm 10.29.2 везде |
| FB-16 | ОТМЕНЕНА | перепроверка 31.07: все 104 документа валидный UTF-8, перекодировка не требуется |
| FB-17 | открыта | — |
| FB-18 | FB-18A готов; FB-18B — первая поставка 04.08 (исполняемый реестр 61 требования: 50 PASS / 10 BLOCKED / 1 NA, Beads b4x-c4q); закрытие после FB-03/31/33-36/04/32/02/21/23 | — |
| FB-19 | ВЫПОЛНЕНА | Beads b4x-iir, closed 03.08; quic_test.go + geodat_test.go, найден и исправлен баг в convertV2CidrToText (err != nil) |
| FB-20 | ВЫПОЛНЕНА | Beads b4x-azj, closed 03.08; metrics/ содержит MetricsCollector (687 строк) |
| FB-21 | открыта | — |
| FB-22 | ВЫПОЛНЕНА | Beads b4x-0xa, closed 04.08; nfq drop-path v4/v6: action.Plan+Executor fail-open (action_executor.go), интеграционные тесты |
| FB-23 | открыта | — |
| FB-24 | открыта | — |
| FB-25 | открыта | — |
| FB-26 | открыта | — |
| FB-27 | ВЫПОЛНЕНА | Beads b4x-95i, closed 02.08; commits 53be408a/44beac3c/340ae441 |
| FB-28 | ВЫПОЛНЕНА | Beads b4x-pp4, closed 03.08; IV-18 suite, 24 entries, 57 mon gates |
| FB-29 | ВЫПОЛНЕНА | Beads b4x-04h, closed 02.08; commit 5b0a364e |
| FB-30 | ВЫПОЛНЕНА | Beads b4x-ivz, closed 03.08; commit f1149b3f |
| FB-31 | открыта | — |
| FB-32 | открыта | — |
| FB-33 | открыта | — |
| FB-34 | открыта | — |
| FB-35 | открыта | — |
| FB-36 | открыта | — |
| FB-37 | ВЫПОЛНЕНА | Beads b4x-4vt, closed 03.08; вариант (а) — intentional no-op задокументирован |
| FB-38 | ВЫПОЛНЕНА | Beads b4x-izm, closed 03.08; guard learnedIPAuthorizationAllowed в nfq/handler.go (TCP/UDP legacy-пути), learnedIPCache legacy-only + счётчик в sni/match.go, 2 теста |

---

## 0. ПРАВИЛА РАБОТЫ

### 0.1. Обязательный порядок выполнения

Нельзя выполнять задачи только по плоскому порядку `P0 → P1 → P2`. Используй следующий dependency graph:

```text
FB-14: перенести owner decisions в canonical documents
→ подтвердить/обновить FB-18A static crosswalk
→ FB-03: canonical gate registry + активные producers/consumers + meta-suite
→ FB-07 и FB-28…FB-36: Monitoring/IV/registry/crosswalk normative gaps
→ FB-18B: executable production crosswalk
→ обновить remediation backlog и зависимости
→ остальные P0/P1/P2 implementation fixes
→ полная IV/FT execution
→ target field validation
→ финальный независимый read-only аудит
```

Допускается параллельно до завершения нормативного preflight выполнять локальные независимые исправления, не зависящие от спорной семантики: FB-01, FB-06, FB-08, FB-09, FB-13, FB-15, FB-16, FB-19 и подтверждённые build/test fixes. Нельзя объявлять их завершением общего remediation.

**Итеративная группа FB-02 ↔ FB-07 ↔ FB-28:** эти задачи имеют взаимные зависимости (FB-02 включает MON→ABD/DDI bridge, FB-07 включает ABD/DDI integration, FB-28 зависит от FB-07 и питает его validation). Они исполняются одной совместной итерацией по фазам (FB-07 фаза A → общие schema/суites FB-28 → фазы B–D вместе с FB-02), а не строго линейно одна после другой. Линейный порядок между ними не является обязательным; каждая фаза фиксирует свой criterion до перехода к следующей.

### 0.2. Неизменяемость исходного аудита

1. **Не изменяй `artifacts/audit/**`**, созданные исходным аудитом. Это исторический evidence bundle.
2. Новые отчёты, логи, crosswalk и remediation evidence размещай в:

```text
artifacts/remediation/
```

3. Не меняй статусы в исходных `req_index_*.md`. Создавай новый `artifacts/remediation/requirement_status_after_fix.*`.
4. Restore points размещай в `artifacts/remediation/backup_<UTC_TIMESTAMP>/` либо используй настоящий Git branch/worktree. Не складывай backup в audit bundle.

### 0.3. Нормативные документы

1. Не меняй нормативные документы произвольно.
2. Разрешённые нормативные изменения:
   - FB-14 — перенос всех owner decisions и устранение конфликтов;
   - FB-18/FB-28…FB-36 — исправления, подтверждённые ARCH↔IV crosswalk;
   - FB-21 — согласованная владельцем норма PPE default для новой установки Keenetic NDM + MediaTek;
   - FB-16 — только фиксация факта UTF-8, без перекодировки;
   - иное изменение — только после явного owner decision, записанного в remediation report.
3. Каждая нормативная правка должна содержать `было → стало`, source requirement IDs, новую версию/дату, SHA-256 и migration note.
4. Нельзя исправлять код под старую конфликтующую формулировку, если FB-14 уже задаёт новую семантику.

### 0.4. Запрет самовольного de-scope

Coding-agent не имеет права самостоятельно решать, что обязательная capability, stage или addendum «не входит в релиз», только потому что она не подключена или трудна в реализации.

De-scope допустим только через:

```text
owner decision
→ canonical document revision
→ registry applicability update
→ dependent verdict update
→ API/UI/migration update
→ explicit NOT_APPLICABLE или BLOCKED verdict
```

Без этой цепочки требуемая, но недостижимая subsystem получает `FAIL`, а не удаляется ради зелёной сборки.

### 0.5. Что считается реализацией

Для каждой задачи требуется доказать:

```text
normative requirement
→ production root
→ registration/wiring
→ full call chain
→ runtime side effect
→ failure path
→ cleanup/rollback
→ active gate producer
→ verdict consumer
→ integration/negative/mutation tests
→ evidence artifact tied to commit
```

Не считаются реализацией:

- новый тип/interface/schema без production caller;
- helper, вызываемый только тестом;
- test-only adapter;
- metric name без producer;
- gate без consumer/promotion blocker;
- manually populated `Valid()` object;
- API endpoint без runtime subsystem;
- Markdown readiness report;
- `grep` по имени функции или метрики без выполнения side effect;
- успешный `go test`, не входящий через production root.

### 0.6. Работа с gates и verdicts

1. Gate не обязан быть только Prometheus counter. Canonical runtime state хранится у owner subsystem; Prometheus — экспорт/observability surface.
2. Каждый gate имеет `GateID`, global class, owner, runtime producer, verdict consumer, promotion blocker, reset/expiry semantics, applicability, tests и evidence.
3. Missing producer/consumer, skipped suite, stale generation и unavailable evidence не трактуются как zero/PASS.
4. Zero-tolerance counters обязаны реально становиться non-zero на negative/mutant fixture и блокировать соответствующий verdict.
5. `WARP_CAUSAL_TRACE_READY` — узкий causal verdict. Nested, non-RU, camouflage, Android и production readiness имеют отдельные verdicts согласно FB-14.

### 0.7. Тестовая среда

1. Linux/amd64 Docker — обязательная CI/reference среда, но **не единственная целевая платформа роутера**.
2. Выполни build для всех заявленных `GOOS/GOARCH` targets из Makefile/release workflow.
3. Hardware/PPE/WARP/NDM/forwarded-client claims требуют реального target evidence или честного `BLOCKED_BY_TARGET`.
4. Windows-host не считается runtime target.
5. Любой test/tool, меняющий tracked files, выполняй в disposable clone/worktree; изменение фиксируй как test-isolation defect.

### 0.8. Коммиты и сдача

1. После каждой логически завершённой задачи создай отдельный commit с ID задачи.
2. Перед commit фактически выполни критерий задачи.
3. После каждой задачи должны оставаться зелёными применимые:

```text
go build ./...
go vet ./...
go test -count=1 ./...
```

4. `go test -race` можно группировать по крупным этапам, но перед сдачей обязателен полный прогон.
5. Не меняй assertions и expected results только ради PASS.
6. Не скрывай `BLOCKED_BY_TARGET`, `BLOCKED_BY_CAPABILITY` или `BLOCKED_BY_FB03`.
7. В каждом PR/commit report укажи production root, call chain, tests, gates, cleanup и residual risks.

---
## 0.9. Примечание о сохранении исходного backlog

Все исходные FB-01…FB-27 сохранены по существу. Их findings, affected files и исходные acceptance intentions не отменяются. В этой редакции:

- исправлены conflict-prone instructions;
- усилены production-reachability criteria;
- добавлены подтверждённые FB-28…FB-36;
- изменён dependency order;
- исторические audit artifacts остаются неизменными.

---

## 1. P0 — БЛОКЕРЫ (без них ветка не релизится)

### FB-01. Починить компиляцию тестов capture/ppe [S]
- **Проблема:** `src/capture/ppe/product_bundle_test.go:100-101` — `cfg := config.NewConfig()` (значение `config.Config`) передаётся туда, где нужен `*config.Config` (`NewProductService(func() *config.Config {...})`, `service.ApplyConfig(ctx, cfg)`). `go test ./...` падает: `FAIL capture/ppe [build failed]` — единственный FAIL из 42 пакетов (подтверждено и в `-race`).
- **Что сделать:** поправить тест под реальную сигнатуру (см. сигнатуру `NewProductService`/`ApplyConfig` в `src/capture/ppe/`): использовать указатель (напр. `cfg := config.NewConfig(); svc := NewProductService(func() *config.Config { return &cfg }, ...)` — **сверь точные сигнатуры в коде**, не гадай). Убедись, что тест осмыслен (не `t.Skip`).
- **Критерий:** `go test -count=1 ./capture/...` → PASS; `go test -count=1 ./...` → все 42 пакета OK.
- **Зависит:** —

### FB-02. Интегрировать продуктовый слой `silentpath` / Monitoring / ABD-DDI / WARP / serviceprofile / fieldtest [XL] — РЕШЕНИЕ ВЛАДЕЛЬЦА: полная интеграция

- **Проблема аудита:** пакеты `src/warp` (24 файла), `src/serviceprofile` (17), `src/fieldtest` (26), `src/silentpath` (10) имеют 0 production importers/callers; `go list -deps` от main их не включает; API/CLI/runtime entry points отсутствуют либо декларативны. Требования WARP v1.2, SP v1.6, FT v1.5 и SPF v1.0 не исполняются production-бинарём.
- **Решение владельца:** обязательные подсистемы должны быть интегрированы полностью. Самовольный вариант «не входит в релиз» запрещён.

#### Обязательная архитектурная последовательность

Не использовать старый порядок `WARP → SPF → FT → SP`. Он смешивает data plane, control plane и validation infrastructure.

```text
capture / identity / CSI / GSO-PPE visibility prerequisites
→ useful progress + silentpath observation
→ Continuous Monitoring
→ ABD authoritative diagnosis
→ DDI-guided Discovery
→ scoped canary/runtime transaction
→ optional WARP/MASQUE transport, когда он causal-eligible
→ Service Profile projection/recommendation
```

`fieldtest` подключается поперечно: каждая production subsystem обязана регистрировать реальные suites/gates/evidence по мере интеграции.

#### 1. `src/silentpath`

Подключить к реальному flow/progress path согласно `B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md`:

- `BaselineModel` (SPF-19);
- `RetryCorrelator` (SPF-20);
- `DifferentialProbeController` (SPF-21);
- quarantine (SPF-40);
- thresholds/budgets (SPF-41);
- suppressors;
- same-client controls;
- scoped lease/rollback lifecycle.

Confidence ladder без реального correlation/probe source не считается интеграцией.

#### 2. Monitoring + ABD/DDI bridge

- Monitoring получает bounded observations из production paths и создаёт только `MonitorAssessment`/diagnostic demand.
- Passive observation не создаёт `BlockingProfile`, config mutation или transport binding.
- ABD является единственным owner компиляции raw evidence → immutable `BlockingProfile`.
- DDI хранит/version-check/revalidates profile и передаёт его в guided Discovery, но не создаёт второй compiler.
- Production chain: `SPF/MON → ABD → BlockingProfile → DDI → Discovery` должна иметь integration tests.

#### 3. `src/warp`

Подключить согласно `B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md`, но только после prerequisites:

- enrollment/session lifecycle;
- base transport/TUN/MASQUE path;
- exact scoped `TransportAuthorization`;
- BindingID/RouteTokenID ownership;
- causal trace;
- route/path counters;
- cleanup/rollback;
- separate base/camouflage/nested/non-RU/Android verdicts;
- `warp_trace_secret_leak_total` и другие применимые hard gates с реальными producers/consumers.

WARP не является глобальным prerequisite SPF и не может активироваться по DNS/QUIC hint или одному timeout.

#### 4. `src/serviceprofile`

Подключить согласно SP v1.6:

- deterministic compiler в ordinary B4 objects;
- managed/manual ownership;
- pinned/excluded preservation;
- preview diff;
- transactional apply/rollback;
- capability projection classifier/GSO/PPE/SPF/MON/ABD/DDI/WARP/canary;
- `warp_recommendation` YAML, включая `path_proof_supported`;
- recommendation state machine из FB-32;
- SP-30…SP-32;
- API/UI/import/export/migration.

Profile может только сузить capability. Он не создаёт hidden authorization и не владеет WARP/PPE/NFQUEUE lifecycle.

#### 5. `src/fieldtest`

- runnable local controller: `tools/field-test-controller` / CLI `b4-field-test` (FT-C, FT v1.5 §2234+; preflight/run/compare/validate/canary/rollback/export);
- `Controller` реально вызывает `HardGatesPass`;
- FT-AC (9), FT-AD (7), FT-AE (12) mutant fixtures существуют и исполняются;
- Monitoring suites FT-MON-A…J добавлены;
- suites регистрируются и запускаются через production validation API/CLI;
- hardware suite не заменяется unit test;
- unavailable target возвращает `BLOCKED_BY_TARGET`, не PASS;
- final aggregation использует canonical verdict/gate registry.

- **Критерий:**
  1. `go list -deps` production binary включает применимые packages.
  2. Для каждого package существует реальный root: main/bootstrap, registered HTTP/CLI handler, packet/TUN listener или controller loop.
  3. Integration tests входят через те же roots.
  4. Новые `artifacts/remediation/FB02_*` содержат call graphs и executed evidence.
  5. Исходные audit indexes не изменяются; новый status report показывает requirement transitions.
- **Зависит:** FB-14, FB-03; silentpath/Monitoring portions также зависят от FB-07/FB-28; WARP recommendation — от FB-31/FB-32.

### FB-03. Создать canonical hard-gate registry, активировать runtime producers/consumers и подключить meta-suite [XL]

- **Проблема:** из большого набора требуемых gates production-аудит подтвердил только один активный counter `unrelated_control_action_total`; WARP/SPF/FT/MON gates отсутствуют, не производятся либо не потребляются. `WARP_CAUSAL_TRACE_READY` и `BLOCKED_TARGET_VALIDATION` представлены константами; meta-suite и `fieldtest.HardGatesPass` не вызываются production code.

#### 1. Сначала canonical registry, затем код

Создать один machine-readable gate registry. Для каждого gate:

```text
GateID
CanonicalMetricName (если применимо)
GlobalGateClass
OwnerStage
RuntimeProducer
VerdictConsumer
PromotionBlocker
ResetSemantics
Expiry/GenerationBinding
Applicability
TestProducer
MutationTest
EvidenceArtifact
```

Свести расхождения WARP §73B, IV §38A.9, FT §26 и audit lists через owner decisions FB-14/FB-18. Не выбирать одну старую редакцию `WARP_CAUSAL_TRACE_READY`: реализовать узкий causal verdict и отдельные capability verdicts.

#### 2. Runtime ownership

- Gate state принадлежит subsystem owner.
- Prometheus export отражает state/counter, но не является единственным source of truth.
- Zero-tolerance event counters инкрементируются в реальных violation branches.
- Current readiness gates вычисляются из current generation evidence и инвалидируются при reload/capability loss/expiry.
- Missing metric/producer не считается zero.

#### 3. Producers и consumers

Для каждого применимого gate доказать:

```text
negative fixture
→ production violation branch
→ gate becomes violated/non-zero
→ canonical verdict becomes FAIL/BLOCKED
→ apply/promotion rejected
→ cleanup/rollback
```

Добавить producers для WARP trace/leak/drop/path, SPF safety, FT evidence, GSO/PPE/CSI, Monitoring и других registered families. Не создавать мёртвые metrics.

#### 4. Meta-suite

Подключить `validation/meta.go` и `fieldtest/hard_gates.go` к:

- validation API/CLI;
- release profile execution;
- config/apply readiness;
- canary/promotion decision;
- instance reconfiguration;
- report aggregation.

Meta-suite обязана обнаруживать:

- removed gate;
- forced zero;
- missing producer;
- unconsumed gate;
- skipped required suite;
- stale generation;
- unknown treated as PASS;
- verdict alias backed by separate state.

#### 5. Verdicts

Реально вычислять:

```text
WARP_CAUSAL_TRACE_READY
WARP_BASE_TRANSPORT_READY
WARP_CAMOUFLAGE_READY
WARP_NESTED_READY
WARP_NON_RU_READY
WARP_ANDROID_VALIDATED
WARP_PRODUCTION_READY
BLOCKED_TARGET_VALIDATION
```

и остальные principal verdicts из FB-34. `BLOCKED_TARGET_VALIDATION` должен быть terminal/blocking для capability claim, но не маскировать независимые неприменимые claims.

- **Критерий:**
  1. Canonical gate registry проходит schema/orphan/duplicate validation.
  2. Каждый required gate имеет runtime producer и verdict consumer либо explicit applicability=`not_applicable` с нормативным основанием.
  3. Mutation suite делает каждый gate violated и видит блокировку promotion.
  4. `/metrics`, API и report согласованы с internal state.
  5. Missing/skipped/stale evidence не даёт PASS.
  6. `artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.*` содержит evidence, а не grep-only proof.
- **Зависит:** FB-14 canonical decisions; реализация subsystem-specific producers может завершаться совместно с FB-02/FB-07/FB-27/FB-28.

### FB-04. #277: полностью интегрировать hardened Telegram bridge и убрать silent drop [L]

- **Проблема:** `src/mtproto/transparent.go` сохраняет legacy `(bool, net.Conn)` contract, fixed 5s deadline и `return true, nil` при zero-byte timeout/dial failure. Добавленные TGB types/FSM/pending/route helpers не подключены к TPROXY listener production path.

#### 1. Structured outcome

Заменить legacy boolean semantics на один production contract, совместимый с addendum:

```text
claimed
handoff
parked
rejected
terminal_error
```

Outcome содержит connection/prefix/reason/bytes/wait/route attempts и ownership. Compatibility adapter не имеет права терять distinctions.

#### 2. Zero-byte soft timeout

```text
zero bytes at soft deadline
→ не closed
→ не handled/claimed
→ park в bounded PendingHandshakeManager
```

Pending manager обязан владеть реальным `net.Conn`, cancellation, hard deadline, per-client/global budgets, prefix buffer и cleanup.

#### 3. Hard timeout

Только hard deadline может завершить zero-byte connection как observable:

```text
idle_preconnect_expired
+ metric/event
+ reason
+ socket cleanup
+ pending budget release
```

Это не unsupported MTProto и не successful handle.

#### 4. Dial failure

Dial failure не помещается автоматически в first-byte pending manager, если данные уже получены. Использовать route ladder:

```text
primary route failure
→ bounded next route
→ prefix-preserving handoff/direct fail-open where valid
→ observable terminal outcome
```

Не допускать recursive/unbounded retry и silent socket loss.

#### 5. Production wiring

Доказать цепочку:

```text
TPROXY/listener accept
→ bridge FSM
→ pending manager или handshake decode
→ route ladder
→ prefix-preserving relay/handoff
→ shutdown/reload cleanup
```

- **Критерий:**
  - delayed first byte >5s продолжает соединение;
  - hard timeout observable и освобождает budgets;
  - partial prefix 1–63 bytes сохраняется без loss/duplication;
  - dial fail проходит route ladder/fail-open, не `true,nil`;
  - client close/cancel/reload/shutdown/exhaustion tests PASS;
  - integration test входит через production listener, не напрямую через helper;
  - `ISSUE_277_RESOLVED` остаётся false без Android/target evidence.
- **Зависит:** FB-14 п.14; FB-02 production integration.

### FB-05. #278: использовать detector prior в guided Discovery без обхода safety baselines [M]

- **Проблема:** `src/discovery/hint_planner.go:56` игнорирует `prior`; DDI-6 API и DDI-7/ABD-11 behavior не исполняются.
- **Что сделать:**
  1. Провести `prior` через registered API/schema/runtime.
  2. Использовать prior только для ordering, ranking, bounded budget allocation и candidate-family preference.
  3. Prior не может удалять mandatory baselines, full fallback search, controls, suppressors или mandatory target validation.
  4. Provisional DNS/QUIC hint не может создавать `ActionAuthorization`/`TransportAuthorization`.
  5. Stale/network-mismatched/generation-mismatched prior отклоняется.
- **Критерий:**
  - `_ = prior` отсутствует;
  - тест показывает изменение ranking/order, но не удаление mandatory candidates/controls;
  - stale/malformed prior не влияет на plan;
  - API compatibility/migration tests PASS;
  - production Discovery endpoint/controller реально вызывает planner.
- **Зависит:** FB-14 п.1/13, FB-31 causal mapping.

## 2. P1 — MAJOR

### FB-06. CI: добавить `go vet` и `-race` [S]
- **Проблема:** `.github/workflows/release.yml:90-92` — `go test ./...` без `-race` и без `go vet`. goleak — в 3 файлах (найди через grep `goleak`), fuzz-тесты (25 шт.) не в CI.
- **Что сделать:** в release.yml (и docs.yml при необходимости): `go vet ./...` перед тестами; `go test -race -count=1 ./...`; шаг для fuzz (smoke: `go test -fuzztime=5s -run=^$` по fuzz-целям) — либо задокументируй, почему нет.
- **Критерий:** CI-конфиг содержит vet + race; локальный прогон `go vet ./...` и `go test -race ./...` зелёные (после FB-01).
- **Зависит:** FB-01 (race-прогон PPE).

### FB-07. MON v1.0: реализовать strangler-замену Watchdog и authoritative Monitoring [XL]

- **Проблема:** MON v1.0 не подключён; legacy `applyBatchResults` и direct apply остаются active source of truth; `/api/monitor/v1` отсутствует; Monitoring gates/suites отсутствуют; конфиг-поле `legacy_watchdog_direct_apply` (MON addendum §77, default `false`, при `true` — startup warning) не реализовано; отчёты `docs/reports/mon-11-compatibility-cutover.md` и `docs/reports/mon-12-field-validation.md` содержат ложное утверждение «Direct legacy Watchdog apply remains disabled on the production-safe compatibility path» (независимый аудит B4X-AUDIT-0009): `applyBatchResults` активен (`watchdog/applier.go:18`, `watchdog_heal.go:111`).

#### Фаза A — canonical model и shadow wiring

- ObservationBus с bounded ingestion/backpressure;
- `MonitorSubject`, `MonitorAssessment`, full scope key;
- independent health и diagnostic axes;
- temporal buckets, recurrence, decay, contradiction/source independence;
- persistence/expiry/generation/network-context lifecycle;
- Monitoring не мутирует config и не создаёт BlockingProfile.

Shadow mode:

```text
legacy Watchdog и Monitoring считают
→ mutating owner остаётся только legacy transaction path
→ parity/contradiction evidence собирается
```

- `monitor.DiagnosticScheduler` стартует в `main.go` (production entry, не только в тестах);
- конфиг-поле `legacy_watchdog_direct_apply` (default `false`, при `true` — startup warning), счётчик `monitor_legacy_watchdog_direct_apply_total`;

#### Фаза B — MON→ABD/DDI integration

- bounded quick/deep trigger planner;
- WAN/visibility/resource/suppressor gates;
- production chain `MON → ABD → BlockingProfile → DDI/Discovery`;
- Monitoring не выполняет direct apply;
- API `/api/monitor/v1` и events/status/schema.

#### Фаза C — событийный cutover

Cutover только после:

```text
shadow parity
+ scheduler readiness
+ ABD/DDI readiness
+ transactional apply readiness
+ rollback readiness
+ API migration tests
```

После cutover:

- legacy mutating `/api/watchdog/*` → `410 Gone`/stable migration error;
- read-only alias максимум один minor release и читает Monitoring state;
- `applyBatchResults` и другие legacy direct mutation callers недостижимы;
- restart/reboot не восстанавливает legacy owner;
- отчёты `docs/reports/mon-11-compatibility-cutover.md` и `docs/reports/mon-12-field-validation.md` исправлены: до cutover их утверждение о «direct apply disabled» заменяется фактическим статусом;
- только затем `MON_PRODUCTION_READY` может стать PASS.

#### Фаза D — validation

Реализовать IV-18 и FT-MON-A…J из FB-28.

- **Критерий:**
  - full production chain зарегистрирован;
  - shadow parity/contradiction tests;
  - no passive→direct mutation test;
  - reverse-call analysis показывает 0 production callers legacy mutating path после cutover;
  - API migration/restart/rollback/storage-pressure/privacy tests;
  - `MON_PRODUCTION_READY` зависит от active gates и не является константой.
- **Зависит:** FB-14 п.3, FB-03, FB-28; integration with ABD/DDI — FB-02.

### FB-08. Не держать глобальный mutex на всю canary-транзакцию [M] **— ВЫПОЛНЕНО** (Beads b4x-vt3, 03.08)

- **Проблема:** `RolloutManager.Apply` держит `m.mu` во время canary до 1h; cancel/rollback/status/abort могут блокироваться.
- **Что сделать:** реализовать explicit transaction state machine:

```text
prepare under lock
→ reserve generation/transaction ID
→ release global lock
→ run canary under per-transaction ownership
→ re-acquire lock for compare-and-commit
```

Требования:

- commit/last-good/cooldown transitions сериализованы;
- stale compare-and-commit отклоняется;
- rollback/cancel активного canary обрабатывается быстро;
- новый Prepare не обязан запускать параллельную incompatible transaction: он может быстро вернуть `BUSY`/generation conflict;
- Close/AbortPending не зависают до MaxCanaryDuration;
- no mixed generation/resource ownership.

- **Критерий:** concurrency/race tests показывают быстрый status/cancel/rollback; incompatible Prepare быстро получает deterministic result; last-good/rollback invariants сохранены; `go test -race ./runtimecontrol/...` PASS.
- **Зависит:** —

### FB-09. Abort hold на FIN/RST [M] **— ВЫПОЛНЕНО** (Beads b4x-0to, 03.08)
- **Проблема:** `src/nfq/tcp_hold_config.go:17-18` — константы `tcpHoldAbortFIN`/`tcpHoldAbortRST` объявлены, нигде не используются (grep = 2 совпадения — только объявления). На FIN/RST held-пакет не релизится явно — висит до таймаута 750ms (fail-open сохранён, но инвариант hold не исполняется).
- **Что сделать:** реализовать пути abort hold: при FIN/RST на held-потоке — немедленный релиз/отмена hold по правилам ARCH §42-45; покрыть тестами (FIN и RST).
- **Критерий:** тесты: FIN/RST на held-потоке завершают hold немедленно (не по таймауту); существующие nfq-тесты (113 файлов) PASS.
- **Зависит:** —

### FB-10. CSI-15: единый compact immutable `GSOPassToken` [M] **— ВЫПОЛНЕНО** (Beads b4x-bed, 02.08, e23ba6ab)

- **Проблема:** текущий token не несёт canonical authorization/policy references; RST/GSO и CSI задают разные schemas.
- **Что сделать:** реализовать один type согласно FB-14:

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

Не копировать полные mutable `Authorization`/`EffectivePolicy` objects. Resolve возможен только по immutable current-generation ID/digest.

Обязательные semantics:

- single-use consume;
- exact flow/client/generation binding;
- expiry;
- replay rejection;
- no reclassification/re-authorization on secondary pass;
- bounded storage;
- cleanup при generation retirement;
- canonical serialization/schema и migration старого token, если persistence существует.

- **Критерий:** tests на serialization плюс consume/replay/stale generation/wrong flow/expiry/retirement cleanup; RST/GSO и CSI импортируют один type; duplicate schema отсутствует.
- **Зависит:** FB-14 п.4; FB-27 для full GSO runtime integration.

### FB-11. Подключить `CaptureEnvelopeEnabled` к production behavior либо выполнить owner-approved de-scope [M]

- **Проблема:** флаг отображается в diagnostics/UI diff, но не влияет на packet capture/table topology.
- **Что сделать:** предпочтительный путь — подключить флаг к реальному capture envelope:
  - topology/marks/rules;
  - SYN/SYN-ACK/FIN/RST/first-N/QUIC observation;
  - capability/readiness/status;
  - transactional apply/rollback;
  - generation-bound behavior.

Удаление допускается только после отдельного owner decision и полного normative de-scope по правилу 0.4. Coding-agent не может удалить обязательную Stage 4 capability самостоятельно.

- **Критерий:** переключение флага меняет observed production topology/behavior и имеет integration/rollback tests; либо приложен owner-approved de-scope bundle с registry/verdict/API/UI/migration updates.
- **Зависит:** FB-14, FB-18B.

### FB-12. PPE self-test: авто-старт при `mode: startup-and-change` [M] **— ВЫПОЛНЕНО** (Beads b4x-1lb, 02.08, 5bb47b13)
- **Проблема:** self-test стартует только через HTTP (`src/capture/ppe/capture_offload_product.go:183`); при `mode: startup-and-change` авто-запуск не подключён (`reconciler.go:122`).
- **Что сделать:** при активации режима запускать self-test автоматически (реконсиляция/старт сервиса), результат — в статус; покрыть тестом.
- **Критерий:** тест: при конфиге `mode=startup-and-change` self-test выполняется без HTTP-вызова; статус содержит результат.
- **Зависит:** —

### FB-13. Коллизия JSON-тегов в fieldtest [S] **— ВЫПОЛНЕНО** (Beads b4x-abc, 03.08)
- **Проблема:** `src/fieldtest/session.go:59` — `ConfigGen, RouteGen, SessionGen uint64` — все три `json:"config_gen,omitempty"` (vet error). Потеря RouteGen/SessionGen при сериализации трассы (норма FT v1.5: трасса несёт ConfigGen/RouteGen/SessionGen).
- **Что сделать:** развести теги (`config_gen`, `route_gen`, `session_gen`); проверить обратную совместимость сериализации (схема трассы FT) — обновить схему/тесты.
- **Критерий:** `go vet ./...` чист; тест сериализации события трассы сохраняет все 3 поля.
- **Зависит:** —

### FB-14. Перенести все owner decisions из `B4X_FB14_CONFLICTS_RESOLVED.md` в canonical documents [XL, PRE-FLIGHT] **— ВЫПОЛНЕНО** (Beads b4x-lv0, 04.08)

- **Проблема:** исходный audit backlog содержит старые defaults. Они superseded и не должны применяться.
- **Authoritative input:** полный `B4X_FB14_CONFLICTS_RESOLVED.md`, включая FB-18A appendix.

#### Обязательные 14 решения

1. **DDI-4 ownership:** ABD — единственный compiler raw evidence → `BlockingProfile`; DDI только envelope/freshness/persistence/revalidation/delivery.
2. **ADR-WARP:** нормативны ADR-WARP-1…7 (строки 398/463/509/632/889/1199/1379); «changelog 1..6» — ложное срабатывание аудита: changelog-секции в WARP v1.2 не существует (grep «changelog» — 0 совпадений); конфликт снят, правок не требуется.
3. **Legacy Watchdog API:** event-driven cutover; после authoritative Monitoring mutating routes недоступны, read-only alias ограничен одним minor release.
4. **GSOPassToken:** один compact immutable token с IDs/digests, single-use и generation binding.
5. **Subsystem order:** разделить data plane, diagnostic/control plane и transport escalation; универсальная `WARP→RST/GSO→PPE→SPF` запрещена.
6. **IV totals:** totals только generated из canonical registry; ручные 39/77/86/146 не участвуют в release decision.
7. **IV registry:** один Exact Source-Stage Registry; stale/delta sections только generated views.
8. **Version references:** Architecture v2.4, WARP v1.2, SP v1.6, ABD v1.2, DDI/TGB v1.0, SPF v1.0, FT/IV v1.5.
9. **WARP causal verdict:** узкий `WARP_CAUSAL_TRACE_READY`; base/camouflage/nested/non-RU/Android/production verdicts отдельно.
10. **Unhealthy controls:** базовый запрет и SP-30 объединяются; unhealthy/inconclusive/unknown всегда block action/promotion.
11. **16 KiB:** default bounded reassembly memory budget, не protocol threshold; configurable validated maximum с global bounds.
12. **GSO classify:** `GSO_CLASSIFY_READY`; classify не разрешает normalization/mutation; action требует additional gates/token/authorization.
13. **strict/scoped-hints:** hints provisional; hint-only destructive authorization запрещён.
14. **Telegram zero-byte:** soft timeout parks, hard timeout only observable cleanup; fixed-5s handled/drop запрещён.

#### Документальная работа

Для каждого решения:

- найти все conflicting definitions;
- выбрать canonical owner/schema;
- внести `было → стало`;
- удалить/пометить `superseded` старую норму;
- обновить diagrams, API/schema/verdict names, registry entries, version/hash;
- обновить migration/compatibility note;
- добавить static conflict check.

#### Критерий

```text
14/14 decisions merged into canonical documents
+ 0 active conflicting definitions
+ 0 duplicate canonical schemas
+ 0 stale normative version references
+ generated registry consistency PASS
+ new SHA-256 recorded
+ independent conflict scan finds none of the 14 conflicts
```

Сам файл resolutions не закрывает FB-14 без canonical edits.

- **Зависит:** —; выполнить до задач, зависящих от спорной semantics. FB-04/FB-10 являются downstream, не prerequisites.

## 3. P2 — MINOR / ЧИСТКА

### FB-15. Сборка из свежего клона [S]
- **Проблема:** `src/http/ui/dist/` и `src/http/ui/src/models/defaults.json` gitignored; Makefile `build` не зависит от `build-ui`/`gen-defaults` → `make build` падает (`go:embed ui/dist/*` — `src/http/server.go:24`).
- **Что сделать:** Makefile: `build: swagger gen-defaults build-ui ...` (или закоммитить сгенерированные ассеты — реши, дефолт: зависимости в Makefile). pnpm packageManager пинит 10.29.2 (установлен 9.15.9) — синхронизировать (corepack или обновить пин).
- **Критерий:** в свежем клоне `make build` (Linux) проходит без ручных шагов.
- **Зависит:** —

### FB-16. Кодировки: ОТМЕНЕНО — все документы уже UTF-8 [S]
- **Перепроверка 31.07 (строгая):** все 10 `B4_*.md`, 2 `B4X_*.md` и все 92 файла `docs/**` (104 файла) — **валидный UTF-8** (декодер с `throwOnInvalidBytes=true` не нашёл ни одного невалидного байта). Включая `B4_FORK_PATCH_PLAN.md`, `B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md` и `docs/audit/b4-1.73-flow-path.md`, которые в ранних артефактах аудита были ошибочно помечены как cp866 (вероятная причина: чтение через консоль с ANSI-декодированием).
- **Что сделать:** перекодировка НЕ требуется. Задача сводится к: (а) НЕ выполнять никаких перекодировок; (б) при обновлении артефактов аудита (например, в новом `arch_iv_audit.md` или заметках) указывать корректный факт «все документы UTF-8»; (в) в `B4X_AUDIT_VERDICT.md`/`B4X_FIX_BACKLOG.md`/`findings_draft.md` упоминания cp866 являются устаревшими — не удалять их из эталонов без отдельного решения владельца, но и не действовать по ним.
- **Критерий:** ни один файл не перекодирован; любые новые записи об аудите утверждают «все документы — UTF-8».
- **Зависит:** —

### FB-17. Нормативные правки в src/warp [S]
- **Проблема (внутри мёртвого пакета):** geo TTL 300s вместо нормы 120s (`src/warp/geo.go:52`); `InnerRevokedBeforeParent` не проверяется (`src/warp/isolation.go:16`); `CandidateResult.ExpiresAt` не заполняется (`src/warp/selection.go:15`).
- **Что сделать:** исправить 3 места + тесты. (Актуально только в рамках FB-02 полной интеграции.)
- **Критерий:** тесты warp: TTL=120s, inner-revoke блокирует, ExpiresAt заполнен; 19/19 PASS.
- **Зависит:** FB-02.

### FB-18. ARCH v2.4 ↔ IV v1.5: FB-18A static crosswalk и FB-18B executable production crosswalk [XL, BLOCKING]

#### FB-18A — статическая сверка

Статическая двусторонняя сверка уже выполнена и поставляется в:

```text
B4X_FB18_ARCH_IV_CROSSWALK.json
B4X_FB14_CONFLICTS_RESOLVED.md, раздел FB-18A
```

Baseline: 40 consolidated ARCH clauses; 23 MAPPED, 9 PARTIAL, 5 MISSING, 3 SEMANTIC_MISMATCH. Ручное число «39 IV requirements» не является canonical total.

**Важно (объём «40»):** число 40 относится только к consolidated clauses §106–145. Главные инварианты ARCH §5.1–5.17 и hold/replay §42–45 (из индекса аудита `req_index_part3.md`, разделы 5.1–5.3) в это число НЕ входят и отдельно перечислены в `B4X_FB18_ARCH_IV_CROSSWALK.json` → `additional_requirements`. FB-18B обязан покрыть и их (объединённый crosswalk: 40 clauses + 17 инвариантов + 4 hold/replay).

Coding-agent обязан после FB-14:

- пересчитать crosswalk по новым hashes;
- подтвердить, что 40 ARCH clauses всё ещё корректно извлечены;
- не считать `MAPPED` runtime PASS;
- внести новые нормативные tasks FB-28…FB-36.

#### FB-18B — executable crosswalk

После FB-03 и реализации новых validation contracts для каждого применимого требования из объединённого crosswalk — consolidated clauses ARCH-106…145 + главные инварианты §5.1–5.17 + hold/replay §42–45 (полный список: `B4X_FB18_ARCH_IV_CROSSWALK.json`) — доказать:

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

Нельзя использовать только `MAPPED`, grep, unit helper или report claim.

- **Критерий:**
  - updated machine-readable crosswalk tied to current commit/document hashes;
  - 0 applicable MISSING/PARTIAL/SEMANTIC_MISMATCH;
  - every PASS has production-root evidence;
  - gaps добавлены в updated backlog до продолжения remaining fixes;
  - `FINAL_VERIFICATION_BLOCKED` снимается только после FB-18B.
- **Зависит:** FB-14, FB-03, FB-07, FB-28…FB-36, FB-09/FB-27 where applicable.

### FB-19. Добавить meaningful tests для geodat и QUIC [M]

- **Проблема:** активные `src/geodat` и `src/quic` не имеют тестов.
- **Что сделать:** покрыть не просто >0%, а ключевые semantics:
  - geodat decode/invalid/truncated/oversized input;
  - deterministic domain/IP matching;
  - memory/bounds/no duplicate copies where applicable;
  - QUIC parsing/version/Initial/error paths;
  - malformed/truncated/coalesced packets;
  - destination/client scope and cache expiry;
  - no panic/property/fuzz smoke.
- **Критерий:** `go test ./geodat/... ./quic/...` PASS; coverage report перечисляет critical functions; malformed/fuzz corpus исполняется; mutation/no-op replacement хотя бы ключевого decision function обнаруживается тестом.
- **Зависит:** —

### FB-20. Пустой пакет metrics [S] **— ВЫПОЛНЕНО** (Beads b4x-azj, 03.08)
- **Проблема:** `src/metrics/` — пустой пакет (коллектор живёт в `http/handler`).
- **Что сделать:** ASSUMPTION (владелец решение не дал, выбран безопасный дефолт): удалить пустой пакет, импорты поправить; ничего не переносить. Если при удалении обнаружится, что пакет используется — оставить и задокументировать.
- **Критерий:** `go build ./...` OK; пакета-пустышки нет (или задокументированное использование).
- **Зависит:** —

### FB-21. PPE: безопасное авто-включение per-flow exclusion на новой установке Keenetic NDM + MediaTek [M] — РЕШЕНИЕ ВЛАДЕЛЬЦА

- **Требование владельца:** основная опция аппаратного offload включена по умолчанию только для новой установки, когда подтверждены Keenetic/NDM + MediaTek SoC + capability support. В остальных случаях default `detect`. Явный выбор пользователя не перетирается.
- **Существующая база:** detector/UI/policy/reconciler уже присутствуют; `disable-global` остаётся debug-only и никогда не включается автоматически.

#### Условия auto-exclude

Все условия обязательны:

```text
new installation / migration has no explicit user choice
+ NDM confirmed
+ MediaTek/MT762 family confirmed
+ per-flow exclusion capability probe PASS
+ transactional prepare succeeds
+ visibility self-test PASS
+ rollback target exists
```

При UNKNOWN/FAIL любого условия:

```text
offload_policy=detect
```

Нельзя сначала безусловно включить exclusion, а затем лишь сообщить failure self-test. Self-test является pre-commit readiness condition; временные rules принадлежат transaction и очищаются при fail.

#### Что сделать

1. Ввести persisted tri-state/provenance explicit choice: unset/auto, user-detect, user-exclude.
2. Миграция новых установок выполняет hardware/capability detection и staged self-test.
3. User OFF сохраняется при всех следующих стартах/upgrades.
4. Non-Keenetic/non-MediaTek/unsupported → detect.
5. Port=0 не ломает self-test; HTTP UI не является prerequisite PPE service.
6. Обновить addendum §3.2/§10 как согласованную нормативную правку.
7. Добавить restart/reboot/rollback/NDM regeneration tests.

- **Критерий:** NDM+MediaTek+probe+self-test → committed exclude; failure/unknown → detect и 0 leaked rules; user detect не перетирается; `disable-global` никогда auto; target-side proof или `BLOCKED_BY_TARGET`.
- **Зависит:** FB-12, FB-03 PPE gates; нормативная правка разрешена правилом 0.3.

### FB-22. Stage 19: подключить action/executor.go в production NFQ-путь [M] **— ВЫПОЛНЕНО** (Beads b4x-0xa, 04.08)
- **Проблема:** `src/action/executor.go` («centralized packet builder» по PATCH_PLAN Stage 19) вызывается только из тестов; в production пути NFQ не используется.
- **Что сделать:** подключить executor в реальный путь обработки (nfq handler → action executor), сохранив fail-open; покрыть интеграционным тестом. Детали: `patch_plan_audit.md` (Stage 19).
- **Критерий:** executor достижим из nfq-пути (не только тесты); интеграционный тест PASS.
- **Зависит:** —

### FB-23. Stage 33: подключить `routing.FallbackManager` только через authorized transactional transport path [L]

- **Проблема:** manager не подключён к NFQ/TUN production decisions.
- **Что сделать:** подключить цепочку:

```text
confirmed scoped failure
+ healthy controls
+ compatible failure-family mapping
+ valid TransportAuthorization
→ transactional route/binding prepare
→ bounded canary/path proof
→ promote или rollback
```

Запрещено:

- destination-global state;
- single-timeout fallback;
- DNS/QUIC hint-only authorization;
- recursive fallback;
- second direct-apply engine вне runtimecontrol;
- route existence как единственный path proof.

- **Критерий:** production NFQ/TUN/controller root вызывает manager после authorization; negative controls reject; canary/rollback/cleanup tests; no leaked marks/routes; exact client/service/component/generation scope.
- **Зависит:** FB-02 silentpath/MON/ABD/DDI, FB-31, runtimecontrol readiness.

### FB-24. Stage 23: подключить adaptive matrix и shadow probes к production Discovery [M]

- **Проблема:** `RunAdaptiveMatrix` вызывается только тестом; `MaxShadowProbes` не потребляется.
- **Что сделать:** подключить к registered Discovery controller/API/runtime. Matrix должна:
  - принимать current compatible BlockingProfile/prior;
  - использовать prior только для ranking/budget;
  - сохранять mandatory baselines, controls и full fallback family;
  - иметь bounded concurrency/time/resource budgets;
  - публиковать evidence и cancellation/cleanup;
  - не выполнять direct apply; winner проходит canary/runtimecontrol.

Самовольное удаление/de-scope запрещено. Если capability действительно отменяется владельцем, применить полный процесс 0.4.

- **Критерий:** root-to-matrix integration test; MaxShadowProbes влияет на bounded execution; mandatory candidates не исчезают; cancellation/reload cleanup; no direct promotion.
- **Зависит:** FB-05, FB-02 ABD/DDI, FB-31.

### FB-25. Stages 25/26: подключить real ClientHello lab capture и `FakeProfileCompiler` [L]

- **Проблема:** `SetClientHelloSink` не wired; sink nil; lab API пуст; compiler test-only.
- **Что сделать:**
  1. Зарегистрировать bounded generation-scoped sink при bootstrap/runtime apply.
  2. Реальный packet path передаёт eligible ClientHello segments после privacy/scope filters.
  3. Capture start/stop/status/API имеют auth, quotas, TTL, cleanup и secret/privacy handling.
  4. Reassembly/capture artifacts не смешиваются между clients/generations.
  5. `FakeProfileCompiler` подключить к explicit lab/catalog workflow; output проходит schema validation, preview и не auto-promotes.
  6. Restart/reload/cancel очищают sink и buffers.

Самовольный de-scope запрещён; owner-approved de-scope требует процесса 0.4.

- **Критерий:** integration test через NFQ root → sink → lab API → compiler preview; non-eligible traffic не сохраняется; quotas/cleanup/privacy tests; sink non-nil только при active authorized session.
- **Зависит:** capture envelope/reassembly readiness, FB-11; compiler output uses FB-22 executor semantics.

### FB-26. Stages 28–31: интегрировать Level C strategies через centralized executor [L]

- **Проблема:** multisplit, HostFakeSplit, Fake Payload Catalog, FakeMix/TLSRecordSplit существуют только в unit tests; NFQ использует legacy path.
- **Что сделать после FB-22:**
  - зарегистрировать typed strategy capabilities/plans;
  - compile immutable ActionPlan;
  - validate protocol/phase/representation compatibility;
  - enforce ActionAuthorization, packet budgets, single-use tokens where required;
  - use centralized packet builder/checksums/fail-open;
  - expose diagnostics/metrics;
  - add negative/cross-service/GSO/retransmission tests;
  - no direct strategy branch outside executor.

Самовольный de-scope запрещён. Стратегия может быть disabled-by-default/experimental только если это уже допускает normative scope и verdict/UI это отражают.

- **Критерий:** каждая required strategy reachable from production executor; incompatible plan rejected before packet mutation; no legacy duplicate implementation; integration and packet fixtures PASS.
- **Зависит:** FB-22, FB-10/FB-27 where GSO involved.

### FB-27. GSO pipeline: production topology, observe/classify/action gates и transactional lifecycle [XL] **— ВЫПОЛНЕНО** (Beads b4x-95i, 02.08, 53be408a/44beac3c/340ae441)

- **Проблема:** GSO queue topology, normalizer и topology transactions test-only; production pool создаётся без них; normalized metric unreachable.
- **Что сделать:**

#### Observe/classify

- production topology wiring through runtimecontrol;
- `GSO_CLASSIFY_READY` from current metadata/parity/resource/visibility evidence;
- UNKNOWN/STALE/FAIL → automatic downgrade to observe;
- classify does not permit normalization or mutation.

#### Action/normalization

Дополнительно требуют:

```text
ActionAuthorization
+ canonical single-use GSOPassToken
+ GSO_RUNTIME_READY
+ strategy compatibility
+ transactional secondary topology
+ rollback/cleanup readiness
```

#### Lifecycle

- prepare secondary queue/topology;
- readiness/canary;
- atomic cutover;
- old generation retirement;
- queue/token cleanup;
- rollback on drop/budget/capability failure;
- no mixed generation;
- PPE visibility coordination where applicable.

Самовольное de-scope запрещено. Observe-only degraded mode допустим как runtime fallback, но не удовлетворяет required classify/action release claims.

- **Критерий:** NewGSOQueueTopology and transactions reachable through production runtime API; parity IPv4/IPv6/GSO-MSS/retransmission tests; mutation rejected without token/gate; queue/token leak tests; target evidence or explicit BLOCKED_BY_TARGET.
- **Зависит:** FB-03, FB-10, FB-12/PPE visibility, runtimecontrol.

### FB-28. IV-18: Continuous Monitoring conformance and Watchdog cutover suite [XL, P0-NORMATIVE] **— ВЫПОЛНЕНО** (Beads b4x-pp4, 03.08)

- **Проблема:** ARCH-120…123 не имеют отдельной IV suite/stage/registry coverage.
- **Что сделать:** добавить `IV-18` и зарегистрировать `MON-1…MON-12`, `FT-MON-A…FT-MON-J`.
- Suite обязана проверять:
  - ObservationBus and bounded ingestion;
  - full scope subjects/assessments;
  - resolution snapshots;
  - temporal buckets/recurrence/decay/independence/contradictions;
  - source health;
  - quick/deep trigger budgets and suppressors;
  - production chain MON→ABD→DDI;
  - no passive observation→direct mutation;
  - reverse reachability legacy Watchdog;
  - restart/storage pressure/privacy/meta-mutations;
  - event-driven cutover and rollback.
- **Критерий:** registered CLI/API suite executes; mutants are detected; `MON_PRODUCTION_READY` impossible with reachable legacy mutating path.
- **Зависит:** FB-14, FB-03, FB-07.

### FB-29. Resolution experiments и per-address A/AAAA outcomes [L, P1] **— ВЫПОЛНЕНО** (Beads b4x-04h, 02.08, 5b0a364e)

- **Проблема:** exact client-observed endpoint и independent current resolution смешаны; first success может скрывать sibling failures.
- **Что сделать:** machine-readable experiment kinds:

```text
client_observed_exact_endpoint
independent_current_resolution
```

Для каждого terminal A/AAAA address хранить address/family/provenance/selected state/DNS-TCP-TLS-HTTP-QUIC outcomes/latency/attribution/evidence refs. Aggregation не скрывает sibling failures.
- **Критерий:** fixtures с mixed IPv4/IPv6 outcomes; first-success masking mutation обнаруживается; missing per-address evidence блокирует `ABD_CLIENT_RESOLUTION_READY`.
- **Зависит:** FB-03, ABD/DDI production integration.

### FB-30. Evidence authority, attribution separation и stage-aware observers [L, P1] **— ВЫПОЛНЕНО** (Beads b4x-ivz, 03.08, f1149b3f)

- **Проблема:** IV не формализует authority levels и observer capabilities.
- **Что сделать:** поддержать authority:

```text
passive-monitoring
provisional-fast
authoritative-abd
android-canary
```

Разделить `ProbeFailureCode`, `FailureAttribution`, `BlockingHypothesis`, `Recommendation`. Каждый observer объявляет capabilities; unavailable=`NO_OPINION`; TCP/TLS-only observer не подтверждает HTTP/body hypothesis; exact/independent observations не смешиваются.

Добавить verdicts `ABD_CLIENT_RESOLUTION_READY`, `ABD_MULTI_VANTAGE_READY`.
- **Критерий:** schema/runtime/API/tests; capability mismatch and unavailable observer fixtures; stale/cross-context evidence rejected.
- **Зависит:** FB-03, FB-29.

### FB-31. Causal matrix failure family → candidate family [L, P0-SAFETY]

- **Проблема:** guided search/transport fallback не имеют единой causal eligibility matrix.
- **Что сделать:** canonical machine-readable mapping:

```text
hypothesis/evidence family
→ eligible candidate families
→ forbidden candidate families
→ mandatory narrower families
→ prerequisites
→ controls
→ target validation
```

Покрыть IP/SYN/CIDR, DNS, QUIC, SNI/fingerprint, threshold/application failures. WARP/SOCKS/TUN только scoped eligible-to-test при compatible authoritative evidence. Provisional hint не authorizes transport.
- **Критерий:** positive/negative/mutation matrix tests; broad WARP escalation by DNS-only/QUIC-only/single timeout blocked.
- **Зависит:** FB-14 п.10/13, FB-03, FB-30.

### FB-32. Service Profiles v1.6: SP-30…SP-32 и recommendation state machine [XL, P1]

- **Проблема:** IV/SP coverage не включает полный v1.6 recommendation contract.
- **Что сделать:** зарегистрировать и реализовать:

```text
SP-30 BlockingProfile transport-recommendation compiler
SP-31 Scoped WARP recommendation UX and validation transaction
SP-32 WARP recommendation release integration
```

State machine:

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

Profile projection читает current classifier/GSO/PPE/SPF/MON/ABD/DDI/WARP/canary verdicts и только сужает capability. Promotion требует target success, same-client controls, exact scope, current path/representation proof и rollback.
- **Критерий:** compiler/API/UI/persistence/migration/integration tests; no hint-only validation; expiry/invalidation and user rollback.
- **Зависит:** FB-02, FB-03, FB-31, WARP/runtime readiness.

### FB-33. Canonical Exact Source-Stage Registry и generated totals [XL, P0-NORMATIVE]

- **Проблема:** IV §23.1/§58 неполны; counts 39/77/86/146 расходятся.
- **Что сделать:** один machine-readable registry всех documents/requirements/stages:

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

Delta lists только generated filtered views. Генерировать prose totals/reports/UI. CI fail на duplicate/orphan/missing hash/stage/dependency/verdict.
- **Критерий:** all normative documents covered; totals deterministic; stale refs detected; FB-18 uses registry, not manual numbers.
- **Зависит:** FB-14; должен быть доступен FB-03/FB-18B.

### FB-34. Canonical principal verdict registry и alias mapping [L, P0-NORMATIVE]

- **Проблема:** Architecture/IV используют неполные и несовместимые verdict names.
- **Что сделать:** registry:

```text
canonical name
aliases
owner stage
dependency expression
required gates
required target evidence
blocked variants
expiry/invalidation
```

Включить CSI/GSO/PPE/SPF/MON/ABD/DDI/TGB/WARP/profile/canary principal verdicts. Alias не имеет отдельного state store. API/UI/reports используют canonical name.
- **Критерий:** duplicate state/name tests; dependency aggregation follows ARCH graph; stale/missing evidence invalidates; compatibility migration tests.
- **Зависит:** FB-14, FB-33; consumers in FB-03.

### FB-35. No-flag-day migration matrix для крупных subsystem [L, P1]

- **Проблема:** общая L8 validation не доказывает shadow/cutover/removal по subsystem.
- **Что сделать:** для Monitoring, GSO, PPE, WARP, profiles, action executor/fallback и других applicable systems:

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

Доказать production reachability нового path, отсутствие callers старого mutating path, restart/reboot invariants, adapter без own state, atomic rollback и audit event.
- **Критерий:** migration matrix + reverse-call artifacts; seeded reactivation of legacy path detected by meta-suite.
- **Зависит:** subsystem implementations; FB-03/FB-34.

### FB-36. Capability dependency graph: execution scheduling отдельно от verdict aggregation [M, P0-NORMATIVE]

- **Проблема:** IV run order ставит WARP до ABD и пропускает MON.
- **Что сделать:** разрешить безопасный parallel physical execution, но dependency aggregation строго:

```text
Classifier/Capture
→ CSI + GSO/RST + PPE visibility
→ Progress/SPF
→ MON
→ ABD
→ DDI/Discovery
→ scoped canary/runtimecontrol
→ base WARP causal readiness where selected
→ Service Profile recommendation readiness
```

TGB может выполняться параллельно после capture/routing prerequisites. Early WARP test не удовлетворяет отсутствующий MON/ABD/DDI dependency.
- **Критерий:** registry dependency tests; shuffled suite execution gives same correct verdict; missing upstream dependency blocks downstream PASS.
- **Зависит:** FB-33/FB-34; production consumers FB-03.

### FB-37. `liveRuntime.Drain()`: задекларировать intentional no-op или удалить из интерфейса Runtime [S, P2] **— ВЫПОЛНЕНО** (Beads b4x-4vt, 03.08; вариант а)

- **Проблема:** независимый аудит (`B4X_AUDIT_STATUS_REPORT.md`, B4X-AUDIT-0001, Patch Plan Этап 27): `src/runtimecontrol/live_runtime.go:315` — `Drain()` безусловный no-op (`return nil`); единственная реализация `Runtime` в production. Реальная защита (`InvalidateGeneration` при смене поколения) выполняется раньше, синхронно внутри `Promote()`; отдельного per-generation ресурса для drain нет. Вызовы `old.runtime.Drain(ctx)` (`rollout_manager_apply.go:111`, `rollout_manager_pending.go:163`) создают ложное впечатление защитного дренирования; будущая вторая реализация `Runtime` с реальными ресурсами унаследует no-op молча. **Норматив:** ARCH v2.4 §75 «Transactional apply» (строки 1847-1860) требует поведение `atomic generation switch → drain/retire previous generation` (при ошибке previous generation остаётся активной); патч-план (Этап 8, строка 415) предписывает механизм retire через `InvalidateGeneration(gen)` в хранилищах. Норматив требует поведения, а не метода `Drain()`.
- **Что сделать:** (а) задекларировать `Drain()` как intentional no-op: комментарий в интерфейсе `Runtime` и в `live_runtime.go:315` с root-cause (контракт ARCH §75 «drain/retire» исполняется `Promote()`/`InvalidateGeneration`/last-good; отдельного ресурса нет), либо (б) при подтверждении отсутствия контрактной нагрузки — удалить `Drain()` из интерфейса и обоих call sites **с доказательством**, что контракт §75 (retire previous generation при ошибке остаётся активной) не зависит от метода. Сохранить `fakeRuntime.drainN`-семантику в тестах, если метод остаётся.
- **Критерий:** интерфейс не содержит вводящего в заблуждение метода (или метод явно документирован как no-op с причиной); `go vet` PASS; `go test ./runtimecontrol/...` PASS; тест подтверждает, что generation-switch защита не зависит от `Drain()` (остаётся в `Promote()`/`InvalidateGeneration`).
- **Зависит:** нет (LOW; не пересекается с FB-08 — canary mutex и FB-09 — hold на FIN/RST).

### FB-38. Legacy `learnedIPCache` (`sni/match.go`): недостижим при strict/scoped-hints или явно legacy-only [M, P2]

- **Проблема:** независимый аудит (B4X-AUDIT-0002, CSI gap 2.4): `src/sni/match.go` `learnedIPCache` (поля 48-51; использование 430-490, 697-737) keyed только по destination IP (`map[string]*learnedIPEntry`), не per-client; безопасность держится на guard clause (`Targets.DomainOnly` check под read/write lock, без TOCTOU). v2-механизм `ScopedLearnedObservation` → `HostHintStore` (`src/classifier/scoped_learned.go`, `src/classifier/hints.go`) client-scoped и wired; legacy-путь достижим только в чистом legacy-режиме (`EvidenceLegacyLearnedIP`, `classifier/phase.go:112`). **Норматив:** ARCH v2.4 §11 сохраняет `EvidenceLegacyLearnedIP` как тип evidence, но §12 ставит `legacy global learned IP` предпоследним в порядке evidence (ниже `source-scoped learned observation`) и §21:863 требует «ключ MUST включать клиента; глобальный learned IP недостаточен»; CSI addendum CSI-5 «Remove authoritative legacy learned-IP path» (строки 770-794): `no action authorization from legacy learned IP`, `no global route learning`, коммит `demote legacy learned IP to scoped provisional evidence`.
- **Что сделать:** (а) сделать legacy-путь недостижимым для **authorization** при effective policy `strict`/`scoped-hints` — запрет fallback в legacy-режим для non-legacy policies (проверить/усилить guard на `EffectiveDomainPolicy`); как evidence legacy learned IP остаётся допустим только с низким confidence и коротким cap (ARCH §12, :753), но никогда не авторизует action (CSI-5); (б) явно пометить `learnedIPCache` как legacy-only (комментарий + диагностический counter/log при использовании), если это соответствует FB-14 п.13 (hints — provisional; hint-only destructive authorization запрещён); (в) зафиксировать тестами: strict/scoped-hints не используют learned-IP по destination IP.
- **Критерий:** в strict/scoped-hints режимах `learnedIPCache` не участвует в authorization (unit-тесты обоих режимов; per-client тест для `HostHintStore` уже есть — `classifier/hints_test.go`); если legacy остаётся — явная пометка + диагностика; meta-suite не фиксирует скрытое legacy-использование; `go test ./sni/... ./classifier/...` PASS.
- **Зависит:** FB-14 п.13 (owner decision strict/scoped-hints); ADR-CSI-2/ADR-CSI-6.

---

## 4. ДЕФИНИЦИЯ ГОТОВНОСТИ (Definition of Done) — проверь ВСЁ перед сдачей

### 4.1. Нормативная готовность

1. FB-14: 14/14 owner decisions внесены в canonical documents; старые definitions удалены/superseded.
2. Document versions/hashes обновлены и записаны.
3. FB-33 Exact Source-Stage Registry полный и deterministic.
4. FB-34 principal verdict registry полный; aliases не создают второй state.
5. FB-36 dependency graph согласован.
6. FB-18A пересчитан по новым hashes.
7. FB-18B завершён: нет applicable MISSING/PARTIAL/SEMANTIC_MISMATCH.

### 4.2. Production reachability

Для каждой закрытой задачи есть evidence:

```text
production root
→ registration
→ call chain
→ runtime side effect
→ failure path
→ cleanup/rollback
```

8. `go list -deps` и reverse-call analysis подтверждают required package reachability.
9. Нет required function, вызываемой только tests/examples/benchmarks.
10. Нет legacy compatibility path, продолжающего mutating logic после cutover.
11. Config/API/UI fields имеют runtime consumers и одинаковую semantics.

### 4.3. Gates, verdicts и validation

12. Каждый applicable hard gate имеет active producer, consumer, promotion blocker и reset/expiry semantics.
13. Negative/mutant fixture реально нарушает gate и блокирует verdict/promotion.
14. Missing/skipped/unknown/stale не становится PASS.
15. Meta-suite registered и выполняется из validation API/CLI/release orchestration.
16. IV-18 Monitoring suite и FT-MON-A…J выполняются.
17. FT-AC/AD/AE mutants существуют и detected.
18. `BLOCKED_BY_TARGET`/`BLOCKED_BY_CAPABILITY` честно сохраняются.

### 4.4. Build/static/unit/integration

19. `go build ./...` на Linux/amd64 — PASS.
20. Build для всех declared router targets — PASS.
21. `go vet ./...` — 0 findings.
22. configured linters/staticcheck — PASS.
23. `go test -count=1 ./...` — PASS.
24. `go test -race -count=1 ./...` — PASS в CGO-capable Linux environment.
25. Fuzz smoke/property/mutation/leak suites — PASS по registry.
26. `make build` из fresh clone — PASS без manual hidden steps.
27. CI содержит vet/race и применимые fuzz/meta checks.

### 4.5. Transaction/lifecycle

28. No mixed generation.
29. Canary lock не блокирует cancel/rollback/status.
30. Every apply has rollback target and cleanup proof.
31. No leaked NFQUEUE queues/tokens/marks/routes/PPE/WARP/TUN/sockets/goroutines/temp files.
32. Restart/reboot/crash-before/after-commit tests выполнены.
33. Foreign resources не удаляются.

### 4.6. Target/field evidence

34. Keenetic/NDM/PPE claims подтверждены target-side counters/capture либо `BLOCKED_BY_TARGET`.
35. Android YouTube/Telegram claims подтверждены реальным client evidence либо blocked.
36. WARP path/causal/cleanup claims подтверждены counters/trace/capture.
37. Performance/resource budgets проверены на заявленном weak-router class.
38. Linux/amd64 CI не выдаётся за hardware proof.

### 4.7. Evidence integrity

39. Исходный `artifacts/audit/**` не изменён.
40. Все новые логи/reports находятся в `artifacts/remediation/**`.
41. Каждый artifact содержит commit SHA, config/capability hashes, commands, exit codes, environment и timestamps.
42. Dirty tree/test-generated diff не скрыт.
43. Исторические audit findings не переписаны; создан after-fix status report.

### 4.8. Финальный verdict

До выполнения всех применимых пунктов сохраняется:

```text
FINAL_VERIFICATION_BLOCKED
```

Финальный independent audit запускается только после полного remediation bundle. Coding-agent не имеет права сам объявлять `B4X_ARCHITECTURE_COMPLIANT`; это verdict независимого аудитора.

## 5. СПРАВОЧНИК ПО КОМАНДАМ И СРЕДАМ ВЕРИФИКАЦИИ

### 5.1. Reference CI на Windows-host через Linux Docker

Рабочее дерево в исходном аудите: `D:\\b4x`. Порядок генерации сохраняется:

```powershell
# 1. Generate defaults in Linux container
docker run --rm -v D:\b4x:/src -w /src/src `
  -e GOMODCACHE=/gomod -v C:\Users\AlexZander\go\pkg\mod:/gomod `
  golang:1.25-alpine go run tools/gendefaults.go

# 2. Build UI on host or a pinned Node container
cd src\http\ui
corepack enable
pnpm install --frozen-lockfile
pnpm build

# 3. Build, vet, tests
docker run --rm -v D:\b4x:/src -w /src/src `
  -e GOMODCACHE=/gomod -v C:\Users\AlexZander\go\pkg\mod:/gomod `
  golang:1.25-alpine sh -ceu "go build ./... && go vet ./... && go test -count=1 ./..."

# 4. Race
docker run --rm -v D:\b4x:/src -w /src/src `
  -e GOMODCACHE=/gomod -v C:\Users\AlexZander\go\pkg\mod:/gomod `
  golang:1.25-bookworm sh -ceu "go test -race -count=1 ./..."
```

Используй фактическую Go version, pinned проектом/CI. Не обновляй toolchain/dependencies без отдельной задачи.

### 5.2. Fresh clone

```bash
git clone <repo> b4x-clean
cd b4x-clean
make build
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
```

Fresh clone не должен зависеть от untracked UI/default assets.

### 5.3. Declared router targets

Получить targets из Makefile/release workflow и собрать каждый, не угадывая architecture:

```bash
make list-targets  # если команда отсутствует, добавить эквивалентный documented target inventory
make build-all-targets
```

Если таких команд нет, зафиксировать точные `GOOS/GOARCH/build tags/CGO` из release workflow и выполнить их явно.

### 5.4. Validation CLI/API

После FB-03/FB-28/FB-33/FB-34:

```bash
b4-validate list
b4-validate plan full
b4-validate full --profile release
b4-validate requirement <ID>
b4-validate meta
```

Сохранять stdout/stderr/exit code/report/artifact index в `artifacts/remediation/logs/`.

### 5.5. Target field commands

Точные команды зависят от доступного Keenetic/Entware устройства и должны браться из Field Test registry. Минимальный evidence включает:

- process/config/capability hashes;
- nftables/iptables/NFQUEUE counters;
- PPE/offload state and per-flow exclusions;
- route/rule/mark ownership;
- target-side capture;
- Android client timestamps/flow IDs;
- cleanup state after rollback/restart.

При отсутствии target не симулировать PASS: вернуть `BLOCKED_BY_TARGET` с reproduction plan.

---

## 6. КЛЮЧЕВЫЕ ФАЙЛЫ И АРТЕФАКТЫ (карта правок)

| Задача | Основные файлы/areas |
|---|---|
| FB-01 | `src/capture/ppe/product_bundle_test.go` |
| FB-02 | `src/silentpath/*`, `src/monitor/*`, `src/detector/*`, `src/discovery/*`, `src/warp/*`, `src/serviceprofile/*`, `src/fieldtest/*`, `src/main.go`, HTTP/CLI/bootstrap |
| FB-03 | canonical gate registry, `src/validation/*`, `src/fieldtest/hard_gates.go`, subsystem producers/consumers, metrics/API/reporting |
| FB-04 | `src/mtproto/transparent.go`, outcome/FSM/pending/prefix/route files, TPROXY listener |
| FB-05 | `src/discovery/hint_planner.go`, DDI/ABD prior schema/API/runtime |
| FB-06 | `.github/workflows/release.yml`, docs workflow/fuzz jobs |
| FB-07 | `src/watchdog/*`, `src/monitor/*`, HTTP/API/router/bootstrap, persistence, runtimecontrol |
| FB-08 | `src/runtimecontrol/rollout_manager_apply.go`, rollout state/types/tests |
| FB-09 | `src/nfq/tcp_hold_config.go`, handler/FSM/hold tests |
| FB-10 | canonical GSO token type/store/consumer, CSI/GSO imports |
| FB-11 | config/capture/tables/classifier/runtime topology/UI/API |
| FB-12 | PPE reconciler/product service/self-test lifecycle |
| FB-13 | `src/fieldtest/session.go`, trace schema/tests |
| FB-14 | Architecture/patch plan/all affected addenda/registries/changelogs |
| FB-15 | Makefile, UI assets generation, package manager pin |
| FB-16 | documentation facts only; no byte conversion |
| FB-17 | `src/warp/geo.go`, `isolation.go`, `selection.go` |
| FB-18 | crosswalk generator, `artifacts/remediation/FB18_*` |
| FB-19 | `src/geodat/*`, `src/quic/*` tests/fuzz |
| FB-20 | `src/metrics/*`, imports/docs |
| FB-21 | PPE config migration/provenance/detect/self-test/addendum/UI |
| FB-22 | `src/action/executor.go`, NFQ handler/strategy compiler |
| FB-23 | routing fallback, NFQ/TUN/controller/runtimecontrol |
| FB-24 | adaptive Discovery matrix/runtime/API/config |
| FB-25 | NFQ ClientHello sink, lab controller/API/compiler/catalog |
| FB-26 | typed Level C strategies, executor, catalog, packet fixtures |
| FB-27 | GSO topology/normalizer/runtime transactions/gates/tokens |
| FB-28 | IV v1.5 successor sections, MON/FT-MON registry/suites |
| FB-29 | resolver/ABD experiment schemas and per-address evidence |
| FB-30 | observer capabilities/evidence authority/attribution schemas |
| FB-31 | causal candidate eligibility matrix/validator/planner |
| FB-32 | Service Profiles SP-30…32/compiler/recommendation/API/UI |
| FB-33 | Exact Source-Stage Registry generator/schema/CI |
| FB-34 | principal verdict registry/alias migration/API/UI/report |
| FB-35 | migration matrices/reverse-call tools/restart tests |
| FB-36 | dependency graph/aggregator/scheduler tests |
| FB-37 | `src/runtimecontrol/live_runtime.go:315`, `rollout_manager_apply.go:111`, `rollout_manager_pending.go:163`, интерфейс `Runtime`/тесты |
| FB-38 | `src/sni/match.go` (learnedIPCache), `src/classifier/scoped_learned.go`, `src/classifier/hints.go`, policy guard/тесты |

Новые artifacts размещать только в `artifacts/remediation/`, например:

```text
artifacts/remediation/FB03_GATE_PRODUCER_CONSUMER_MATRIX.json
artifacts/remediation/FB18_ARCH_IV_EXECUTABLE_CROSSWALK.json
artifacts/remediation/REQUIREMENT_STATUS_AFTER_FIX.json
artifacts/remediation/TEST_EXECUTION_INDEX.md
artifacts/remediation/logs/
```

---

## 7. НЕ ЗАБЫВАТЬ

- Не ломать подтверждённые working invariants: clean SYN, candidate≠authorization, cross-service isolation, last-good/cooldown/rollback и существующие безопасные Core Fix portions.
- «Пакет компилируется» не означает, что он включён в binary/runtime.
- Unit tests helper-функций не заменяют production-root integration.
- Field Test framework не является доказательством field execution.
- Prometheus metric без producer/consumer не является hard gate.
- Missing metric не равен нулю.
- Legacy alias не может хранить второй state или mutating logic.
- WARP не включается по provisional hints, одному timeout или destination-only state.
- Service Profile не создаёт hidden authorization и не владеет low-level resources.
- `gso_mode=classify` не разрешает packet mutation.
- Telegram soft timeout не закрывает socket; dial failure проходит route ladder, а не first-byte parking.
- PPE auto-exclude — только new install + explicit capability/self-test/rollback; user OFF сохраняется.
- Все документы UTF-8; не выполнять перекодировку.
- Не переписывать исходный audit bundle после исправлений.
- После крупных правок использовать Git commit/worktree или `artifacts/remediation/backup_*`, не `artifacts/audit/backup_*`.
- Любой owner-approved de-scope должен пройти normative registry/verdict/API/UI/migration update.
- Пока FB-18B и active gate coverage не завершены, сохранять:

```text
FINAL_VERIFICATION_BLOCKED
ARCH_IV_TRACEABILITY_INCOMPLETE
ACTIVE_GATE_COVERAGE_INCOMPLETE
MONITORING_VALIDATION_MISSING
CANONICAL_REGISTRY_INCOMPLETE
```

---

## Приложение A. Исходный audit backlog — сохранён дословно как historical evidence

> **Не исполнять этот блок как отдельное задание.** Ниже сохранён исходный `B4X_AUDIT_FIX_TASKS.md` без сокращений для traceability. При расхождении исполняется основная revised-редакция выше и `B4X_FB14_CONFLICTS_RESOLVED.md`.
>
> # B4X — ЗАДАНИЕ НА ИСПРАВЛЕНИЕ ПО ИТОГАМ АУДИТА
> 
> **Репозиторий:** AlexZander85/b4x, ветка `agent/classifier-v2.3-capture-envelope`
> **База:** B4 1.73.0 (commit `7160ee8f...`); рабочее дерево = HEAD `49a73e17...` + 33 untracked (git-репозитория нет)
> **Дата аудита:** 31.07.2026 · **Вердикт аудита: `B4X_NOT_COMPLIANT`** (полный текст — `artifacts/audit/B4X_AUDIT_VERDICT.md`)
> **Источники деталей (читать при работе):** `artifacts/audit/` — `B4X_FIX_BACKLOG.md`, `B4X_FINDINGS_CATALOG.md`, `hard_gates_audit.md`, `warp_audit.md`, `mon_abd_ddi_audit.md`, `csi_ppe_rstgso_audit.md`, `sp_ft_spf_audit.md`, `patch_plan_audit.md`, `patch_plan_quality.md`, `test_quality_audit.md`, `req_index_part1..3.md`, `findings_draft.md`, `logs/`
> 
> ---
> 
> ## 0. ПРАВИЛА РАБОТЫ
> 
> 1. **Порядок:** выполняй по приоритету P0 → P1 → P2. Зависимости указаны в каждой задаче (поле «Зависит»). Независимые задачи можно делать параллельно.
> 2. **Верификация — только на Linux/amd64 (целевая платформа роутера) через Docker.** Windows-сборка невозможна: пакет `log` использует syslog/`unix.Dup2` (Unix-only). Команды — в разделе 7.
> 3. **НЕ трогай `artifacts/audit/**`** — это эталон результатов аудита.
> 4. **НЕ меняй нормативные документы** (B4_FORK_*.md и т.п.) — кроме задачи FB-16 (перекодировка) и FB-14 (переиздание согласованных правок; каждую правку помечай как изменение документа).
> 5. Задачи с пометкой **[РЕШЕНИЕ ВЛАДЕЛЬЦА]**: сделай безопасный дефолт (указан), пометь в коде/PR `ASSUMPTION`, не блокируйся.
> 6. Каждая задача должна заканчиваться **критерием приёмки** из раздела «Критерий» — проверь его фактически (команда/тест) перед отметкой Done.
> 7. После каждой задачи: `go vet ./...` и `go test ./...` должны оставаться зелёными (кроме состояний, явно отмеченных).
> 8. Git-репозитория нет: если нужен restore point — скопируй изменяемые файлы в `artifacts/audit/backup_<дата>/` перед большими правками.
> 
> ---
> 
> ## 1. P0 — БЛОКЕРЫ (без них ветка не релизится)
> 
> ### FB-01. Починить компиляцию тестов capture/ppe [S]
> - **Проблема:** `src/capture/ppe/product_bundle_test.go:100-101` — `cfg := config.NewConfig()` (значение `config.Config`) передаётся туда, где нужен `*config.Config` (`NewProductService(func() *config.Config {...})`, `service.ApplyConfig(ctx, cfg)`). `go test ./...` падает: `FAIL capture/ppe [build failed]` — единственный FAIL из 42 пакетов (подтверждено и в `-race`).
> - **Что сделать:** поправить тест под реальную сигнатуру (см. сигнатуру `NewProductService`/`ApplyConfig` в `src/capture/ppe/`): использовать указатель (напр. `cfg := config.NewConfig(); svc := NewProductService(func() *config.Config { return &cfg }, ...)` — **сверь точные сигнатуры в коде**, не гадай). Убедись, что тест осмыслен (не `t.Skip`).
> - **Критерий:** `go test -count=1 ./capture/...` → PASS; `go test -count=1 ./...` → все 42 пакета OK.
> - **Зависит:** —
> 
> ### FB-02. Интегрировать продуктовый слой (warp/serviceprofile/fieldtest/silentpath) [XL] — РЕШЕНИЕ ВЛАДЕЛЬЦА: полная интеграция
> - **Проблема:** пакеты `src/warp` (24 файла), `src/serviceprofile` (17), `src/fieldtest` (26), `src/silentpath` (10) имеют **0 импортеров/вызовов** во всём `src` (grep `warp.`/`serviceprofile.`/`fieldtest.`/`silentpath.` = 0; `go list -deps ./` от main их не включает; в `src/main.go` и `src/http/handler` — 0 упоминаний; API-эндпоинтов нет). Требования документов WARP v1.2 (0/44 IMP), SP v1.6 (9/22), FT v1.5 (8/14), SPF v1.0 (26/74) в production-бинаре **не исполняются**.
> - **Решение владельца (31.07): интегрировать каждый пакет согласно своему addendum:**
>   1. `src/warp` → **`B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md`** — подключить ядро: enrollment + geo-аттестация + causal trace + счётчик `warp_trace_secret_leak_total` (см. FB-03); точки входа — реальный путь обработки пакетов (nfq) и/или HTTP API.
>   2. `src/serviceprofile` → **`B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md`** — подключить компиляцию/применение профилей, ownership, `warp_recommendation` YAML (добавить поле `path_proof_supported`; YAML-экспорт сейчас не реализован).
>   3. `src/fieldtest` → **`B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md`** — `Controller` должен вызывать `HardGatesPass` (сейчас `fieldtest/hard_gates.go:5` никем не вызывается); создать мутант-фикстуры FT-AC (9), FT-AD (7), FT-AE (12) — сейчас не существуют.
>   4. `src/silentpath` → **`B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md`** — детекционная цепочка: `BaselineModel` (SPF-19), `RetryCorrelator` (SPF-20), `DifferentialProbeController` (SPF-21), quarantine (SPF-40), thresholds (SPF-41) — сейчас ABSENT, «confidence ladder» без источника корреляции.
>   - Детали по каждому пакету: `artifacts/audit/warp_audit.md`, `sp_ft_spf_audit.md`, `mon_abd_ddi_audit.md`, `req_index_part1..3.md`.
> - **Что сделать:** интеграция в порядке: WARP → SPF → FT → SP. Прогресс фиксировать в комментариях. После каждого пакета — build/vet/test зелёные.
> - **Критерий:** пакеты достижимы из main (`go list -deps ./` включает их); для каждого addendum соответствующие требования в `req_index_*.md` получают статус IMP; профильные тесты исполняются из production-путей (не только unit).
> - **Зависит:** — (FB-03 частично входит в шаги 1–3)
> 
> ### FB-03. Активировать hard-gate счётчики и вердикты; подключить meta-suite [XL]
> - **Проблема:** из 160 требуемых счётчиков-гейтов в production активен **1**: `unrelated_control_action_total` (CSI-18, `src/crossservice/validation.go:265,392`). Отсутствуют: все 58 WARP-гейтов (§72/73/73A/73B: `warp_trace_secret_leak_total`, P0-dropped и др.), все 22 SPF-гейта, 82 FT-гейта §26. Вердикты декларативны: `WARP_CAUSAL_TRACE_READY` — константа `src/fieldtest/cleanup.go:36`; `BLOCKED_TARGET_VALIDATION` — константы `src/validation/verdict.go:9`, `src/fieldtest/promotion.go:7`. Meta-suite реализована, но **никем не вызывается**: `src/validation/meta.go`, `src/fieldtest/hard_gates.go`.
> - **Что сделать:**
>   1. Полные перечни имён и норм — `artifacts/audit/hard_gates_audit.md` (там же: расхождение WARP §73B=26 vs IV §38A.9=56 vs FT §26; имена `RequiredHardGates` совпадают с FT §26 только 7 из 17 — **сначала согласуй список имён**, зафиксируй решение).
>   2. Реализовать счётчики как Prometheus-метрики (паттерн существующего `unrelated_control_action_total` в `crossservice/validation.go`), инкремент в реальных ветках кода (warp trace → leak counter; drop → P0 dropped).
>   3. Вызывать meta-suite: `validation/meta.go` + `fieldtest/hard_gates.go` из точек, где принимаются решения (HTTP API валидации, применяемые конфиги, инстанс-реконфигурация).
>   4. Вердикты: `WARP_CAUSAL_TRACE_READY` и `BLOCKED_TARGET_VALIDATION` должны вычисляться реальными проверками (условия — WARP v1.2 и IV v1.5; составы НЕ идентичны между документами — зафиксируй, какую редакцию берёшь).
> - **Критерий:** grep показывает вызовы инкремента для каждого гейта; в runtime-метриках появляются имена гейтов; `BLOCKED_TARGET_VALIDATION` реально блокирует валидацию при невыполненных условиях (тест).
> - **Зависит:** FB-02 (частично: счётчики WARP/SPF живут в мёртвых пакетах) — можно начинать с гейтов живых подсистем.
> 
> ### FB-04. #277: убрать молчаливый drop в Telegram bridge [M]
> - **Проблема:** `src/mtproto/transparent.go:97-104`: при 5s deadline и zero-byte ответе — `return true, nil` (молчаливый destructive drop, `handled=true`, без fail-open); `:157` — dial fail → тоже `return true, nil`. Норма DDI/TGB: парковка в `PendingHandshakeManager` и observable-классификация, НЕ `handled=true`.
> - **Что сделать:** для zero-byte-таймаута и dial-fail: (а) не помечать как handled (вернуть `false` + observable-статус), (б) парковать соединение в `PendingHandshakeManager` (найди его в `src/mtproto/`), (в) обеспечить fail-open (клиентское соединение не убивается молча), (г) покрыть тестами оба пути. Учесть противоречие документов: zero-byte close трактуется и как `idle_preconnect_expired`, и как «never silently claimed» (см. FB-14, п.14) — выбери безопасную трактовку (не молчать), пометь ASSUMPTION.
> - **Критерий:** новые тесты: zero-byte timeout и dial-fail НЕ дают `handled=true` и НЕ закрывают клиентское соединение без observable-статуса; `go test ./src/mtproto/...` PASS.
> - **Зависит:** —
> 
> ### FB-05. #278: использовать detector prior в discovery [M]
> - **Проблема:** `src/discovery/hint_planner.go:56` — `_ = prior` (detector prior игнорируется). DDI-6: API не расширен (нет параметра prior), DDI-7/ABD-11 не исполняются.
> - **Что сделать:** использовать `prior` в планировании hints (сверь контракт в ABD v1.2 / DDI/TGB); расширить API по DDI-6 (параметр prior в соответствующем эндпоинте — найди текущий API hints); покрыть тестами.
> - **Критерий:** `_ = prior` отсутствует; hint-планирование учитывает prior (тест с приоритетным prior меняет порядок/вес hints); API-тест на новый параметр PASS.
> - **Зависит:** —
> 
> ---
> 
> ## 2. P1 — MAJOR
> 
> ### FB-06. CI: добавить `go vet` и `-race` [S]
> - **Проблема:** `.github/workflows/release.yml:90-92` — `go test ./...` без `-race` и без `go vet`. goleak — в 3 файлах (найди через grep `goleak`), fuzz-тесты (25 шт.) не в CI.
> - **Что сделать:** в release.yml (и docs.yml при необходимости): `go vet ./...` перед тестами; `go test -race -count=1 ./...`; шаг для fuzz (smoke: `go test -fuzztime=5s -run=^$` по fuzz-целям) — либо задокументируй, почему нет.
> - **Критерий:** CI-конфиг содержит vet + race; локальный прогон `go vet ./...` и `go test -race ./...` зелёные (после FB-01).
> - **Зависит:** FB-01 (race-прогон PPE).
> 
> ### FB-07. MON v1.0: реализовать strangler-замену Watchdog [XL]
> - **Проблема:** MON v1.0 (32 требования, 0 IMP) не начат: `src/watchdog/applier.go:18` — legacy `applyBatchResults` активен, direct apply работает; `/api/monitor/v1` отсутствует; ключей `legacy_watchdog_*` нет; shadow-пробы в `src/discovery/adaptive.go` — другая сущность.
> - **Что сделать:** по MON v1.0 (6 фаз shadow/cutover): реализовать shadow-режим монитора рядом с watchdog (обе ветки считают, применяются только watchdog), затем cutover по флагу `legacy_watchdog_*`; добавить `/api/monitor/v1`; по завершении — удалить `applyBatchResults` и legacy-путь. Детали: `mon_abd_ddi_audit.md` (раздел MON).
> - **Критерий:** `applyBatchResults` удалён или не вызывается; /api/monitor/v1 отдаёт состояния по MON-1..12; тесты shadow-режима (результаты совпадают до cutover).
> - **Зависит:** —
> 
> ### FB-08. Не держать глобальный мьютекс на canary-транзакцию [M]
> - **Проблема:** `src/runtimecontrol/rollout_manager_apply.go:33-34` — `m.mu.Lock()` + defer на весь `Apply`, включая `runtime.Canary` (:66); `MaxCanaryDuration=1h` (`rollout_types.go:21,165-166`) → `Prepare`/`Rollback`/`AbortPending`/`Close` заблокированы до часа.
> - **Что сделать:** разбить критическую секцию: не держать `m.mu` на время canary (отдельный canary-lock или staged-применение: собрать план под локом, отпустить, применить, вернуться за локом для фиксации). Сохранить инварианты last-good/cooldown/rollback (они реализованы и работают).
> - **Критерий:** тест: во время активного canary параллельный вызов `Prepare`/`Rollback` не блокируется до завершения canary (таймаут <1h); все существующие runtimecontrol-тесты PASS.
> - **Зависит:** —
> 
> ### FB-09. Abort hold на FIN/RST [M]
> - **Проблема:** `src/nfq/tcp_hold_config.go:17-18` — константы `tcpHoldAbortFIN`/`tcpHoldAbortRST` объявлены, нигде не используются (grep = 2 совпадения — только объявления). На FIN/RST held-пакет не релизится явно — висит до таймаута 750ms (fail-open сохранён, но инвариант hold не исполняется).
> - **Что сделать:** реализовать пути abort hold: при FIN/RST на held-потоке — немедленный релиз/отмена hold по правилам ARCH §42-45; покрыть тестами (FIN и RST).
> - **Критерий:** тесты: FIN/RST на held-потоке завершают hold немедленно (не по таймауту); существующие nfq-тесты (113 файлов) PASS.
> - **Зависит:** —
> 
> ### FB-10. CSI-15: поля GSOPassToken [M]
> - **Проблема:** `src/nfq/gso_token.go:25-36` — GSOPassToken без `Authorization`/`EffectivePolicy`/`CandidateDisposition` (требуются CSI §18:1153-1178); по RST/GSO H4 (379-398) — PASS. Субординация определений не задана (см. FB-14 п.4).
> - **Что сделать:** добавить недостающие поля (согласуй с CSI §18); формализуй, какое определение главное (дефолт: CSI §18, т.к. детальнее); обновить RST/GSO H4 при необходимости; тесты на новые поля.
> - **Критерий:** gso_token содержит 3 поля; тест сериализации/парсинга токена с новыми полями PASS; CSI-15 в `csi_ppe_rstgso_audit.md` переходит в PASS (артефакт не менять — отметь в комментарии).
> - **Зависит:** —
> 
> ### FB-11. Wire или удалить `CaptureEnvelopeEnabled` [M]
> - **Проблема:** `src/config/types.go:106` — флаг используется только в `diagnostics.go:300` (статус) и `classifier_v23.go:241` (diff UI) и тесте; на фактическую обработку пакетов не влияет; контур iptables строится из старого `cfg.Queue.Mark` (`src/tables/iptables.go:361-362`).
> - **Что сделать:** подключить флаг к реальному контуру: выбор mark/цепочки при построении iptables и/или ветка обработки в capture/PPE (first-N/SYN-ACK/FIN/RST/QUIC) — либо удалить флаг и задекларировать. Сверь Stage 4 в `patch_plan_quality.md`.
> - **Критерий:** переключение флага меняет наблюдаемое поведение (тест: построенные iptables-правила/обработка отличаются); или флаг удалён и упоминания вычищены.
> - **Зависит:** —
> 
> ### FB-12. PPE self-test: авто-старт при `mode: startup-and-change` [M]
> - **Проблема:** self-test стартует только через HTTP (`src/capture/ppe/capture_offload_product.go:183`); при `mode: startup-and-change` авто-запуск не подключён (`reconciler.go:122`).
> - **Что сделать:** при активации режима запускать self-test автоматически (реконсиляция/старт сервиса), результат — в статус; покрыть тестом.
> - **Критерий:** тест: при конфиге `mode=startup-and-change` self-test выполняется без HTTP-вызова; статус содержит результат.
> - **Зависит:** —
> 
> ### FB-13. Коллизия JSON-тегов в fieldtest [S]
> - **Проблема:** `src/fieldtest/session.go:59` — `ConfigGen, RouteGen, SessionGen uint64` — все три `json:"config_gen,omitempty"` (vet error). Потеря RouteGen/SessionGen при сериализации трассы (норма FT v1.5: трасса несёт ConfigGen/RouteGen/SessionGen).
> - **Что сделать:** развести теги (`config_gen`, `route_gen`, `session_gen`); проверить обратную совместимость сериализации (схема трассы FT) — обновить схему/тесты.
> - **Критерий:** `go vet ./...` чист; тест сериализации события трассы сохраняет все 3 поля.
> - **Зависит:** —
> 
> ### FB-14. Устранить 14 меж-документных противоречий [M]
> - **Что сделать:** для каждого пункта — выбрать редакцию (дефолт указан), внести правку в документ (переиздать с пометкой), обновить код/тесты при необходимости. Полный список:
>   1. DDI-4 ownership: делегирование компиляции raw evidence→BlockingProfile — ABD v1.2:129 vs DDI/TGB:1668-1676. Дефолт: ABD v1.2 (кто владеет компиляцией — зафиксировать).
>   2. ADR-WARP 1..7 (историческая формулировка «changelog v1.2 1..6» снята как ложное срабатывание: changelog-секции в WARP v1.2 не существует). Дефолт: 1..7.
>   3. MON §57: срок жизни legacy `/api/watchdog/*` не задан (MON-11 без deadline). Дефолт: задать дату cutover в MON §57.
>   4. GSOPassToken два определения (RST/GSO H4 vs CSI §18). Дефолт: CSI §18 главный (см. FB-10).
>   5. Порядок цепочек: CSI-14 (1142) без WARP/PPE vs SPF §0.1 (71-93) WARP→RST/GSO→PPE→SPF vs SPF:1217 (PPE-proof). Дефолт: единая цепочка SPF §0.1.
>   6. IV v1.5: acceptance criteria фактически 86, заголовок §45 «редакция 1.3» и «77». Дефолт: 86, исправить заголовок.
>   7. IV §23.1 registry: не включает IV-13..17, FT-AC..AE, SP-20..23/30..32. Дефолт: дополнить.
>   8. Ссылки на SP v1.5 / ARCH v2.3 в цепочках. Дефолт: v1.6 / v2.4.
>   9. `WARP_CAUSAL_TRACE_READY`: WARP v1.2 vs IV v1.5 — неидентичный состав условий. Дефолт: единый состав (перечислить).
>   10. §28A.4 (forbidden при unhealthy controls) vs SP-30 DoD. Дефолт: SP-30 DoD (детальнее).
>   11. Порог 16 KiB (PATCH_PLAN label) vs IV §22. Дефолт: согласовать одно значение.
>   12. `gso_mode=classify` «рекомендуемый production mode» — разрешающий gate не формализован. Дефолт: формализовать gate.
>   13. scoped-hints vs strict: условия выбора не определены. Дефолт: определить условия.
>   14. zero-byte close: `idle_preconnect_expired` vs «never silently claimed» (DDI/TGB:962-969 vs 1875). Дефолт: «never silently claimed» (см. FB-04).
> - **Критерий:** 14 пунктов сняты; каждый — с записью «было → стало»; код/тесты синхронизированы.
> - **Зависит:** FB-04, FB-10 (пункты 4, 14).
> 
> ---
> 
> ## 3. P2 — MINOR / ЧИСТКА
> 
> ### FB-15. Сборка из свежего клона [S]
> - **Проблема:** `src/http/ui/dist/` и `src/http/ui/src/models/defaults.json` gitignored; Makefile `build` не зависит от `build-ui`/`gen-defaults` → `make build` падает (`go:embed ui/dist/*` — `src/http/server.go:24`).
> - **Что сделать:** Makefile: `build: swagger gen-defaults build-ui ...` (или закоммитить сгенерированные ассеты — реши, дефолт: зависимости в Makefile). pnpm packageManager пинит 10.29.2 (установлен 9.15.9) — синхронизировать (corepack или обновить пин).
> - **Критерий:** в свежем клоне `make build` (Linux) проходит без ручных шагов.
> - **Зависит:** —
> 
> ### FB-16. Кодировки: ОТМЕНЕНО — все документы уже UTF-8 [S]
> - **Перепроверка 31.07 (строгая):** все 10 `B4_*.md`, 2 `B4X_*.md` и все 92 файла `docs/**` (104 файла) — **валидный UTF-8** (декодер с `throwOnInvalidBytes=true` не нашёл ни одного невалидного байта). Включая `B4_FORK_PATCH_PLAN.md`, `B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md` и `docs/audit/b4-1.73-flow-path.md`, которые в ранних артефактах аудита были ошибочно помечены как cp866 (вероятная причина: чтение через консоль с ANSI-декодированием).
> - **Что сделать:** перекодировка НЕ требуется. Задача сводится к: (а) НЕ выполнять никаких перекодировок; (б) при обновлении артефактов аудита (например, в новом `arch_iv_audit.md` или заметках) указывать корректный факт «все документы UTF-8»; (в) в `B4X_AUDIT_VERDICT.md`/`B4X_FIX_BACKLOG.md`/`findings_draft.md` упоминания cp866 являются устаревшими — не удалять их из эталонов без отдельного решения владельца, но и не действовать по ним.
> - **Критерий:** ни один файл не перекодирован; любые новые записи об аудите утверждают «все документы — UTF-8».
> - **Зависит:** —
> 
> ### FB-17. Нормативные правки в src/warp [S]
> - **Проблема (внутри мёртвого пакета):** geo TTL 300s вместо нормы 120s (`src/warp/geo.go:52`); `InnerRevokedBeforeParent` не проверяется (`src/warp/isolation.go:16`); `CandidateResult.ExpiresAt` не заполняется (`src/warp/selection.go:15`).
> - **Что сделать:** исправить 3 места + тесты. (Актуально только при FB-02 Вариант A.)
> - **Критерий:** тесты warp: TTL=120s, inner-revoke блокирует, ExpiresAt заполнен; 19/19 PASS.
> - **Зависит:** FB-02.
> 
> ### FB-18. Постатейная сверка ARCH v2.4 (40) и IV v1.5 (39) [L]
> - **Проблема:** оба документа индексированы (`req_index_part3.md`), но постатейно не сверены; IV критерии 1–86 неисполнимы без активных gates (FB-03); ARCH §42-45 (hold) — покрыт FB-09, §132-136 (WARP) — FB-02.
> - **Что сделать:** после P0: постатейно прогнать 79 требований против кода, зафиксировать статусы (артефакт: доп. файл `artifacts/audit/arch_iv_audit.md` — можно создавать, он новый).
> - **Критерий:** 79 требований со статусами; расхождения внесены в backlog.
> - **Зависит:** FB-03, FB-09.
> 
> ### FB-19. Тесты для geodat и quic [M]
> - **Проблема:** `src/geodat`, `src/quic` — 0 тестов при активном использовании (см. `wiring_analysis.md`).
> - **Что сделать:** минимальные unit-тесты ключевых функций (найди через `go test -cover` какие файлы без покрытия; приоритет — логика маршрутизации/парсинга).
> - **Критерий:** `go test ./geodat/... ./quic/...` → PASS с покрытием >0%.
> - **Зависит:** —
> 
> ### FB-20. Пустой пакет metrics [S]
> - **Проблема:** `src/metrics/` — пустой пакет (коллектор живёт в `http/handler`).
> - **Что сделать:** ASSUMPTION (владелец решение не дал, выбран безопасный дефолт): удалить пустой пакет, импорты поправить; ничего не переносить. Если при удалении обнаружится, что пакет используется — оставить и задокументировать.
> - **Критерий:** `go build ./...` OK; пакета-пустышки нет (или задокументированное использование).
> - **Зависит:** —
> 
> ### FB-21. PPE: авто-включение по умолчанию на Keenetic (NDM) + MediaTek [M] — РЕШЕНИЕ ВЛАДЕЛЬЦА
> - **Требование владельца (31.07):** «Аппаратный offload: per-flow исключение» — опция с галочкой в настройках (уже есть, см. ниже), НО должна быть **включена по умолчанию**, если программа определила железо роутера как Keenetic (Netcraze) с чипсетом (процессором) MediaTek. В остальных случаях — выключена (мониторинг), пользователь включает галочкой.
> - **Норма (addendum §3.2 «User-facing toggle», строки 162-177; §10 UI, строки 716-738):** toggle OFF → `offload_policy=detect` (только детекция, rules не ставятся), ON → `offload_policy=exclude` (per-flow PPE exclusion + self-test + visibility-гейт). `disable-global` — debug-режим, «никогда не включается автоматически» (этот запрет НЕ относится к основной опции). Опция описана именно для «совместимых Keenetic с MediaTek». Авто-включения основной опции документ НЕ описывает — это **новая норма**, требующая правки addendum §3.2 (согласовано владельцем).
> - **Что уже есть (НЕ переписывать, использовать):**
>   - Детектор железа: `src/capture/ppe/detect.go` — NDM по `/var/run/ndm` или `ndmc` (:68-76; «Netcraze» = NDM, Netcraze Development Module — термин в репо отсутствует), SoC по `/proc/cpuinfo` (`mediatek`/`mt762` → `SocFamily=mediatek`, :83-84), capability-проба connskip (:94-155). `report.Supported = Platform.NDM && IPv4.State==Supported` (:56).
>   - Детектор вызывается в production: `src/http/handler/capture_offload.go:38,56`, `src/capture/ppe/product_service.go:82,115,139` (через `ProductService.Start` → `Capabilities`).
>   - UI-галочка: `src/http/ui/src/components/classifier/PPEPanel.tsx:105-108` (toggle «Аппаратный offload», OFF→detect, ON→exclude).
>   - Применение: `product_service.go:189-202` — policy != `exclude` → требование отключено, rules не ставятся; policy == `exclude` и `capability.Supported` → ApplyConfig + lifecycle.
>   - Конфиг: `src/config/classifier_v23.go:7-8` (`OffloadPolicyDetect`/`OffloadPolicyExclude`), дефолт `OffloadPolicyDetect` (:332).
> - **Что сделать:**
>   1. Реализовать авто-выбор политики при первом старте (миграция конфига, `src/config/migration_ppe_product.go:23-33`): если (а) `OffloadPolicy` не задан пользователем явно (пусто/дефолт detect без признака явного выбора) и (б) детектор подтвердил **NDM + MediaTek** (и capability-supported) → установить `OffloadPolicy=exclude` (правила применятся при старте). **ВНИМАНИЕ:** текущая миграция (:29-30) прямо запрещает авто-exclusion («Operators must enable per-flow exclusion explicitly») — это противоречит решению владельца; изменить для новых установок на Keenetic+MediaTek, сохранив запрет для `disable-global` и для явного выбора пользователя.
>   2. Признак «явного выбора»: после того как пользователь переключил галочку вручную, авто-включение больше НЕ перетирает выбор (галочка OFF → detect сохраняется навсегда до нового включения вручную).
>   3. Порядок запуска: `src/http/server.go:43` — `ensureProcessPPE` до проверки `Port==0` (:44) — **оставить как есть** (PPE не зависит от веб-сервера; при Port==0 авто-включение должно работать без веб-интерфейса), но проверить: self-test (`HTTPHealthChecker` в `product_service.go:117`) не должен требовать работающий веб-сервер при `Port==0`; при необходимости — degrade/пропуск health-зависимых шагов.
>   4. Обновить addendum §3.2 + §10: добавить абзац «На Keenetic NDM с MediaTek SoC и подтверждённой capability per-flow exclusion включается по умолчанию; явный выбор пользователя сохраняется» (правка документа, помечена как согласованная).
>   5. Тесты: на шаблоне `src/capture/ppe/detect_test.go` (fake Runner с NDM+MediaTek и без) — миграция выставляет exclude только в кейсе NDM+MediaTek; non-Keenetic/non-MediaTek → detect; явный пользовательский detect не перетирается.
> - **Критерий:** unit-тест миграции: NDM+MediaTek → `OffloadPolicy=exclude` и при старте применены правила; не-Keenetic или не-MediaTek → `detect`, rules не ставятся; пользовательская галочка OFF не перетирается при последующих стартах; addendum обновлён.
> - **Зависит:** —
> 
> ### FB-22. Stage 19: подключить action/executor.go в production NFQ-путь [M]
> - **Проблема:** `src/action/executor.go` («centralized packet builder» по PATCH_PLAN Stage 19) вызывается только из тестов; в production пути NFQ не используется.
> - **Что сделать:** подключить executor в реальный путь обработки (nfq handler → action executor), сохранив fail-open; покрыть интеграционным тестом. Детали: `patch_plan_audit.md` (Stage 19).
> - **Критерий:** executor достижим из nfq-пути (не только тесты); интеграционный тест PASS.
> - **Зависит:** —
> 
> ### FB-23. Stage 33: подключить routing.FallbackManager [M]
> - **Проблема:** `routing.FallbackManager` не подключён к nfq/tun (PATCH_PLAN Stage 33 PARTIAL).
> - **Что сделать:** подключить FallbackManager к реальным путям принятия решений (nfq/tun); покрыть тестом. Детали: `patch_plan_audit.md` (Stage 33).
> - **Критерий:** FallbackManager вызывается из production-пути; тест переключения fallback PASS.
> - **Зависит:** —
> 
> ### FB-24. Stage 23: подключить адаптивную матрицу + shadow-пробы [M] — НОВОЕ (reachability-верификация 31.07)
> - **Проблема:** `src/discovery/adaptive.go:232` RunAdaptiveMatrix вызывается ТОЛЬКО из `adaptive_test.go`; config `MaxShadowProbes` нигде не потребляется; guided strategy search (ABD) и shadow-пробы в production не исполняются.
> - **Что сделать:** подключить матрицу к discovery suite (runtime.go) или удалить/задекларировать как не входящую в релиз (решение зафиксировать). Детали: `artifacts/audit/reachability/REACHABILITY_VERDICT.md` (FAIL #3).
> - **Критерий:** RunAdaptiveMatrix достижим из production-пути (не только тесты) ИЛИ удалён с вычищенными упоминаниями; `go test ./discovery/...` PASS.
> - **Зависит:** —
> 
> ### FB-25. Stages 25/26: wired lab capture + FakeProfileCompiler [M] — НОВОЕ (reachability-верификация 31.07)
> - **Проблема:** `nfq/types.go:88` SetClientHelloSink не вызывается нигде (sink nil → `nfq/handler.go:261` submitClientHelloSegment no-op); `lab/fake_profile_compiler.go:202` CompileFakeProfile — только тесты; GET /api/lab/clienthello возвращает пустой список.
> - **Что сделать:** (а) wired SetClientHelloSink из production-пути (по требованию «Real ClientHello Laboratory capture» PATCH_PLAN Stage 25) + триггеры запуска захвата; (б) подключить компилятор профилей к каталогу (или задекларировать не входящим в релиз). Детали: `reachability/REACHABILITY_VERDICT.md` (FAIL #4, #5).
> - **Критерий:** sink не nil в production-пуле; захват ClientHello достижим из runtime/API; тест интеграции через root PASS (или задекларировано).
> - **Зависит:** —
> 
> ### FB-26. Stages 28–31: решение по Level C стратегиям [M] — НОВОЕ (reachability-верификация 31.07)
> - **Проблема:** multisplit (`action/strategy.go:303-306`), HostFakeSplit (`action/hostfakesplit.go:81`), Fake Payload Catalog (`discovery/profile_catalog.go:118`), FakeMix/TLSRecordSplit (`action/fakemix.go:82`, `tlsrecordsplit.go:64`) — все только unit-тесты; nfq использует legacy-путь.
> - **Что сделать:** после FB-22 подключить к action-пути (через Executor) или задекларировать «не входит в релиз» (решение владельца; дефолт — задекларировать, если FB-22 не даёт точек интеграции). Детали: `reachability/REACHABILITY_VERDICT.md` (FAIL #6–9).
> - **Критерий:** каждая стратегия достижима из production-пути ИЛИ задокументирована как не входящая в релиз; тесты PASS.
> - **Зависит:** FB-22.
> 
> ### FB-27. GSO-пайплайн: подключить или задекларировать [M] — НОВОЕ (reachability-верификация 31.07)
> - **Проблема:** GSO normalizer-топология (`nfq/topology.go:28` NewGSOQueueTopology, `gso_normalizer.go:12`), транзакции поколений (`runtimecontrol/gso_topology_transaction.go:15,109`) — вызываются ТОЛЬКО из тестов; production-пул `nfq.NewPool` (discovery/runtime_backend.go:47) строится без GSO-топологии; метрика MetricNFQueueGSONormalized (gso_fastpath.go:211) недостижима.
> - **Что сделать:** подключить топологию к runtime-control API (транзакции StageTopologyStartSecondary) или задекларировать неактивным с вычисткой/документированием недостижимых метрик. Согласовать с FB-10 (поля токена). Детали: `reachability/REACHABILITY_VERDICT.md` (FAIL #26).
> - **Критерий:** NewGSOQueueTopology/транзакции достижимы из runtime-control API ИЛИ задекларировано; `go test ./nfq/... ./runtimecontrol/...` PASS.
> - **Зависит:** —
> 
> ---
> 
> ## 4. ДЕФИНИЦИЯ ГОТОВНОСТИ (Definition of Done) — проверь ВСЁ перед сдачей
> 
> 1. `go build ./...` (linux/amd64) — OK.
> 2. `go vet ./...` — OK (0 находок; включая fieldtest/session.go — FB-13).
> 3. `go test -count=1 ./...` — все 42 пакета PASS (включая capture/ppe — FB-01).
> 4. `go test -race -count=1 ./...` — PASS (linux/amd64, CGO=1).
> 5. CI (`release.yml`): vet + race присутствуют (FB-06).
> 6. `make build` из свежего клона (Linux) — проходит (FB-15).
> 7. Hard-gate счётчики: grep по именам гейтов показывает вызовы (FB-03).
> 8. `artifacts/audit/**` не изменён (кроме допустимых новых файлов: backup, arch_iv_audit.md).
> 9. Каждая задача: критерий приёмки проверен фактически (команда/тест), результат — в комментарии к задаче.
> 
> ## 5. СПРАВОЧНИК ПО КОМАНДАМ (верификация, Linux/amd64)
> 
> Рабочее дерево — `D:\b4x` (Windows-хост). Все прогоны Go — в Docker linux/amd64 (порядок важен — сначала генерация UI):
> 
> ```powershell
> # 1) сгенерировать defaults.json (Linux-only из-за log/syslog)
> docker run --rm -v D:\b4x:/src -w /src/src -e GOMODCACHE=/gomod -v C:\Users\AlexZander\go\pkg\mod:/gomod golang:1.25-alpine go run tools/gendefaults.go
> 
> # 2) собрать UI (Windows-хост)
> cd src\http\ui; pnpm install --frozen-lockfile; pnpm build
> 
> # 3) build + vet + test (CGO=0)
> docker run --rm -v D:\b4x:/src -w /src/src -e GOMODCACHE=/gomod -v C:\Users\AlexZander\go\pkg\mod:/gomod golang:1.25-alpine sh -c "go build ./... && go vet ./... && go test -count=1 ./..."
> 
> # 4) race (CGO=1, bookworm)
> docker run --rm -v D:\b4x:/src -w /src/src -e GOMODCACHE=/gomod -v C:\Users\AlexZander\go\pkg\mod:/gomod golang:1.25-bookworm go test -race -count=1 ./...
> ```
> 
> - Эталонные логи текущего состояния: `artifacts/audit/logs/` (go-build.log, go-vet.log, go-test.log), сводка прогонов: `artifacts/audit/B4X_TEST_EXECUTION_INDEX.md`.
> - Порядок сборки подтверждён рабочим: gen-defaults → pnpm build → go build OK.
> 
> ## 6. КЛЮЧЕВЫЕ ФАЙЛЫ (карта правок)
> 
> | Задача | Файлы |
> |---|---|
> | FB-01 | `src/capture/ppe/product_bundle_test.go` |
> | FB-02 | `src/warp/*`, `src/serviceprofile/*`, `src/fieldtest/*`, `src/silentpath/*`, `src/main.go`, `src/http/handler/*` |
> | FB-03 | `src/warp/*`, `src/silentpath/*`, `src/fieldtest/*`, `src/validation/meta.go`, `src/validation/verdict.go`, `src/fieldtest/hard_gates.go`, `src/crossservice/validation.go` (паттерн) |
> | FB-04 | `src/mtproto/transparent.go`, `src/mtproto/pending_handshake.go` (найди) |
> | FB-05 | `src/discovery/hint_planner.go`, API hints |
> | FB-06 | `.github/workflows/release.yml`, `docs.yml` |
> | FB-07 | `src/watchdog/applier.go`, `src/monitor/*`, `src/http/handler/*` |
> | FB-08 | `src/runtimecontrol/rollout_manager_apply.go`, `rollout_types.go` |
> | FB-09 | `src/nfq/tcp_hold_config.go`, `src/nfq/handler.go` |
> | FB-10 | `src/nfq/gso_token.go` |
> | FB-11 | `src/config/types.go`, `src/tables/iptables.go`, `src/capture/*`, `src/classifier/classifier_v23.go` |
> | FB-12 | `src/capture/ppe/reconciler.go`, `capture_offload_product.go` |
> | FB-13 | `src/fieldtest/session.go` |
> | FB-14 | документы (список в задаче) |
> | FB-15 | `Makefile`, `src/http/ui/.gitignore`, `package.json` (pnpm pin) |
> | FB-16 | `B4_FORK_PATCH_PLAN.md`, `B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md`, `docs/audit/b4-1.73-flow-path.md` |
> | FB-17 | `src/warp/geo.go`, `isolation.go`, `selection.go` |
> | FB-18 | (новый артефакт) `artifacts/audit/arch_iv_audit.md` |
> | FB-19 | `src/geodat/*`, `src/quic/*` |
> | FB-20 | `src/metrics/*`, `src/http/handler/*` |
> | FB-21 | `src/http/server.go` |
> | FB-22 | `src/action/executor.go`, `src/nfq/*` |
> | FB-23 | `src/routing/fallback*.go`, `src/nfq/*`, `src/tun/*` |
> | FB-24 | `src/discovery/adaptive.go`, `src/discovery/runtime.go`, `src/config/classifier_v23.go` |
> | FB-25 | `src/nfq/types.go`, `src/nfq/handler.go`, `src/lab/*`, `src/http/handler/clienthello_lab.go` |
> | FB-26 | `src/action/*`, `src/discovery/profile_catalog.go`, `src/lab/*` |
> | FB-27 | `src/nfq/topology.go`, `src/nfq/gso_normalizer.go`, `src/runtimecontrol/gso_topology_transaction.go`, `src/nfq/gso_fastpath.go` |
> 
> ## 7. НЕ ЗАБЫВАТЬ
> 
> - Часть требований «уже реализована» — НЕ ломать: Core Fix (16 stages, `nfq/tcp_gate.go` clean SYN), PPE 38/49, RST/GSO пассивная подсистема (обнаружение/suppression/rollback — подтверждено reachability), CSI 25/32 (включая `classifier/authorization.go` — candidate≠authorization; запрет mark `0x08000000` = `ProcessedBit 1<<27` в `packetmark/marks.go:5` — прежний аудит подтверждён), runtimecontrol last-good/cooldown/rollback, 41/42 зелёных пакетов (включая -race).
> - Кодировки: **все 104 файла документов (10 B4_*.md, 2 B4X_*.md, 92 docs/**) — валидный UTF-8** (строгая проверка throwOnInvalidBytes; см. FB-16). Упоминания cp866 в артефактах — устаревшие, не действовать по ним.
> - Независимая верификация reachability (31.07): `artifacts/audit/reachability/` — `patch_plan_1_18.md`, `patch_plan_19_36.md`, `warp_reachability.md`, `sp_ft_spf_reachability.md`, `csi_rstgso_reachability.md`, `mon_abd_ddi_reachability.md`, `REACHABILITY_VERDICT.md` (сводка FAIL #1–26, ложные readiness, поправки). Новые задачи из неё: FB-24..FB-27.
> - После больших правок — restore point в `artifacts/audit/backup_<дата>/`.
> - Полная трассируемость требований: `artifacts/audit/findings_draft.md` секция N + `req_index_part1..3.md`.
