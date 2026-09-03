# Аудит качества тестового покрытия — D:\b4x

**Дата:** 2026-07-31
**Метод:** статический анализ (grep по `src/`, ~783 .go файла) + данные уже выполненного прогона `go test ./...` (linux/amd64, `artifacts/audit/logs/go-test.log`).
**Ограничения:** read-only аудит; файлы не изменялись (кроме этого артефакта). Подсчёты — по тест-функциям с именем `Test*` (включая receiver-методы), файлы `*_test.go`. Никакой код не компилировался и не исполнялся в рамках данного аудита.

**Исходные данные прогона:** 41/42 пакетов OK; FAIL только `capture/ppe [build failed]`:
`product_bundle_test.go:100:62` — `cannot use cfg (config.Config) as *config.Config` (NewProductService) и `:101:57` (ApplyConfig). Это API-drift: production-код перешёл на `*config.Config`, тест написан под старую сигнатуру. Пакет падает в CI **на этапе сборки**, т.е. все 52 его теста фактически не исполняются.

---

## 1. Сводная таблица по пакетам

Легенда: **TableDriven** — вхождения `t.Run(`/`cases :=`; **Neg** — имена тестов `Test.*(Error|Reject|Invalid|Zero|Negative|Boundary|Limit|Timeout|Malformed|Overflow|OutOfRange)`; **HardGates** — `Test.*(Gate|Leak|Secret|Auth|Race|Permission|Deny|Isolation|Tamper)` (строгий паттерн); **Mock** — файлы с `mock|fake|stub` в имени + вхождения `mock|fake|stub|fixture|httptest` в тексте.

| Пакет | *_test.go | src .go | Тест-функций | TableDriven | Neg | HardGates | Mock-файлы | Mock-вхождений |
|---|---|---|---|---|---|---|---|---|
| capture/ppe | 21 | 41 | 52 | 0 | 8 | 3 | 0 | 4 |
| warp | 18 | 18 | 19 | 0 | 4 | 5 | 0 | 0 |
| serviceprofile | 3 | 17 | 3 | 0 | 0 | 0 | 0 | 0 |
| fieldtest | 1 | 25 | 1 | 0 | 1 | 0 | 0 | 0 |
| silentpath | 9 | 9 | 16 | 0 | 1 | 2 | 0 | 0 |
| monitor | 10 | 11 | 17 | 0 | 1 | 2 | 0 | 0 |
| detector | 11 | 25 | 22 | 0 | 6 | 1 | 0 | 0 |
| crossservice | 1 | 1 | 4 | 0 | 2 | 0 | 0 | 0 |
| runtimecontrol | 5 | 10 | 21 | 1 | 3 | 1 | 0 | 0 |
| observability | 1 | 2 | 3 | 0 | 0 | 0 | 0 | 0 |
| discovery | 17 | 24 | 48 | 2 | 4 | 2 | 0 | 6 |
| nfq | 27 | 63 | 113 | 4 | 7 | 14 | 0 | 12 |
| tables | 6 | 19 | 60 | 92 | 4 | 3 | 0 | 10 |
| tproxy | 2 | 6 | 5 | 1 | 0 | 0 | 0 | 0 |
| tun | 2 | 8 | 8 | 4 | 0 | 1 | 0 | 0 |
| ai | 8 | 6 | 19 | 2 | 3 | 2 | 0 | 13 |
| diagnostics | 2 | 3 | 9 | 0 | 1 | 0 | 0 | 0 |
| http/handler | 15 | 44 | 69 | 23 | 6 | 4 | 0 | 151 |
| validation | 1 | 15 | 1 | 0 | 0 | 0 | 0 | 0 |
| **ВСЕГО по репо** | **268** | — | **1077** | — | — | — | — | — |

Замечания к таблице:
- **warp**: паттерн «1 тест-файл = 1 concern» (18 файлов / 19 функций); расширенный security-набор (с учётом `Bounds|Redact`): `TestAuthorizationIsScopedAndRevocable`, `TestCamouflageAuthorizationRequiresExactIdentityAndGeneration`, `TestEnrollmentCannotAuthorizeDataPlane`, `TestOuterInnerStateCannotCrossAuthorize`, `TestSecretStoreCopiesAndRedacts`, `TestTraceEnvelopeSequenceChecksumAndPriority`, `TestTraceExportRedactsAndBounds`, `TestHealthTrackerBoundsSelfHeal`.
- **nfq** — самый сильный пакет: 113 тестов, 14 hard-gate тестов (см. §4, нормы RST/GSO/QUIC/capture gates).
- **http/handler** — сильный: 69 тестов, 23 table-driven, 151 mock-вхождение (`httptest`).
- **tables** — 60 тестов, 92 `t.Run` (самый table-driven пакет).
- **tproxy/tun** — тесты есть, но мелкие (5 и 8 функций; tproxy: только mark/порт + `TestMain`-leak-verify).
- **validation** — 15 src-файлов при 1 тесте: registry-тест проверяет hash/orphans, остальной код не покрыт.
- **observability** — 3 теста на 2 src-файла, без негативных сценариев.
- Mock-файлы с `fake|stub` в имени отсутствуют во всех анализируемых пакетах (моки строятся inline-структурами/`httptest`).

---

## 2. Глубина тестов отключённых пакетов (warp, serviceprofile, fieldtest, silentpath)

Все 4 пакета не подключены к production (zero importers — подтверждено `B4X_UNTESTED_REQUIREMENTS.md`), их тесты — чистые unit-тесты без интеграции.

- **warp** (`trace_test.go`, 21 строка): проверяет `TransportTraceEnvelope.Seal()/Valid()`, monotonic sequence, отказ на дубликате, `ValidateTraceCompatibility`. Остальные 17 файлов — по одному gate-тесту каждый (authorization, enrollment, camouflage, cutoff, geo-quorum, manifest, nested, isolation, RST-obs, selection, tun-registry, secrets-redaction). **Чего нет:** IPC-супервизор (WARP-4), реальные TUN/NDM-жизненный цикл (WARP-5), 28-gate causal-trace сюита (§73B), route/path-proof счётчики, nested-бэкенд e2e, манифест/лицензионный жизненный цикл. Всё — in-memory, 0 table-driven, 0 моков.
- **serviceprofile** (3 теста / 3 функции): `transaction_test.go` (18 строк) — `Begin→Apply→Rollback` с двумя managed-сетами; `compiler_test.go`, `ownership_test.go` — по одному кейсу. **Чего нет:** diff-компиляции профилей, beginner-UI флоу (SP v1.6), промоушн-логики, интеграции с config/PPE, граничных случаев (пустые сеты, дубликаты ID, конфликты ownership).
- **silentpath** (9 файлов / 16 тестов) — **лучший из четырёх**: differential proof (candidate+control, «control bypass» отказ), leases (scope/rollback), unique progress (дубликат/overlap/out-of-order/wrap), GSO=MSS parity, suppressors (fresh+explicit error), milestones, visibility-degrade, exact-scope authorization, evidence expiry, rollback budget. **Чего нет:** ретрай-окно/тайминги (SPF-05), эквивалентность портированного z2k (SPF-04), fault-injection, e2e через реальный capture-путь, спупурессы времени (grace/preconnect/resource pressure — SPF-11 частично).
- **fieldtest** (1 тест / 23 строки) — **худшее соотношение норма↔тесты**: `session_test.go` проверяет только EventStream (отказ на дубликате EventSeq) и длину Pseudonym. **Чего нет:** FT-AC 9 обязательных мутантов causal envelope, FT-AD route/path proof + forwarded correlation, FT-AE 12 обязательных негативных кейсов (nested WARP, geo quorum, cleanup), FT-R silent observation, FT-U scoped recovery/lease/cooldown, промоушн-вердикты FT-Q/FT-V. Пакет имеет 25 src-файлов — самый «серый» в плане покрытия.

---

## 3. CI / race / goleak / fuzz / benchmark

| Аспект | Статус | Детали |
|---|---|---|
| CI-тесты | ⚠️ | `.github/workflows/release.yml`: `go test ./...` (working-directory: src) — **без `-race` и без `go vet`**; `docs.yml` — только pnpm build. |
| `-race` в CI | ❌ | Не найден ни в workflows, ни в Makefile. |
| goleak | ✅ частично | 3 файла с `go.uber.org/goleak`: `ai/stream_leak_test.go`, `discovery/runtime_join_test.go`, `log/flusher_leak_test.go`; плюс 7 пакетов используют внутренний `leaktest.VerifyTestMain` в `TestMain` (discovery, http/ws, mtproto, nfq, socks5, tproxy, watchdog). |
| Fuzz | ✅ | **25 функций** `Fuzz*` в 13 пакетах: action (8), classifier (2), diagnostics (2), discovery (4), lab (2), nfq (2), dns (1), routing (1), runtimecontrol (1), sni (1) и др. |
| Benchmark | ✅ | **28 функций** `Benchmark*` (action, lab, nfq, diagnostics, discovery, runtimecontrol, ai, http/handler, utils). |
| Отключённые пакеты | ❌ | warp/serviceprofile/fieldtest/silentpath: 0 fuzz, 0 benchmark, 0 goleak (кроме отсутствия вызовов — сами пакеты не покрыты никакими динамическими инструментами). |

---

## 4. Соответствие 10 ключевым нормам (req_index_part1-3.md)

| # | Норма (id в req_index) | Требование | Тесты в src | Вердикт |
|---|---|---|---|---|
| 1 | WARP causal trace (§73B, 28 gates; WARP-4; FT-AC) | TransportTraceEnvelope, sequence, приоритеты P0/P1/P2, checksum, mutation gates | `warp/trace_test.go` (1 тест: seal/valid/dup/checksum/priority), `warp/product_test.go` (redact/bounds) | 🔴 Частично: 2 теста против 28-gate нормы; нет мутантов, IPC, persistence |
| 2 | Secret leak (§72 base gates, 10 gates) | Никакого секрета в маршрутах/трафике, redaction | `warp/secrets_test.go` (2 теста: copy+redact, enrollment rollback), `warp/trace_test.go` (redaction) | 🟡 Юнит-уровень есть, e2e-проверки секретов в реальном data-plane нет |
| 3 | MON shadow/cutover (§0.1, §60, §80, §91) | Strangler: shadow parity, 6 стадий cutover, legacy gates, no direct apply | `monitor/compat_test.go` — 1 касательный тест (checkpoint с `CutoverVersion`) | 🔴 Пробел: нет shadow-parity (FP/FN), нет стадий cutover, нет тестов «no config mutations in shadow» |
| 4 | PPE self-test (PPE-06/10/24, PPE-45/46) | Контролируемый functional self-test, health, source-port, visibility gate, reject generic success | 7 файлов `selftest_*` + `visibility_gate_test.go`: controller failure, health (строгий протокол + reject generic), source port, store, visibility gate (block/promote) | 🟡 Сильно на компонентном уровне, НО весь пакет не собирается в CI (API-drift, §0) |
| 5 | SPF hard gates (SPF-01..19: progress, differential proof, lease, milestones, suppressors, visibility) | Useful Progress=unique range, контрольная группа, lease exact-scope, milestone tracking | `silentpath/`: differential (SPF-12), progress (SPF-10/15: dup/overlap/oow/wrap, GSO=MSS), leases (SPF-13), suppressors (SPF-11), milestones (SPF-16), visibility (SPF-17), scope/auth (SPF-13/18) | 🟡 Лучшее покрытие среди отключённых, но пакет не в production-пути; нет таймингов/ретраев/инъекций |
| 6 | CSI same-client / negative-control (CSI-10; FT-U same-client Gmail/Google) | Same-client изоляция, negative-control A/B, contamination D, YouTube state на shared-IP reject | `crossservice/` 1 файл: `TestValidateRejectsYouTubeStateOnGmailSharedIPFlow`, `TestValidateRejectsRawDomainAndMissingScenario`, passing-matrix, fresh generation | 🔴 Минимально: 4 теста, нет negative-control сюиты, нет contamination-сценариев |
| 7 | FT causal trace (FT-AC 9 мутантов, FT-AE 12 негативных кейсов) | Mutation testing envelope, generation/nested/cleanup | `fieldtest/session_test.go` (1 тест: dup EventSeq + pseudonym длина) | 🔴 Критический пробел: 1 тест против 9+12 обязательных кейсов |
| 8 | IV meta-suite (§38.1, IV-11) | `blocking_requirements_without_tests==0`, duplicate ids==0, integrity, reproducibility | `validation/registry_test.go` (1 тест: canonical hash, orphans) | 🔴 Нет runner-а/сюиты; сам gate «требование без теста» не исполняется ничем |
| 9 | Camouflage hard gates (§73A, 12 gates) | Pin обязателен, generation-owned, cutoff, no post-cutoff mutation | `warp/`: camouflage_auth (exact identity+generation), cover_sni (pin обязателен), cutoff (reject wrong gen/dup), nested (invalidate on parent), isolation, authorization, manifest (reject runtime download) | 🟡 Юнит-покрытие широкое (8 файлов), но без реального CONNECT-IP пути |
| 10 | RST/GSO safety gates (H7.1, RG-06, GSO-01) | Observe-only по умолчанию, exact FlowKey, rollback non-sliding, GSO capability gate, MSS clamp parity | `nfq/passive_rst_test.go` (4: conservative impossible-window + safety gates, non-sliding rollback + hard gates, burst flow/client isolation, observe-only), `nfq/` GSO (tun_srcmap, topology, tcp_hold, quic gates), `tables/gso_topology_test.go` | 🟢 Наиболее зрелая норма: глубокие hard-gate юнит-тесты |

---

## 5. Общая оценка

**Сильные стороны:**
- Общий объём: 268 test-файлов / 1077 тест-функций, 25 fuzz, 28 benchmark — уровень юнит-тестирования выше среднего для embedded-сетевого стека.
- nfq (113 тестов, 14 hard-gate), http/handler (69/151 mock), tables (60/92 table-driven), ppe selftest-компоненты, silentpath (16 unit-тестов на 9 файлов) — образцовые для своей области.
- Стиль имён тестов «Rejects/DoesNotPromote/Requires» — негативные сценарии встроены в архитектуру тестов по всему репо; security-семейства (auth/gate/leak) явно вынесены в отдельные файлы.

**Слабые стороны:**
- 4 пакета с нормативным ядром (warp 18/18, silentpath, fieldtest 1/25, serviceprofile 3/17) **не подключены к production** — их 39 тестов покрывают только юнит-логику, а всё, что требует интеграции (IPC, TUN/NDM, e2e капчур-путь), не тестируемо.
- CI не запускает `-race` и `go vet`; goleak — лишь 3 файла; race-детектор нигде в автотестах не участвует.
- **capture/ppe — красный в CI**: тестовая база 52 функций фактически не исполняется (build failed из-за API-drift `*config.Config`); 21 test-файл даёт 0 table-driven — хрупкий стиль «по одному кейсу на файл».
- Крупные нормативные сюиты (MON shadow/cutover, FT-AC/AE мутанты, IV meta-suite, CSI negative-control) не имеют тестов вообще или имеют 1 касательный тест.

## 6. Топ-5 пробелов покрытия относительно норм

1. **MON shadow/cutover** (§0.1/§60/§80/§91): нет shadow-parity, cutover-стадий, legacy-гейтов — 0 профильных тестов при том, что мониторинг подключен к production.
2. **FT causal trace** (FT-AC/AD/AE): 1 тест против 9 обязательных мутантов + 12 негативных кейсов + route/path-proof; пакет на 25 src-файлов покрыт одним тестом.
3. **IV meta-suite** (§38.1/IV-11): нет исполняемого runner-а; gate `blocking_requirements_without_tests==0` не проверяется кодом (1 unit-тест hash/orphans).
4. **PPE apply-pipeline** (PPE-24/26/45/46): selftest-компоненты покрыты, но e2e-конвейер apply→verify→self-test→status не тестируется, а пакет не собирается из-за API-drift — все 52 теста «мёртвые» до фикса сигнатур.
5. **Интеграционные/динамические проверки**: отсутствие `-race` в CI, goleak только в 3 файлах, warp/serviceprofile без единого integration-теста — ключевые hard-gate нормы (secret leak в data-plane, WARP trace I/O вне packet path) не проверяются динамически.
