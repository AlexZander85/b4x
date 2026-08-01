# REACHABILITY_VERDICT — независимая верификация аудита B4X (31.07.2026)

**Объект:** AlexZander85/b4x, ветка `agent/classifier-v2.3-capture-envelope` (рабочее дерево D:\b4x, не git).
**Метод:** для каждого механизма — доказанная цепочка production root → import → runtime owner → implementation → observable side effect → cleanup/rollback.
**НЕ засчитывались:** unit-вызовы, конструктор-тесты, Valid(), test-only адаптеры, документация, API type без handler, пакет без импорта из production root.
**Инструменты:** grep/чтение кода (главный агент + 7 субагентов explore, read-only); сборка/`go list -deps` — linux/amd64 (Docker, сессия 2); повторная перепроверка спорных фактов главным агентом 31.07 вечер.

---

## 1. Итоговая статистика

| Область | REACHABLE | PARTIAL | FAIL | NA |
|---------|-----------|---------|------|----|
| PATCH_PLAN этапы 1–18 | 13 | 2 (4, 7) | 1 (17) | 2 (1, 2) |
| PATCH_PLAN этапы 19–36 | 6 (20,21,22,24,27,34) | 2 (32, 35) | 10 (19,23,25,26,28,29,30,31,33,36) | — |
| PPE addendum (8 стадий) | 8 | — | — | — |
| CSI addendum | 4 (вкл. promote-гейт, счётчик) | — | — | — |
| RST/GSO addendum | passive-RST подсистема | — | GSO-пайплайн, active RST, rst_path | — |
| WARP v1.2 | 0 | — | 9 (все) | — |
| SP v1.6 | 0 | — | 5 (все) | — |
| FT v1.5 | 0 | — | 5 (все) | — |
| SPF v1.0 / silentpath | 0 | — | все (вкл. 3 ABSENT) | — |
| MON v1.0 | legacy watchdog активен | — | strangler-замена | — |
| ABD v1.2 | detector suite API | BlockingProfile schema | guided search (Stage 23) | — |
| DDI/TGB | — | — | bridge legacy-путь, prior | — |

**Итого FAIL (severity HIGH): 26 механизмов.** Вердикт прежнего аудита **B4X_NOT_COMPLIANT подтверждён** (с учётом 1 поправки вниз: marks.go — прежний аудит был прав).

## 2. FAIL-механизмы с файл:строка (сводная таблица)

| # | Механизм | Файл:строка | Задача |
|---|----------|-------------|--------|
| 1 | Stage 17: stream-offset planner (extsplit/desync/combo/firstbyte/disorder) | `src/action/stream_map.go`, `planner.go:69` Plan; legacy-инъекции `nfq/handler.go:434+` | **FB-22** (новое: расширить) |
| 2 | Stage 19: action.Executor / packet builder | `src/action/executor.go:45,66`; nfq шлёт старым путём `nfq/nfq.go:66`, `verdict.go:69` | **FB-22** |
| 3 | Stage 23: адаптивная матрица + shadow probes | `src/discovery/adaptive.go:232` RunAdaptiveMatrix; MaxShadowProbes не потребляется | **FB-24** (новая) |
| 4 | Stage 25: Real ClientHello Lab capture | `src/nfq/types.go:88` SetClientHelloSink — не вызывается (sink nil); `nfq/handler.go:261` submitClientHelloSegment no-op | **FB-25** (новая) |
| 5 | Stage 26: Fake Profile Compiler | `src/lab/fake_profile_compiler.go:202` — только тесты | **FB-25** (новая) |
| 6-9 | Stages 28–31: Level C стратегии (multisplit, hostfakesplit, fake payload catalog, fakemix/tlsrecordsplit) | `src/action/strategy.go:303-306`, `hostfakesplit.go:81`, `discovery/profile_catalog.go:118`, `fakemix.go:82`, `tlsrecordsplit.go:64` | **FB-26** (новая) |
| 10 | Stage 33: FallbackManager | `src/routing/fallback.go:234` — только тесты | **FB-23** |
| 11 | Stage 36: fieldtest-сюит (14 сценариев) | `src/fieldtest/*` — 0 импортеров | **FB-02** |
| 12 | WARP v1.2: все 9 механик | `src/warp/*` — 0 импортеров (enrollment, secrets in-memory, geo:32/62, trace.go, routing/selection, isolation, masque/manifest, cover, verdicts) | **FB-02/FB-03/FB-17** |
| 13-17 | SP v1.6: compiler/ownership/warp_profile/warp_recommendation/transaction | `src/serviceprofile/*` — 0 импортеров; `path_proof_supported` ABSENT | **FB-02** |
| 18-22 | FT v1.5: Controller/HardGatesPass/мутанты/сессии/сценарии | `src/fieldtest/*` — 0 импортеров; `hard_gates.go:5` | **FB-02/FB-03/FB-13** |
| 23-25 | SPF: BaselineModel/RetryCorrelator/DifferentialProbeController | ABSENT в `src/silentpath/` | **FB-02** |
| 26 | GSO-пайплайн (primary+normalizer топология, транзакции поколений) | `src/nfq/topology.go:28` — только тесты; `runtimecontrol/gso_topology_transaction.go` — только тесты | **FB-27** (новая) |

## 3. Ложные readiness-отчёты (найдено)

| Отчёт | Проблема |
|-------|----------|
| `artifacts/audit/patch_plan_audit.md:17` (Этап 7) | «wired» — фактически TCPFlowStore конструируется только в `tcp_test.go:98,124` (PARTIAL, severity LOW) |
| `artifacts/audit/patch_plan_audit.md:27` (Этап 17) | PARTIAL — по строгим критериям FAIL/HIGH (планировщик недостижим) |
| `docs/reports/cross-service/CSI_IMPLEMENTATION_REPORT.md:13` (CSI-3) | заявлен без оговорки default-off (CSI-3 — default-off механика) |
| `PPE_STAGE_7_IMPLEMENTATION_REPORT.md` | неточность формулировки: lifecycle-wrapper «available but not globally instantiated», фактически ensureProcessPPE вызывается из `server.go:43` — инициализирован; итоговый статус gate корректен (не ложный readiness, но зафиксировано) |
| `PPE_STAGE_8_IMPLEMENTATION_REPORT.md` | «beginner-safe UI controls» — UI не собран (ui/dist отсутствует), бинарно не подтверждён |

**Корректные отчёты (не ложные):** `docs/validation/rst-gso-h10.md` (NO-GO), `docs/validation/keenetic-android-v23.md`, WARP_* (честные), PPE_STAGE_*_VALIDATION (PASS_WITH_LIMITATIONS + дисклеймеры), flow-path.md:389 NO-GO.

## 4. Поправки к прежнему аудиту (итог перепроверки)

1. **marks.go / 0x08000000 — прежний аудит ПРАВ.** `packetmark/marks.go:5`: `ProcessedBit = 1 << 27 == 0x08000000`. Бит зарезервирован, других использований в src нет (кроме дефолта `ProcessedMarkMask: 1 << 27`, config/classifier_v23.go:332 — тот же бит). Промежуточное замечание «не подтверждается» — ошибка интерпретации, СНЯТО.
2. **`warp_trace.go` не существует** (ранняя сводка неточна): causal trace — `src/warp/trace.go`; функций Ready() в warp нет (вердикт-классы — camouflage_auth.go:22-27). Выводы не меняются (пакет test-only).
3. **GSO-normalizer**: промежуточное предположение о достижимости (pool.go:138) опровергнуто — pool.go:138 достижим только через NewGSOQueueTopology (тесты); production-пул — NewPool (discovery/runtime_backend.go:47) без GSO. Итог: GSO-пайплайн FAIL.
4. **PassiveRST — прежний аудит ПРАВ**: подсистема активна (handler.go:230,245; connstate.go:382-401; hardening_status.go:41-44; live_runtime.go:280).

## 5. Что работает (REACHABLE, подтверждено цепочками)

- Core Fix: конфиг/версионирование, ClassificationPhase/Evidence/Confidence, client identity, bounded HostHintStore, DNS-парсер, DNS→first-flow, QUIC→TCP handoff, NFQ-решение+DomainOnly v2, TLS-метаданные, reassembly (config-gated), ECH-policy, hold/replay (config-gated), idempotency.
- Metrics/Observability (Stage 20), Discovery sandbox (21), ProbeOutcome (22), Failure Inbox (24), transactional apply/canary/rollback (27), Backend config API (34), UI backend-часть (35-PARTIAL).
- PPE стадии 1–8 (включая visibility-гейт — активен: server.go:177, tcp_hold_worker.go:74 и др.).
- CSI: candidate≠authorization, promote-гейт, unrelated_control_action_total.
- PassiveRST-подсистема (observe/suppress/rollback/API).
- MON legacy watchdog (applyBatchResults — активен, цепочка main.go:392→watchdog_tick.go:32→watchdog_heal.go:111→applier.go:44).

## 6. Новые задачи для fix backlog (FB-24 … FB-27)

| Задача | Содержание | Severity |
|--------|-----------|----------|
| **FB-24** | Stage 23: подключить RunAdaptiveMatrix + shadow-пробы к discovery suite (или удалить/задекларировать) | M |
| **FB-25** | Stages 25/26: wired lab capture (SetClientHelloSink из production, HTTP-триггеры) + FakeProfileCompiler в runtime | M |
| **FB-26** | Stages 28–31: решение по Level C стратегиям — подключить к action-пути (после FB-22) или задекларировать «не входит в релиз» | M |
| **FB-27** | GSO-пайплайн: подключить NewGSOQueueTopology/транзакции к runtime-control API или задекларировать неактивным (сейчас недостижим, но код и метрики существуют) | M |

Остальные FAIL покрыты существующими FB-02/03/04/05/07/10/13/14/17/22/23.

## 7. Ограничения верификации

- Статические проверки (grep/чтение/`go list -deps`); динамическая трассировка не выполнялась (продукт — роутерный классификатор, linux-only).
- `go list -deps` (сессия 2, linux/amd64) — основной источник по импортам; повторные grep подтвердили отсутствие внешних импортеров у warp/serviceprofile/fieldtest/silentpath.
- Реальные side effects (PPE на Keenetic, RST suppression на трафике) не исполнялись — статусы «REACHABLE» означают достижимость кода из production-пути, не полевую верификацию.
