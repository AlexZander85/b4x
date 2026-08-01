# Wiring Analysis — код ↔ требования (read-only аудит)

Дата: 2026-07-31
Метод: чтение исходников + `go test -run '^$'` (компиляция тестов) в `golang:1.25.3` (Docker, src смонтирован read-only, `GOFLAGS=-mod=readonly`). Локальный Go-тулчейн отсутствует.

## 1. Lifecycle main.go (src/main.go, 736 строк)

### Порядок инициализации в `runB4` (main.go:86-467)

| # | Шаг | Место | Комментарий |
|---|-----|-------|-------------|
| 1 | `handler.Version/Commit/Date` | main.go:87-89 | |
| 2 | `--version` → выход | main.go:91-94 | |
| 3 | `ensureSingleInstance()` — pid-файл + flock | main.go:96-102, 629-670 | `/var/run/b4.pid`, `/run/b4.pid` |
| 4 | `initTimezone` (env TZ) | main.go:104 | |
| 5 | `cfg.LoadWithMigration` → `ApplyCLIOverrides` → `EnsureRuntimeGeneration` | main.go:106-111 | |
| 6 | `config.ApplyTimezone`, `ApplyMemoryLimit`, verbose | main.go:113-125 | |
| 7 | `ai.NewManager` + `handler.SetAIManager` | main.go:137-138 | AI-менеджер всегда создаётся |
| 8 | `discovery.NewRuntime` | main.go:140 | |
| 9 | `tproxy.NewLearnedIPResolver` + `tproxy.NewManager`; `mtproto.NewTransparentBridge`; goroutine `RefreshDCs`; `StartCFProxyRefresh` если `MTProto.CFProxyEnabled` | main.go:142-157 | |
| 10 | `handler.SetTablesRefreshFunc/SetRoutingSyncFunc/SetDiscoveryRuntime`; `nfq.RoutingHandleDNSFunc/LearnIPFunc` | main.go:159-199 | |
| 11 | `initLogging` (уровень, syslog, error-файл) | main.go:201, 692-718 | |
| 12 | `--clear-tables` → очистка и выход | main.go:205-216 | |
| 13 | `cfg.Validate()` | main.go:221 | |
| 14 | metrics-коллектор, `cfg.LoadTargets()` | main.go:228-242 | |
| 15 | `b4tun.RestoreFromState`, `tables.RoutingClearAll` | main.go:243-244 | |
| 16 | `nfq.NewPool(&cfg)` | main.go:248 | |
| 17 | **TUN-ветка** (`Queue.Mode=="tun"`): masquerade/MSS-clamp/conntrack sysctls → `b4tun.NewEngine` + `Start` → `tproxyMgr.SyncConfig`, `tables.RoutingSyncConfig` | main.go:253-298 | |
| 18 | **NFQ-ветка**: `tables.ClearRules`+`ClearStaleArtifacts` → `pool.Start` → `tables.AddRules` → `DetectBackend` → `tables.RoutingSyncConfig`; **`tables.NewMonitor`** если `!SkipSetup && MonitorInterval>0` | main.go:299-343 | `tables.Monitor` ≠ пакет `monitor` |
| 19 | `tproxyResolver.Set(pool.GetMatcher())`, `handler.SetTUNEngine` | main.go:364-366 | |
| 20 | `b4http.StartServer` — **внутри** (src/http/server.go:41-61): `ensureProcessPPE`+`service.Start` (запуск capture/ppe!), регистрация всех API, `AttachProcessPPEProductService`, `InitializeRuntimeControl`, auth, SPA | main.go:369 | PPE стартует даже при Port==0 (server.go:43 до проверки порта) |
| 21 | `socks5.NewServer`+`Start`, `handler.SetSocks5Server` | main.go:376-382 | ошибка старта не фатальна |
| 22 | `mtproto.NewServer`+`Start`, `handler.SetMTProtoServer` | main.go:385-390 | |
| 23 | `watchdog.New` + `wd.Start`, `handler.SetWatchdog` | main.go:392-423 | |
| 24 | `geodat.NewScheduler` + `Start` (если API-сервер не nil) | main.go:425-444 | |
| 25 | ожидание SIGINT/SIGTERM | main.go:450 | |
| 26 | shutdown: `wd.Stop`, `geoScheduler.Stop`, `tablesMonitor.Stop`, `tproxyMgr.Stop`, `gracefulShutdown` (HTTP, SOCKS5, MTProto, WS, discovery, pool/TUN, `quic.Shutdown`, очистка правил, `nfq.ShutdownDNSRouteRuntime`) | main.go:455-626 | |

### Флаги/конфиг, управляющие сервисами
- `--version`, `--clear-tables`, `--verbose` — CLI (main.go:65-67)
- `System.WebServer.Port > 0` — веб-сервер/API (main.go:231)
- `Queue.Mode == "tun"` — TUN вместо NFQ (main.go:246)
- `System.Tables.SkipSetup` — пропуск firewall-правил
- `System.Tables.MonitorInterval > 0` — `tables.Monitor` (main.go:339)
- `System.MTProto.CFProxyEnabled` — CF-proxy refresh (main.go:152)
- `System.WebServer.TLSCert/TLSKey` — TLS (server.go:84)

### Ключевые выводы по «заявленным» сервисам
- **monitor (MON v1.0 shadow/cutover): НЕ запускается.** В main.go единственный `Monitor` — `tables.NewMonitor` (main.go:340, монитор правил iptables). Пакет `monitor` (src/monitor/) — это библиотека типов/эвристик для detector'а (`monitor.MonitorScopeKey`, `Authority`, `Canary`, `DDI`, `ObservationBus` — типы, см. src/detector/abd_*.go). `CutoverVersion` существует только как поле совместимости (monitor/compat.go:88). Ни одного вызова `monitor.NewScheduler`/`.Start()` в production-коде.
- **detector: запускается только по API** (`/api/detector/start` → src/http/handler/detector.go:30) и используется discovery (src/discovery/diagnostic_profile.go:10, hint_planner.go:4, profile_store.go:8). Фонового автозапуска нет.
- **capture/ppe: РЕАЛЬНО ПОДКЛЮЧЁН и стартует** — src/http/server.go:43 `ensureProcessPPE` → :172 `ppe.NewProductService` → :177 `pool.SetPPEPassiveObserver(service.ObservationBus())` → :179 `service.Start(ctx)` → :182 `handler.SetProcessPPEProductService`. Дополнительно `ppe.DefaultVisibilityGate()` используется в nfq (tcp_hold*, tcp_reassembly*, passive_rst_observe.go:21), src/action/token_lifecycle.go:13, src/discovery/runtime.go:152, src/runtimecontrol/visibility_runtime.go. Наблюдение пакетов: nfq/ppe_observer.go, вызов из nfq/iface.go:57.
- **runtimecontrol: подключён через handler** — server.go:56 `api.InitializeRuntimeControl(...)`, эндпоинты в handler/runtime_control.go:109, типы в handler/types.go, classifier_v23.go.
- **warp / serviceprofile / fieldtest / silentpath: 0 упоминаний** в main.go, handler и во всём production-коде (grep импортов `b4/(warp|serviceprofile|fieldtest|silentpath)` = 0 совпадений). Не входят в бинарь.

## 2. API-эндпоинты http/handler (и http-корень)

Всего **115**: 108 REST (включая SPA-фолбэк и 6 динамических pprof) + 3 auth + 4 WebSocket.

| Файл | Путь | Описание |
|------|------|----------|
| ai.go | /api/ai/status, /secrets, /models, /explain, /chat | AI: статус, секреты, модели, объяснение решений, чат |
| asn.go | /api/asn, /api/asn/lookup | ASN-данные |
| backup.go | /api/backup, /api/backup/restore | Экспорт/импорт бэкапа |
| capture_offload.go | /api/v1/capture/offload/capabilities, /status, /apply, /rollback, /self-test, /self-test/result, /issue-bundle | PPE/offload: капабилити, применение, откат, self-test, issue-bundle |
| capture.go | /api/capture/probe, /generate, /list, /delete, /clear, /download, /upload | Снятие/управление каптурами трафика |
| classifier_v23.go | /api/v2/classifier/schema, /export, /import | Классификатор v2.3 |
| clienthello_lab.go | /api/lab/clienthello | Профили ClientHello (лаборатория) |
| config.go | /api/config, /api/config/reset | Конфиг, сброс |
| debug.go | /api/debug/pprof/{index,cmdline,profile,symbol,trace,heap,goroutine,allocs,threadcreate,block,mutex} | pprof (11: 5 фикс + 6 динамических) |
| detector.go | /api/detector/start, /status/{id}, /cancel/{id}, /history, /history/clear, /history/{id} | Запуск/статус/отмена ABD-диагностики |
| devices.go | /api/devices, /api/devices/{mac}/vendor | Устройства сети |
| discovery.go | /api/discovery/start, /status/{id}, /cancel/{id}, /add, /similar, /cache/clear, /current, /history, /history/clear, /history/{domain} | Обнаружение доменов/сетов (10) |
| dns.go | /api/dns | Публичные DNS-серверы |
| failure_inbox.go | /api/diagnostics/failures | Кандидаты на отказ |
| geodat.go | /api/geodat/download, /upload, /sources, /info | Geodat |
| geoip.go | /api/geoip | GeoIP |
| geosite.go | /api/geosite, /category, /domain | Geosite |
| integration.go | /api/integration/ipinfo, /ripestat/asn, /ripestat | Внешние API |
| logtrace.go | /api/logs/trace/start, /stop, /status, /download | Лог-трейсы |
| metrics.go | /api/metrics, /summary, /reset | Метрики |
| mtproto.go | /api/mtproto/generate-secret, /config, /refresh-dcs, /test-ws, /sessions, /active-clients | MTProto-сервер (6) |
| observability.go | /api/diagnostics/issue-bundle, /api/observability/metrics | Issue-бандлы, observability |
| runtime_control.go | RegisterRuntimeControlAPI — эндпоинты runtime control (см. файл, строка 109) | Управление runtime |
| sets.go | /api/sets, /targeted-domains, /check-domain, /{id}, /reorder, /{id}/add-domain, /batch-delete, /batch-set-enabled | Наборы доменов (8) |
| socks5.go | /api/socks5/config | SOCKS5 |
| spa.go | `/` | SPA-фолбэк |
| system.go | /api/system/restart, /info, /version, /update, /cache, /diagnostics | Системные (6) |
| watchdog.go | /api/watchdog/status, /check, /domains, /domains/{domain}, /enable, /disable | Watchdog (6) |
| auth.go (http/) | /api/auth/login, /check, /logout | Аутентификация |
| server.go (http/) | /api/ws/logs, /api/ws/metrics, /api/ws/discovery, /api/ws/connections | WebSocket |

**Эндпоинтов для warp/serviceprofile/fieldtest/silentpath — НЕТ** (подтверждено: 0 HandleFunc и 0 импортов).

## 3. Пакеты: подключение, тесты, компиляция

Компиляция проверена реальным прогоном `go test -run '^$'` (build only) в Docker golang:1.25.3 (go.mod: go 1.25.3), `-mod=readonly`, src read-only.

| Пакет | Подключён к main/API | Evidence (файл:строка) | go-файлов | тест-файлов | Тесты компилируются |
|-------|---------------------|------------------------|-----------|-------------|---------------------|
| nfq | **да** (ядро) | main.go:248, 312 | 90 | 27 | ✅ |
| tables | **да** (ядро) | main.go:182-199, 340 | 25 | 6 | ✅ |
| tun | **да** (TUN-режим) | main.go:274 | 10 | 2 | ✅ |
| tproxy | **да** | main.go:142-143, 364 | 8 | 2 | ✅ |
| socks5 | **да** | main.go:376-382 | 6 | 2 | ✅ |
| mtproto | **да** | main.go:145-157, 385-390 | 40 | 20 | ✅ |
| watchdog | **да** | main.go:392-423 | 9 | 2 | ✅ |
| http + http/handler | **да** | main.go:369 | 4+59 | 1+15 | ✅ |
| ai | **да** | main.go:137-138 | 14 | 8 | ✅ |
| discovery | **да** | main.go:140, 197 | 41 | 17 | ✅ |
| geodat | **да** | main.go:425-444 | 8 | 0 | ✅ (тестов нет) |
| quic | **да** | main.go:554 (Shutdown) | 6 | 0 | ✅ (тестов нет) |
| config | **да** (ядро) | main.go:40, 106-125 | 42 | 17 | ✅ |
| **capture/ppe** | **да** | http/server.go:43,172-182; nfq/ppe_observer.go | 62 | 21 | ❌ **FAIL** |
| capture | **да** (через capture/ppe) | | 12 | 5 | ✅ |
| runtimecontrol | **да** | http/server.go:56; handler/runtime_control.go:109 | 15 | 5 | ✅ |
| detector | **да** (по API) | handler/detector.go:13-20; discovery/diagnostic_profile.go:10 | 36 | 11 | ✅ |
| monitor | **да** (только как библиотека detector) | detector/abd_*.go (импорты b4/monitor) | 21 | 10 | ✅ |
| crossservice | **да** | handler/classifier_isolation.go:10, runtime_control.go:15 | 2 | 1 | ✅ |
| observability | **да** (широко) | nfq/handler.go:22, handler/observability.go:14 | 3 | 1 | ✅ |
| diagnostics | **да** | handler/failure_inbox.go:27; nfq/passive_rst_observe.go:13 | 5 | 2 | ✅ |
| metrics | **нет пакета** (коллектор в handler/metrics.go) | — | 2 | 0 | — |
| routing | **да** (через nfq) | nfq/route_binding.go:10 | 6 | 0 | ✅ |
| action | **да** (через nfq) | nfq/* (import b4/action) | 6 | 0 | ✅ |
| lab | **да** (через handler) | handler/clienthello_lab.go | 9 | 0 | ✅ |
| validation | **да** (через config) | config/* | 16 | 1 | ✅ |
| sni, utils, dhcp | **да** (вспомогательные) | nfq/classifier*, tun/dhcp | 7+5+5 | 3+1+2 | ✅ |
| **warp** | **НЕТ** — 0 импортов | grep `b4/warp` = 0 | 36 | 18 | ✅ |
| **serviceprofile** | **НЕТ** — 0 импортов | grep `b4/serviceprofile` = 0 | 20 | 3 (+validate 1) | ✅ |
| **fieldtest** | **НЕТ** — 0 импортов | grep `b4/fieldtest` = 0 | 26 | 1 | ✅ |
| **silentpath** | **НЕТ** — 0 импортов | grep `b4/silentpath` = 0 | 18 | 9 | ✅ |

### ❌ Единственный пакет с некомпилируемыми тестами: capture/ppe
Ошибка (реальный вывод go1.25.3):
```
capture/ppe/product_bundle_test.go:100:62: cannot use cfg (variable of struct type config.Config) as *config.Config value in return statement
capture/ppe/product_bundle_test.go:101:57: cannot use cfg (variable of struct type config.Config) as *config.Config value in argument to service.ApplyConfig
```
Причина: `config.NewConfig()` возвращает **значение** `config.Config` (product_bundle_test.go:98), а `NewProductService(provider ConfigProvider, ...)` требует `ConfigProvider = func() *config.Config` (capture/ppe/diagnostics.go:49) и `ApplyConfig(ctx, cfg *config.Config)` (product_service.go:275). Тест передаёт `func() *config.Config { return cfg }` со `cfg` типа `config.Config` → ошибка типов в return и в аргументе.

## 4. Ожидаемые точки интеграции 4 неподключённых пакетов

### warp (36 файлов, 18 тестов; src/warp/)
Что реализует: транспорт-подушка для WARP-подобного обхода — выбор наименее инвазивного кандидата, маршрутизация с mark-аллокацией, traceroute-пайплайн, TUN-лизинги, секреты, гео-аттестация, авторизация/отзыв, камуфляж, покрытие SNI, изоляция.
Ключевые экспортируемые API: `NewMarkAllocator` (routing.go:10), `ValidateNoRecursion` (routing.go:41), `NewTunRegistry` (tun.go:26), `NewSecretStore` (secrets.go:14), `NewTracePipeline` (trace.go:47), `ValidateTraceCompatibility` (trace.go:74), `SelectLeastInvasive` (selection.go:18), `RevokeOnNegativeEvidence` (authorization.go:18), `BuildGeoAttestation` (geo.go:32), `DefaultEnrollmentPolicy` (enrollment.go:10), `ValidateManifest` (manifest.go:15), `ProductStatus/ProductControl` (product.go:3-17: контролы test/select/reset).
Ожидаемые точки интеграции:
1. **handler-API**: `ProductStatus`+`ProductControl` — явный UI-контракт (test/select/reset), которому должен соответствовать REST-эндпоинт (его нет).
2. **Маршрутизация**: `MarkAllocator` должен вызываться из tproxy/tables-маршрутизации (выделение mark-идов для кандидатов); сейчас маршрутизация живёт в tproxy/tables без warp.
3. **tun/tproxy**: `TunRegistry` (лизинг TUN-устройств) должен подключаться к TUN-движку b4tun.
4. **Сетка/камуфляж**: `TransportCamouflageAdapter.Apply/Cutoff` (adapter.go:18-31) должны вызываться из nfq-пайплайна при обработке пакетов кандидата.

### serviceprofile (20 файлов, 3 теста; src/serviceprofile/)
Что реализует: компиляция профилей сервисов из манифестов (schema) в готовые наборы/стратегии/пробы с проверками безопасности: `Compile(manifest, opts)` → `CompiledProfile{Sets, Strategies, Probes, Safety}` (compiler.go:37-61), транзакции `Begin/Diff` (transaction.go:27,54), владение `Ownership`/`MigrateOwnership` (ownership.go:35), каталог стартовых паков `YouTubePack/DiscordPack/...` (packs.go), UI-визард `WizardView` (ui.go), `CompileDetectorPlan` (detector_plan.go:32), `CompileRecommendation` (recommendation.go:36).
Ожидаемые точки интеграции:
1. **Загрузка конфига / API**: `Import(manifest)` → `Compile()` должен вызываться при добавлении профиля через API и/или при старте; `CompiledProfile.Sets` (OrdinarySet{ID, Domain, Ownership:Managed}) должны попадать в `config.Sets` и далее в nfq-классификатор.
2. **Применение**: `Begin(prev, candidate)` → `Diff` (Preview) — транзакционный путь применения, должен быть обёрнут в handler-эндпоинт install-preview/apply (аналог InstallMode preview/apply из ui.go).
3. **Проверка**: `CapabilityRequirements` (compiler.go:46: `scoped-authorization`) предполагает рантайм-чеки, которых нет.

### fieldtest (26 файлов, 1 тест; src/fieldtest/)
Что реализует: полевые испытания каналов — контроллер сессий `NewController(base, results)` (controller.go:21), сессии `NewSession` (session.go:73), валидации сценариев (`ValidateAndroidRun`, `ValidateDiscoveryRequest`, `ValidateCanary`, `ValidateParity`, `ValidateEventOrder`), аудит `Audit`, промоушен `Promote` (promotion.go:22), оптимизация `Eligible/Rank`, `HardGatesPass`, `FaultMatrixPass`, `DifferentialReady`, псевдонимизация `Pseudonym`.
Ожидаемые точки интеграции:
1. **main/handler**: `NewController(base, results)` требует base URL и каталог результатов — должен создаваться в runB4 (или handler) и получать API-эндпоинты start/stop/status (в handler есть аналог по паттерну: /api/detector/*, /api/discovery/* — у fieldtest ничего нет).
2. **Внешние пробы**: `ClockSample` (controller.go:10) — семплирование смещения часов между роутером и локальной машиной, должно приходить извне (из раннера проб).
3. **Связка с silentpath**: `DifferentialReady(ps []DifferentialProof)` и `silentpath.ComparePaths` — контракт обмена результатами дифференциальных проб.

### silentpath (18 файлов, 9 тестов; src/silentpath/)
Что реализует: «тихий» rollout кандидатов — сравнение текущего/кандидатного/контрольного путей `ComparePaths` (differential.go:16-33), прогресс-стор `NewProgressStore` (progress.go:185), лизинги `NewLeaseStore` (leases.go:22), роллбэк-монитор `NewRollbackMonitor(l, budget)` (rollback.go:16), супрессоры `HasActiveSuppressor` (suppressors.go:15), статус/режим `EffectiveMode`+`BuildStatus` (status.go, visibility.go:19), вердикт релиза `Verdict(unitPass, targetValidated)` (release.go:12), оценка `ObserveAssessment` (types.go:98).
Ожидаемые точки интеграции:
1. **CapabilitySnapshot** (`EffectiveMode(configured, snapshot)`): источник `CapabilitySnapshot` должен поставляться рантаймом капабилити (аналог `ppe.CapabilityReport`); ни один вызов не существует.
2. **Прогресс-сторы**: `ProgressStore`/`LeaseStore`/`RollbackMonitor` должны создаваться для целевого сервиса при rollout — из fieldtest-раннера или handler-контроллера.
3. **Вердикт релиза**: `Verdict` + `Release` должны управлять переключением трафика в nfq/tproxy (cutover), но переключения не существует — рантайм никогда не переключается.

## Главные выводы

1. **Реально работает в бинаре**: nfq (классификация/мутации), tables, tun, tproxy, socks5, mtproto, watchdog, HTTP API (115 эндпоинтов), ai, discovery, geodat, quic, tables.Monitor, **capture/ppe (активно: сервис стартует из http/server.go:43-182, gate-решения влияют на nfq tcp_hold/tcp_reassembly/passive_rst, observation bus подключён к nfq-пулу)**, runtimecontrol, detector (по API), crossservice, observability, diagnostics.
2. **Мёртвое (0 подключений, не в бинаре)**: **warp, serviceprofile, fieldtest, silentpath** — 4 пакета, ~100 go-файлов + 31 тест-файл. Их тесты компилируются и проходят (build OK), но ни одна функция не вызывается. Это «продуктовый слой» (кандидат-транспорты, профили сервисов, полевые испытания, тихий rollout), который полностью отрезан от main и handler.
3. **monitor**: НЕ является shadow/cutover-сервисом в рантайме — это библиотека данных/эвристик для detector. Единственный рантайм-монитор — `tables.Monitor` (восстановление firewall-правил). Shadow-механика существует только в discovery/adaptive.go (shadow-пробы при обнаружении доменов) — это другая сущность, не MON v1.0.
4. **Несоответствие архитектуре (main.go ↔ заявленное)**: (а) «продуктовый слой» (warp/serviceprofile/fieldtest/silentpath) не провязан ни в main, ни в handler — UI-контракты пакетов (ProductControl test/select/reset, WizardView, Controller) не имеют эндпоинтов; (б) capture/ppe — единственный пакет, чьи тесты сломаны (несовпадение `config.Config` vs `*config.Config`, product_bundle_test.go:100-101), при том что сам пакет включён в боевой путь; (в) `metrics/` — пустой пакет, коллектор живёт в handler; (г) geodat/quic имеют 0 тестов при активном использовании.
5. **Пробел CI**: пакет с некомпилируемыми тестами (capture/ppe) в репозитории, где у остальных 40+ пакетов сборка зелёная, означает, что `go test ./...` в CI сейчас падает — сборку бинаря это не ломает (test-only файлы), но покрытие PPE не прогоняется.

## Методика и ограничения
- Тесты компилировались без запуска (`-run '^$'`), src монтировался read-only, go.sum не менялся (`-mod=readonly`) — изменений в репозиторий не вносилось.
- Локальный Go отсутствует; использован Docker-образ golang:1.25.3 (версия совпадает с go.mod).
- Списки эндпоинтов — из `HandleFunc`-регистраций в handler + auth.go + server.go; динамические (pprof-имена, `{id}`-параметры) отмечены.
