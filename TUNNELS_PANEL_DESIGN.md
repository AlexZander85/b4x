# Tunnels Management Pane — Design & Implementation

**Статус:** реализовано (этап 1: панель + routing.mode=tunnel + carrier-реестр; этап 2: AWG-WARP сборка + цепочки masque+awg / awg+masque)
**Ветка:** `agent/classifier-v2.3-capture-envelope`

## 0. Назначение

Панель управления резервными туннелями в существующем веб-UI B4:

- единый обзор всех туннелей (конфиг-включённость, carrier-регистрация, runtime-состояние, регион/локация);
- настройки всех фич каждого туннеля (регионы, локации, обфускация, маскарад, мосты и т.д.);
- назначение туннеля спискам доменов (сетам) через новый режим маршрутизации;
- рестарт туннеля (один цикл супервизии) из UI;
- честное отображение цепочек (awg+awg, masque+masque, awg+masque, masque+awg, «НЕ РФ») и движков, чья сборка ожидается.

Канон проекта соблюдён: honest boundaries (никаких полусостояний), fail-closed, nil-safe disabled shapes, конфиг-сбережение через валидируемый пайплайн `saveAndPushConfig`.

## 1. Состав туннелей

| Вид (kind) | Движок | Конфиг-секция | Carrier | Транспорт |
|---|---|---|---|---|
| `masque` | `src/warpservice` (MASQUE-H2) | `system.warp` | **да** (новый `MasqueCarrier`, netstack v1) | IPv4/TCP |
| `proton` | `src/protonservice` (AWG) | `system.proton` | да | UDP full-scope |
| `opera` | `src/operaservice` | `system.opera` | **да** (новая регистрация) | TCP only |
| `fxvpn` | `src/fxvpservice` | `system.fxvpn` | **да** (новая регистрация) | TCP only |
| `tor` | `src/torservice` | `system.tor` | да | TCP only |
| `warp` (AWG-WARP) | `src/awgwarpservice` (движок `transport/wg`, WG-enrollment мост) | `system.warp.awg` | **да** (Runtime сам carrier, UDP full-scope через netstack сессии) | UDP full-scope |
| `masque+awg` (цепочка) | `src/warpchainservice` → `nested.MasqueAwgRuntime` | `system.warp.chains[]` | **да** (внутренний AWG netstack: TCP + UDP) | UDP full-scope |
| `awg+masque` (цепочка) | `src/warpchainservice` → `nested.WgMasqueRuntime` | `system.warp.chains[]` | **да** (внутренний MASQUE netstack, re-attach канон warpservice) | IPv4/TCP |
| `awg+awg` (цепочка W+W) | `src/warpchainservice` → `transportwg.NestedWgRuntime` (R3/gool) | `system.warp.chains[]` | **да** (внутренний AWG netstack: TCP + UDP; два wg-слота) | UDP full-scope |
| `masque+masque` (цепочка M+M) | `src/warpchainservice` → `nested.MasqueMasqueRuntime` | `system.warp.chains[]` | **да** (внутренний MASQUE netstack v1, re-attach канон warpservice; два masque-слота) | IPv4/TCP |
| `nonru` (НЕ РФ, эксперим.) | `src/nonruservice`: nested.MasqueMasqueRuntime над плейном базового warp (warpservice.Plane) + NonRUGate (E6/E7) | `system.warp.nonru` (требует system.warp.enabled) | **динамически** (карриер регистрируется/снимается хуками гейта: PASS_NON_RU → register, любая причина закрытия → unregister + detach) | IPv4/TCP (netstack v1, ErrCarrierNoUDP) |
| `h3` | зарезервирован | — | нет | UDP full-scope |

AWG-WARP режимы данных: `netstack` (умолчание — userspace-карриер, пор routing.mode=tunnel) и `kernel` (`/dev/net/tun` + PBR field-слой: `system.warp.awg.kernel.{interface,table,rule_priority,fwmark,from_cidrs}`; userspace-карриера нет — маршрутизацию ведут селекторы from_cidrs через policy-правила).

Панельная часть `nonru` (geo-gate) закрыта этапом 5 (топология по ADR-WARP-6, честный пресет); **этап 6 закрыл daemon assembly (E6/E7)** — см. §6.

## 2. Маршрутизация доменных списков через туннель

Новый режим сета: `routing.mode = "tunnel"` + `routing.tunnel = <kind>`.

- Валидация (`src/config/validation.go`): kind обязателен, замкнутый набор `RoutingTunnelKinds` (warp/masque/h3/opera/fxvpn/proton/tor), нормализация регистра.
- `RoutingUsesTProxy("tunnel") = true` → проксирующий путь: mark + tproxy-редирект (те же правила nft/iptables, что и для SOCKS-режима).
- `tproxy.Manager.SyncConfig` резолвит carrier через `reserve.Lookup(kind)`:
  - carrier зарегистрирован → `Listener` создаётся с полем `Tunnel reserve.Carrier`; TCP-коннекты диалятся через `carrier.DialStream`; для tor при известном SNI-домене используется `DialStreamHost` (onion без резолва);
  - carrier НЕ зарегистрирован → листенер не создаётся, порт закрыт, промаркированный трафик получает отказ: **fail-closed, никогда не уходит мимо туннеля**.
- UDP: `routing.upstream.udp && carrier.SupportsUDP()` (нативно — только proton); TCP-only carriers честно отказывают (`reserve.ErrCarrierNoUDP`).
- `fail_open` (`routing.upstream.fail_open`) работает как и в proxy-режиме — с помеченным direct-фолбэком (без петель).
- `tables.buildRouteState`: `upstreamKey = "tunnel:"+kind` — смена вида туннеля перезаводит правила.
- После старта всех движков main делает один re-sync `tproxyMgr.SyncConfig` + `RoutingSyncConfig` (движки стартуют позже первого sync при загрузке).

## 3. Carrier-реестр (src/reserve)

- `operaservice.Runtime.Kind()` = opera; `fxvpservice.Runtime.Kind()` = fxvpn (регистрируются в main по канону proton: после Start, до Stop).
- `warpservice.MasqueCarrier` — адаптер kind=masque: держит один netstack на текущей generation сессии, при ошибке dial пересоздаёт (re-attach) и ретраит; `SupportsUDP()=false` (netstack v1 — IPv4/TCP only).
- `reserve.ErrCarrierNoUDP` — честный отказ TCP-only carriers.

## 4. HTTP API

Новый файл `src/http/handler/tunnels.go`:

| Метод | Путь | Назначение |
|---|---|---|
| GET | `/api/tunnels` | обзор: карточки всех видов (priority, transport, udp, config_enabled, carrier_registered, running/listening, state, region/location), пресеты цепочек, назначения (сеты с mode=tunnel), список зарегистрированных carriers |
| POST | `/api/tunnels/restart?kind=` | диспетч рестарта (opera: Kick; fxvpn/proton: RestartNow; tor: асинхронный RestartNow; masque: lifecycle принадлежит супервизору — 400 honest) |
| GET | `/api/warp/status` | проекция warpservice (ранее отсутствовала; nil-safe disabled shape) |

Существующие детальные API сохранены: `/api/{tor,opera,fxvpn,proton}/{status,locations,location,region,restart,reissue,newnym,bridges,...}`.

## 5. Веб-UI

Новая вкладка **Туннели** (`/tunnels`) — канон проекта (React 19 + MUI 7 + i18n en/ru):

- `src/http/ui/src/components/tunnels/` — Page, TunnelsPane (обзор + цепочки + назначение), TunnelCard, TunnelSettingsDialog (полный редактор фич каждого туннеля: регион/локация/обфускация/маскарад/мосты/scopes), Assignments (таблица сет→туннель с переключением через `PUT /api/sets/{id}`), StringListField.
- `hooks/useTunnels.ts` — поллинг обзора 5 c + рестарт-действия.
- `api/tunnels.ts`, `models/tunnels.ts`, баррель `@b4.tunnels`.
- Редактор сета (`components/sets/routing/TrafficRouting.tsx`): новый пункт режима «Туннель (reserve carrier)» + селектор вида + UDP/fail_open + диаграмма потока.
- `models/config.ts`: `TunnelKind`, `routing.tunnel`, TS-модели `system.{warp,opera,fxvpn,proton,tor}`.

Переключение региона/локации на запущенном туннеле применяется на лету (через `PUT /api/{opera/region,proton/location,fxvpn/location}` — один цикл супервизии) в дополнение к сохранённому конфигу. Включение/выключение туннеля — через `PUT /api/config` + перезапуск B4 (движки конфиг-первичны; честное предупреждение в UI).

## 6. Ограничения (honest boundaries)

- ~~AWG-WARP (`warp`) и вложенные цепочки: движки есть, конфиг-схемы и daemon-сборка ожидают~~ **Этап 2 закрыл**: AWG-WARP (system.warp.awg + src/awgwarpservice, WG-enrollment POST-с-реальным-ключом) и цепочки masque+awg / awg+masque (system.warp.chains[] + src/warpchainservice над transport/nested). Каждая цепочка владеет ДВУМЯ отдельными identity-слотами (один CF-девайс на слой, red line #3); валидатор отвергает коллизии слотов со одиночными транспортами.
- ~~`awg+awg` (W+W) остался за этапом~~ **Этап 3 закрыл**: цепочка awg+awg собрана в src/warpchainservice над `transportwg.NestedWgRuntime` (design §7 R3, gool-паттерн: Backend-B loopback-forwarder в netstack внешнего слоя). ДВА wg-слота (внешний junk-active профиль, внутренний vanilla), per-slot once-per-boot бюджет регистрации, MTU-градиент 1280/1200, keepalive 5/20; карриер — TCP+UDP через внутренний AWG netstack (приоритет 13 — глубже кросс-транспортных цепочек: двойной WG на одном семействе CF-краёв).
- **Этап 3 закрыл kernel-TUN режим AWG-WARP** (PBR field-слой, design §7 «kernel-TUN PBR — основной путь роутера»): system.warp.awg.mode=kernel + подсекция kernel (interface/table/rule_priority/fwmark/from_cidrs). Проводит `awgwarpservice.KernelPBR` через session-хуки KernelUp/KernelDown (addr replace /32, link up, default в выделенной таблице, на каждый селектор правило `pref P not fwmark M from CIDR table T`; анти-луп — ListenFwMark устройства). Userspace-карриера в kernel-режиме НЕТ (ErrKernelMode, карриер не регистрируется, кросс-валидация отвергает routing.tunnel=warp); kernel-сессия — linux + CAP_NET_ADMIN, проверяется полевым ручным гейтом (как transport/wg tun.go).
- ~~Остались за этапом: `masque+masque` (WARP+WARP) и `nonru` (geo-gate)~~ **Этап 4 закрыл masque+masque**: цепочка собрана в `src/warpchainservice` над `nested.MasqueMasqueRuntime` (внешний supervisor как capsule plane — канон M+W; контрольный TCP внутреннего слоя диалится через netstack внешнего, per-generation child rebuilds). ДВА masque-слота (внешний — reconciler супервизора сервиса, внутренний — reconciler движка); карриер IPv4/TCP через внутренний MASQUE netstack (re-attach канон warpservice), приоритет 12 — глубочайшая эскалация (гомогенное семейство краёв + TCP-only).
- **Этап 5 закрыл панельную часть `nonru`** (honest-unavailable пресет): пресет в chains отвечает топологией по ADR-WARP-6 (`masque-h2 → masque-h2`: вложенный WARP через базовый warp), note `nonru_geo_gated` + i18n (en/ru); tooltip больше не показывает сырой ключ. Честные границы закреплены тестами: пресет не подхватывает config-состояние (замкнутый набор chain-kind делает запись nonru невалидной), туннельной карточки-фасада нет, рестарт отвергает 400 unknown_kind. Сборка в демоне (E6/E7: nested WARP runtime над базовым warp, гео-гейт/quorum, route promotion/revocation) остаётся за этапом. Заодно закрыт пропуск этапа 4: `masque+masque` добавлен в рестарт-диспетчер (раньше известный kind получал 400 unknown_kind вместо честного 409 не-running).
- **Этап 6 закрыл daemon assembly `nonru` (E6/E7, ADR-WARP-6)**: `src/nonruservice` собирает вложенный WARP как M+M-композицию над ПЛЕЙНОМ базового warp (`warpservice.Plane` — WritePacket/SubscribePackets/Snapshot, без lifecycle-контроля; база — предусловие: config-валидация отвергает nonru без system.warp.enabled, runtime паркуется в waiting-base до появления базового identity). Гейт `transport/warp.NonRUGate` подключён по-настоящему (E7): Transport-фабрика строит TunnelGeoTransport над ЖИВОЙ внутренней сессией (`Supervisor.CurrentSession` — новый снапшот-аксессор, H2-only честно) с HTTPSExchange через ОБЩИЙ внутренний netstack (карриер + гео-пробы на одном userspace-хосте), CurrentGen = pathSerial (инкремент при смене сессии → §69-20 stale parent route token). Провайдеры: 2× whoami DNS-authority (akamai/google — голосуют, оракул IP→страна по geoip.dat: `geodat.LoadCountryPrefixes` + бинарный поиск с wider-prefix-first) + cf-trace корроборатор (warp=on|plus). Route promotion/revocation = регистрация/снятие карриера kind=nonru в reserve (приоритет 11 — глубже M+M; OnRouteRevoke также detach netstack — латентность ревокации в бюджете). Карриер IPv4/TCP (ErrCarrierNoUDP, §38). UI: пресет available + живые note (gate_open/gate_closed/assembly_pending), чип кликабелен (диалог system.warp.nonru: endpoint/identity/fingerprint/MTU/TTL/refresh/ru_countries/fallback), селектор routing.tunnel=nonru, GET /api/nonru/status (nil-safe). ПО ПРОЧЕЯВЛЕНИЮ ТЕСТА ИСПРАВЛЕН ПРОДУКТОВЫЙ ДЕДЛОК: Status() держал r.mu при вызове gate.Status(), чьи Base/InnerColo-колбэки брали r.mu снова — проекции вынесены за лок. Оракул честен: geoip.dat отсутствует → OracleLoaded=false, всё классифицируется unknown, кворум не формируется, гейт закрыт (никаких полусостояний).
- AWG-WARP: WG-registration не имеет renewal-пути (перевыпуск = слот удалить + перезапуск); рестарты сервисные под cap max_restarts_per_hour (по умолчанию 6/час, proton-канон).
- `awg+masque`: внутренний MASQUE netstack v1 — IPv4/TCP only (`reserve.ErrCarrierNoUDP` на UDP-ветке); `masque+awg` честно несёт UDP full-scope через внутренний AWG netstack.
- MASQUE-carrier (одиночный): IPv4/TCP только (netstack v1); UDP-лег нет до появления UDP-capable carrier-адаптера.
- Рестарт masque не поддерживается (lifecycle — супервизор WARP). Рестарты warp/цепочек: retire+rebuild под своими cap'ами.
- Locales-списки стран для proton/fxvpn не тянутся в панель автоматически — выбор country/host по ISO-коду вручную (валидация на сервере против живого каталога при применении на лету).

## 7. Файлы

Бэкенд: `src/config/{types,validation}.go`, `src/reserve/registry.go`, `src/warpservice/carrier.go`, `src/{operaservice,fxvpservice}/carrier.go`, `src/tproxy/{carrier,manager,listener,listener_udp}.go`, `src/tables/{routing,routing_proxy}.go`, `src/http/handler/{tunnels,common}.go`, `src/main.go`, `src/config/validation_tunnel_test.go`.

Этап 2 (AWG-WARP + цепочки): `src/transport/wg/{enrollment.go,enrollment_test.go}` (WG-registration мост: POST с реальным curve25519 ключом, hex client_id → base64 reserved), `src/config/awgwarp.go` + `validation_awgwarp_test.go` (system.warp.awg + system.warp.chains[]: каталоги по слоям, разные edge, cap inner MTU 1200, коллизии слотов), `src/awgwarpservice/{service,carrier}.go` + тесты (supervisor-канон proton: once-per-boot регистрация, restart caps, carrier kind=warp UDP full-scope), `src/transport/nested/accessors.go` (InnerSession/InnerSupervisor снапшоты), `src/warpchainservice/{service,carrier}.go` + тесты (M+W: outer supervisor как plane; W+M: inner supervisor из движка; carriers masque+awg / awg+masque), `src/main.go` (wiring + child-first shutdown), `src/http/handler/tunnels.go` (живые карточки, chain-пресеты, restart warp|chains, /api/awgwarp/status).

Фронтенд: `src/http/ui/src/{components/tunnels/*, api/tunnels.ts, hooks/useTunnels.ts, models/tunnels.ts}`, интеграция в `App.tsx`, `tsconfig.json`, `barrels/icons.ts`, `components/sets/routing/TrafficRouting.tsx`, `models/config.ts`, `i18n/{en,ru}.json` (этапы 1+2).

## 8. Tunnel Health & Benchmark (design v1, 2026-09-20)

Цель: единый слой измерения здоровья внешних туннелей (доступность/латентность/скорость/loss) и ранжирование по score; ручной и автоматический замер; отображение в админке.

ПОЛИТИКА (подтверждена владельцем): авто-переприоритизация — ТОЛЬКО рекомендация/score в UI. Смена маршрутов (какой туннель реально выбран) — исключительно через явный promote/rollback (канон canary, src/fieldtest/promotion.go, src/runtimecontrol/*). Авто-замер не меняет routing молча.

МОДЕЛЬ (новый пакет src/transport/health):
  type Metrics struct { Kind; Available bool; RTTms; TTFBms; ThroughputMbps float64; LossPct float64; Bytes int64; Probes, Failures int; Score float64(0..100); Verdict("healthy|degraded|unavailable|poor"); Error; MeasuredAt time.Time }
  type Prober interface { Measure(ctx, reserve.Carrier) Metrics }
Общий, транспорт-агностичный: проба идёт через reserve.Carrier.DialStream — работает для любого kind (warp/masque/h3/opera/fxvpn/proton/tor/nonru/chains).

ИЗМЕРЕНИЕ (одна проба, bounded):
  - availability/latency: DialStream(TargetIP:443) + TLS-хендшейк до ServerName; TTFB = время до первого байта ответа на GET Path; RTT ~ время установления (dial+handshake).
  - throughput: bounded download до MaxBytes (дефолт 64 KiB) → Mbps.
  - loss: доля неудачных проб (failures/probes). ЧЕСТНО: это availability-приближение, не счётчик ретрансмитов на проводе.
  Дефолты: TargetIP=1.0.0.1:443, ServerName=www.cloudflare.com, Path=/cdn-cgi/trace, Timeout=8s, Samples=1, MaxBytes=64KiB.

СКОРИНГ (v1, калибруется): Score = 100*(0.40*successRatio + 0.35*latencyFactor + 0.25*throughputFactor);
  latencyFactor = clamp(1 - (TTFBms-50)/950, 0, 1); throughputFactor = clamp(Mbps/10, 0, 1).
  Verdict: healthy >= 70, degraded >= 40, poor < 40, unavailable если Available=false.

КАДЕНЦИЯ: ручной замер — эндпоинт; авто-режим (фаза B) — супервизор по образцу opera.HealthConfig (cheap 60s / deep 5m), результат кладётся в per-kind кэш + метрики observability.

API:
  - GET  /api/tunnels              → в tunnelsCard добавляется "health": Metrics (из кэша, omitempty).
  - POST /api/tunnels/measure      → замер по ?kind=<kind> или по всем зарегистрированным carrier'ам; ответ {"results": {kind: Metrics}}.
  Роут монтируется в RegisterTunnelsApi (src/http/handler/tunnels.go:74-81), dispatch по образцу handleTunnelsRestart (:495).

UI (фаза C): models/tunnels.ts + TunnelCard.tsx — колонки latency/throughput/loss/score/verdict, кнопка "Measure", сортировка по score, бейдж рекомендации "лучший". Тумблер авто-замера.

REUSE (проверено):
  - reserve.List()/Entry{Priority}/Kind — registry.go:59-64,195.
  - opera.HealthConfig cheap/deep + HealthStatus (образец каденса) — transport/opera/health.go:79-128,243.
  - ProbeTCP443RTT/RankCandidatesByRTT — transport/proton/latency.go:25,117.
  - WarpScan/WarpScanHit{RTT}/WarpScanStats — transport/wg/warpscan.go:94,100,253 (cooldown/persist: seek.go,lastgood.go).
  - ProbeOutcome{TTFB,ThroughputBps,Retransmissions}/ScoreOutcome/ScoreWeights — discovery/probe_outcome.go, adaptive.go:152,168.
  - CandidateMetrics/GoodputBPS/Rank — fieldtest/optimizer.go:5,19.
  - monitor.AxisState/Aggregate — monitor/assessment.go.
  - MetricsRegistry.Set/Observe — observability/observability.go.
  - fxvpn.ProbeExit — transport/fxvpn/exitprobe.go:46 (образец сквозной пробы).

ОГРАНИЧЕНИЯ (honest boundaries):
  - Квота fxvpn 50 ГиБ/мес → MaxBytes мал (64 KiB) и Samples=1 по умолчанию; никаких больших download-тестов через fxvpn.
  - Замер идёт через туннель → трафик/нагрузка; не запускать все туннели одновременно без ограничения.
  - loss — приближение по пробам, не счётчик TCP-ретрансмитов.
  - score v1 — эвристика, калибровать полем.

ФАЗЫ:
  A (этот слой): пакет health + Prober через reserve.Carrier + POST /api/tunnels/measure + поле health в GET /api/tunnels + юниты (fake carrier).
  B: авто-супервизор (каденция opera) + per-kind метрики observability + persisted last-measure.
  C: UI (карточки, кнопка, рейтинг, рекомендация).

## 9. Решения E-FXVPN (2026-09-20, поле b4x-auj)

- **Masque (RFC 9298 CONNECT-UDP) — отложен, не реализуем (`bd b4x-d73`, GATED).** Ходит на тот же `*.m1.fastly-masque.net:2499`; префикс `23.235.42.0/24` заблокирован по IP на L3 (голый SYN → No route to host на :80/:443/:2499) — UDP не обходит IP-блэкхол; продакшн-список не отдаёт `protocols[]`/masque; UDP-эгресс уже есть у WARP/Proton. **Гейт возврата:** (а) `protocols[].name=="masque"` в serverlist И (б) конкретная нужда в UDP через Fastly.
- **Маскировка эджа fxvpn (FX-M0..M4) не лечит IP-префиксный блок (`bd b4x-esc`, DECISION).** Контентная (SNI/JA3/JA4) против L3-блэкхола бесполезна; под носителем избыточна. В коде оставлена (включена, бесплатна), но ответ на РФ-блок — носитель. См. `PROJECT_DIRECTIVES.md` §7 питфолл 29.
- **Рабочий путь fxvpn из РФ = вложение (§7.5)**, подтверждено полем: `nested=true`, `carrier=h2`, выход `loc=DE/BR`, 12/12 HTTP 200. Демон: `Options.Carrier` + `loop`-bootstrap.
- Health-дашборд туннелей (§8) — только рекомендация; маршрутизация меняется явным promote.
