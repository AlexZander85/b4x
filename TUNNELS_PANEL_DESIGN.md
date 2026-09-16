# Tunnels Management Pane — Design & Implementation

**Статус:** реализовано (этап 1: панель + routing.mode=tunnel + carrier-реестр)
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
| `warp` (AWG-WARP) | `src/transport/wg` | — (сборка ожидается) | нет | UDP full-scope |
| `h3` | зарезервирован | — | нет | UDP full-scope |

Цепочки (`awg+awg`, `masque+masque`, `awg+masque`, `masque+awg`, `nonru`): движок `src/transport/nested` (PairConfig, обе композиции) готов и e2e-тестирован; схемы в b4.json пока нет — в панели отображаются как пресеты с честным «движок ожидает сборки», без молчаливых полусостояний.

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

- AWG-WARP (`warp`) и вложенные цепочки: движки есть, конфиг-схемы и daemon-сборка ожидают следующих этапов; панель показывает их состояние честно (недоступно, с примечанием), не предлагая неработающих переключателей.
- MASQUE-carrier: IPv4/TCP только (netstack v1); UDP-лег нет до появления UDP-capable carrier-адаптера.
- Рестарт masque не поддерживается (lifecycle — супервизор WARP).
- Locales-списки стран для proton/fxvpn не тянутся в панель автоматически — выбор country/host по ISO-коду вручную (валидация на сервере против живого каталога при применении на лету).

## 7. Файлы

Бэкенд: `src/config/{types,validation}.go`, `src/reserve/registry.go`, `src/warpservice/carrier.go`, `src/{operaservice,fxvpservice}/carrier.go`, `src/tproxy/{carrier,manager,listener,listener_udp}.go`, `src/tables/{routing,routing_proxy}.go`, `src/http/handler/{tunnels,common}.go`, `src/main.go`, `src/config/validation_tunnel_test.go`.

Фронтенд: `src/http/ui/src/{components/tunnels/*, api/tunnels.ts, hooks/useTunnels.ts, models/tunnels.ts, barrels/tunnels.ts}`, интеграция в `App.tsx`, `tsconfig.json`, `barrels/icons.ts`, `components/sets/routing/TrafficRouting.tsx`, `models/config.ts`, `i18n/{en,ru}.json`.
