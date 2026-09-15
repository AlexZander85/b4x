# Research: rethink-app, sing-box, rawabypassapp

Дата: 2026-09-15. Репозитории: celzero/rethink-app, SagerNet/sing-box (1.14-dev), rawa-anm/rawabypassapp.

## A. rethink-app (celzero) — Rethink DNS + Firewall + VPN

Android (Kotlin + Go-движок firestack, hard-fork outline-go-tun2socks, AAR через gomobile).

Ключевая архитектура: весь сетевой движок — отдельный Go-проект, Kotlin — только оркестрация/UI/БД.

- **Идентификаторы прокси — строковые префиксы** (`ORBOT*`, `wg<id>`, `TCP*`, `S5*`, `HTTP*`, `SYSTEM`) — произвольное число «виртуальных» прокси в одном tun-инстансе.
- **Split-tunnel по приложениям**: маппинг `(uid, packageName) → proxyId` — разные приложения через разные туннели одновременно.
- **Hop-менеджер** (`WgHopManager`): пары src→hop с валидацией графа (no self-hops, no cycles, каскадные удаления); hop-конфиги добавляются первыми при старте; `testHop()` до коммита; `removeHop()` = `hop("", src)`.
- **Статусная модель самолечения**: `status == null` (прокси исчез) → **re-add**; `TNT` (up-but-not-responding) → **refresh**; пауза/резюм по политикам сети (metered/SSID). `refreshOrPauseOrResumeOrReAddProxies`.
- **DNS-агрегат с гонкой (Smart DNS/Plus)**: параллельная регистрация всех DoH/DoT транспортов в агрегат `Backend.Plus`, Go сам гоняет гонку и держит самый быстрый живой резолвер; при `DEnd` → переустановить транспорт.
- **Race (happy-eyeballs)**: `net/doh/Race.java` — параллельные пробы, побеждает первый успешный.
- **DoH с подстановкой IP** вместо хоста (`replaceHostWithIp`) — анти-DNS-пойзонинг.
- **DNSCrypt relays** (анонимный DNSCrypt — «Tor для DNS»).
- **Tor через внешний Orbot** (broadcast-протокол NetCipher, SOCKS 9050/HTTP 8118) — Tor как «просто ещё один upstream-прокси».
- `setPcap` — pcap-режим в проде для отладки DPI; `restartTun(tunFd,…)` — обновление туннеля без пересоздания fd.
- Пробы с `protectFd`/`bindToNw` — health-check без петель маршрутизации.

## B. rawabypassapp (rawa-anm) — RawaBypass (Tauri v2 + Rust)

Кросс-платформенный десктопный обход DPI (контекст РФ/ТСПУ). Четыре движка, каждый — локальный SOCKS на своём порту; общий shutdown-broadcast; системный прокси с fail-safe сбросом.

1. **DPI-прокси** (dpi.rs): split TLS record header (пауза 10 мс), fake-пакет + дренаж ответа (50 мс в никуда), hostcase (`hOsT:`), hostdot (`Host: .example.com`).
2. **Tor** (tor.rs): **нативный Rust arti-client 0.20** (features `bridge-client`, `pt-client`), свой SOCKS4/5-сервер (~90 строк), bridge-строки парсятся в `BridgesConfigBuilder`. PT заявлены фичей, но в UI конфигурируются только bridge-строки (внешние PT-бинари arti).
3. **P2P mesh** (libp2p): Kademlia DHT, mDNS, relay-client, dcutr (hole punching), «beacon» exit-узлы, ссылки-мультиаддрессы.
4. **VLESS**: парсер `vless://` (в т.ч. Reality: pbk/sid/spx, flow xtls-rprx-vision, fp-фингерпринт) → генерация конфига Xray-core JSON → встроенный xray.exe как subprocess.

Уроки: arti можно крутить библиотекой без внешнего процесса, НО pt-client требует внешние PT-бинари; ручной SOCKS-парсер на Go не нужен (есть свой src/socks5).

## C. sing-box (SagerNet, 1.14-dev) — универсальная прокси-платформа

### C.1 Архитектура

Registry + дженерик-регистрация + DI через context (`service.FromContext[T]`), никаких глобальных синглтонов:

```go
outbound.Register[option.TorOutboundOptions](registry, C.TypeTor, NewOutbound)
```

- `adapter.Outbound`: Type/Tag/Network/Dependencies/DialContext/ListenPacket + Lifecycle `Start(stage)`/`Close`; стадии Initialize→Start→PostStart→Started.
- **`detour`-поля в dialer-опциях**: любой outbound через любой outbound, рекурсивно; топологическая сортировка зависимостей при старте.
- Rich dial-опции: `bind_interface`, `routing_mark`, `tcp_fast_open`, `tcp_multi_path`, `connect_timeout`, `network_strategy` + `fallback_delay` (happy-eyeballs по типам сетей).

### C.2 Встроенный Tor outbound (protocol/tor, библиотека cretz/bine)

- Опции: `executable_path` (внешний tor), `extra_args`, `data_directory`, **`torrc: map[string]string`** (произвольные опции — включая UseBridges/Bridge/ClientTransportPlugin).
- **proxybridge** (`common/proxybridge/bridge.go`): loopback SOCKS5-сервер со случайными кредами (randomHex(16), 127.0.0.1, случайный порт), через `RESETCONF Socks5Proxy/Username/Password` **весь исходящий трафик tor-процесса заворачивается через sing-box dialer** → «Tor через любой outbound» без патчей Tor.
- После старта: `EnableNetwork(true)`, `GETINFO net/listeners/socks` → Tor SOCKS; UDP не поддерживается (os.ErrInvalid).
- obfs4/snowflake/meek/webtunnel нативно НЕ реализованы (только SIP003-плагины для shadowsocks).

### C.3 selector + urltest — механика авто-выбора

- **Selector**: ручной выбор, персистент в CacheFile (bbolt), переживает рестарт; `interrupt_exist_connections` — опциональный разрыв при смене; `RealTag()` — разворачивание вложенных групп.
- **URLTest**: url (default gstatic generate_204), interval 3м, **tolerance 50 мс (гистерезис: смена только если новый быстрее текущего более чем на tolerance)**, idle_timeout 30м; **ленивый тикер** — проверки только при активности (Touch() на Dial), самоостановка при простое; батч-проверка concurrency=10 с персональными таймаутами, результаты ≤interval переиспользуются; мукс-сессии — с KeepSession (тест не убивает общую сессию); при ошибке dial — `history.DeleteURLTestHistory(tag)` → откат на живой; InterfaceUpdated → внеплановый CheckOutbounds.

### C.4 uTLS и Reality

- `utls.fingerprint`: chrome (все варианты, incl. chrome_pq), firefox, edge, safari, ios, android, 360, qq, `random` (один раз на процесс), `randomized` (псевдослучайный CH на каждое соединение); обёртки переписывают ALPN после BuildHandshakeState; ECH, `disable_sni` (+InsecureServerNameToVerify), `fragment`/`record_fragment` + `fragment_fallback_delay` (TLS-фрагментация анти-DPI), **`spoof`/`spoof_method`** (подмена заголовков на raw-уровне), kTLS.
- **Reality**: требует uTLS; авторизация прячется в SessionID (версия+время [0..3], short_id [8..16]); authKey = ECDH(клиентская эфемерная X25519, public_key сервера) → HKDF-SHA256(salt=Random[:20], info="REALITY") → AES-GCM(SessionID[:16], nonce=Random[20:], AAD=Raw); верификация сервера — ed25519-сертификат с HMAC-SHA512(authKey); чужой сервер → **тихий fallback: полноценный HTTP/2 GET на https://<sni> с UA реального браузера** — активный пробер видит легитимный сайт.

### C.5 Мультиплексирование

sing-mux (h2mux-наследник): `enabled`, `protocol` (h2mux/smux/yamux), `max_connections`, `min_streams` (тёплые соединения), `max_streams`, `padding` (анти-DPI паддинг кадров), `brutal` (TCP Brutal CC: up/down mbps). Множество стримов на одном соединении — один handshake, устойчивость к rate-limit.

### C.6 Embedding

```go
ctx := include.Context(context.Background())
var options option.Options; json.Unmarshal(configBytes, &options)
instance, _ := box.New(box.Options{Context: ctx, Options: options})
instance.PreStart(); instance.Start(); defer instance.Close()
```

tun-inbound с `auto_route` + **`auto_redirect` (nftables-редирект с marks/nfqueue — быстрый путь Linux-роутера)**; rule-set (.srs local/inline/remote с ETag/SHA256, mmap), geosite/geoip; правила по process/user/inbound-интерфейсу; clashapi REST для живого управления.

## D. Сводная таблица лучших практик для Tor-туннеля на роутере

| # | Практика | Источник | Применение в b4x |
|---|---|---|---|
| 1 | Loopback SOCKS5-мост со случайными кредами → весь egress tor через наш dialer (Socks5Proxy) | sing-box proxybridge | единая точка контроля egress tor (mark/bait/carrier) |
| 2 | Tor как outbound + `torrc`-map для мостов | sing-box protocol/tor | торrc-рендер из TorConfig |
| 3 | urltest: tolerance-гистерезис 50 мс, ленивый тикер, idle_timeout, сброс истории при ошибке | sing-box | выбор моста/входа, анти-флаппер |
| 4 | Selector + персистентность выбора + interrupt-группы | sing-box | ручной выбор входа из GUI, переживает ребут |
| 5 | Статусная модель самолечения: null→re-add, TNT→refresh, пауза по политике | rethink-app | реанимация мостов без рестарта туннеля |
| 6 | Гонка транспортов (happy-eyeballs) — побеждает первый успешный | rethink-app Race.java, sing-box fallback_delay | параллельный bootstrap нескольких входов |
| 7 | DNS-агрегат с гонкой для bootstrap-резолва мостов | rethink-app Plus/SmartDNS | DoH-bootstrap адресов мостов |
| 8 | DoH с подстановкой IP вместо хоста | rethink-app | анти-пойзонинг при сборе мостов |
| 9 | Hop-менеджер с валидацией графа | rethink-app WgHopManager | цепочки «tor → PT → фронт» |
| 10 | uTLS-фингерпринты + randomized; TLS-фрагментация; spoof | sing-box | ClientHello каналов к мостам/брокеру |
| 11 | Мукс + padding + Brutal CC | sing-box | скорость на lossy-каналах (для собственного транспорта) |
| 12 | arti как встраиваемый Tor (Rust) | rawabypassapp | НЕ подходит: CGO_ENABLED=0 в b4x |
| 13 | DPI-арсенал split/fake/hostcase | rawabypassapp | уже есть в движке b4x (fakedsplit/fakeddisorder) — применить к egress туннеля (bait) |
| 14 | Общий shutdown-bus + fail-safe системного прокси | rawabypassapp | порядок остановки, LAN не остаётся без сети |
| 15 | PCAP-режим в проде | rethink-app setPcap | отладка DPI на роутере |
| 16 | P2P-дискаверия адресов мостов | rawabypassapp p2p | идея на будущее (вне скоупа) |
