# Research: реализация Tor-туннеля в Nova (PC) и Nova-Android

Дата: 2026-09-15. Репозитории: `github.com/confeden/Nova` (PC, Windows), `github.com/confeden/Nova-Android` (Android). Все факты ниже верифицианы по коду с указанием файлов.

## A. Назначение и архитектура Nova

Nova — мульти-транспортный маршрутизатор для обхода DPI (ориентир — РФ): Tor — один из выходов наряду с WARP, Opera VPN, Proton (AWG), MASQUE, VLESS и прямым обходом.

- **Nova-PC**: Python (`nova.pyw` + `resources/*`), Rust-движок nova-rs, Go-хелперы. Tor — **внешние дочерние процессы** `nova-tor.exe` (C-tor 0.4.9.12 из Tor Expert Bundle 15.0.22) + `nova-lyrebird.exe` (lyrebird 0.8.1), управляются из `resources/nova_tor.py` (3194 строки). Порт реализации с Android.
- **Nova-Android**: Kotlin + Go-ядро `nova-core` (gomobile). Tor — **встроенный C-tor через JNI** (`info.guardianproject:tor-android:0.4.8.22`), а pluggable transports (obfs4/webtunnel/snowflake/meek_lite) — **библиотечно, внутри Go-ядра** (не отдельный бинарь).

Ключевой инвариант обеих платформ: **настоящие сокеты к мостам открывает код Nova** (Android — `VpnService.protect()`, PC — Job Object), а не tor.

```
TUN → tun2proxy → 127.0.0.1:SocksPort (tor)
                    └─ ClientTransportPlugin obfs4|webtunnel|snowflake socks5 127.0.0.1:N (Go-ядро)
                         └─ protect()-нутый TCP/UDP → мост
```

## B. Анатомия Tor-подсистемы (файлы)

| Файл | Содержимое |
|---|---|
| `Nova-Android/app/src/main/java/com/example/nova/TorTransport.kt` (633 стр.) | `TorTransport.start()/stop()`, `NEEDS_FRESH_PROCESS`, `writeTorrc()`, `bindTorService()`, `awaitBootstrap()` (BOOTSTRAP_TIMEOUT_MS=150s), `strictPrivateDnsHost()` |
| `Nova-Android/.../TorBridges.kt` (1332 стр.) | `TorBridge` (parse/arg/dialTarget/isUsable/addressIsDecoration), `TorBuiltinBridges` (SNOWFLAKE_CDN77/SNOWFLAKE_AMP), `TorBridgeStore` (AtomicFile tor_bridges.json), `TorEntryModeStore`, `TorAutoEntryProgress` (30 мин TTL), `TorBridgeManager` (refreshInBackground/probeAlive/fetchRaced/fetchMoat/fetchMoatViaRelay/trimKeepingEveryKind) |
| `nova-core/engine/tor_obfs4.go` (632 стр.) | `ptProxy` — loopback SOCKS5-сервер в Go-ядре: реестр `ptTransports` (obfs4, webtunnel, meek_lite, snowflake), `handle()` (SOCKS5 handshake → CONNECT → ACL → `factory.ParseArgs` → `factory.Dial(protectedDial)` → `pipe` half-close), `socks5ReadHandshake/UserPassword/Connect`, `parseBridgeArgs` (экранирование `\` по pt-spec), `protectedDial` |
| `nova-core/engine/tor_snowflake.go` (335 стр.) | `snowflakeTransport` адаптер; `ParseArgs` (url/ampcache/fronts/front/ice/max/utls-imitate/utls-nosni/fingerprint/proxy → `sflib.ClientConfig`); кэш клиентов `snowflakeArgsKey` (ключ из сырых аргументов), `snowflakeMaxPeers=8`, `snowflakeMaxClients=16`; `installSnowflakeHooks` |
| `nova-core/engine/tor_snowflake_net.go` (280 стр.) | `protectedPionNet` (все сокеты pion через протектор), `failingPionNet` (fail-loud сеть вместо nil — pion на nil молча создаёт обычную сеть, G154) |
| `Nova-Android/.../NovaVpnService.kt` | `runTorPhase/runTorEntryAttempt/holdTorSession/awaitTorBridges/openSocksTunnel`; константы TOR_BRIDGE_WAIT_MS=120s, TOR_SESSION_PROBE_TIMEOUT_MS=12s, TOR_PHASE_HANDOVER_WAIT_MS=20s, TOR_PROOF_WINDOW_MS=45s |
| `Nova-Android/.../ConnectionSelectorPolicy.kt` | `TOR_ENTRY_{AUTO,WEBTUNNEL,OBFS4,SNOWFLAKE,VANILLA,DIRECT}`, DEFAULT_TOR_ENTRY=auto |
| `Nova/resources/nova_tor.py` (3194 стр.) | `TorManager` (сессии, `_walk_attempts`, `_run_attempt`, `_await_bootstrap`, `_hold`), `BridgeCollector` (`collect`, гонка зеркал, `_probe_alive`, `_choose_snowflake_set`), `ManagedPt` (env TOR_PT_*, CMETHOD-парсинг), `TorControl` (cookie auth), `render_torrc()`, `parse_bridge_line`, KillOnCloseJob (Job Object), `tor_safe_path` (8.3-имена), пробы: `tcp_connect_probe`, `webtunnel_upgrade_probe` (строго HTTP/1.1!), `socks5_connect_probe` |
| `Nova/resources/nova_vpn_slots.py` | SECONDARY_{AUTO,OPERA,TOR}, TOR_ENTRIES, TOR_AUTO_ATTEMPTS=("webtunnel","obfs4","snowflake","vanilla"), TOR_SOCKS_PORT=1375, TOR_HTTP_PORT=1378 |

go.mod nova-core: `goptlib v1.6.0`, `lyrebird v0.0.0-20260312101154-fc105a03c0e0`, `snowflake/v2 v2.14.1` (**форк** с двумя ловушками: `NetWrapper func(transport.Net) transport.Net` в webrtc.go и `BrokerDialContext` в rendezvous.go — патч `tools/deps/patches/snowflake.patch`), `webtunnel v0.0.3` (indirect, от lyrebird), `utls v1.8.2` (совпадает с b4x).

## C. Типы входов (ENTRY_MODES, обе платформы)

`AUTO_ATTEMPTS = (webtunnel, obfs4, snowflake, vanilla)` — порядок по замеренной вероятности пройти из РФ. `direct` исключён из auto (замер из РФ: застревает на `Bootstrapped 10% (conn_done)`).

1. **webtunnel** — `webtunnel.Transport` из lyrebird. Снаружи валидный HTTPS+WebSocket к живому сайту; секрет — путь в `url=`. Адрес моста — заглушка `2001:db8::/32` (DECORATION_TRANSPORTS — «идентификатор для tor, не адрес»).
2. **obfs4** — `obfs4.Transport` (lyrebird), аргументы `cert=…;iat-mode=…` через SOCKS5-поля. Поток «равномерно случайный с первого байта» — и одновременно признак для DPI.
3. **snowflake** — встроен в Go-ядро через `snowflake/v2/client/lib` (v2.14.1, форк-ловушки). Рандеву через брокера (CDN77-фронтинг или AMP-кэш Google), данные по WebRTC (pion). Два встроенных набора (`SNOWFLAKE_CDN77` / `SNOWFLAKE_AMP`). Аргументы: url, ampcache, fronts/front, ice, max, utls-imitate, utls-nosni, fingerprint, proxy. Отвергаются: `sqsqueue`/`sqscreds` (внутри snowflake — `log.Fatalln` = смерть процесса), `max` вне 1..8.
4. **vanilla** — обычные мосты/релеи, tor соединяется сам.
5. **direct** — `UseBridges 0` (только ручной).
6. **meek_lite** — в реестре PT скомпилирован, но **не имеет входа в UI** (нет источника живых строк); SUPPORTED_TRANSPORTS ровно четыре: obfs4, webtunnel, snowflake, vanilla.

**C-tor, не arti** — на обеих платформах. Arti нигде не используется (SOCKS к ORPort моста умеет только C-tor).

## D. torrc (генерируется на каждое подключение)

```
ClientOnly 1
SocksPort 127.0.0.1:1375            # только PC (фикс. порт для PAC)
HTTPTunnelPort 127.0.0.1:1378       # только PC
SocksPolicy accept 127.0.0.0/8
SocksPolicy reject *
ControlPort 127.0.0.1:auto          # PC: ControlPortWriteToFile
CookieAuthentication 1
DormantCanceledByStartup 1
AvoidDiskWrites 1                   # Android (медленный диск)
GeoIPFile/GeoIPv6File               # PC, кавычки, удвоенные бэкслэши
UseBridges 0|1
ClientTransportPlugin <t> socks5 127.0.0.1:<порт>   # PT-входы
Bridge <строка моста>
```

Android НЕ задаёт SocksPort в torrc — `TorService` кладёт 9050/auto, порт узнаётся через `GETINFO net/listeners/socks`. Изоляции потоков нет (единый пул цепочек, ротация `SIGNAL NEWNYM`). Padding/conflux не настраиваются.

PC-специфика: все пути дублируются на **argv** (tor 0.4.9.12 читает argv через ANSI codepage); `tor_safe_path()` — 8.3-короткие имена; torrc-defaults создаётся пустым; `__OwningControllerProcess <pid>`.

Формат bridge-строки (юнит обмена; хранится целиком):
```
<transport> <addr:port> [FPR] <k=v>…
snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B28…
          url=https://1098762253.rsc.cdn77.org/ fronts=www.cdn77.com,www.phpmyadmin.net
          ice=stun:stun.antisip.com:3478,… utls-imitate=hellorandomizedalpn
```
Валидация (обе платформы): ASCII-only; запрет ISO control chars (перевод строки = инъекция torrc, G174); запрет `\ # "`; fingerprint 40 hex; **бюджет аргументов ≤ 510 Б** (поля login+password SOCKS5 по 255, RFC 1929); `sqsqueue=`/`sqscreds=` — отказ; snowflake `max=` ∈ 1..8; заглушки адресов (192.0.2., 198.51.100., 203.0.113., 0.0.0.0, 2001:db8:, ::, ::1) никогда не набираются.

## E. Оптимизации скорости и DPI-резистентности

- **webtunnel** — снаружи обычный HTTPS к живому сайту с настоящим сертификатом; блокировать можно только домен. Замеры: OnionHop отдаёт живые строки (57,5% по WS-апгрейду из РФ).
- **obfs4** — «похоже ни на что» = одновременно признак для DPI; 14/14 рукопожатий из РФ, но считается детектируемым.
- **snowflake** — рандеву фронтингом CDN (CDN77 primary, AMP-кэш + front=www.google.com fallback; у них общие fingerprints, одновременно в torrc — только один набор); транспорт WebRTC к «случайной снежинке» (жилой IP добровольца); uTLS-имитация `utls-imitate=hellorandomizedalpn`.
- **Bootstrap по движению**: падение после 150 с без роста процента ИЛИ hard cap (180 с; snowflake 300 с — холодный сидел на 50% 150 с, тёплый data-dir поднимался за 51 с).
- **Терпеливый control-port**: 60 с ожидания (tor открыл listener, но 5+ с парсил 26 МБ GeoIP).
- **Параллельный сбор**: 4 зеркала списка гонкой (первый непустой, 25 с cap); пробы — пул 8 воркеров, бюджет 60 с, лимиты на транспорт (16 TCP / 8 webtunnel-апгрейдов).
- **Дешёвая liveness-проба**: `SOCKS5 CONNECT 1.1.1.1:443` через tor; успех = exit открыл TCP. Не HTTP 200 — Cloudflare отвечает Tor-выходам челленджами (G165).
- **Лог без спама**: строка на смену тега bootstrap или +10%; повтор 30 с.
- **Порядок остановки обратный пуску**; half-close (`CloseWrite`) в pipe.
- `NEEDS_FRESH_PROCESS` + будильник: «свежий процесс стоит нескольких секунд» (второй `tor_run_main` в процессе = SIGABRT).

## F. Сбор и менеджмент мостов

Источники (порядок по замерам с Ростелеком AS12389):
1. **OnionHop-Bridges-Collector** — 4 зеркала (raw.githubusercontent, github.io, jsdelivr, statically) гонкой: `obfs4_tested.txt`, `webtunnel_tested.txt`, `vanilla_tested.txt`. 100% живых из 250, обновление раз в час.
2. **Delta-Kronecker Tor-Bridges-Collector** — fallback, только obfs4 (38–44% живых).
3. **Moat** `https://bridges.torproject.org/moat/circumvention/settings` — POST `{"country":"ru","transports":["webtunnel","obfs4","snowflake"]}` (Moat-строка snowflake несёт фронты, подобранные под страну: `cdn.zk.mk,img.icons8.com,cdn.kde.org`). Прямой путь по IPv6 (SNI-фильтр bridges.torproject.org в РФ только по IPv4); затем через прокси (Android — TLS-релей автора).
4. **Встроенные**: `pt_config.json` Tor Browser (PC) / `TorBuiltinBridges` (Android, строки из `tools/snowflake/client/torrc` собранной версии).

Выбор набора snowflake — замером: CDN77 → AMP-кэш; оба молчат → всё равно CDN77 с принудительным вердиктом «жив» (проба идёт без uTLS/фронтинга, рандеву в транспорте — с ними; вердикты кэшируются на прогон, G202).

Пробы живости: obfs4/vanilla — TCP-connect (6 с); webtunnel — WebSocket upgrade GET, ожидание `101`, **строго HTTP/1.1** (по h2 заголовки Upgrade запрещены — 0 из 8 живых), ALPN http/1.1, без редиректов; snowflake — любой HTTP-код от места встречи. Анти-SSRF: только `is_global`-адреса, dial именно проверенного адреса.

Хранение/ротация: `trim_keeping_every_kind` — круговое усечение до 40 с сохранением каждого вида; сбор успешен при ≥1 живом мосте из сети; неудачный сбор сохраняет прошлый список; свежесть 24 ч; повтор не раньше 300 с; dedup `id = transport|fingerprint||endpoint`.

## G. Жизненный цикл (PC TorManager)

- `start(entry, bridge_lines)`; generation-счётчик против гонок stop/start; preflight (бинарники, каталоги, свободные порты).
- `_walk_attempts`: auto → порядок входов минус память `auto_entry.txt` (30 мин; без неё рестарт вечно повторял webtunnel, G197); исчерпание → сброс памяти.
- `_run_attempt`: мосты для входа → ManagedPt (env `TOR_PT_*`, `CMETHODS DONE`, 10 с) → torrc → spawn tor (argv, Job Object, pid-файл) → control-файлы (60 с) → AUTHENTICATE cookie → bootstrap-поллинг `GETINFO status/bootstrap-phase` (1 с) → `net/listeners/socks` → 3 liveness-пробы.
- `_hold`: опрос 2 с; проба 60 с; **2 неудачи → `SIGNAL ACTIVE` + `NEWNYM`**; мертва после 4 неудач и 30 с → teardown + рестарт; рестарт с последнего рабочего входа (TOR-2), лимит 3/30 мин.
- `new_identity()` — `SIGNAL NEWNYM`.
- Остановка: `SIGNAL SHUTDOWN` → 3 с → kill; lyrebird — stdin-close; Job Object гарантирует смерть детей; убийство PID только после сверки образа.
- Слот SecondaryVpnController: Opera падает 180 с → переход на Tor; Tor «failed» 15 с → дальше; Tor — «медленный резерв»: фоновые триалы возврата на Opera с бэкоффом 20 мин → 2 ч.

Android: `runTorPhase` (handover-заслон 20 с, G203) → `runTorEntryAttempt` (awaitTorBridges 120 с → TorTransport.start → tun2proxy) → `holdTorSession` — **трёхзначный исход**: true (прервали) / false (умер) / **null (поднялся, но ни байта не провёз — следующий вход)**; первая успешная проба очищает память перебора и публикует latency.

## H. Что сознательно НЕ сделано в Nova

Arti не используется; stream isolation не настраивается; circuit padding/conflux не трогаются; relay scanning отсутствует (только мосты); SQS-рандеву и meek/conjure/dnstt/scramblesuit распознаются, но не подключаются.

## I. Выводы для b4x (кратко)

1. PT-прокси как loopback SOCKS5 в собственном процессе (lyrebird-библиотеки + snowflake client lib) — все PT без внешних бинарей, полный контроль сокетов (mark/bait).
2. ACL разрешённых целей на loopback SOCKS; отказ кодом `0x02`, дозвон-неудача — `0x04`.
3. Параноидальный парсинг bridge-строк (бюджет 510 Б, DECORATION-адреса, sqs-отказ) как переносимый контракт.
4. Конвейер сбора мостов (гонка зеркал, Moat country+transports, бюджеты проб per-transport, trim-keeping-every-kind, неудачный прогон не стирает список).
5. Пробы per-transport: WS-upgrade строго HTTP/1.1 для webtunnel; «любой HTTP-код» для рандеву; liveness = SOCKS CONNECT, не HTTP 200.
6. Каскад входов auto с межпроцессной памятью 30 мин; трёхзначный исход hold-цикла.
7. Bootstrap-надзор по прогрессу; терпеливый control-port; рестарт с последнего рабочего входа; бюджет рестартов.
8. torrc как чистая функция + argv-пути + пустой torrc-defaults + `__OwningControllerProcess`.
9. Файлы вместо prefs для кросс-процессной конфигурации; «говорить вслух» каждый переход состояния.
10. Форк snowflake с ловушками NetWrapper/BrokerDialContext + кэш клиентов с ключом из сырых аргументов + fail-loud сеть для pion.
