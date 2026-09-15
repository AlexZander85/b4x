# Research: Tor-инструменты (tor-relay-scanner, tor-relay-scanner-go, torware, tessera, snowflake)

Дата: 2026-09-15. Репозитории: ValdikSS/tor-relay-scanner, juev/tor-relay-scanner-go, SamNet-dev/torware, NubsCarson/tessera, syphyr/snowflake (форк torproject/snowflake v2.14.0).

## 1. tor-relay-scanner (ValdikSS, Python v1.0.5)

Назначение: сканер достижимости Tor-релеев «снаружи» — находит relays, не заблокированные провайдером, оформляет как Bridge-строки.

- Источник списка (`TorRelayGrabber.grab`, src/tor_relay_scanner/scanner.py, 417 строк): onionoo `details?type=relay&running=true&fields=fingerprint,or_addresses,country` → CORS-прокси icors.vercel.app → GitHub-зеркало ValdikSS/tor-onionoo-mirror → Bitbucket-зеркало → опционально файл (--relay-infile/-outfile, офлайн-повтор). Прокси — только для скачивания списка.
- Критерии отбора: `random.shuffle`; страны `-c "se,gb,nl,-us,!tr"` (без префикса = приоритетная сортировка, default 1000; `-` исключить; `!` только-эти); порты `-p 443 -p 9001` (релей размножается на записи с единственным совпавшим адресом). Скорость/флаги НЕ фильтруются (в запросе только fingerprint, or_addresses, country).
- Алгоритм: чанки по 30, asyncio.gather; внутри релея параллельно проверяются ВСЕ or_addresses (IPv4+IPv6); повтор чанков до `-g` рабочих (default 5); таймаут — общий бюджет на соединение.
- **Глубокая проба (`TCPSocketConnectChecker.connect` с `-s/--ssl`) — главная ценность**:
  1. Реальный TLS-хендшейк со **случайным SNI** `www.<4–25 base32>.org`, CERT_NONE (имитация TLS-отпечатка Tor);
  2. Ячейка **VERSIONS**: `b"\x00\x00\x07\x00\x06\x00\x03\x00\x04\x00\x05"` (circid=0, cmd=7, версии 3–6); ответ обязан начинаться с `\x00\x00\x07`;
  3. **NETINFO** (`\x00\x00\x00\x01\x08…` + нули) + `--ssl-data-amount` (default 8) фиктивных **CREATE**-ячеек `b"\x00\x00\x00\x05\x01" + 509 нулей`; финальная проверка: ответ `\x00\x00\x00\x05\x04` (circid=5, cmd=4 = **CREATED**).
  Это одновременно проверка «живой Tor-нод» и «DPI пропускает TLS до стадии приложения».
- Выход: `ip:port FINGERPRINT` (IPv6 в скобках); `--torrc` → `Bridge ` + `UseBridges 1`; `--browser` → патч prefs.js Tor Browser.

## 2. tor-relay-scanner-go (juev, Go)

Зависимости: carlmjohnson/requests, json-iterator/go, sourcegraph/conc, spf13/pflag.

- Отличия от Python: **только TCP-connect** (TLS/VERSIONS/NETINFO/CREATE НЕ портированы); баг — проверяется только `OrAddresses[0]`; для релея выбирается один случайный OR-адрес; таймаут default 200 мс; общий --deadline 1m; conc-пул 100 горутин; фильтры `-x` exclude_port, `-4/-6`, `-j` JSON; тот же фолбэк-набор onionoo.
- Библиотечный интерфейс задуман: `scanner.New(...) → Grab()/GetJSON()`.
- Вывод: `Bridge addr fingerprint` + `UseBridges 1` (+ `ClientPreferIPv6ORPort 1` при -6).
- Для b4x: берём каркас (пул+канал+deadline), чиним все OR-адреса, добавляем глубокую пробу из Python-оригинала.

## 3. torware (SamNet-dev, Bash v1.1) — СЕРВЕРНЫЙ менеджер

Один bash-скрипт на 10 036 строк. Назначение: установка Tor **bridge/middle/exit-ноды** в Docker — НЕ клиентский туннель.

- Транспорты: obfs4-bridge (официальный образ thetorproject/obfs4-bridge:0.24), snowflake-proxy (волонтёрский), Lantern Unbounded, MTProxy. WebTunnel НЕ поддерживается.
- torrc-генерация `generate_torrc(idx)`: Nickname, ContactInfo (санитизация кавычек/бэкслешей), ORPort 9001+idx, CookieAuthentication 1, BandwidthRate/Burst, AccountingMax, exit-политики.
- ControlPort-доступ без библиотек: `get_control_cookie()` (чтение control_auth_cookie из volume, hex, кэш 60 с, атомарная запись) + `controlport_query()` (`AUTHENTICATE <hex>` + `GETINFO traffic/read|written|circuit-status|orconn-status|accounting/*` через ncat, timeout 5).
- Bridge line: чтение `/var/lib/tor/pt_state/obfs4_bridgeline.txt` с подстановкой `<IP ADDRESS>/<PORT>/<FINGERPRINT>`.
- Health-check 15-точечный; TUI-дашборд; Telegram-бот; backup identity-ключей.
- Для b4x: паттерн ControlPort-cookie + набор GETINFO для health/статистики; чек-лист health-check; авторестарт-политика.

## 4. tessera (NubsCarson, Rust) — ARC-креденшалы + Tor-обход

Research-проект: анонимные rate-limited креденшалы (IETF privacypass ARC) + CONNECT-прокси поверх Tor. Для b4x важны ТОЛЬКО инженерные практики управления Tor (креденшалы/ZK избыточны):

- **`crates/tessera-client/src/torrc.rs`** — генератор клиентского torrc: `enum PluggableTransport {Obfs4, Snowflake, WebTunnel}`, `BridgeConfig::validate()`: пустой plugin → ошибка; 0 bridge-линий → ошибка; **CRLF в любом поле → ошибка** (анти-инъекция); первая лексема Bridge-строки обязана совпадать с транспортом. Тесты — против `tor --verify-config`.
- **`scripts/run-onion-client.sh`**: SOCKS на 19250 (не 9050 — не пересечься с системным), **ожидание `Bootstrapped 100%` в логе** (до 60 с, не sleep), **fail-loud**: PT выбран, а бинарник не найден → жёсткая ошибка, никакого тихого падения в открытый Tor; `TESSERA_ALLOW_CLEARNET_FALLBACK=1` — явный opt-out.
- **`tessera-relay`**: `TorSocksDialer` — hostname (в т.ч. `.onion`) передаётся в SOCKS **нересолвленным** (нет DNS-утечек); `ConnectionRefused` на SOCKS-порту = «Tor не запущен», без ретраев; cold-start 3 ретрая × 2 с только на прогреве.
- `demo-bridge-entry.sh`: эталонный end-to-end с локальным obfs4-bridge (pt_state/obfs4_bridgeline.txt + fingerprint).
- docs/CENSORSHIP_RESISTANCE.md: матрица транспортов obfs4 (шум) / snowflake (видеозвонок) / webtunnel (HTTPS за реальным доменом); принцип «вход (PT) — отдельно, приватность — отдельно».

## 5. snowflake (syphyr, срез upstream v2.14.0)

Форк = срез upstream-main + debian-упаковка; авторских изменений по содержимому не выделяется. От «классического» снежинка-кода отличается:

- **covert-dtls** (`theodorsm/covert-dtls v1.5.0`) — маскировка DTLS ClientHello: `disable` / `randomize` (уникальный отпечаток) / `mimic` (свежий Chrome/Firefox) / `randomizemimic` (случайный из базы, рекомендуется; default в standalone-прокси).
- **uTLS** (`refraction-networking/utls v1.8.2` + ptutil/utls) для брокера: `-utls-imitate`, `-utls-nosni`.
- pion v4 (webrtc/v4.2.3-securityfix), **KCP** (`xtaci/kcp-go/v5`) + **smux** — Turbo Tunnel: поверх последовательности эфемерных WebRTC-соединений живёт долгоживущая KCP-сессия (окно 65535, congestion off, stream mode), поверх — smux (KeepAliveTimeout 10 мин, MaxStreamBuffer 1 МБ).
- SQS-rendezvous (client/lib/rendezvous_sqs.go — тянет aws-sdk-go-v2), AMP-cache, Prometheus-метрики брокера.

Архитектура:
- **`client/lib`** (имя пакета `snowflake_client`) — библиотека для встраивания: `ClientConfig{BrokerURL, AmpCacheURL, SQSQueueURL, SQSCredsStr, FrontDomain, FrontDomains, ICEAddresses, KeepLocalAddresses, Max, UTLSClientID, UTLSRemoveSNI, BridgeFingerprint, CommunicationProxy, CovertDTLSConfig, CovertDTLSFingerprint}`; `NewSnowflakeClient(config)` → `transport.Dial() net.Conn` (до PT-сервера моста); `SetRendezvousMethod(RendezvousMethod)` — плаггable рандеву (`Exchange([]byte) ([]byte, error)`); события через `AddSnowflakeEventListener`.
- `Transport.Dial()`: Peers-коллектор (ReconnectTimeout=10 с, до Max), затем сессия: магия `turbotunnel.Token {0x12,0x93,0x60,0x5d,0x27,0x81,0x75,0xf5}` + 8-байтный ClientID в начале каждого нового WebRTC; encapsulationPacketConn (length-prefixed, ≤1048575 Б) → RedialPacketConn (очереди 512, тихий передиал) → KCP → smux → SnowflakeConn. SnowflakeTimeout=20 с (stale-детектор), DataChannelTimeout=10 с.
- ICE: SettingEngine — IP-фильтр (резать локальные/loopback), mDNS off, stdnet; опционально весь ICE через SOCKS5-UDP (`proxy.NewTransportWrapper`); не-trickle ICE (GatheringCompletePromise). NAT-детект RFC 5780; при unknown спуфится unrestricted.
- Брокер: POST `/client` `ClientPollRequest{Offer, NAT, Fingerprint}`; unrestricted-клиенту сначала предлагается restricted-прокси (балансировка); AMP-эндпоинт `/amp/client/` (armor HTML, max-age=15).
- Клиент PT-режимом: `client/snowflake.go` (goptlib), **перезапись конфига SOCKS-аргументами на каждое соединение** (ampcache/sqsqueue/fronts/ice/max/url/utls-nosni/utls-imitate/fingerprint/covertdtls-*).

**CDN-фронтинг обязателен?** Нет (прямой HTTPS возможен для тестов, SQS — без CDN), но в цензурной практике — да, front/ampcache нужны.

**Встраивание**: прямой импорт `client/lib` — готовый snowflake-клиент без внешнего процесса; поверх `Dial()` net.Conn должен говорить Tor-протокол.

## Сводка заимствований для b4x

| # | Практика | Источник |
|---|---|---|
| 1 | Глубокая проба релея: TLS random SNI → VERSIONS → NETINFO+CREATE → CREATED | tor-relay-scanner |
| 2 | Цепочка источников onionoo с фолбэками + файловый кэш | tor-relay-scanner |
| 3 | Каркас сканера (пул+канал+deadline+goal) — починив OrAddresses[0] и добавив глубокую пробу | tor-relay-scanner-go |
| 4 | ControlPort-cookie + GETINFO traffic/circuit/orconn/bootstrap | torware |
| 5 | torrc-генератор с валидацией (CRLF-бан, сверка транспорта, verify-config в тестах) | tessera |
| 6 | Fail-loud PT (нет бинарника → ошибка, не тихий open-Tor); opt-out только явной переменной | tessera |
| 7 | `TorSocksDialer`: hostname нересолвленным в SOCKS; ConnectionRefused = Tor мёртв без ретраев | tessera |
| 8 | Прямой импорт `client/lib` (ClientConfig, Dial, SetRendezvousMethod, events) | snowflake |
| 9 | Turbo Tunnel паттерн (Token+ClientID → encapsulation → Redial → KCP → smux) — если свой мост | snowflake |
| 10 | uTLS + covert-dtls (randomizemimic) для всех HTTPS/DTLS наружу | snowflake |
| 11 | Удаление SQS-рандеву в форке → сбрасывает всё дерево aws-sdk-go-v2 (важно для MIPS vendor) | b4x-специфика (по мотивам Nova-отказа от sqs) |
