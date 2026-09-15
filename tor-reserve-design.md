# E-TOR: Tor-резерв — дизайн (v1, 2026-09-15)

**Статус: ПРОЕКТ.** Родительские слои: `proton-awg-design (1).md` §12 (зафиксированная
композиция Tor-over-carrier — условия §12.4 выполнены, решение владельца от 2026-09-15),
канон резервных туннелей warp/opera/fxvpn/proton. Этапы: TT1–TT10 (патч-план
`tor-reserve-patch-plan.md`).

Позиция: **R-reserve, TCP-only, самый низкий приоритет в реестре** (ниже proton) +
**scoped-egress для `.onion`**. Никогда — молчаливая подмена, никогда — глобальный
тумблер (урок ProtonVPN-Next из proton-design §12.1: «всё или ничего» — не наш путь;
scoped-маршрутизатор b4x уже решает per-flow).

Цель владельца: **самый быстрый и самый DPI-резистентный Tor-туннель для роутера** —
все виды входов уровня Nova (webtunnel, obfs4, snowflake, meek_lite, vanilla, direct),
плюс то, чего нет ни у кого: движок анти-DPI b4x, защищающий собственные хендшейки
туннеля (NFQ-bait), и композиция Tor-внутри-носителя на полную скорость релеев.

## Источники (скачаны и прочитаны полностью)

| Референс | Отчёт | Что взято |
|---|---|---|
| confeden/Nova (PC) | `artifacts/tor-research/research-nova-tor.md` | PT-прокси в процессе, конвейер сбора мостов, лестница входов, парсер bridge-строк, bootstrap-надзор, hold-цикл |
| confeden/Nova-Android | там же | tor_obfs4.go/tor_snowflake.go (инбокс PT как библиотек), форк-ловушки snowflake, трёхзначный исход hold |
| ValdikSS/tor-relay-scanner | `artifacts/tor-research/research-tor-tooling.md` | глубокая проба релея (VERSIONS/NETINFO/CREATE→CREATED), цепочка onionoo-источников |
| juev/tor-relay-scanner-go | там же | каркас сканера (пул+deadline+goal), баги для исправления |
| SamNet-dev/torware | там же | ControlPort-cookie + GETINFO-набор для health/статистики |
| NubsCarson/tessera | там же | torrc-генератор с валидацией, fail-loud PT, TorSocksDialer (hostname нересолвленным) |
| syphyr/snowflake (v2.14.0) | там же | client/lib как встраиваемая библиотека, covert-dtls, uTLS, Turbo Tunnel, SQS-дерево aws-sdk на выкидывание |
| celzero/rethink-app | `artifacts/tor-research/research-rethink-singbox-rawa.md` | статусная модель самолечения, гонка транспортов, DNS-агрегат с гонкой |
| SagerNet/sing-box | там же | **proxybridge** (loopback SOCKS5 со случайными кредами → весь egress tor через наш dialer), urltest-гистерезис, uTLS/Reality-паттерны |
| rawa-anm/rawabypassapp | там же | DPI-арсенал (уже есть в b4x), урок arti (не подходит: CGO=0) |
| b4x HEAD adbecc2 | `artifacts/tor-research/research-b4x-reserve-arch.md` | контракт резерва, эталон protonservice, примитивы, красные линии, ограничения платформы |

---

## §0. Что это и роль

E-TOR — резервный туннель на базе сети Tor: внешний процесс C-tor (Entware/путь
владельца) + **все pluggable transports внутри процесса b4 как библиотеки** (lyrebird:
obfs4/webtunnel/meek_lite; snowflake/v2: client/lib) + собственный egress-мост,
который собирает в одной точке контроль всех исходящих соединений tor (маркировка
SO_MARK, NFQ-bait первого полёта, композиция через другой резерв, failover-диалер).

Роль в деревьях выбора:

- **Carrier последней надежды** (kind `tor`, priority 5 — ниже proton 10): TCP-only,
  честный отказ на UDP (`SupportsUDP()=false`), для scope'ов «сайт недоступен всеми
  остальными способами». Осознанное отклонение от proton-design §12.3 («Tor никогда
  в деревьях выбора») — санкционировано владельцем в постановке задачи: Tor = ещё
  один именованный резерв, но с самой низкой ценой выбора.
- **Scoped-egress для `.onion`**: суффикс-правило в socks5/routing — единственный
  транспорт, который умеет `.onion` вообще.

Честные границы (владелец должен знать до включения):

1. Tor медленнее любого другого резерва: 3 хопа; релеи — единицы-десятки Мбит/с,
  мосты — 1–10 Мбит/с, snowflake — 0.5–2 Мбит/с. Это последний рубеж, не основной
  канал.
2. ToS-серая зона (Tor в прошивке роутера) — оптика для провайдера. Включается
  только явно, выключен по умолчанию.
3. Выходной IP — Tor-exit (не гео-выбор как у proton/opera/fxvpn); страна выхода
  не управляема (только отображается).
4. Анонимность ≠ цель b4x: цель — доступность. Настройки скорости (reduced padding,
  shared circuits) документированы как компромисс «скорость vs метаданные» (§6).

---

## §1. Проверенные факты (по референсам, file:line в research-отчётах)

### 1.1 Процессная модель Tor

Чистый Go-клиента Tor не существует: arti (Rust, FFI) отпадает по CGO_ENABLED=0
(rawabypassapp использует arti, но PT у него — внешние бинари; waytor
экспериментален — proton-design §12.2). Все жизнеспособные интеграции — внешний
C-tor: Nova-PC (nova-tor.exe 0.4.9.12, Tor Expert Bundle), Nova-Android
(tor-android 0.4.8.22, JNI), ProtonVPN-Next (libtor.so, executable_path),
sing-box (`executable_path` + библиотека cretz/bine для control-протокола).

**Решение: внешний C-tor из Entware** (`opkg install tor`, бинарь `/opt/bin/tor`)
или путь владельца. Не embed: кросс-сборка C-проекта под ~15 архитектур
(mips/mipsle/softfloat...) и сопровождение security-обновлений — вне скоупа;
Entware уже собирает tor под все целевые архитектуры и обновляет его. Отсутствие
бинарника — честное состояние `binary-missing` с подсказкой (событие + статус),
не ошибка сборки. Версия детектится (`tor --version`), возможности — опционально
(conflux только ≥0.4.8).

### 1.2 torrc

Канон генерации (tessera torrc.rs + Nova render_torrc): **чистая функция** от
конфига; валидация до записи (запрет CRLF в любом поле — анти-инъекция; первая
лексема Bridge-строки = имени транспорта; tessera тестирует против
`tor --verify-config`); torrc-defaults пустой («никакие чужие дефолты не
применяются»); пути на argv, не в конфиге; `__OwningControllerProcess <pid>`
(смерть родителя = смерть tor). Наш torrc (полный — §7.4).

### 1.3 Порты и слушатели

- `SocksPort 127.0.0.1:auto` + `GETINFO net/listeners/socks` — фактический порт
  узнаём после старта (Nova-Android: фиксированный порт = «отказ там, где отказывать
  не за что»); SocksPolicy accept 127.0.0.0/8, reject *.
- Control: `ControlSocket unix:<data>/control.sock` где поддерживается, иначе
  `ControlPort 127.0.0.1:auto` + CookieAuthentication 1 (CookieAuthFile в data-dir).
- `GETINFO status/bootstrap-phase` — поллинг прогресса (тэг + PROGRESS=NN);
  `net/listeners/socks`; `traffic/read|written`; `circuit-status`/`orconn-status`
  (живые мосты → атрибуция победившего входа); SIGNAL NEWNYM/ACTIVE/SHUTDOWN;
  SETCONF для опциональных фич (conflux) с честной проверкой ответа.

### 1.4 Pluggable transports

PT 1.0: `ClientTransportPlugin <transport> socks5 127.0.0.1:<port>` — но для
socks5-формы порт должен быть известен ДО рендера torrc → порядок: старт PT-листенеров
(127.0.0.1:0) → фактический порт → рендер torrc → spawn tor. Вход в PT — обычный
SOCKS5 (RFC 1928 CONNECT), аргументы моста — в RFC 1929 login/password (по 255 Б,
итоговый бюджет 510 Б — «обрезанные аргументы выглядят как "мост не отвечает", и
найти причину невозможно», Nova). Ответы PT: отказ ACL — код 0x02, дозвон-неудача —
0x04 (tor различает «мост мёртв» и «прокси не понял»).

Библиотеки (проверено go.mod nova-core): `lyrebird/transports/{base,obfs4,webtunnel,meeklite}`
— фабрики `ParseArgs(args) → Transport`, `Dial(protectedDial)`; snowflake/v2
`client/lib` (имя `snowflake_client`): `NewSnowflakeClient(ClientConfig) →
transport.Dial() net.Conn`, `SetRendezvousMethod`, `AddSnowflakeEventListener`.

### 1.5 Мосты: формат, источники, Moat

Формат: `<transport> <addr:port> [FPR] <k=v>…`; fingerprint 40 hex; адреса-заглушки
у webtunnel/snowflake (`2001:db8::/32` и др.) — идентификатор, не адрес. Moat:
`POST https://bridges.torproject.org/moat/circumvention/settings`
`{"country":"XX","transports":["webtunnel","obfs4","snowflake"]}` — несёт фронты,
подобранные под страну. Валидация строки (Nova-канон): ASCII-only; запрет
ISO-control/`\#"`; бюджет аргументов ≤510 Б; `sqsqueue`/`sqscreds` — отказ (внутри
snowflake `log.Fatalln` = смерть процесса); snowflake `max` ∈ 1..8; заглушки
никогда не набираются.

### 1.6 Сеть релеев (vanilla-вход)

Onionoo: `details?type=relay&running=true&fields=fingerprint,or_addresses,country`
(+ расширение `observed_bandwidth` — наша добавка для скоростного отбора). Фолбэки:
CORS-прокси → GitHub-зеркало → Bitbucket → локальный кэш-файл. Глубокая проба
(ValdikSS): TLS со случайным SNI `www.<base32>.org` → ячейка VERSIONS
(`00 00 07 00 | 06 00 03 00 04 00 05`) → проверка ответа `00 00 07` → NETINFO +
N×CREATE (`00 00 00 05 | 01` + 509 нулей) → ответ обязан быть CREATED
(`00 00 00 05 | 04`). Это доказывает: (а) живой Tor-нод, (б) DPI пропускает TLS
до стадии приложения.

### 1.7 Скорость в самом Tor

Conflux (0.4.8+): параллельные legs → throughput-режим. `ConnectionPadding`
(auto/reduced/full), `ReducedConnectionPadding`. `LearnCircuitBuildTimeout 0` —
статический CBT (предсказуемость на нагруженном CPU роутера). GeoIP-файл — 26 МБ
парсинга (Nova: 5+ с молчания control) — клиенту НЕ нужен, если не выбирать exit
по стране (наш случай — §6.2).

### 1.8 Композиция «весь egress tor через наш SOCKS5»

Директива torrc `Socks5Proxy user:pass@127.0.0.1:port` заворачивает ВСЕ исходящие
TCP tor (OR/Dir-соединения к релеям и vanilla-мостам) в наш loopback-прокси
(sing-box proxybridge: случайные креды, RESETCONF Socks5Proxy/Username/Password —
патчить tor не нужно). PT-соединения идут через наш in-process PT-прокси — вторым
хопом не становятся (PT сам открывает сокет). Итог: обе категории egress сходятся
в нашем диалере — единая точка маркировки/bait/композиции.

### 1.9 Стримы и .onion

Tor SOCKS принимает hostname (в т.ч. `.onion`) нересолвленным — DNS-утечек нет
(tessera TorSocksDialer). Изоляция стримов — флаги SocksPort (IsolateDestAddr и
т.д.): каждая изоляция = отдельная цепочка = медленнее; по умолчанию — общий пул
(Nova: «изоляции нет, ротация NEWNYM»).

---

## §2. Входы: полный каталог (лестница уровня Nova + наши)

| Вход | Что видит DPI | Проходимость РФ (замеры Nova) | Скорость | Источник линий |
|---|---|---|---|---|
| **webtunnel** | валидный HTTPS+WS к живому сайту с настоящим сертом | лучшая (OnionHop: 57.5% живых по WS-апгрейду) | средняя | OnionHop/Moat/owner |
| **obfs4** | равномерно случайный поток (и это признак) | 14/14 рукопожатий, но считается детектируемым | средняя | OnionHop/Moat/owner |
| **snowflake** | WebRTC-«видеозвонок» (covert-dtls randomizemimic) + HTTPS к CDN-фронту | самая устойчивая по адресам | низкая (0.5–2 Мбит/с) | builtin CDN77/AMP + Moat-фронты |
| **meek_lite** | обычный HTTPS к CDN (domain fronting) | высокая, но медленный | низкая | owner-only (нет надёжного живого источника) |
| **vanilla** | Tor-TLS (отпечаток Tor) | релеи блокируются по IP/фингерпринту | высокая (релеи быстрее мостов) | **наш relay-scanner** + Moat/owner |
| **vanilla-through-carrier** | трафик носителя (AWG/QUIC/TLS) — Tor невидим | = носителю (warp/masque/proton держат РФ) | высокая (релеи, без мостов) | relay-scanner |
| **direct** | Tor-TLS к релеям без мостов | РФ: застревает на 10% | — | ручной |

Режимы entry (`config.tor.entry.mode`):

- **auto** — лестница с обучением (§2.1): webtunnel → obfs4 → snowflake → vanilla
  (+ vanilla-through-carrier если включён egress.through и carrier жив). direct и
  meek в auto НЕ участвуют (direct — по замерам бесполезен; meek — нет источника
  строк, только ручной).
- **webtunnel | obfs4 | snowflake | meek | vanilla | direct** — пин одного входа.

Распознаём, но не подключаем (KNOWn vs SUPPORTED, Nova-канон «счёт, которым нельзя
воспользоваться, — неверный счёт»): obfs2/obfs3, scramblesuit, meek (не lite),
conjure, dnstt. Отказ в парсере с честной причиной. Скоуп открыт для будущего.

### 2.1. auto: mixed-set racing с обучением (наша разработка, §инновации)

Nova ходит входы последовательно (каждый — отдельная попытка tor, минуты на
худший случай). Наш вариант для роутера — **один процесс tor со смешанным набором
мостов**: в torrc кладём webtunnel(2) + obfs4(2) + snowflake(1 сет) одновременно;
tor сам параллельно пробует мосты (внутренний шедулинг), мы следим за
`orconn-status`/`entry-guards` → как только bootstrap дошёл до 100%, читаем
фактически подключённый мост → **транспорт-победитель записывается в память входа**
(файл, TTL 30 мин — Nova auto_entry-паттерн) и становится головой лестницы на
следующих стартах.

Если mixed-set не поднялся за stall-окно (§4.4) — падаем на последовательный
проход Nova-стиля (по одному транспорту за попытку, память исключает повторно
провалившиеся). Так мы получаем: скорость гонки в счастливом случае + чистую
атрибуцию отказов в несчастливом.

### 2.2. vanilla-through-carrier (наша разработка)

Vanilla-релеи, найденные сканером, доступны **через живой носитель** (warp/masque/
h3/opera/fxvpn/proton): egress-мост (§3) диалит релеи через `reserve.Lookup(kind)`
другого резерва. Провайдер видит только протокол носителя; Tor- TLS спрятан целиком.
Это proton-design §12.1 (Tor-over-AWG у Next), обобщённый на все носители b4x и
включённый в лестницу auto. Инвариант §12.4: смерть носителя = разрыв цепочек tor
(никакой утечки в прямую сеть) — Tor Supervision rebuild'ит соединения через
другого носителя или падает в backoff.

---

## §3. Egress-мост: единая точка контроля

### 3.1. Два пути исходящего трафика tor

```
tor-процесс ──(Socks5Proxy, случайные креды)──► egress-bridge (loopback SOCKS5)
                                                    │  policy per-connection:
                                                    │  direct | carrier | auto
                                                    │  SO_MARK(MarkTorEgress)
                                                    │  NFQ-bait (opt-in)
                                                    ▼
                                              мост/релей/фронт

tor-процесс ──(ClientTransportPlugin socks5)──► in-process PT-proxy (lyrebird+snowflake)
                                                    │  тот же egress-диалер
                                                    ▼
                                              obfs4/webtunnel/meek/snowflake endpoint
```

egress-bridge = loopback SOCKS5-сервер (переиспользуем handshake-код src/socks5) со
случайными кредами, генерируемыми на каждый старт (sing-box proxybridge-паттерн;
креды — не секрет, а защита от чужих локальных процессов). PT-прокси — отдельный
loopback SOCKS5 (Nova ptProxy-паттерн) с ACL разрешённых целей (только адреса
мостов из конфигурации; чужой локальный процесс не получает дозвон наружу).

### 3.2. Egress-диалер

`transport/tor/egress.go`: для каждого соединения — класс (bridge-pt | bridge-vanilla
| relay-dir | rendezvous-broker | bootstrap-source) → политика:

- `direct` — обычный диал + SO_MARK MarkTorEgress (bit 21, следующий свободный в
  packetmark/marks.go после opera 1<<23, fxvpn 1<<22);
- `through:<kind>` — `reserve.Lookup(kind).DialStream` (носитель);
- `auto` — failoverDial-канон operaservice (direct с таймаутом 5 с → негативный
  кэш 60 с после 2 фейлов → carrier-first + self-heal проба возврата на direct).

Self-loop guard: отказ диалить слушатели самого tor (SOCKS/Control/PT) и адреса
активной сессии носителя, если носитель =我们自己 (прямая петля запрещена by
construction). Hostname-мосты резолвятся через `dns/doh.go MarkedDoHClient`
(без утечки в ISP DNS), диал только по is_global-адресам (анти-SSRF, Nova-гигиена
проб).

### 3.3. Выбор носителя

`config.tor.egress.through`: `none | warp | masque | h3 | opera | fxvpn | proton |
auto` (auto = старший по приоритету зарегистрированный carrier; смерть носителя →
tor теряет цепочки → супервизор rebuild'ает через следующего). Рандеву snowflake
(брокер/фронты) и bootstrap-источники (onionoo/Moat) — по policy `bootstrap-source`:
по умолчанию direct-with-carrier-fallback, никогда через сам tor.

### 3.4. NFQ-bait: движок защищает туннель (наша разработка)

В b4x уже есть механика: SO_MARK egress → OUTPUT mangle → action queue →
fakedsplit/fakeddisorder (opera OP-M3, fxvpn FX-M3). Для E-TOR: `config.tor.
egress.bait_profile: none | first-flight` — маркированные пакеты PT-хендшейков
попадают под fake-первый-полёт движка. Наибольший выигрыш — webtunnel (TLS
ClientHello к живому сайту получает ту же защиту, что и обычный 443-трафик LAN) и
vanilla (Tor-TLS ClientHello). Честный статус active/inactive (opera nfwBait-канон:
пока таблицы не подтвердили правило — bait «неактивен»). **Это уникально: ни Nova,
ни sing-box, ни Tor Browser не защищают собственные хендшейки туннеля анти-DPI
движком.** Включается только явно (красная линия: bait никогда не молча).

---

## §4. Bootstrap и сбор входов

### 4.1. Конвейер сбора мостов (Nova BridgeCollector, адаптировано)

Источники (порядок):

1. **Builtin snowflake** — CDN77 и AMP-наборы (строки из client/torref собранной
   версии snowflake; встроены в бинарь, версия синхронизирована с зависимостью).
2. **OnionHop-Bridges-Collector** — 4 зеркала (raw.githubusercontent, github.io,
   jsdelivr, statically) **гонкой**, первый непустой ответ выигрывает, cap 25 с;
   файлы obfs4_tested.txt / webtunnel_tested.txt / vanilla_tested.txt.
3. **Moat** `/moat/circumvention/settings` c country из конфига (default ru) и
   transports [webtunnel, obfs4, snowflake]; прямой путь, затем через egress-диалер
   (carrier-fallback), никогда через tor.
4. **Owner lines** — `config.tor.bridges.lines` (валидируются тем же парсером).

Свежесть 24 ч; повтор не раньше 300 с; **неудачный прогон сохраняет прошлый список**
(AtomicFile-канон, tmp+fsync+rename); dedup `transport|fingerprint|endpoint`;
trim-keeping-every-kind до 40 (иначе редкие виды вытесняются — Nova: «кнопка,
которая молча не подключается»). Сбор успешен при ≥1 живом мосте из сети (builtin
не считаются — TOR-1 Nova).

### 4.2. Пробы живости per-transport (обязательные различия)

- obfs4/vanilla: TCP-connect 6 с;
- webtunnel: WebSocket-upgrade GET, ожидание `101 Switching Protocols`, **строго
  HTTP/1.1** (h2 запрещает Upgrade — замер Nova: 0 из 8 живых), ALPN http/1.1,
  raw-сокет, без редиректов;
- snowflake: любой HTTP-код от места встречи («корень брокера отдаёт то 404, то
  502»); выбор CDN77 vs AMP — замером с кэшированием вердикта на прогон (G202) и
  принудительным «жив» при молчании обоих (обычная проба без uTLS/фронтинга, а
  рандеву в транспорте — с ними).

Бюджеты per-transport: 16 TCP / 8 webtunnel-апгрейдов / snowflake без потолка;
общий потолок 60 с; пул 8 воркеров.

### 4.3. Relay-scanner (vanilla-вход, наша разработка поверх ValdikSS)

`transport/torscan/`: onionoo с фолбэк-цепочкой (прямая → CORS-прокси → GitHub →
Bitbucket → кэш-файл); фильтры страна/порты (default 443, 9001; страна — приоритет
сортировки, не жёсткий фильтр); **глубокая проба** (TLS random SNI → VERSIONS →
NETINFO+CREATE → CREATED — §1.6) — отличает «порт открыт» от «Tor жив и DPI его
пропускает»; goal-driven раннее завершение (default 6 релеев); пул горутин с
deadline (каркас tor-relay-scanner-go, но проверяем ВСЕ or_addresses — фикс бага
juev-порта); **скоростной отбор**: запрашиваем observed_bandwidth, сортировка по
ней (top-квантиль) — релеи-гварды со скоростью, а не случайные. Выход — vanilla
bridge-строки `ip:port FINGERPRINT` в bridges.json. Скан — фоновой (budget 90 с,
tick-подконтрольный), не блокирует старт если строки уже есть.

### 4.4. Bootstrap-надзор (progress-based, Nova)

- Поллинг `GETINFO status/bootstrap-phase` 1 с; падение попытки: **150 с без роста
  процента** ИЛИ hard cap 180 с (snowflake 300 с — холодный сидел на 50% 150 с).
- Терпеливый control-port: до 60 с ожидания listener/cookie (GeoIP-урок — нам
  неактуален при geoip=off, но дисциплина остаётся).
- «10 молчаливых опросов» — отдельная причина отказа.
- Лог без спама: строка на смену тэга/+10%; повтор неизменного 30 с.
- Liveness: SOCKS5 CONNECT через tor каждые 60 с (успех = exit открыл TCP);
  **не HTTP 200** (CF отвечает Tor-выходам челленджами, G165). 2 неудачи →
  `SIGNAL ACTIVE` + `NEWNYM`; 4 неудачи + 30 с → teardown+restart **с последнего
  рабочего входа** (TOR-2 Nova: возврат после сна/Wi-Fi — секунды, а не минуты);
  бюджет рестартов restartGuard 6/ч + 300 с.
- Exit-проба (г periodic): `https://check.torproject.org/api/ip` **через tor** —
  JSON `{"IsTor":true,"IP":"…","CountryCode":"…"}`; это и верификация выхода, и
  страна для статуса. Не чаще раза в 30 мин.

---

## §5. Обфускация и DPI-резистентность (сводка стека)

1. **Разнообразие входов** (§2): семь видов, DPI-профили от «обычный HTTPS к сайту»
   до «видеозвонок» и «невидимость внутри носителя».
2. **NFQ-bait первого полёта** (§3.4) — движок b4x на службе туннеля.
3. **uTLS**: snowflake-брокер `utls-imitate=hellorandomizedalpn` (+utls-nosni опции
   из строки моста); covert-dtls `randomizemimic` для DTLS. utls v1.8.2 уже в
   vendor b4x — версионное совпадение со снежинкой без конфликтов.
4. **Гигиена**: geoip=off (нет 26 МБ парсинга и файла на флешке), AvoidDiskWrites 1,
   ClientOnly 1, SafeLogging 1, SocksPolicy loopback-only, ControlSocket unix где
   поддерживается, DoH для hostname-мостов, bootstrap-источники никогда через tor.
5. **Анти-зондирование**: webtunnel — пробер видит живой сайт; obfs4 — известная
   теоретическая пробиваемость → он никогда не голова лестницы (после webtunnel),
   страйки ротируют мосты; мёртвый PT-транспорт выключается из auto до конца TTL
   памяти входа.
6. **Padding**: `ReducedConnectionPadding 1` по умолчанию (скорость/роутер),
   full — opt-in владельца (privacy); компромисс документирован в §0.4.
7. **NEWNYM-гигиена**: ротация цепочек по событию (2 liveness-фейла, смена моста,
   смена носителя) — не по таймеру (анти-паттерн частых NEWNYM).

---

## §6. Скорость (целевые механизмы — «самый быстрый Tor на роутере»)

1. **Conflux opportunistic** (≥0.4.8): SETCONF ConfluxEnabled=1, ConfluxClientUX=
   throughput|latency по `config.tor.speed.conflux`; при отказе SETCONF — честное
   событие `tor_conflux_unavailable`, работа продолжается (одна нога).
2. **GeoIP off** (default): быстрый старт, меньше флешки; страна выхода узнаётся
   exit-пробой (§4.4), не из geoip-таблиц.
3. **Общий пул цепочек** по умолчанию (без IsolateDestAddr — Nova-позa) для
   LAN-bulk; opt-in `isolation: per-destination` для параноиков (документированная
   цена: больше цепочек = медленнее).
4. **Прогрев**: после bootstrap — `SIGNAL NEWNYM` + predictive circuits; первый
   стрим LAN не ждёт постройки цепочки.
5. **LearnCircuitBuildTimeout 0** — статический CBT: предсказуемость на CPU роутера.
6. **Snowflake max=2** (default; 1..8) — больше пиров = шире канал; ICE-лист
   курируемый (стун-серверы из Moat-строки, дефолт из builtin).
7. **Скоростной отбор релеев** сканером (§4.3): observed_bandwidth top-квантиль —
   vanilla-гварды со скоростью десятки Мбит/с, а не 1–5.
8. **Racing bootstrap** (§2.1): смешанный набор мостов в одном torrc — гонка
   выигрывает секунды, а не минуты последовательных попыток.
9. **KCP+smux внутри snowflake** (Turbo Tunnel, upstream v2.14) — уже в библиотеке.
10. **Честные цели**: vanilla/through-carrier — 10–50 Мбит/с (зависит от релея);
    webtunnel/obfs4 — 1–10; snowflake/meek — 0.5–2. Метрики `tor_bootstrap_seconds`,
    `tor_first_stream_ttfb_ms`, `tor_bytes_read/written` — поле покажет.

---

## §7. Хранилище и безопасность

### 7.1. Layout (слот /opt/etc/b4/tor/, все AtomicFile)

```
/opt/etc/b4/tor/
  torrc              # рендер (0600, только нам)
  data/              # tor DataDirectory (0700): кэш консенсуса, guards, cookies
  bridges.json       # публичные факты: {version, updated_at, source, bridges[], last_error}
  entry_memory.txt   # память входа auto: epoch-ms + провалившиеся/победитель
  control.cookie     # runtime tor (0600, в data/)
  tor.pid            # pid + ожидаемый путь бинаря для сверки
```

Секретов собственных нет (мосты — публичные факты; идентификации/регистрации, в
отличие от proton, не требуется). data/ — единственный тор-стейт; AvoidDiskWrites 1
минимизирует износ флешки.

### 7.2. Процесс

- Spawn: argv-пути (`-f torrc --DefaultsTorrcFile <пустой> --DataDirectory …`),
  `__OwningControllerProcess <pid>` в torrc, env TOR_CONTROL_SOCKET… — минимально.
- Идентификация: pid-файл + сверка `/proc/<pid>/exe` с ожидаемым бинарем — убийство
  ТОЛЬКО по паре (pid+образ), никогда по имени процесса (Nova-урок: «не задеть
  чужой tor»; на роутере чужой tor = Entware-сервис).
- Остановка: `SIGNAL SHUTDOWN` → 3 с → SIGTERM → 3 с → SIGKILL; PT-прокси гасим
  после tor (порядок обратен пуску). Смерть b4 = смерть tor (owning controller).
- Ресурсы: tor на MIPS — ~15–30 МБ RSS; супервизор не рестартует чаще
  restartGuard; при OOM-признаках (смерть процесса сразу после старта ×3) —
  backoff + событие (роутер скажет своё слово, §13).

### 7.3. torrc-инъекции

Все строки мостов и опций проходят парсер (§1.5): ASCII-only, запрет control-chars/
`\#"`, CRLF-бан (tessera), транспорт-токен сверен, бюджет 510 Б. Рендер — чистая
функция; в тестах — `tor --verify-config` если бинарь есть (integration-гейт).

### 7.4. Целевой torrc (рендер из конфига)

```
# Written by b4x E-TOR. Regenerated on every start.
ClientOnly 1
AvoidDiskWrites 1
SafeLogging 1
SocksPort 127.0.0.1:auto SocksPolicy... # + isolation-флаги по конфигу
SocksPolicy accept 127.0.0.0/8
SocksPolicy reject *
ControlSocket unix:/opt/etc/b4/tor/data/control.sock   # либо ControlPort 127.0.0.1:auto
CookieAuthentication 1
DormantCanceledByStartup 1
NumEntryGuards 1
LearnCircuitBuildTimeout 0
ConnectionPadding reduced|full
UseBridges 1|0
Socks5Proxy <rand-user>:<rand-pass>@127.0.0.1:<egress-port>   # vanilla/direct; PT — не нужно
ClientTransportPlugin obfs4 socks5 127.0.0.1:<pt-port>
ClientTransportPlugin webtunnel socks5 127.0.0.1:<pt-port>
ClientTransportPlugin meek_lite socks5 127.0.0.1:<pt-port>
ClientTransportPlugin snowflake socks5 127.0.0.1:<pt-port>
Bridge webtunnel 2001:db8::/32:443 <fp> url=https://… cert=…
Bridge obfs4 45.66.35.35:443 <fp> cert=… iat-mode=0
Bridge snowflake 192.0.2.3:80 2B280B… fingerprint=2B28… url=… fronts=… ice=… utls-imitate=hellorandomizedalpn
__OwningControllerProcess <pid>
```

GeoIP-строки отсутствуют при geoip=off (default). Conflux — SETCONF после старта
(не в torrc: старые tor падают на неизвестной опции в конфиге, SETCONF — мягче).

---

## §8. Здоровье и жизненный цикл

### 8.1. Состояния (service-level, канон protonservice)

```
idle → binary-missing → bridges-wait → starting → bootstrapping → established
      ↘ backoff ↖ (restartGuard)                    ↙ rotating ↺
running/listening — отдельно; listening = bootstrap 100 + SOCKS подтверждён
                                   + первая liveness-проба OK
```

- `binary-missing` — честное состояние с подсказкой `opkg install tor` (событие
  `tor_binary_missing` + поле статуса hint). Никакой автозагрузки.
- `bridges-wait` — сбор мостов для выбранного входа (snowflake — сразу builtin,
  «нет смысла ждать полный сбор», Nova TOR-1).
- `rotating` — NEWNYM/смена моста/носителя без teardown.

### 8.2. Supervisor (tick 30 с, канон)

- `ensureBridges` (свежесть/пауза/провал-сохраняет-старое) → `ensureProcess` →
  `ensureBootstrap` → `ensureLiveness` → `ensureExitProbe` (30 мин) →
  `ensureConflux` (SETCONF если поддерживается) → `exportState`.
- `enabled=false` — честный no-op, ноль горутин (красная линия).
- Смерть tor-процесса (wait pid) → событие + rebuild по restartGuard.
- Смерть носителя (через carrier-composition) → цепочки умрут сами → liveness
  поймает → NEWNYM; если носитель не вернулся — egress-диалер переключит на
  следующего (auto) или teardown+restart (pinned).

### 8.3. Страйки и ротация

- Мосты: `twg.StrikeState`-паттерн (новый экземпляр для тор-адресов): 2 страйка →
  cooldown 300 с → мост исключается из набора до конца cooldown; исчерпание набора
  → переклейка входа (лестница).
- Входы: память входа TTL 30 мин (провалившиеся исключаются из auto до истечения);
  победитель — голова; очистка по первому успеху и ручной смене входа.
- Рестарты: с последнего рабочего входа (TOR-2); бюджет 6/ч + cooldown 300 с.

### 8.4. Watchdog/FD-дисциплина

FD-утечки — больное место проекта (FD-бинари под запретом): PT-прокси и egress-мост
— bounded-соединения (лимит на PT-SOCKS 256, egress 512); goleak в тестах;
`metrics/collector.go` события в GUI-фид.

---

## §9. Интеграция в движок

### 9.1. Реестр и carrier

```go
// src/reserve/registry.go
KindTor Kind = "tor"          // TCP-only reserve, lowest priority
PriorityTor = 5               // ниже proton (10); последняя надежда

// src/packetmark/marks.go
MarkTorEgress uint32 = 1 << 21 // следующий свободный egress-бит (23=opera, 22=fxvpn)
```

`torservice/carrier.go`: `SupportsUDP()=false` (честный отказ, красная линия
«UDP-scope никогда в TCP-only резерв»); `DialStream` → `socks5.DialUpstream` к tor
SOCKS — **hostname проходит насквозь** (atypDomain, `.onion` нересолвленным, tessera-
канон). `ErrNotListening` до bootstrap. Self-loop guard: отказ если addr = слушатель
самого tor.

Опциональная capability `HostCarrier` (интерфейс-проба, реализуется тором):
`DialStreamHost(ctx, host string, port uint16)` — для scoped-роутера будущего, где
`.onion` и доменные scope'ы идут по имени (виртуальный диапазон 198.18.0.0/15 —
фаза 2, §13).

### 9.2. Anti-loop

- `BypassSuffixes` тор-уровня: onionoo/Moat/зеркала collector'а + фронты snowflake
  **никогда** не ходят через сам tor (это bootstrap-источники — петля = смерть
  бутстрапа). Идут direct или через ДРУГОГО носителя (egress-диалер).
- MarkTorEgress-пакеты исключены из захвата движком при bait=none (bypass-правило
  OUTPUT, как у opera/fxvpn), включены в action queue при bait=first-flight.
- Scoped-роутер не направляет tor-egress обратно в tor (mark-контракт).

### 9.3. Wiring main.go (после fxvpn-блока, до serviceprofile)

```go
var torEngine *torservice.Runtime
if cfgPtr.Load().System.Tor.Enabled {
    rt, err := torservice.Build(cfgPtr.Load(), torservice.Options{Now: time.Now})
    // err → log + torEngine=nil (honest disabled)
    // Start(appCtx) → регистрация
}
handler.SetTorRuntime(torEngine)
if torEngine != nil {
    reserve.Register(torEngine)
}
// shutdown: reserve.Unregister(reserve.KindTor) ДО torEngine.Stop()
```

`Options.Carrier DialFunc` — не нужен (композиция через egress-диалер и reserve.
Lookup, а не инъекция) — отличие от proton, осознанное: носителей много, выбор
per-connection.

### 9.4. Конфиг (src/config/tor.go)

```go
type TorEntryConfig struct {
    Mode       string `json:"mode"`                  // auto|webtunnel|obfs4|snowflake|meek|vanilla|direct
    RaceWindow int    `json:"race_window,omitempty"` // 0 => 2 параллельных головы mixed-set
}
type TorBridgesConfig struct {
    Lines          []string `json:"lines,omitempty"`   // owner bridge lines (валидация парсером)
    BuiltinSnowflake bool  `json:"builtin_snowflake"` // default true
    CollectURLs    []string `json:"collect_urls,omitempty"` // доп. зеркала OnionHop
    Country        string   `json:"country,omitempty"`      // Moat + relay-scan ("" => ru)
    RecollectPauseSec int   `json:"recollect_pause_sec,omitempty"` // 0 => 300
}
type TorEgressConfig struct {
    Through     string `json:"through,omitempty"`      // ""|none|warp|masque|h3|opera|fxvpn|proton|auto (default none)
    BaitProfile string `json:"bait_profile,omitempty"` // ""|none|first-flight (default none)
}
type TorSpeedConfig struct {
    Conflux    string `json:"conflux,omitempty"`    // ""|auto|off|throughput|latency (default auto)
    Padding    string `json:"padding,omitempty"`    // ""|reduced|full (default reduced)
    GeoIP      bool   `json:"geoip"`                // default false
    SnowflakeMax int  `json:"snowflake_max,omitempty"` // 0 => 2 (1..8)
    Isolation  string `json:"isolation,omitempty"`  // ""|none|per-destination (default none)
}
type TorScopesConfig struct {
    Suffixes []string `json:"suffixes,omitempty"` // доп. scope'ы → tor (кроме .onion, который всегда)
}
type TorConfig struct {
    Enabled             bool   `json:"enabled"`
    BinaryPath          string `json:"binary_path,omitempty"` // "" => автодетект /opt/bin/tor|/usr/sbin/tor
    DataPath            string `json:"data_path,omitempty"`   // "" => /opt/etc/b4/tor
    Entry               TorEntryConfig   `json:"entry"`
    Bridges             TorBridgesConfig `json:"bridges"`
    Egress              TorEgressConfig  `json:"egress"`
    Speed               TorSpeedConfig   `json:"speed"`
    Scopes              TorScopesConfig  `json:"scopes"`
    MaxRestartsPerHour  int    `json:"max_restarts_per_hour,omitempty"` // 0 => 6
    BootstrapTimeoutSec int    `json:"bootstrap_timeout_sec,omitempty"` // 0 => 180
    RelayScan           TorRelayScanConfig `json:"relay_scan"`           // enabled/ports/countries/goal/timeout
}
```

Валидация (всегда, даже disabled): mode ∈ enum; строки мостов — полный парсер
(§1.5); through ∈ enum носителей; bait/padding/conflux/isolation ∈ enum;
SnowflakeMax ∈ 1..8; пути абсолютные при enabled; BinaryPath — существует и
исполняем (при enabled — ошибка, при disabled — предупреждение-статус).
Migration не нужна (новый ключ `tor` = zero value = disabled).

### 9.5. HTTP API (src/http/handler/tor.go, канон)

- `GET /api/tor/status` — {enabled, running, listening, state, entry{mode, active,
  winner}, bridges{alive, byTransport}, bootstrap{progress, tag}, egress{through,
  bait}, exit{ip, country, isTor, checkedAt}, version{tor, conflux}, events[]}
- `POST /api/tor/restart`, `POST /api/tor/newnym` (ротация цепочек)
- `PUT /api/tor/entry` {"mode": …} → валидация → персист b4.json → рестарт
- `GET /api/tor/bridges` (список + свежесть + source), `POST /api/tor/bridges/refresh`
- `POST /api/tor/scan` (relay-scanner по требованию, budget-bounded)

### 9.6. CLI: `b4 torctl status|entry <mode>|bridges|scan|test` (fxvpnctl-канон).

### 9.7. Observability

События (snake_case имена, kebab-case классы): tor_started, tor_binary_missing,
tor_bootstrap_progress (тэг-смены), tor_established, tor_entry_won {transport},
tor_entry_failed {transport, class}, tor_rotated, tor_bridge_strike, tor_carrier_
switched, tor_exit_verified, tor_exit_mismatch, tor_process_died, tor_conflux_
enabled/unavailable, tor_bait_active/inactive.

Метрики: tor_bootstrap_seconds, tor_first_stream_ttfb_ms, tor_circuits_alive,
tor_bridges_alive {transport}, tor_streams_total {result}, tor_dial_total {result},
tor_bytes_read / tor_bytes_written, tor_entry_attempts_total {entry,result},
tor_process_restarts_total, tor_control_errors_total, tor_scan_relays_found.
Ring событий 32 (канон). Redaction: SafeLogging 1 в тор; в наших событиях нет
клиентских IP.

---

## §10. Зависимости (исключение из красной линии — точный перечень)

Красная линия «ноль новых зависимостей» (proton-design §10.1) нарушается ТОЛЬКО в
размере, санкционированном владельцем (постановка задачи 2026-09-15), и ТОЛЬКО
чистым Go (CGO_ENABLED=0 сохраняется; все ~15 LINUX_ARCHS остаются зелёными):

| Модуль | Версия | Зачем | Лицензия |
|---|---|---|---|
| …/pluggable-transports/goptlib | v1.6.0 | PT-SOCKS-модель (типы) | CC0 |
| …/pluggable-transports/lyrebird | v0.0.0-20260312… | obfs4 + webtunnel + meeklite + base-фабрики | BSD-2 |
| …/pluggable-transports/snowflake/v2 | v2.14.1 **(b4x-форк)** | snowflake client/lib | BSD-3 |
| транзитивно: pion/* v4, xtaci/kcp-go/v5, xtaci/smux, theodorsm/covert-dtls, …/ptutil | — | WebRTC/DTLS/KCP/smux | MIT/BSD |

**b4x-форк snowflake** (tools/snowflake, replace-директива; Nova-паттерн) с ровно
двумя изменениями против v2.14.1:

1. **Ловушки сокетов** (порт Nova-патча snowflake.patch): `NetWrapper
   func(transport.Net) transport.Net` в webrtc.go и `BrokerDialContext` в
   rendezvous.go — без них pion-сокеты и брокер-диалы уходят мимо нашего
   egress-диалера (маркировка/bait/carrier невозможны; Nova G154 — «pion на nil
   молча создаёт обычную сеть»).
2. **Вырезан SQS-рандеву** (rendezvous_sqs.go + aws-sdk-импорты): строки с
   `sqsqueue=`/`sqscreds=` мы и так отвергаем в парсере (log.Fatalln внутри —
   смерть процесса); вырезание сбрасывает ~15 пакетов aws-sdk-go-v2 из vendor —
   критично для MIPS-образов. Fail-loud: SQS-аргумент → ошибка до создания клиента.

utls v1.8.2 — уже в vendor, версия совпадает с требованиями снежинки (конфликтов
нет). quic-go не затрагивается (snowflake его не использует). gvisor не
затрагивается. NOTICE/THIRD_PARTY обновляются на этапе TT9 (лицензии таблицей).

Чего НЕТ в зависимостях: cretz/bine (свой минимальный control-клиент ~300 строк —
torware доказывает, что cookie-auth + GETINFO + SIGNAL — это строковый протокол;
канон проекта — свои минимальные реализации: свой STUN, свой SOCKS5), sing-box
(берём паттерны, не код), tor-бинарь (Entware).

---

## §11. Этапы TT1–TT10 (патч-план — каноничная истина объёмов)

| Этап | Содержимое | Верификация |
|---|---|---|
| TT1 | Конфиг (tor.go + validation + defaults) + KindTor/PriorityTor + MarkTorEgress + таксономия событий/классов/метрик | unit-тесты конфига (валидация всегда), vet/test/race |
| TT2 | Парсер bridge-строк + bridges.json (AtomicFile) + builtin snowflake-наборы | инъекционные/бюджетные/заглушечные кейсы (Nova-канон) |
| TT3 | Egress-диалер (policy/marks/self-loop/DoH) + egress-bridge (loopback SOCKS5) | fake-carrier тесты, негативный кэш, loop-guard |
| TT4 | Collector (зеркала-гонка + Moat + freshness + trim) | httptest-стенды (consent rule), гонка/пауза/сохранение |
| TT5 | PT-прокси (loopback SOCKS5 + lyrebird×3 + snowflake-адаптер + ACL + protected-dial) | фабрики ParseArgs/Dial на фейк-транспортах, ACL, коды 0x02/0x04 |
| TT6 | Control-клиент + процесс-супервизор + torrc-рендер + bootstrap-надзор | транскрипты control-протокола, verify-config (если бинарь), тайминги |
| TT7 | torservice-сборка: состояния, лестница входов + память, liveness, NEWNYM, страйки, exit-проба | интеграционные сценарии (фейк-tor скрипт-стенд), state-машина |
| TT8 | Carrier + registry + HTTP API + main.go wiring + shutdown-порядок + observability + CLI | handler-тесты, wiring-смоук, vet/test/race, goleak |
| TT9 | Relay-scanner (onionoo-цепочка + глубокая проба + bandwidth-отбор) | httptest onionoo, фейк-TLS-релей стенд, бюджеты |
| TT10 | Полевая валидация: pcap-доказательства хендшейков, инвариант «не утекает мимо носителя», kill-семантика, NOTICE/лицензии, changelog | полевой пакет (с разрешения владельца), acceptance §13 патч-плана |

Порядок TT1→TT10; каждый этап заканчивается зелёными vet/test/race и нулём
регресса; никакого кода «на будущее».

---

## §12. Красные линии этапа E-TOR

1. Зависимости — ровно перечень §10; любое расширение — отдельное решение владельца.
2. Конфиг валидируется всегда (даже disabled); опечатка не может спрятаться до
   дня включения.
3. Никаких живых сетевых запросов из юнит-тестов (consent rule): httptest-стенды;
   поле — отдельно, с разрешения.
4. События snake_case, классы kebab-case, метрики с префиксом `tor_`; bounded всё
   (ring 32, серии, соединения).
5. Приоритет 5 — ниже всех; никакой молчаливой подмены; UDP — честный отказ.
6. Anti-loop: bootstrap-источники никогда через tor; self-loop guard в диалере и
   carrier; MarkTorEgress-контракт с движком.
7. Bait/NFQ-маршрутизация никогда не включается молча (announces itself: событие
   tor_bait_active + честный inactive-статус).
8. Падение tor не рвёт носитель; падение носителя рвёт цепочки tor (by
   construction, инвариант §12.4 proton-design); kill-семантика проверяется.
9. Shutdown: Unregister ДО Stop; порядок остановки обратен пуску; b4-смерть =
   tor-смерть (owning controller + pid+exe-свёрка).
10. vet/test/race зелёные; регресс 0; ноль горутин при enabled=false; FD-бюджеты
    bounded (goleak).
11. Секретов нет: bridges.json — публичные факты; в статус/API — только
    redacted-поля; SafeLogging 1.

---

## §13. Открытые вопросы (решит поле)

1. Версия tor в Entware на целевом Keenetic (conflux доступность — узнаём
   `tor --version` на первом же старте; SETCONF-механика честно деградирует).
2. Реальная скорость pion/webrtc на MIPS-роутере (snowflake может оказаться
   последней надеждой только на ARM-моделях — метрики покажут; MIPS-деградация
   не блокирует релиз, документируется в статусе).
3. Живучесть OnionHop-зеркал с ISP владельца (если нет — Moat + owner lines
   держат; collector отчитывает source в bridges.json).
4. Достаточность builtin CDN77-фронтов против текущих блокировок (Moat-фронты
   по country — наш основной адаптивный источник).
5. Стабильность deep-probe сканера против ТСПУ (CREATE-проба может быть
   классифицирована как сканирование — бюджеты и частота ограничены конфигом;
   полевой вердикт).
6. Timing 198.18.0.0/15 виртуального диапазона для tproxy-пути (фаза 2, после
   того как scoped-деревья потребителей registry станут реальностью).
7. Нужен ли HTTPTunnelPort (сегодня: нет — LAN-клиенты идут через socks5-сервер
   b4/tproxy; откроем по полевой просьбе).

---

## §14. Что сознательно НЕ делаем (и почему)

- **Arti** — Rust/FFI, CGO_ENABLED=0 запрещает; C-tor из Entware закрывает потребность.
- **Embed tor-бинаря** — кросс-сборка C под 15 архитектур + security-сопровождение
  вне скоупа; Entware уже делает это лучше.
- **SQS-рандеву snowflake** — вырезан в форке (log.Fatalln внутри, aws-sdk-дерево
  в vendor; строки отвергаются парсером до клиента).
- **conjure/dnstt/scramblesuit/obfs2/obfs3** — распознаём, не подключаем (нет
  источников живых строк; Nova-канон «счёт, которым нельзя воспользоваться»).
- **Stream isolation по умолчанию** — общий пул цепочек (скорость LAN-bulk);
  per-destination — opt-in с документированной ценой.
- **Выбор exit-страны** — не клиентская опция Tor без мостов/exit-энроллмента;
  страна отображается (exit-проба), не выбирается.
- **Kernel-TUN режим** (как у proton) — не применим: tor — TCP-only, без UDP, без
  своего устройства; scoped-потоки идут через socks5-сервер/tproxy → carrier.
- **HTTPTunnelPort** — нет потребителя на роутере (§13.7).
- **Свой bridge/relay-узел** (torware-путь) — это серверная история, отдельный
  продукт, не клиентский резерв.
- **Глобальный тумблер «весь трафик через Tor»** (путь Next) — никогда; только
  scope'ы + последний приоритет в деревьях (§0).
