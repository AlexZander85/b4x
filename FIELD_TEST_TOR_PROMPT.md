# ПРОМТ ДЛЯ АГЕНТА: полевой прогон E-TOR (Tor-резерв) на живом Keenetic

> Скопировать целиком в сессию полевого агента. Промт самодостаточен: суть
> реализации, провода, матрица проверок, критерии PASS/FAIL, красные линии.
> Отвечать владельцу по-русски. Дисциплина деплоя — AGENTS.md: ТОЛЬКО копии
> `b4.exp-tor<N>` на флешке `$F/bin/`; живые `/opt/sbin/b4` и
> `/opt/etc/b4/b4.json` НЕ трогать; сначала S99b4 stop для тестового бинаря —
> НИКОГДА не поднимать два бинаря одновременно.

## 0. Контекст и цель

Ветка `agent/classifier-v2.3-capture-envelope` (HEAD — взять свежий, после
коммита `3525acf` с дизайном), реализация E-TOR по `tor-reserve-design.md` /
`tor-reserve-patch-plan.md` (этапы TT1–TT10 должны быть закрыты; если ревью
`tor-reserve-review.md` наложило P0 — сначала убедись, что они закрыты в
собираемом HEAD).

E-TOR — Tor-резерв: внешний tor (Entware `opkg install tor`) + все PT
внутри бинаря b4 (obfs4/webtunnel/meek_lite — lyrebird; snowflake — форк) +
egress-мост (весь исходящий трафик tor под контролем: SO_MARK bit 21,
NFQ-bait, опционально через другой резерв-носитель).

Цель прогона — доказать на живой сети (по убыванию важности):
1. **Инвариант носителя**: при `egress.through=<kind>` ВЕСЬ трафик tor виден
   на проводе ТОЛЬКО внутри протокола носителя (pcap: ноль прямых пакетов к
   релеям/мостам Tor).
2. **Входы работают**: лестница auto поднимается (mixed-set racing → winner),
   пины webtunnel/obfs4/snowflake/vanilla подключаются на живой сети РФ.
3. **DPI-профиль на проводе**: webtunnel = валидный HTTPS к живому сайту;
   obfs4 = случайный поток; vanilla-direct = Tor-TLS (ожидаемо режется);
   vanilla-through-carrier = только пакеты носителя.
4. **Kill-семантика**: смерть tor не рвёт носитель; смерть носителя рвёт
   цепочки tor с восстановлением; смерть b4 убивает tor (без сирот).
5. **Живучесть**: FD-soak 12–48 ч без утечки; рестарты под restartGuard.
6. **Скорость**: bootstrap-время по входам, TTFB первого стрима, throughput.

## 1. Суть реализации (обязательно к пониманию)

### 1.1 Топология
```
[LAN-клиент] → socks5-сервер b4 / scoped-правила
    → tor SOCKS (127.0.0.1:auto, hostname насквозь, .onion нересолвленным)
        → тор-цепочка (мост/релей):
            PT-входы:    tor → PT-прокси b4 (in-process) → obfs4/webtunnel/meek/snowflake
            vanilla:     tor → egress-мост b4 (Socks5Proxy, случ. креды) → релей
        → 3 хопа → exit
```
egress-диалер: `direct` (SO_MARK 1<<21, опц. NFQ-bait) | `through:<kind>` |
`auto`. Bootstrap-источники (onionoo/Moat/зеркала) и рандеву snowflake НИКОГДА
не идут через сам tor — только direct или через ДРУГОГО носителя.

### 1.2 Что уходит в эфир (по входам)
- **webtunnel**: HTTPS+WebSocket к живому сайту (настоящий сертификат, SNI
  сайта); секрет — путь в URI. После upgrade — бинарный поток.
- **obfs4**: TCP с равномерно случайным потоком с первого байта (даже
  хендшейк нечитаем), длины пакетов случайны.
- **snowflake**: (а) HTTPS к CDN-фронту (брокер-рандеву, uTLS
  hellorandomizedalpn), (б) WebRTC/DTLS к случайной «снежинке» (covert-dtls
  randomizemimic) — выглядит как видеозвонок.
- **meek_lite**: обычный HTTPS к CDN.
- **vanilla**: Tor-TLS (характерный ClientHello, ячейки VERSIONS после
  handshake) — в РФ ожидаемо блокируется; проверяем ТОЛЬКО через носителя.
- **Через носителя (egress.through=proton и т.п.)**: на проводе ВИДЕН ТОЛЬКО
  протокол носителя (для proton — AWG/QUIC Initial с SNI из белого пула).

### 1.3 Деградации и честные состояния (для интерпретации!)
- `binary-missing` — tor не установлен (`opkg install tor`); это НЕ баг.
- `bridges-wait` — сбор мостов; snowflake ставится сразу из builtin-наборов.
- Bootstrap: stall 150 с без роста / hard cap 180 с (snowflake-only 300 с) —
  вход считается проваленным, лестница идёт дальше; память входа TTL 30 мин.
- Conflux: SETCONF при старте tor ≥0.4.8; отказ = событие
  `tor_conflux_unavailable`, работа продолжается одной ногой.
- Exit-проба раз в 30 мин: `IsTor:false` → событие `tor_exit_mismatch`
  (информационно, БЕЗ ротации — это не jail).
- Liveness: SOCKS CONNECT раз в 60 с; 2 фейла → SIGNAL ACTIVE+NEWNYM;
  4 фейла+30 с → teardown+restart с winner-входа; капы 6/ч+300с.

## 2. Конфигурация (b4.json, ТОЛЬКО копия на флешке)

```
system.tor:
  enabled: true
  binary_path: ""              # автодетект /opt/bin/tor
  data_path: ""                # => /opt/etc/b4/tor
  entry:  {mode: "auto", race_window: 2}
  bridges:
    lines: []                  # owner-строки (если есть) — валидируются парсером
    builtin_snowflake: true
    country: "ru"              # Moat + relay-scan
  egress:
    through: "none"            # шаги 1-4: none; шаг 5+: proton/warp/auto
    bait_profile: "none"       # шаг 7: first-flight
  speed: {conflux: "auto", padding: "reduced", geoip: false, snowflake_max: 2}
  scopes: {suffixes: []}       # .onion всегда tor, без конфигурации
  relay_scan: {enabled: true, ports: [443, 9001], countries: ["se","nl","de","fi"], goal: 6}
```

Наблюдаемость: `GET /api/tor/status` → {state, listening, entry{mode,active,
winner}, bridges{alive,byTransport}, bootstrap{progress,tag}, egress{through,
bait}, exit{ip,country,isTor}, version{tor,conflux}, events[]}. Прочее:
`POST /api/tor/restart|newnym`, `PUT /api/tor/entry`, `GET /api/tor/bridges`,
`POST /api/tor/bridges/refresh`, `POST /api/tor/scan`. CLI: `b4 torctl …`.
Метрики: `tor_bootstrap_seconds`, `tor_first_stream_ttfb_ms`,
`tor_circuits_alive`, `tor_bridges_alive{transport}`, `tor_bytes_read/written`,
`tor_entry_attempts_total{entry,result}`.

## 3. Предпосылки (до шага 0)

1. Сборка arm64: docker, `CGO_ENABLED=0 GOOS=linux GOARCH=arm64` (канон
   PROJECT_DIRECTIVES); бинарь → `$F/bin/b4.exp-tor1` (флешка).
2. `opkg install tor` на роутере; `tor --version` записать в отчёт (conflux
   доступность зависит от версии).
3. tcpdump на WAN-интерфейсе роутера (entware) или зеркалирование порта;
   tshark на ПК для разбора.
4. Живой baseline-бинарь НЕ трогаем; тестовый бинарь стартует с конфигом-
   копией `b4.tor.json` на флешке; S99b4 живого инстанса — стоп на время
   прогона (согласовать с владельцем), либо прогон на отдельном окне, если
   владелец разрешит параллельно.
5. Часы живые; флешка смонтирована (data/ на /opt/etc/b4/tor — создать).

## 4. Матрица шагов

### Шаг 0 — подъём и бинарная линия
`egress.through=none`, entry=auto. `GET /api/tor/status` после старта.
PASS: state прошёл `bridges-wait → starting → bootstrapping → established`;
listening=true; события `tor_started`, `tor_bootstrap_progress` (тэги),
`tor_established`, `tor_entry_won` (транспорт победителя); bridges.alive ≥ 1.
Фиксируем: версию tor, время bootstrap (`tor_bootstrap_seconds`), winner.
FAIL-режимы: `tor_binary_missing` (не установлен — установить, не баг);
bootstrap stall >150 с на всех входах → записать какие, собрать
`tor_entry_attempts_total`, pcap хвостов.

### Шаг 1 — провод: DPI-профиль каждого входа (главное для обфускации)
Для каждого пина (поочерёдно `PUT /api/tor/entry`): webtunnel, obfs4,
snowflake, meek_lite (если owner-строка есть) — pcap на WAN во время
bootstrap + 1 мин стрима (curl через socks5 b4 → `https://check.torproject.org/api/ip`).
Критерии PASS по pcap:
- webtunnel: TLS ClientHello с SNI живого сайта (не torproject!), валидный
  сертификат сервера виден; после handshake — HTTP/1.1 Upgrade (101) и
  бинарный поток; НИКАКИХ tor-ячеек в открытую;
- obfs4: первый байт и далее — непарсибельный шум; tcpdump не показывает
  TLS-структуру; длины сегментов нерегулярны;
- snowflake: (а) HTTPS к фронту CDN с uTLS-подобным CH ( hellorandomizedalpn ),
  (б) DTLS-трафик к residential/облачным IP (снежинки), профиль «видеозвонка»;
- vanilla (direct, only для документирования): Tor ClientHello → записать,
  ЗАБЛОКИРОВАН ли (ожидание: да/зависло на 10%) — это входное данное сети.
FAIL: webtunnel-мост с SNI torproject.org / самоподписанным сертом; obfs4
читаем; snowflake без фронта (прямой к брокеру).

### Шаг 2 — инвариант носителя (КЛЮЧЕВОЙ)
`egress.through=proton` (или warp — что живо), entry=vanilla (мосты из
relay_scan), поднять. pcap на WAN ≥10 мин живого стрима.
PASS-критерии (все обязательны):
- на проводе ТОЛЬКО пакеты протокола носителя (для proton: AWG-UDP к узлу
  Proton; для warp: QUIC к CF) — ноль TCP к релеям Tor, ноль к мостам;
- счётчики: `tor_dial_total{result=ok}` растёт, все диалы через carrier;
- в статусе egress.through=proton; tor established; exit-проба IsTor=true;
- скорость стрима через vanilla-through-carrier записана (это наш
  «быстрый Tor»: ожидание 10-50 Мбит/с на быстрых релеях).
FAIL: ЛЮБОЙ прямой пакет к релею/мосту в pcap = утечка мимо носителя —
CRITICAL, стоп прогона, сохранить pcap, зафиксить класс утечки (PT? control?
DoH? bootstrap?).

### Шаг 3 — kill-семантика (3 подтеста)
3а. `kill <tor-pid>` (по pid-файлу): b4 не падает; состояние →
backoff/restart; носитель (proton) жив (`/api/proton/status` established);
событие `tor_process_died` + рестарт под капами.
3б. Носитель убить (`POST /api/proton/restart` до established или стоп
сервиса): цепочки tor умирают; liveness-фейлы → NEWNYM; egress auto →
переключение (событие `tor_carrier_switched`) или teardown+restart (pinned).
НЕТ прямых диалов к релеям в этот момент (pcap-хвост или счётчик dialer).
3в. `kill -TERM <b4-pid>`: через 5 с на роутере НЕ остаётся процессов tor
(`ps | grep tor` — пусто, кроме системного tor-сервиса Entware, если он был
выключен); pid-файл убран; слушатели (socks/pt/egress-мост) закрыты
(netstat).
PASS: все три; FAIL: сироты-процессы, livelock рестартов, утечка в прямую.

### Шаг 4 — лестница и память входов
Выставить entry=auto; исказить условие (например, owner-строки только
обfs4 с мёртвым мостом): наблюдать последовательный проход, события
`tor_entry_failed{transport,class}`, запись в entry_memory.txt, TTL 30 мин.
Затем вернуть рабочие строки: вход поднимается; при повторном старте
winner-вход идёт первым (bootstrap быстрее — записать дельту секунд).
PASS: прохождение лестницы, честные классы отказов, winner-ускорение ≥1
повторного старта.

### Шаг 5 — relay-scanner (vanilla-материал)
`POST /api/tor/scan` (или `b4 torctl scan`): наблюдать `tor_scan_relays_found`,
время, found ≥ goal; выборка релеев в bridges.json. Проверить 2-3 найденных
релея через `egress.through=none` TCP-connect вручную (сверка достижимости).
Оценить: не триггерит ли сканер IDS провайдера (замечания владельца по
стабильности сети во время скана — субъективно, записать).
PASS: found ≥ goal, строки валидны, сработал bandwidth-отбор (в bridges.json
релеи с высоким observed_bandwidth — сверить 1-2 по onionoo публично).

### Шаг 6 — FD-soak и устойчивость (12–48 ч)
Оставить рабочий вход (winner) + egress через носителя; лёгкий фон-стрим.
Каждые 2 ч фиксировать: `ls /proc/<b4pid>/fd | wc -l`, `ls /proc/<torpid>/fd |
wc -l`, RSS обоих, `tor_circuits_alive`, счётчики restarter'а.
PASS: FD стабилен (±10%), RSS без монотонного роста, рестарты ≤ капов,
`tor_bytes_read/written` растут. FAIL: FD-рост → сохранить `goroutine`-дамп
(pprof, если включён) и список fd — это FD-история проекта, обязательно.

### Шаг 7 — NFQ-bait на хендшейках туннеля (опционально, если движок активен)
`egress.bait_profile=first-flight`, entry=webtunnel (максимальный смысл:
обычный HTTPS). pcap: ClientHello к webtunnel-мосту получает ту же
первичную обработку, что и LAN-443 (fakedsplit/fakeddisorder профиль движка
— сверить с текущей стратегией на 443). Событие `tor_bait_active`.
PASS: bait-событие, изменения в тайминге/сегментации первых пакетов в pcap,
туннель при этом ПОДНИМАЕТСЯ (bait не ломает хендшейк webtunnel — если
ломает: FAIL + класс `tor_bait_breaks_handshake`, bait=off откатить).
ВНИМАНИЕ: bait — эксперимент; если webtunnel с bait не поднимается, а без
bait поднимается — записать и выключить (решение за владельцем).

### Шаг 8 — скорость и UX-феноменология
Для каждого работающего входа (webtunnel/obfs4/snowflake/vanilla-through-
carrier): 3× измерить (а) bootstrap-время с холодного старта, (б) TTFB
первого curl через socks5, (в) iperf-подобный throughput (curl большого
файла через tor, например speedtest-файл через https). Свести таблицу.
Заодно: `.onion`-доступ через socks5 b4 (пример: `http://2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion/`
— DuckDuckGo onion) — PASS: загрузился, DNS-запроса onion-имени в ISP-DNS
нет (pcap:53 на WAN — только штатные).

### Шаг 9 — A/B против «Tor без b4» (контроль скорости)
На той же сети: Tor Browser на ПК (или `tor` из Entware руками) через те же
типы мостов (строки из bridges.json) — замерить bootstrap/throughput.
PASS-ориентир: E-TOR не хуже, по vanilla-through-carrier — существенно лучше
(наш «быстрый Tor»). Это субъективный слой — записать числа, не гейт.

## 5. Красные линии (нарушение = немедленный стоп)

1. Живой плейн (`/opt/sbin/b4`, `/opt/etc/b4/b4.json`) не трогать; только
   копии `b4.exp-tor*` и конфиг-копии на флешке.
2. Два бинаря одновременно не поднимать; перед стартом тестового — стоп
   живого (и обратно по окончании).
3. Утечка мимо носителя (шаг 2) — стоп + pcap + репорт; НЕ продолжать
   прогон с дырой.
4. Ничего не устанавливать на роутер кроме `tor` (opkg); никакие PT-бинари
   не ставим — все PT внутри бинаря (если torctl/статус просит бинарь PT —
   это баг, фиксировать).
5. Гигиена моста: проберные CREATE-запросы сканера только в бюджетах
   конфига; не поднимать goal выше 6 без команды владельца.
6. Не модифицировать системный torrc Entware (/opt/etc/tor/torrc чужого
   tor-сервиса); E-TOR живёт только в /opt/etc/b4/tor/.
7. Отчёт честный: деградации, stall-ы, странные тайминги — как есть;
   «работает» ≠ «доказано»; доказательство = pcap/счётчики/события.

## 6. Формат отчёта

На каждый шаг: конфиг → действия → pcap-факты (имена файлов `tor-s<N>[-<вариант>].pcap`)
→ фрагменты `GET /api/tor/status` (events) → метрики → вердикт PASS/FAIL.
Итоговые таблицы: (а) шаг → вердикт; (б) входы → bootstrap/TTFB/throughput;
(в) FD/RSS-динамика. Отдельные секции: «Отклонения от ожиданий» (самое ценное
для доработки), «Вопросы владельцу» (решения по полю). Рекомендация по
перспективе: какой вход держать головой лестницы на этой сети; включать ли
bait; держать ли egress через proton постоянно.
