# ПРОМТ ДЛЯ АГЕНТА: полевой прогон uTLS-маскировки fxvpn и masque warp H3

> Скопировать целиком в сессию полевого агента. Промт самодостаточен: содержит
> суть реализации, нюансы форка, матрицу проверок, критерии PASS/FAIL и красные
> линии. Отвечать владельцу по-русски. Дисциплина деплоя — AGENTS.md (копии
> `b4.exp-*` на флешку, живые `/opt/sbin/b4` и `/opt/etc/b4/b4.json` не трогать).

## 0. Контекст и цель

Ветка `agent/classifier-v2.3-capture-envelope`, HEAD `dc8cb18f`. На ней:
- доработан туннель fxvpn по ревью (F1–F10: время жизни H2-релея, DNS в DialH3,
  преэмптивная ротация, wiring, двухслойный TOFU-пин, страйки узлов, байт-счётчики);
- реализована маскировка (глава 7 ревью): FX-M0 (Firefox cipher/curves, padding
  Initial 1250, preflight QUIC-приманка с TTL), FX-M1 (uTLS для H2 + QUIC через
  форк), FX-M2 (вложение в carrier при блоке порта), FX-M3 (SO_MARK+NFQ bait),
  FX-M4 (observability);
- создан форк `github.com/AlexZander85/quic-go` (ветка `b4x-utls`, тег
  `v0.61.0-b4x.2`, база upstream v0.61.0), подключён `replace` в go.mod + vendor.

Цель прогона — доказать на живой сети:
1. туннели устанавливаются и держат трафик с включёнными отпечатками;
2. отпечаток на проводе действительно браузерный и отличается от ванильного Go;
3. нет регресса связности против ванили (A/B);
4. fail-open не маскирует деградацию (туннель мог подняться «молча на ванили»).

## 1. Суть форка и нюансы реализации (обязательно к пониманию)

### 1.1 Механика
- `quic.Config.UTLSClientHelloID = nil` → ванильный crypto/tls-хендшейк,
  поведение байт-в-байт как у upstream. Установлен ID → hello собирается из
  ClientHelloSpec пресета (Firefox/Chrome) силами uTLS.
- Hello строится из СПЕКИ, а не из config: ALPN берётся из спеки (мы заменяем
  на h3/h2), supported_versions из спеки (мы нормализуем до [1.3]).
- Транспортные параметры едут raw-расширением **57** (quic_transport_parameters)
  с ровно теми байтами, что замаршалил quic-go — инжектятся в спеку в момент
  `SetTransportParameters` (quic-go зовёт его до Start).
- Пресеты несут TCP-наследие: TLSVersMin=1.2 и supported_versions с 1.2 — мы
  нормализуем до 1.3 (RFC 9001; реальный Firefox/Chrome по QUIC предлагают
  только 1.3 — так что это ТОЧНАЯ имитация, а не упрощение).
- IP-литерал в ServerName → SNI-расширение удаляется (RFC 6066, как vanilla;
  пресет иначе кладёт IP в SNI, и строгие серверы молча дропают hello).
- ClientHello-скремблинг quic-go (размазывание hello вокруг SNI по пакетам)
  на uTLS-путях отключён: парсер скремблера заточен под Go-hello и навсегда
  вешал HasData на пресетных hello. Следствие: uTLS-hello уходит ЦЕЛИКОМ
  в первых Initial-пакетах (Firefox ~600 байт CRYPTO — 1-2 пакета). Это
  ожидаемая форма, а не баг.
- Session resumption и 0-RTT на uTLS-пути отключены: каждый реконнект =
  полный хендшейк. Keepalive держит сессию — частых хендшейков быть не должно,
  но если видишь reconnect-шторм, это сигнал (события + счётчики).

### 1.2 Fail-open (критично для интерпретации!)
При любой ошибке применения спеки форк **молча** откатывается на ванильный
crypto/tls-хендшейк (лог `utls: apply preset failed ... falling back`), а
`NewCryptoSetupClient` при ошибке сборки — тоже. Значит:
**«туннель поднялся» ≠ «отпечаток браузерный»**. Факт отпечатка подтверждается
только pcap'ом. Ищи в логах строки `utls:` — их наличие = uTLS не сработал.

### 1.3 Верификация (красная линия)
Верификация НЕ тронута: fxvpn — WebPKI + TOFU-пины (pending→commit после 2xx,
baked seed-пины трёх хостов); warp/masque — пины + WebPKI. Любой
`fxvpn-api-pin-mismatch` / verify error — НЕ проблема маскировки, стоп и репорт.

### 1.4 Известные осознанные отклонения (фиксировать в отчёте как таковые, не как баги)
- Позиция ext 57 (TP) — в конце списка расширений; реальный браузер кладёт в
  другом месте. JA4 это не хеширует, но позиционный анализ теоретически возможен.
- В Firefox-профиле НЕТ Go-ML-KEM группы 0x4588 (это и есть цель).
- uTLS-хелло не скремблится (см. 1.1).
- Нет resumption → нет PSK-расширения в повторных хендшейках.

## 2. Конфигурация (b4.json)

```
system.fxvpn:
  enabled: true
  accounts_path: /opt/etc/b4/fxvpn/accounts.json
  prefer_h3: true|false            # H3-носитель или сразу H2
  masquerade:
    profile: firefox               # firefox (дефолт) | go-plain | off
    preflight_fake: false          # QUIC-приманка, включать ОТДЕЛЬНЫМ шагом
    fake_ttl: 4                    # 2..8; датаграмма должна умереть ДО Fastly
    fake_count: 2
    fake_sni_pool: [...]           # дефолт: Mozilla-имена (detectportal и пр.)
    initial_padding: 1250
    hello_shaping: true            # cipher/curves на plain-Go рунге
    nest_on_port_block: false      # вложение при блоке порта (шаг 8)

system.warp:
  enabled: true
  masquerade:
    fingerprint: ""                # "" (vanilla) | chrome120 (рекоменд) | firefox
```

Текущее состояние: `GET /api/fxvpn/status` → `masquerade{profile,fingerprint,
preflight_fake,hello_shaping}`, `nested`, `bait_active`, `verified_exit`,
события `events[]`. Метрики: `fxvpn_bytes_total{dir}`, `fxvpn_nested`,
`fxvpn_bait_active`, `fxvpn_dial_total{result}`, `fxvpn_quota_remaining_bytes`,
`fxvpn_pool_state{state}`.

Дефолт fxvpn-маскировки = firefox + hello_shaping — т.е. «сделал ничего» ещё
не значит «ваниль на проводе». Ваниль = `profile: off` (или go-plain).

## 3. Предпосылки (до шага 0)

1. Сборка: `make build` (swagger/gen-defaults/build-ui) или для быстрого
   цикла — бинарь с заполненным `src/http/ui/dist`. Не пересобирай форк:
   тег `v0.61.0-b4x.2` зафиксирован; если правка форка понадобится — новый
   тег `v0.61.0-b4x.3` и апдейт replace (один и тот же тег не перепушивать —
   proxy кэширует).
2. fxvpn-аккаунты: провижининг через `fxvpnctl` (L0 CLI) или
   `POST /api/fxvpn/accounts/test` + сохранение refresh-токенов в accounts.json.
   Без аккаунтов H2/H3 поднимется только до bearer-ошибки — это не маскировка.
3. warp-идентичность: enrollment через штатный reconciler (если
   api.cloudflareclient.com фильтруется — путь BuildWithHTTP через прокси).
4. tcpdump на роутере (entware) либо зеркалирование порта; tshark + JA4-тлинт
   на рабочей машине.

## 4. Матрица тестов

### Шаг 0 — базовая линия (vanilla)
`profile: off` (fxvpn), `fingerprint: ""` (warp). Поднять fxvpn H2 и H3.
Снять эталонные Go-отпечатки:
- H2: `tcpdump -i <wan> -s0 -w /tmp/van-h2.pcap host <узел> and port 2499`
  → tshark: `tls.handshake.type==1` → JA3/JA4 = «Go robot» (контроль).
- H3: QUIC Initial на :2499 — tshark расшифровывает Initial автоматически
  (ключи публично выводятся из DCID) → ClientHello с Go-порядком расширений,
  ML-KEM 0x4588, без GREASE.
PASS: образцы сняты, JA4 записан (это база сравнения).

### Шаг 1 — fxvpn H2, firefox
`prefer_h3: false`, `profile: firefox`. Поднять сессию, прогнать TCP-трафик
через резерв (проверка: `verified_exit.ok=true`, счётчик `bytes_up/down` растёт).
pcap ClientHello на :2499. Критерии PASS:
- туннель установлен, трафик ходит;
- JA4 отличается от шага 0; на проводе: GREASE-расширения присутствуют,
  supported_groups = x25519,secp256r1,secp384r1,secp521r1,ffdhe2048,ffdhe3072
  (Firefox-порядок, БЕЗ 0x4588), ALPN h2, шифры Firefox-порядка
  (AES128-GCM → CHACHA20 → AES256-GCM);
- в логах НЕТ строк `utls: ... falling back`.
FAIL: JA4 совпал с шагом 0 (fail-open сработал молча — приложить логи).

### Шаг 2 — fxvpn H3, firefox (форк)
`prefer_h3: true`. pcap QUIC на :2499, tshark: Initial → ClientHello.
Критерии PASS:
- сессия установлена, CONNECT-релеи работают;
- ClientHello внутри Initial: ALPN **h3**, supported_versions **[1.3]**,
  SNI = имя узла из serverlist (hostname), ext 57 (TP) присутствует и
  парсится валидно, группы/шифры Firefox-профиля;
- клиент не предлагал 1.2 в supported_versions и не нёс IP в SNI.
FAIL: `udp-egress-blocked` события при живом прочем трафике (приложить pcap
уходящего Initial — если Initial не ушёл вообще, это наш баг, не ТСПУ).

### Шаг 3 — masque warp H3, chrome120
`system.warp.masquerade.fingerprint: chrome120`. Поднять MASQUE-сессию
(данные идут через CONNECT-IP), pcap QUIC к CF-эндпоинту.
PASS: hello chrome-подобный (порядок/наборы Chrome-120), ALPN h3, сессия
держит пакеты (ValidateDataPlane-эквивалент: эхо через носитель), A/B против
`fingerprint: ""` показывает замену отпечатка.
Нюанс: chrome120 выбран потому, что легитимный WARP-клиент boringssl-базный;
firefox здесь — эксперимент, не эталон.

### Шаг 4 — детект fail-open
Проверить логи демона за шаги 1–3 на `utls:`-строки. Дополнительно: временно
сломать спеку НЕЛЬЗЯ конфигом (валидация отсекает) — поэтому только лог-контроль.
PASS: строк нет ИЛИ есть + JA4-проверка подтвердила ваниль в том соединении
(честно пометить: этот прогон не uTLS).

### Шаг 5 — preflight QUIC-приманка
`prefer_h3: true`, `preflight_fake: true`, `fake_ttl: 4`. pcap UDP к узлу:
перед ClientHello-Initial должны уйти 1-2 датаграммы с БЕЛЫМ SNI
(detectportal.firefox.com и др.) — tshark: это валидные QUIC-Initial с SNI не
равным имени узла. Критерии PASS:
- приманки уходят ДО реального хендшейка из того же 5-tuple;
- хендшейк после них проходит нормально (совместимость: Fastly приманки не
  видит — TTL);
- TTL откалибровать: если приманка ДОЛЕТАЕТ до сервера (сервер логирует
  неверный Initial / соединение деградирует) — уменьшать fake_ttl.
FAIL: приманок нет при включённом флаге (проверь `bait`/`preflight_fake` в
статусе и UDP-сокет с TTL — на платформе без IP_TTL приманка деградирует в
no-op честно).

### Шаг 6 — удержание 30–60 мин
Живая сессия fxvpn под нагрузкой (лёгкий фоновый трафик). Критерии PASS:
- нет реконнект-шторма: события `fxvpn_session_bearer_rotated`,
  `fxvpn_node_degraded`, `fxvpn_pool_blocked` — редки/объяснимы;
- квота-поллинг раз в 15 мин (X-Quota-* обновляется, счётчик
  `fxvpn_quota_remaining_bytes` меняется);
- `fxvpn_bytes_total{up|down}` растёт согласованно с трафиком;
- хендшейков на проводе мало (resumption отключён — полный хендшейк только
  при реконнекте; keepalive держит сессию).

### Шаг 7 — A/B против ванили
На той же сети, тот же узел, тот же носитель: `profile: off` vs
`profile: firefox` (и warp `fingerprint: ""` vs `chrome120`). Сравнить:
время установления, долю успешных хендшейков, поведение при блокировках
(если сеть режет QUIC :2499 — задокументировать, это входное данное для
лестницы, не баг). PASS: отпечатанная версия не хуже по связности.

### Шаг 8 — (опционально) эскалация при блоке порта
`nest_on_port_block: true` + активный carrier (базовый туннель). Симуляция
блока: iptables DROP к :2499 на роутере → 3 подряд неудач → события
`fxvpn_port_block_suspected` → `fxvpn_nested_activated` → сессия
пересобирается ЧЕРЕЗ carrier (в статусе `nested: true`). Снятие блока →
возврат не позже часа (`fxvpn_nested_released`).
ВАЖНО: без активного базового туннеля (Options.Carrier) детектор сработает,
но вложение честно не активируется — это ожидаемое поведение, не баг.

## 5. Красные линии (нарушение = немедленный стоп)
1. Верификация не ослабляется: любой pin-mismatch/verify failure → стоп, репорт
   (это дыра, а не шум).
2. Приманки никогда не подменяют реальный хендшейк и не доходят до Fastly.
3. Control-plane Mozilla/Fastly не получает запросов сверх штатных потоков
   (auth/token/serverlist/квота-поллинг 15 мин). Лишние запросы = баг интеграции.
4. Живой YouTube-плейн и базовые фичи не трогаются; всё — на копиях бинаря.
5. Отчёт честный: fail-open, деградации и отклонения фиксируются как есть.

## 6. Формат отчёта
На каждый шаг: конфиг → действия → pcap-факты (JA3/JA4 хеши + hexdiff против
шага 0 + ключевые расширения) → логи-фрагменты → вердикт PASS/FAIL.
Итоговая таблица «шаг → вердикт». Отдельная секция «Отклонения от ожиданий» —
самое ценное для доработки форка. Файлы pcap именовать `s<N>-<вариант>.pcap`
и приложить к отчёту.
