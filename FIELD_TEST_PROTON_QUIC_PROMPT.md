# ПРОМТ ДЛЯ АГЕНТА: полевой прогон proton-quic (jc=0 + per-handshake I1 + exit-верификация)

> Скопировать целиком в сессию полевого агента. Промт самодостаточен: содержит
> суть реализации, нюансы провода, матрицу проверок, критерии PASS/FAIL и красные
> линии. Отвечать владельцу по-русски. Дисциплина деплоя — AGENTS.md (копии
> `b4.exp-*` на флешку, живые `/opt/sbin/b4` и `/opt/etc/b4/b4.json` не трогать).

## 0. Контекст и цель

Ветка `agent/classifier-v2.3-capture-envelope`, HEAD `2444ffe0` (промт) / kernel-TUN PBR — следующий коммит. На ней закрыты
все находки `proton-awg-reserve-review.md` (P1–P7, L1, L6):
- **P3**: I1 перегенерируется НА КАЖДЫЙ хендшейк (патч vendored amneziawg-go,
  шов `InitPacketSpecFunc`) — свежий DCID + свежий randomness каждый раз;
- **P4**: у `proton-quic` jc=0 — мусорные датаграммы 1–3 байта УДАЛЕНЫ; I1 —
  единственный пакет перед хендшейком; добавлен экспериментальный рунг
  `proton-quic-j40` (jc=4, 40..70 Б, в дефолтную лестницу НЕ входит);
- **P5**: ClientHello внутри Initial — Chrome-класса (GREASE, session_id 32Б,
  cipher-порядок Chrome, supported_versions [GREASE, 0304], key_share X25519,
  alpn h3, quic_transport_parameters c initial_source_connection_id == DCID,
  padding-расширение до ~1200 Б);
- **P1**: exit-верификация — после Established через туннель забирается
  Cloudflare /cdn-cgi/trace; несовпадение страны = `proton_exit_mismatch` +
  страйк узла + пере-seek внутри локации;
- **P6**: X-PM-netzone (публичный IPv4/24 через STUN) едет в каждом logicals;
- **P7**: Reissue роняет живую сессию (`proton_session_retired`);
- **L1**: гейт 30 минут на смену SNI при деградации (быстрый churn сам —
  отпечаток);
- **P2(а/б)**: носитель экспонирован (`reserve.Carrier`: DialStream/DialUDP),
  kind=proton зарегистрирован в реестре с самым низким приоритетом.

Цель прогона — доказать на живой сети:
1. на проводе ЧИСТЫЙ 1250-байтовый Initial без мусора, и DCID НЕ повторяется
   между рукопожатиями (главный критерий P3);
2. расшифрованный Initial читается как браузерный QUIC (P5);
3. exit-верификация работает в обе стороны (verify + mismatch) (P1);
4. netzone вычислен и применён (P6); Reissue честно роняет сессию (P7);
5. нет регресса связности против предыдущей сборки (A/B).

## 1. Суть реализации (обязательно к пониманию)

### 1.1 Что уходит в эфир при одном рукопожатии
Порядок датаграмм к узлу (порт из каталога [443, 88, 1224, 51820, 500, 4500]):
1. **одна** датаграмма 1250 байт — QUIC v1 Initial (I1), SNI из белого пула;
2. (junk НЕТ — jc=0; для `proton-quic-j40` — ровно 4 датаграммы 40..70 Б);
3. 148-байтовый AWG initiation (тип 1) + возможные padding/трейлеры.

Retried-хендшейк (REKEY_TIMEOUT 5 с при seek'е), rekey (~2 мин) и любой
restart шлют НОВЫЙ I1 с НОВЫМ DCID — инвариант P3: «два подряд рукопожатия
одного устройства не содержат побайтово равных InitPacket[0]».

### 1.2 Верификация Initial (тСПУ-эквивалент)
Ключи QUIC Initial публичны (RFC 9001 §5.2, выводятся из DCID) — tshark
расшифровывает Initial автоматически. Внутри должен быть ClientHello:
- расширения ПОРЯДКЕ: GREASE (0x?a?a) → server_name (SNI из пула, НЕ Proton-домен)
  → supported_versions [GREASE, 0304] → key_share (x25519, 32Б) → alpn [h3]
  → quic_transport_parameters → padding;
- в QTP: initial_source_connection_id == DCID пакета (RFC 9368 — то, чего
  не было в старой Nova-реализации);
- session_id 32Б случайных; cipher_suites 1301,1303,1302; compression [0];
- padding-расширение добивает CH до ~1200 Б, хвост пакета — QUIC PADDING до 1250.

### 1.3 Fail-closed и деградации (критично для интерпретации!)
- I1 перегенерация: при ОШИБКЕ парсинга свежей спеки устройство молча шлёт
  статичную цепочку из IpcSet (fail-open к предыдущему поведению, НЕ к
  отсутствию обфускации). Признак регрессии на проводе: одинаковые Initial
  между хендшейками. Код-путь: vendor `device/send.go`, шов только для слота 0.
- Пустой SNI/переполнение → BuildQuicInitial возвращает "" → профиль без I1
  (vanilla-форма). Событий об этом нет — только pcap-контроль.
- Exit-проба едет по WG-дата-плейну (netstack). Если туннель поднялся, но
  проба не прошла — `proton_exit_probe_failed`, VerifiedExit пустой, сессия
  ЖИВЁТ (проба не гейт establishment).
- L1-гейт: при jail-вердикте SNI не меняется 30 минут; на проводе при
  частых rebuild'ах ожидаем ОДНО имя (свежий DCID при этом каждый раз).

### 1.4 Лестница и дисциплины
`[last_good → (preferred) → proton-quic → proton-vanilla → proton-sip → proton-crlf]`.
Регистрация ≤1 на загрузку (CAS-флаг); refresh вместо re-registration;
rebuild ≤6/час + cooldown 300 с; антипетля: `vpn-api.proton.me`,
`api.protonvpn.ch`, `api.protonmail.ch`, `protonpro.xyz`, DoH-резолверы —
никогда через туннель.

## 2. Конфигурация (b4.json)

```
system.proton:
  enabled: true
  identity_path: /opt/etc/b4/proton/identity.json
  location: {mode: "country"|"auto"|"host", country: "NL", host: ""}
  port: 0                      # 0 = round-robin каталога
  mtu: 0                       # 0 = 1420 (Nova live-verified)
  obfuscation:
    enabled: true
    preferred_profile: ""      # "" = дефолт-лестница; "proton-quic-j40" — полевой рунг
    sni_pool: []               # пусто = встроенный белый пул (90 имён)
    i1_adaptation: true
```

Наблюдаемость: `GET /api/proton/status` → `state`, `listening`,
`active_profile`, `active_node`, `active_port`, `verified_exit{ip,country,ok}`,
`events[]`. Метрики: `proton_handshake_total{result}`,
`proton_registration_total`, `proton_profile_seek_total{profile,result}`,
`proton_nodes_source{source}`, `proton_cert_valid_until_seconds`.
Эндпоинты: `/api/proton/locations`, `/api/proton/location` (POST),
`/api/proton/restart` (POST), `/api/proton/reissue` (POST).

## 3. Предпосылки (до шага 0)

1. Сборка: `make build` (или бинарь с заполненным `src/http/ui/dist`).
2. tcpdump на роутере (entware) либо зеркалирование порта; tshark на рабочей
   машине (QUIC Initial расшифровывается автоматически).
3. Часы на роутере живые (ntp-wait гейт: TLS NotAfter контрольного хоста).
4. Регистрация Proton пройдёт ≤1 раза за загрузку — первая же удачная
   registration создаёт identity.json; копии бинаря НЕ должны одновременно
   стартовать с чистым слотом (бюджет один на загрузку на машину).

## 4. Матрица тестов

### Шаг 0 — подъем и базовая линия
`preferred_profile: ""`, `i1_adaptation: true`, location mode=country country=NL.
Поднять резерв: `GET /api/proton/status` → state=established, listening=true.
PASS: `proton_registered` (ровно 1), seek выбрал proton-quic, сессия
established, в events НЕТ `proton_api_*`/`proton-captcha-required`.

### Шаг 1 — провод: чистый I1 (P4)
`tcpdump -i <wan> -s0 -w /tmp/s1-quic.pcap host <entry_ip> and udp` во время
установки. Критерии PASS:
- перед 148-байтовым initiation (тип 1) уходит РОВНО ОДНА 1250-байтовая
  датаграмма; датаграмм короче 40 Б НЕТ вообще (регрессия P4 = мусор 1–3 Б);
- для сравнения: сборка с прошлым поведением (jc=3) шлёт три датаграммы 1–3 Б
  — в новой сборке их быть не должно.
FAIL: датаграммы <40 Б присутствуют → jc не применился (проверь IpcSet-дамп
события `wg_ipc_set_failed`, профиль в active_profile).

### Шаг 2 — провод: DCID уникален per-handshake (P3)
Не поднимая новый pcap-захват, дождаться ≥3 хендшейков: rekey (~2 мин) и/или
ручной `POST /api/proton/restart`. В pcap: Initial'ы разных рукопожатий →
tshark `quic.dcids` (или ручной разбор байт 6..14). Критерии PASS:
- DCID первого Initial каждого рукопожатия РАЗЛИЧНЫ (все пары);
- размер всех Initial = 1250.
FAIL: повтор DCID в двух рукопожатиях → перегенерация не работает; приложить
бинарник/ветку, гипотеза: IpcSet-цепочка перезаписала слот статикой.

### Шаг 3 — глубокий разбор ClientHello (P5)
tshark расшифровка Initial → ClientHello. Критерии PASS (по чек-листу §1.2):
порядок расширений GREASE→SNI→supported_versions→key_share→alpn→QTP→padding;
SCID == DCID пакета; session_id 32Б; alpn h3; supported_versions только 1.3
(+GREASE-head); SNI не является Proton-доменом.
FAIL: структура совпадает со старой минимальной (только SNI) → в эфире не тот
бинарь; сверить version/HEAD.

### Шаг 4 — exit-верификация (P1)
location mode=country country=NL → дождаться события `proton_exit_verified`
(NL). Затем выставить location country=US (POST /api/proton/location) → при
пере-установке проба найдёт NL → PASS-критерии:
- событие `proton_exit_mismatch` (class proton-exit-mismatch), last_failure
  = proton-exit-mismatch;
- узел получает страйк: повторный seek НЕ выбирает тот же endpoint (cooldown);
- статус verified_exit заполнен {ip, country} в обоих случаях.
FAIL: mismatch не эмиттится при заведомой разнице → проверить, что
location.Mode == "country" (mode=auto проверку намеренно пропускает).
Вернуть location country=NL после шага.

### Шаг 5 — netzone (P6)
Событие `proton_netzone_set` с значением вида `a.b.c.0/24` при старте демона.
PASS: событие есть, формат /24 верный (сверить с фактическим публичным IPv4
роутера). Опционально (серверная сторона): ранжирование logicals в
`GET /api/proton/locations` смещает NL-узлы вверх — субъективно, не гейт.
FAIL: `proton_netzone_unresolved` — STUN-якоря недостижимы (проверить
исходящий UDP 19302/3478; это входное данное, не баг, если сеть режет STUN).

### Шаг 6 — Reissue (P7)
`POST /api/proton/reissue`. Критерии PASS:
- событие `proton_session_retired` → `proton_registered` (деталь reissue);
- статус: listening=false (сессия остановлена немедленно), затем на след.
  тике rebuild (капы применяются: если restart_cap_hit=true, rebuild
  откладывается — это норма, дождаться окна);
- registration-вызовы: sessions+credentialless+certificate (новая enrollment).
FAIL: старая сессия продолжает отвечать после reissue (listening не падал) —
регрессия P7, приложить events.

### Шаг 7 — (опционально) рунг j40
`preferred_profile: "proton-quic-j40"` → seek-событие с этим профилем → pcap:
4 junk-датаграммы 40..70 Б + 1250-байтовый Initial. PASS: размеры в границах,
handshake проходит (Proton-пир junk игнорирует — vanilla-safe). Вернуть "".

### Шаг 8 — удержание 30–60 мин
Живая сессия под лёгким фоном. Критерии PASS:
- rekey каждые ~2 мин: каждый rekey = НОВЫЙ DCID (продолжение шага 2);
- нет reconnect-шторма: `proton_session_lost` редки/объяснимы;
- `proton_handshake_total{result=ok}` растёт на rekey, `fail` не растет;
- при деградации (если случилась): SNI в Initial'ах НЕ меняется чаще раза в
  30 мин (L1), fresh DCID — при каждом хендшейке.

### Шаг 9 — (опционально) kernel-TUN PBR (P2 stage в)
`system.proton.tunnel_mode: "kernel"` (нужны linux + /dev/net/tun +
CAP_NET_ADMIN). Демон строит сессию над реальным TUN (b4proton0), ПЕРЕД
гейтом поднимает адреса и PBR: `ip addr add 10.2.0.2/32`, `ip rule add
fwmark 0xb4b4 lookup 5182 priority 15182`, `ip route replace default dev
b4proton0 table 5182`, верификация `ip route get 8.8.8.8 fwmark 0xb4b4`.
События: `proton_kernel_route_applied`, при потере `proton_kernel_route_lost`
+ `proton_kernel_pin_restored` (re-assert каждые 30 с), teardown при остановке.
ТРАФИК в туннель попадает ТОЛЬКО помеченный (mark 0xb4b4) — по умолчанию
ничего не уходит через Proton (красная линия «никогда не подменяет молча»):
проверка управляемого скоупа:
`iptables -t mangle -A OUTPUT -p udp --dport 53 -j MARK --set-xmark 0xb4b4`
→ DNS-проба роутера уходит через NL-выход (сверить `verified_exit`/trace).
Гейт establishment в kernel-режиме честно пропущен (raw-проба над kernel-
стеком не завершается; живость держит watchdog счётчиков) — в статусе
ожидаемо `kernel_route: applied`, `proton_exit_probe_skipped`. Адрес 10.2.0.2
пингуем ВНУТРИ туннеля только помеченным трафиком. Откат: `tunnel_mode:
"netstack"` + restart; teardown снимает rule/table сам.
PASS: applied-событие, верификация route get отвечает dev b4proton0, помеченный
трафик уходит в туннель, немаркированный — нет (tcpdump на WAN: утечек plaintext
в туннель нет и наоборот). FAIL: route get отвечает чужим dev — приложить
`ip rule show` / `ip route show table 5182`.

### Шаг 10 — A/B против предыдущей сборки
Та же сеть, тот же узел: старый бинарь (jc=3, статичный I1) vs новый.
Сравнить: время установления, долю успешных хендшейков, поведение на rekey.
PASS: новая сборка не хуже; субъективное поле: доживает ли поток дольше под
наблюдаемым DPI (записать наблюдение, не гейт).

## 5. Красные линии (нарушение = немедленный стоп)
1. Регистрация Proton ≤1 на загрузку; при `proton-captcha-required` (9001/
   12087) — стоп и репорт (структурный отказ, не ретраить).
2. Верификация не ослабляется: pin-mismatch / cert notBefore в будущем —
   стоп и репорт (это дыра, а не шум).
3. Control-plane Proton/DoH никогда не идёт через туннель (антипетля);
   лишние запросы к vpn-api.proton.me = баг интеграции.
4. Vanilla-safe: ничего не должно модифицировать S/H-параметры против
   vanilla-пира; reserved-байты — нули на проводе.
5. Живой YouTube-плейн и базовые фичи не трогаются; всё — на копиях бинаря.
6. Отчёт честный: fail-open, деградации, несоответствия — как есть.

## 6. Формат отчёта
На каждый шаг: конфиг → действия → pcap-факты (DCID-таблица по хендшейкам,
размеры датаграмм, расшифрованный CH с расширениями) → фрагменты
`GET /api/proton/status` (events) → вердикт PASS/FAIL. Итоговая таблица
«шаг → вердикт». Отдельная секция «Отклонения от ожиданий» — самое ценное
для доработки. Файлы pcap именовать `s<N>-<вариант>.pcap` и приложить.
