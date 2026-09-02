# E-PROTON: ревью реализации туннеля AWG Proton VPN (v1, 2026-09-02)

Статус: ревью кода ветки `agent/classifier-v2.3-capture-envelope` (HEAD 87ef91a) против
дизайна `proton-awg-design (1).md` (v1, 2026-08-30) и `proton-awg-patch-plan.md`.
Объект ревью: `src/transport/proton` (PT1–PT4), `src/protonservice` (PT5–PT6),
`src/transport/wg` (профили proton-*, Seeker, session — затрагивается), `src/config/proton.go`,
`src/http/handler/proton.go`, `src/observability/proton.go`, wiring в `main.go`.

Формат: вердикт и карта → находки по серьёзности → качество обфускации отдельным блоком
(§4, т.к. для Proton маскировка — главная тема дизайна) → рекомендации → примечание:
глава маскировки не требуется (Proton уже несёт amnezia-обфускацию; вместо неё — §6
«Доработка маскировки» с конкретными улучшениями I1/junk).

---

## 1. Вердикт

Наиболее зрелый из трёх резервов: полный lifecycle (ntp-wait → регистрация → node-select →
seek → trust-gate → established → renew), refresh-дисциплина Next (мьютекс+дебаунс+force),
лестница bootstrap (direct → DoH-зеркала Proton → carrier) с 10 seed-пинами и
pending→commit TOFU, интероп-инвариант vanilla-safe (reserved-байты ноль, S/H не
модифицируются), кастомный QUIC-Initial генератор, сверенный с RFC и vendored quic-go
(см. §4.1 — сверено побайтово в этом ревью), wiring в main.go и HTTP API, observability.
Регистрационная дисциплина «≤1 на загрузку» атомарным CAS-флагом — образцовая.

Главные пробелы: **exit-верификация гео-выхода не реализована** (классы и поля есть,
проба никогда не выполняется — r.exit не заполняется нигде), **kind=proton отсутствует в
деревьях выбора** (сервис поднимает WG-сессию в netstack, но ни один scope трафика в неё
не направляется — UDP full-scope-носитель не имеет потребителей), и обфускация I1 имеет
две регрессии маскировки: статичный DCID между хендшейками и junk-пакеты 1–3 байта,
которые сами по себе — сигнатура.

| Область | Оценка |
|---|---|
| Криптоядро (PT1) | Отлично: seed→ed25519 PEM→x25519 clamp, Validate перепроверяет деривацию |
| API-клиент (PT2) | Отлично: лестница, пины, already-tied-ретрай, refresh-дисциплина |
| Каталог узлов (PT3) | Хорошо: v2/v1, 304, asset, интерливинг; Netzone не заполняется |
| Обфускация (PT4) | Хорошо; см. §4 — две регрессии маскировки (I1-статичность, junk-размеры) |
| Сервис (PT5) | Хорошо; exit-верификация отсутствует, i1LastSwap мёртв |
| Интеграция (PT6) | main.go+handler+config есть; **деревья выбора не знают kind=proton** |

---

## 2. Что реализовано (карта)

- `crypto.go` — seed 32Б (единственный секрет), ed25519→PEM SPKI с фиксированным
  DER-префиксом, x25519-приватник clamp(SHA512(seed)[0:32]); все операции stdlib/x-crypto.
- `api.go` — 4 шага регистрации (sessions → credentialless с challenge-кадром → logicals →
  certificate persistent), refresh без Authorization, keep-alive /core/v4/users; заголовки
  Nova (appversion/apiversion/uid/Authorization); классификация 401/403/410 (refused),
  429/5xx (throttled с Retry-After ≤30с), 9001/12087 (captcha — структурный отказ);
  **лестница запроса**: direct-хосты → DoH-зеркала (bare-IP без SNI, пин как якорь) →
  carrier-подшивка под direct-диал; HTTP-ошибка финальна (правильно: Nova ProtonApi.kt:95-100),
  транспортная — эскалирует; 304 трактуется только logicals-лестницей.
- `challenge.go` — кадр с ЖИВЫМИ ключами Nova v1.31 (`deviceName`/`storageCapacity`, не
  дизайн-спеллинги), ротация 5 моделей × 5 локалей × 3 хранилища, персист per-install.
- `doh.go` — TXT d<Base32(host)>.protonpro.xyz через цепочку dns.google → cloudflare-dns
  → quad9, имена раньше адресов; кэш зеркал per-process.
- `pins.go` — 10 seed-пинов (6 API + 4 зеркала), pending→commit после успешного обмена,
  персист pins.json.
- `serverlist.go` — v2 (If-Modified-Since, X-PM-netzone) → v1 (Tier=0) → stale → asset;
  TTL 3ч/15мин ±22%, jitter; SourceLiveV2/V1/Stale/Asset/Cache метки.
- `nodes.go` — free-фильтр (Tier==0, Status==1, EntryIP/Key непустые), один physical per
  logical (правило Nova), интерливинг, порт-каталог round-robin [443,88,1224,51820,500,4500].
- `quici1.go` — настоящий QUIC v1 Initial (см. §4.1).
- `profile.go` — SNI-пул из asset (90 имён), конфиг-override с валидацией (не Proton-домены,
  RFC-1123), IssueProfiles c last-good и случайным SNI.
- `wgbridge.go` — проекция Identity→twg.Identity: CFWarp=false (reserved-байты — ноль на
  проводе, красная линия §11.3 E-WG), синтетический client_id не на проводе.
- `service.go` — states-canvas, restartGuard, registeredThisBoot (CAS), ntp-wait через
  TLS-NotAfter (TimeFresh — изящно), cert-refresh за 30д (без разрыва туннеля — ключ
  производен от seed), keep-alive 12ч, проф. refresh 7д, джейл-детект (ClassStallRX ×2 →
  proton-jailed → Strike узла + ротация), Seeker с лестницей профилей и last-good.
- `main.go:636-655` — if-gate по config, Build/Start, SetProtonRuntime, Stop при
  завершении. `handler/proton.go` — 5 эндпоинтов. `observability/proton.go` — метрики
  (dial/handshake/seek/nodes_source/cert_valid_until/registration/api/refresh).
- `NOTICE.md` — лицензионные аспекты (нулевые новые зависимости подтверждены).

---

## 3. Находки

### HIGH

**P1. Exit-верификация гео-выхода не реализована (дизайн §5).**
Дизайн: «exit-верификация: после DATA GATE — сквозная проба страны выхода; несовпадение =
proton_exit_mismatch + пере-выбор узла внутри локации». Реальность: `ClassExitMismatch`,
`ErrExitMismatch`, `EventExitMismatch` и поле `Status.VerifiedExit` существуют, но
**`r.exit` не присваивается нигде** (grep по protonservice: присвоений нет), проба не
вызывается. Гео-заявка локации неверифицируема: пользователь выбрал NL, а выход может
быть любым (Proton иногда отдаёт узел другой страны под load-балансом — ровно тот случай,
ради которого дизайн ввёл класс). Поле в GUI всегда пустое.
Фикс: после StateEstablished (callback OnEstablished) — сквозная HTTP-проба через
netstack-сессию (GET cloudflare trace / или ipinfo через WG-туннель, паттерн
`fxvpn.ProbeExit` — но через WG data-плейн: twg уже умеет диалить через туннель для
TrustGate; добавить аналогичный probe-host диал), сравнение страны с локацией →
несовпадение: `EventExitMismatch` + Strike узла + пере-seek. Кэшировать результат в
`r.exit`. Оценка: S–M.

**P2. Транспорт не участвует в деревьях выбора: UDP full-scope-носитель без потребителей.**
main.go честно комментирует: «dial is wired when the selection trees learn the proton
kind (design §7)». `Runtime` не экспортирует даже DialStream/DialPacket для
scoped-роутера (в отличие от operaservice/fxvpservice, где DialStream есть, но тоже не
потребляется). Сессия поднимается, траст-гейт проходит — и трафик через неё не идёт.
`Tunnel: Mode: twg.ModeNetstack` — только netstack: kernel-TUN/PBR-путь (по дизайну §7
«основной путь роутера») не построен. **Proton — единственный резерв с UDP-эгрессом, и
именно UDP-потребители (QUIC-scope) не могут его получить.**
Фикс (этап PT6b): (а) экспозить носитель — DialStream (TCP через netstack) +
DialPacket/UDP-форвардер (через netstack UDP или gVisor-стек — twg/netstack уже даёт
обе ноги); (б) регистрация kind=proton в RegionTransportPolicy/деревьях с приоритетом
ниже WARP/MASQUE/H3; (в) kernel-TUN PBR-режим как отдельный этап (по образцу warp-тун).

### MEDIUM

**P3. I1 статичен между хендшейками — повторяющийся DCID (регрессия маскировки).**
I1 генерируется один раз на выпуск профиля (`IssueProfiles` → `BuildQuicInitial`) и
зашивается в конфиг устройства (IpcSet). Amnezia-движок шлёт InitPacket-цепочку **на
каждом рукопожатии** (и на каждом retry каждые 5с, и на каждом rekey). Следствие: в
эфир уходят **многочисленные побайтово идентичные 1250-байтовые датаграммы с одним и
тем же DCID** к одному эндпоинту. Реальный QUIC-клиент НИКОГДА не повторяет DCID; DPI,
ведущий таблицу «DCID per flow», классифицирует поток как replay/подделку за первые
десятки секунд. Это главная регрессия против замысла «I1 = правдоподобный первый
пакет». Детали и фикс — §4.2.

**P4. Junk-пакеты 1–3 байта — сама сигнатура (регрессия маскировки).**
Профиль proton-quic: `jc=3, jmin=1, jmax=3` (дефолты сайта Amnezia). Три UDP-датаграммы
размером 1–3 байта перед рукопожатием: ни один реальный протокол не шлёт 1–3-байтовые
UDP-пакеты на порт 443. Датаграмма меньше минимального заголовка любого известного
протокола — мгновенный классификатор мусора. Дефолты Amnezia рассчитаны на пару
AWG↔AWG (пир понимает), а не на маскировку перед DPI. Детали/фикс — §4.3.

**P5. I1-ClientHello слишком минимальный для deep-пayload классификатора.**
Ключи RFC 9001 корректны (проверено §4.1), Initial расшифровывается как настоящий QUIC —
но внутренний ClientHello спек-невалиден и очевидно синтетичен: пустые cipher_suites,
пустой session_id, одно расширение (SNI), нет key_share / supported_versions / ALPN /
quic_transport_parameters (последний обязателен для QUIC). ТСПУ, расшифровывающий
Initial'ы (ключи публичны по RFC), увидит «QUIC с несформированным TLS» — сигнал
подделки для любого сканера глубже заголовка. Детали/фикс — §4.4.

**P6. `Client.Netzone` не заполняется — X-PM-netzone не шлётся никогда.**
Поле есть, `FetchLogicals` шлёт заголовок при непустом значении — но ни сервис, ни
клиент его не вычисляют (grep: присвоений нет). Дизайн §1.7: `X-PM-netzone: <публичный
IP>/24` — сервер использует для ранжирования близости; без него logicals отдаёт
дефолтный порядок. Функционально не смертельно, но заявленное поведение не соблюдается.
Фикс: вычислить публичный IP один раз при старте (существующий netprobe/STUN-стек
программы: `src/stun`, `src/netprobe`), формат `ip/24`.

**P7. `Reissue` не роняет живую сессию.**
Reissue (сервис:362) перевыпускает identity, но `r.sess` продолжает работать со старым
ключом (комментарий обещает «current session is retired», код этого не делает). MaxConnect
=2 допускает два ключа, так что столкновения нет, но переключение произойдёт только при
естественной смерти старой сессии — неожиданно для оператора. Фикс: в Reissue после
успешной регистрации — Stop() старой сессии (как в SetLocation).

### LOW

**L1. `i1LastSwap` пишется, не читается** (service.go:210,760) — мёртвое поле. Либо
использовать для ≥30-мин гейта реального перевыпуска (сейчас адаптация I1 происходит
неявно при следующем IssueProfiles — случайный SNI и так новый), либо удалить.

**L2. `clockLooksFresh`-проба в ntp-wait не имеет собственного таймаута** ниже callTimeout
(30с × повторы 5с — budget 120с честно истекает; ок, но первая итерация может занять 30с
при чёрной дыре — приемлемо).

**L3. `mirrorCandidates` кэширует зеркала per-process без TTL** (Endpoints.MirrorHosts) —
при смене набора зеркал Proton в runtime (редко) перезапуск. Приемлемо; пометить.

**L4. `refreshSession` при ошибках ≠400/401/422 возвращает ошибку наверх без ретрая в
тот же тик — следующий тик повторит; бэкоффа нет, но тик 30с + капы спасают. Отметить.

**L5. `certRefreshAt` при `exp - now < margin` берёт `exp.Sub(now)/2`** — корректный
edge-case; ок.

**L6. `service_extras.go` живёт в `transport/proton`** (вместе с ServerlistCache-методами
Locations/TimeFresh) — архитектурный гибрид transport/service; терпимо, но при росте
файла вынести. Косметика.

**L7. Дизайн §12 (Tor-over-AWG) честно отложен — зафиксировано, код не пишется. ОК.

---

## 4. Качество обфускации (ядро дизайна §3) — детальный разбор

### 4.1. Криптографическая корректность I1 — ПРОВЕРЕНО, ОТЛИЧНО

Сверка `BuildQuicInitial` с vendored quic-go (пакетный формат, AAD, sample, nonce):

| Элемент | quic-go (packet_packer.go:991-997, initial_aead.go) | proton/quici1.go | Вердикт |
|---|---|---|---|
| AAD AEAD | заголовок включая PKN | `header` включая pkn | ✓ |
| Plaintext AEAD | payload только | payload+padding | ✓ |
| Nonce | iv ⊕ BE64(pn) | iv ⊕ pkn (pn=0 → эквивалентно) | ✓ |
| Sample HP | raw[pnOffset+4:pnOffset+20] | sealed[3:19] (== len(header)-1+4 …) | ✓ |
| Маска first byte | 0x0F для long header | `mask[0]&0x0F` | ✓ |
| Length varInt | pnLen+cipher+tag | pkn+payload+pad+tag | ✓ |
| DCIL/SCIL | high/low nibble | 0x80 (8/0) — три RFC-фикса против Nova-бага, задокументированы | ✓ |
| HKDF-Expand-Label | RFC 8446 | RFC 8446 (исправлен лишний 0x01 Kotlin) | ✓ |
| Паддинг | ≥1200 | итеративная подгонка до 1250 | ✓ |

Три осознанных отклонения от Nova (DCIL-свап, лишний ноль SCID, 0x01 в HKDF) — все в
сторону RFC, все задокументированы в шапке файла, все правильные. Тест
`TestQuicInitialDecryptsPerRFC9001` расшифровывает пакет независимым путём. **Это
лучший I1-генератор из виденных в подобных проектах.**

### 4.2. P3-детализация: статичный DCID
AmneziaWG шлёт ipackets каждый `SendHandshakeInitiation` (ретрай REKEY_TIMEOUT=5с;
rekey каждые 2 мин). Идентичная датаграмма → повтор DCID → DPI-таблица «DCID виделся N
раз» → классификация replay. Варианты фикса (по возрастанию вмешательства):
- **(а) Перевыпуск I1 перед каждым хендшейком на сервисном уровне**: невозможен без
  пере-IpcSet (дорого, рвёт сессию) — отпадает;
- **(б) Патч vendored amneziawg-go**: генерация InitPacket-цепочки на лету (callback
  `InitPacketFunc` в расширенном IpcSet, рендер из chain-spec каждый раз с НОВЫМ DCID/
  random) — ~60 строк патча в vendored-форке (прецедент патчей vendored-кода в проекте
  есть: docs/upstream/amneziawg-timers-race-issue.md). Рекомендуемый путь: спека `<b …>`
  статична, но `<r>`-элементы уже перегенерируются движком? Проверить: amneziawg
  материализует цепочку при IpcSet (один раз) — значит даже `<r>`-хвосты статичны.
  Патч: материализация на каждом хендшейке;
- **(в) Минимальный вариант без патча**: принять маркер для proton-vanilla (последняя
  ступень) и для proton-quic задокументировать риск; при признаках классификации
  (деградация) — смена SNI уже реализована, но DCID остаётся тем же до перевыпуска
  профиля — т.е. действующей ротации нет.
Рекомендация: (б) этапом PT-obf1; инвариант: «два подряд рукопожатия одного устройства
не должны содержать побайтово равных InitPacket[0]» — красный юнит-тест против
amneziawg-go (genTestPair из interop-тестов).

### 4.3. P4-детализация: junk-размеры
`jc=3, jmin=1, jmax=3`: три датаграммы 1–3Б. Фикс: для proton-семейства junk либо
отключить (I1 уже решает задачу первого пакета; junk добавляет маркер, а не маскировку),
либо поднять размеры в правдоподобный диапазон: QUIC-соседство — датаграммы 40–80Б
(«похоже на короткие QUIC-фреймы») как в cf-семействе quic-a (jc=4, jmin=40, jmax=70 —
эти значения уже в каталоге!). Рекомендация: `proton-quic` → `jc=0` (чистый I1);
отдельная ступень `proton-quic-j40` для экспериментов поля. VanillaSafe не нарушается
(junk — client-side).

### 4.4. P5-детализация: ClientHello-обогащение
Цель: расшифрованный Initial содержит ClientHello, неотличимый от браузерного
(хром-класс):
- legacy_version 0x0303, random 32Б (есть);
- session_id 32Б случайных (браузеры шлют непустой);
- cipher_suites: TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256,
  TLS_AES_256_GCM_SHA384 (браузерный порядок Chrome);
- compression_methods: [0];
- extensions в браузерном порядке: GREASE, server_name (пул),
  supported_versions (0x0a2a…: 0x0304), key_share (X25519, 32Б pubkey),
  alpn (h3, h3-29(!): Chrome шлёт «h3» — достаточно), 
  quic_transport_parameters (0x39 — правдоподобные значения: initial_max_data ~1.5МБ,
  max_idle_timeout 30–60с, active_connection_id_limit 2-4, initial_source_connection_id
  = наш DCID(!) — важно: RFC 9000 требует SCID-параметр = DCID пакета, его отсутствие
  сейчас = спек-невалидность), padding-расширение до ~1250.
Объём работы: ~200 строк в quici1.go + golden-тесты (расшифровка, парсинг CH,
инварианты transport-params). Зависимостей нет. Этап PT-obf2.

### 4.5. SNI-пул и адаптация
- Пул 90 имён, embed, конфиг-override с валидацией — реализовано хорошо.
- Адаптация I1 (смена имени при деградации) — происходит неявно при перевыпуске
  IssueProfiles; `i1AdaptationStep`-гейт 30 мин фактически не enforced (L1) —
  перенести логику в IssueProfiles (передавать lastSwap).
- Правило «имя не Proton-домен» — есть (ValidSNIName). Дополнительно: исключить имена,
  чей реальный IP резолвится в Proton-диапазоны (edge-case, поле).

### 4.6. Лестница и Seeker — реализация vs дизайн §3.5
`[last_good → proton-quic → vanilla-off → sip → crlf]` — реализовано
`protonLadderIDs` + `twg.NewSeeker` (Target=TargetProton, InCatalog=членство в списке
узлов, Strikes, LastGoodStore-персист). Сигнатура version-mismatch («handshake ok, tx
растёт, rx нет») — ClassVersionMismatch из wg-движка переиспользуется. Соответствие
дизайну — полное. Замечание: `protonLadderIDs` в сервисе и `protonLadderOrder` в
каталоге дублируют порядок (два источника правды) — консолидировать в wg-пакете.

---

## 5. Приоритетный план правок

| # | Что | Файл | Оценка |
|---|---|---|---|
| 1 | P1: exit-проба через WG-туннель после TrustGate + mismatch→Strike+пере-seek | protonservice | S–M |
| 2 | P2: экспоз носителя (DialStream/UDP) + kind=proton в деревьях выбора; kernel-TUN — отдельным этапом | protonservice + routing/engine | M–L |
| 3 | P4: junk proton-quic → jc=0 (или 40–70) | transport/wg/profiles.go | XS |
| 4 | P5: обогащение ClientHello I1 + transport_parameters | transport/proton/quici1.go | M |
| 5 | P3: перегенерация InitPacket per-handshake (патч vendored amneziawg) | vendor/amnezia-vpn + transport/wg | M |
| 6 | P6: Netzone через netprobe/stun при старте | protonservice | S |
| 7 | P7, L1, L6 | по месту | XS |

---

## 6. Тестовое покрытие (что добавить)

- Красный тест P3-инварианта: два рукопожатия подряд → InitPacket[0] отличаются
  (сейчас — совпадают: тест вскроет регрессию).
- Exit-проба: фейк-edge с известной страной → mismatch путь (P1).
- Golden тест enriched ClientHello: расшифровка Initial, парсинг extensions,
  SCID-параметр == DCID (P5).
- Junk: wire-capture-подобный юнит — размеры junk-датаграмм в профиле
  (детерминированная проверка ≥40Б или jc=0) (P4).
- Netzone: юнит на формат заголовка (P6).

---

## 7. Резюме для владельца

Proton-этап практически готов к полевому включению из трёх резервов единственным — при
условии осознания, что (а) трафик в него пока не направляется (P2 — главный блокер
продуктовой роли), (б) гео-выход неверифицирован (P1), (в) I1-обфускация требует трёх
точечных доработок (P3–P5), иначе её эффективность против грамотного DPI ниже
заявленной дизайном. Криптография, дисциплина регистраций, bootstrap-лестница и
инженерная культура кода — выше среднего по проекту; ревью не нашло в control-plane ни
одного security-дефекта (пины/секреты/редакция — образцово).
