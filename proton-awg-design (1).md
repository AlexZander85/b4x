# E-PROTON: туннель AWG Proton VPN — дизайн (v1, 2026-08-30)

Статус: ПРОЕКТ. Позиция в программе: резервный транспорт R-reserve с гео-выходом
(UDP full-scope), рядом с E-OPERA/E-FXVPN, ниже E-WG/E-NM/E-H3 во всех деревьях выбора.
Родительские слои: E-WG (`src/transport/wg`, amneziawg-go v3 vendored) — движок
дата-плоскости переиспользуется целиком; паттерны сервиса/каталога/пинов — E-OPERA/E-FXVPN.

Источники (все скачаны и прочитаны полностью, отчёты в приложении):
- **Nova-Android v1.31** (tag v1.31, commit abbfe09) — первичный живой референс:
  credentialless-сессия Proton + AWG-клиент против vanilla-WG узлов, проверено владельцем
  на живом подключении. Отчёт: `research-nova-proton.md`.
- **ProtonVPN-Next** (SMH01-MOD-NEXT, HEAD 3fd3589) — неофициальный Android-клиент:
  refresh-сессии, v2-логикалы, bypass-набор из 7 стратегий, 13 SPKI-пинов, sing-box/AWGBox.
  Отчёт: `research-protonvpn-next.md`.
- **Ванильный стек** (proton-vpn-gtk-app 4.18 + python-proton-vpn-api-core 5.5.15) —
  production-уроки жизненного цикла сертификата, local agent, кэширование списка.
  Отчёт: `research-proton-vanilla.md`.
- **b4x** (ветка agent/classifier-v2.3-capture-envelope, HEAD 044eede) — целевой репозиторий.
  Карта переиспользуемых сущностей: `research-b4x-arch.md`.

Ключевая архитектурная идея — та же, что в Nova: **аккаунт Proton не заводится вообще**.
Используется штатный путь официального клиента «подключиться без аккаунта»
(`auth/v4/credentialless`); анти-абузный challenge-кадр фабрикуется из выдуманного, но
постоянного на установку профиля устройства. Ключ WireGuard выпускается **на самом
роутере** и регистрируется в Proton — он не общий и не зашит в бинарь. Узлы —
бесплатный тир (Tier=0) из живого списка, со встроенным офлайн-активом в прошивке.

---

## 0. Что это и роль

Proton VPN free — это **настоящий WireGuard-туннель** (не прокси, в отличие от
Opera/Firefox): контрольная плоскость Proton API по HTTPS, дата-плоскость — UDP
WireGuard до узлов free-тира. Серверы Proton — **vanilla WireGuard**: они не знают
AmneziaWG, и вся обфускация укладывается в семантику «стоковый WG молча отбрасывает
чужие датаграммы» (мусорные пакеты и кастомный I1 уходят вперёд рукопожатия, сам
рукопожатие и транспорт остаются провода-стандартными).

Роль в архитектуре: **R-reserve с гео-выходом** — уникальное сочетание, которого нет
ни у одного из существующих транспортов:

- третий независимый вендор (≠Cloudflare, ≠SurfEasy/Opera, ≠Mozilla/Fastly) — другое
  поле блокировок;
- **UDP full-scope**: единственный резерв с полноценным UDP-эгрессом (Opera/FXVPN —
  TCP-only по протоколу); QUIC/H3-трафикscope проходит нативно;
- **выбор локации**: free-тир Proton даёт страны (NL/US/CA/NO в активе; живой список
  шире) — гео-выход без WG-пулов Cloudflare, ортогонально R2 у E-WG;
- лимитов полосы в коде референсов не обнаружено; единственное жёсткое ограничение —
  `MaxConnect: 2` одновременных подключения на устройство-ключ (поэтому ключ у каждого
  свой, а не общий).

Честные границы (README-уровень): это бесплатная анонимная инфраструктура без гарантий
скорости/доступности; весь трафик видит Proton; использование вне официального клиента —
серая зона ToS. Позиционирование строго «резерв с географией», не основной канал.

---

## 1. Протокол (все факты верифицированы по трём независимым реализациям)

### 1.1. Хосты и заголовки контрольной плоскости

Хосты (Nova ProtonApi.kt:26, оба рабочие):

```
https://vpn-api.proton.me      # первичный
https://api.protonvpn.ch       # запасной
```

Обязательные заголовки каждого запроса (без них — 403, ProtonVPN-Next
NetworkConstants/API_DOCUMENTATION):

| Заголовок | Значение | Источник |
|---|---|---|
| `x-pm-appversion` | `android-vpn@5.4.44.0` | Nova ProtonApi.kt:28 |
| `x-pm-apiversion` | `3` (Nova; Next шлёт `4` — оба проходят) | ProtonApi.kt:29 |
| `Accept` | `application/vnd.protonmail.v1+json` | ProtonApi.kt:81 |
| `User-Agent` | `ProtonVPN/5.4.44.0 (Android 13; Pixel 7)` | ProtonApi.kt:57-58 |
| `x-pm-uid` | UID сессии (аутентиф. запросы) | ProtonApi.kt:87 |
| `Authorization` | `Bearer <AccessToken>` | ProtonApi.kt:88 |

Решение: держим константы Nova (владельчески проверены на живом credentialless-пути
v1.31) как дефолт; версия клиента выносится в конфиг-override для смены без релиза
(Next обновляет spoof-версию `5.19.43.0-dev+play`, apiversion 4 — задокументировано
как альтернатива). TLS-отпечаток: обычный Go TLS 1.3, без uTLS-подмены — Nova тоже
ходит обычным OkHttp (ProtonApi.kt:34-41), сервер не фингерпринтит контрольный канал.

### 1.2. Регистрация: 4 шага, без email/капчи

**Шаг 1 — сессия-носитель** (Nova ProtonApi.kt:178-190):
`POST /auth/v4/sessions`, тело `{}` → `{"UID","AccessToken","RefreshToken","Scopes"}`.
Токены шага 1 НЕ годятся для VPN-эндпоинтов (`9106 MissingScopes: [user, vpn]`) —
это только носитель для шага 2.

**Шаг 2 — credentialless-сессия** (Nova ProtonApi.kt:215-256):
`POST /auth/v4/credentialless` с `Authorization: Bearer <шаг1>` + `x-pm-uid`,
тело — challenge-кадр (§1.3). Ответ: `UID/AccessToken/RefreshToken/Scopes`;
обязательная проверка `Scopes ∋ "vpn"`.
Неидемпотентность: если запрос дошёл, а ответ потерялся на транзите, повтор на новой
сессии возвращает `400 Session already tied to a user` — лечение Нова: взять новую
сессию-носитель и повторить **ровно один раз** (ProtonApi.kt:201-226). ProtonVPN-Next
этой обработки не имеет — берём её у Nova.

**Шаг 3 — список бесплатных узлов** — см. §1.7.

**Шаг 4 — регистрация клиентского ключа** (Nova ProtonApi.kt:303-316):
`POST /vpn/v1/certificate` с телом:

```json
{"ClientPublicKey": "<PEM ed25519, SPKI>", "Mode": "persistent", "DeviceName": "Nova"}
```

Ответ: `ExpirationTime` (unix-секунды; при `Mode: "persistent"` — год), опционально
`Certificate` (X.509 PEM), `IPv4/IPv6/DNS`, `RefreshTime`. Сам сертификат туннелю не
нужен — важен факт, что Proton теперь знает наш публичный ключ (сервер сам выводит
X25519-половину). In-place перевыпуск того же ключа разрешён и бесплатен
(«повторная регистрация того же ключа — лишний запрос без единого последствия»,
ProtonProfileManager.kt:193-198).

### 1.3. Challenge-кадр и выдуманное устройство

Анти-абузный кадр Proton — ключ `vpn-android-v4-challenge-0` (Nova ProtonApi.kt:29,
`v = "2.0.7"`). Nova шлёт выдуманный, но **постоянный на установку** набор
(обоснование ProtonApi.kt:192-200: настоящие Build-значения были бы отпечатком
устройства, а меняющийся от вызова к вызову — хуже для анти-абуза, чем стабильный):

```json
{"Payload": {"vpn-android-v4-challenge-0": {
  "v": "2.0.7", "appLang": "fr", "timezone": "Europe/Paris",
  "deviceNameHash": 3746281946382741, "regionCode": "FR", "timezoneOffset": -60,
  "isJailbreak": false, "preferredContentSize": "1.0", "storageBytes": 6.4e10,
  "isDarkmodeOn": true, "keyboards": ["com.google.android.inputmethod.latin"]
}}}
```

Ротация значений: 5 моделей × 5 локалей × 3 размера хранилища (ProtonProfileStore.kt:296-324);
`deviceNameHash ∈ [1e12, 9e15)`. Роутер генерирует профиль один раз на первый старт,
персистит в identity и больше не меняет. ProtonVPN-Next добавляет поле `type`
(`me.proton.core.challenge.data.frame.ChallengeFrame.Device`) и `deviceName`-hash
(AuthRepository.kt:473-494) — кадр Next с apiversion 4 живой тоже; держим форму Nova
как дефолт (проверена с apiversion 3), форму Next — как второй пресет в конфиге.

CAPTCHA (9001/12087): если Proton включит human-verification на credentialless,
заголовки `x-pm-human-verification-token(-type)` существуют (ProtonAuthApi.kt:104-109),
но роутер WebView не имеет — это **структурный отказ** `proton-captcha-required`
+ событие владельцу, никаких петель. На момент v1.31/v0.4.x credentialless капчу
не требует (живой факт Nova).

### 1.4. Обновление сессии (наше усиление против Nova)

Nova refresh-токен хранит, но НЕ использует — каждый перевыпуск профилей заводит новую
credentialless-сессию. ProtonVPN-Next реализовал refresh правильно
(SessionManager.kt:46-99, ProtonAuthApi.kt:52-58) — берём его:

```
POST /auth/v4/refresh        # БЕЗ Authorization
{"UID": "...", "RefreshToken": "...",
 "ResponseType": "token", "GrantType": "refresh_token",
 "RedirectURI": "http://protonmail.ch"}
```

Дисциплина: мьютекс + debounce 60 с; `force=true` после 401 обходит debounce; максимум
1 повторная попытка на запрос; success = `code==1000 && AccessToken != ""`; refresh-токен
заменяется только если сервер вернул новый; keep-alive `GET /core/v4/users` раз в 12 ч
(чтобы сессия не протухла между перевыпусками сертификата). Ошибка refresh с
HTTP 400/401/422 (= FORCE_LOGOUT-коды Next) → полная перерегистрация через §1.2 —
но не чаще одного раза на загрузку роутера (§6).

### 1.5. Ключи: один seed на всё

Единственная криптографическая операция на устройстве (Nova ProtonCrypto.kt:39-77,
Next Ed25519KeyPair.kt:33-75, ваниль key_mgr.py:52-55 — все три одинаковы):

1. `seed` = 32 случайных байта (crypto/rand), хранится только в identity-слоте 0600;
2. ed25519-публичник → **PEM SubjectPublicKeyInfo** с фиксированным DER-префиксом
   `MCowBQYDK2VwAyEA` (12 байт `30 2A 30 05 06 03 2B 65 70 03 21 00` + ключ) —
   это то, что уходит в `ClientPublicKey`;
3. WireGuard-приватник = **clamp(SHA-512(seed)[0:32])** — стандартная конверсия
   ed25519→x25519 (`crypto_sign_ed25519_sk_to_curve25519`): `priv[0] &= 248;
   priv[31] &= 127; priv[31] |= 64`;
4. сервер выполняет ту же конверсию над публичной половиной ⇒ **одна регистрация
   работает для всех серверов сразу** (ключ не привязан к узлу).

Никаких SRP-6a/bcrypt/подписей в credentialless-потоке нет. Смена сертификата никогда
не меняет WG-ключ (он производен от неизменного seed) — перевыпуск не рвёт туннель.

### 1.6. Сертификат: persistent-год vs ephemeral

Два режима (все три референса):

| | persistent (Nova) | ephemeral/session (ваниль) |
|---|---|---|
| Запрос | `Mode: "persistent"` | `Mode` отсутствует + `Duration: "10080 min"` |
| Срок | ~1 год | ≤7 дней (API запрещает <1 дня, fetcher.py:56-57) |
| Момент обновления | 30 дней до истечения (Nova CERT_RENEW_MARGIN_MS) | серверский `RefreshTime` (≈6 ч до истечения) |

Решение для роутера: **persistent** (Nova, проверено владельцем) — минимум
регистрационного шума; обновление за 30 дней; при ответе без `ExpirationTime` — отказ
`proton-api-invalid`. Бэкофф неудачного обновления — ваниль-формула
`1·2^n·(1±0.22)`, кап на интервале (certificate_refresher.py:62-126). Требование
часов: сертификат имеет `notBefore`; на роутере без RTC перед первой регистрацией
ждём NTP-синхронизации (ванильный урок NotYetValidCertificate — exception_handler.py:287).

### 1.7. Список узлов и free-фильтрация

Два живых эндпоинта (оба используем, лестницей):

- **v2 (Next/ваниль)**: `GET /vpn/v2/logicals?WithEntriesForProtocols=wireguard&WithState=true`
  с `If-Modified-Since` + `X-PM-netzone: <публичный IP>/24`; ответ `LogicalServers[]`
  c полями `Tier, Status, Load, Score, ExitCountry, City, Servers[]{EntryIP,
  X25519PublicKey, Status, Domain, Label}`. Free-фильтр клиентский:
  `Tier == 0 && Status == 1 && physical.Status == 1 && EntryIP != "" &&
  X25519PublicKey != ""`. Кэш: `Last-Modified` (ETag не используется), 304 →
  переиспользование; TTL полного списка 3 ч ± 22%, отдельный `GET /vpn/v1/loads`
  (TTL 15 мин ± 22%), эффективная свежесть = min (logicals.py:54-56, 171-182).
- **v1 (Nova)**: `GET /vpn/logicals?Tier=0` — проще, возвращает только free; НОВА
  фиксирует, что с альтернативных маршрутов этот эндпоинт может подвисать —
  поэтому v1 только второй ступенью.

Встроенный офлайн-актив (урок Nova «список узлов лежит в прошивке на случай, если
список серверов не отвечает»): `proton_nodes.json` в бинаре (embed), 50 узлов
free-тира, **только публичные факты** — 5 полей на узел: `server_name, country, city,
entry_ip, peer_public_key` (public-ключ сервера — не секрет). Требования актива:
интерливинг по странам round-robin (чтобы первые кандидаты не были из одной страны),
первые четыре узла — из разных стран, защита тестом «в активе нет ничего кроме
публичных фактов» (цена ошибки — общий аккаунт на всех при MaxConnect: 2 — нет, у нас
ключей в активе нет, но тест страхует от будущих правок). Живой список всегда в
приоритете; актив — fallback; подмена источника логируется, не молчит.

### 1.8. Дата-плоскость: vanilla WG против AWG-клиента

Серверы Proton — **vanilla WireGuard** (доказательства: рукопожатие Nova собирается по
чистой спецификации Noise_IKpsk2 без AWG-заголовков; «стоковый WireGuard на той стороне
лишние датаграммы просто отбрасывает» ProtonCrypto.kt:305-313; оба клиента работают).

Топология фиксирована Proton (не наш выбор):

| Параметр | Значение | Источник |
|---|---|---|
| Address | `10.2.0.2/32` (+ `2a07:b944::2:2/128` v6) | ProtonProfileStore.kt:284, ваниль wireguard.py:78-91 |
| DNS | `10.2.0.1` (+ `2a07:b944::2:1`) | там же |
| MTU | 1420 (Nova) / 1408 AWG+1400 TUN (Next) / не задан (ваниль) | §3.2 решение |
| AllowedIPs пира | `0.0.0.0/0, ::/0` | все три |
| Порты | WG слушает все UDP: ваниль-каталог `clientconfig` `[443,88,1224,51820,500,4500]`; Next `{443,123,1194,51820}`.random(); Nova round-robin `[51820,443,80,88,4500,1194,5060,1224,4569]` | client_config.py:39-49 |
| Keepalive | 25 с | Next, NAT-паттерн программы |

Порты: держим ванильный каталог `[443,88,1224,51820,500,4500]` как дефолт +
round-robin по профилям очереди (паттерн Nova: «если оператор глушит один порт,
кандидаты на нём просто не ответят и отсеются замером») + конфиг-override одним
значением.

### 1.9. Local agent: не нужен — и как мы это знаем

Ванильный клиент требует local agent (mTLS на `10.2.0.1:65432`, статус `connected`
как единственный источник события Connected, hard-jail режет трафик на шлюзе).
НО: grep по обоим модам — ни Nova, ни ProtonVPN-Next не содержат ни local agent,
ни порта 65432 (проверено: 0 совпадений), при этом:
- Nova проходит e2e-сквозную пробу и объявляется подключённой по живому трафику
  (rx/tx ≥ 32 КБ + сквозная проба) — владелец проверял живьём;
- ProtonVPN-Next верифицирует соединение TCP-зондом через туннель (AGGRESSIVE-режим,
  рестарт после 2 сбоев) и работает;
- сертификат Next хранит только ради локального парсинга `notAfter` — в TLS не подаёт.

Вывод: для credentialless-сессий шлюз не держит трафик в jail до LA-коннекта; LA в
официальном клиенте — канал согласования фич (NetShield и т.п.) и.policy-репортаж.
Наше решение: **LA не реализуем в MVP**; «туннель поднялся, а данные не идут»
(джейл-подобное состояние) ловит существующий WG TrustGate: handshake ok + данные
не идут = структурный отказ `proton-jailed` → ротация профиля. Минимальный LA-клиент
(статус/лимиты/NAT-PMP) — задел PT6+, только если поле покажет, что Proton начнёт
джейлить credentialless-сессии без LA. Заодно: free-тиру features-set отправлять
нельзя даже дефолтные (ошибка сервера — ваниль localagent_mixin.py:125-131) — если LA
когда-нибудь появится, features не запрашиваем.

### 1.10. Лимиты бесплатного тира

- `MaxConnect: 2` (ProtonNodeCatalog.kt:20-22) — лимит одновременных подключений на
  ключ; наш роутер = одно устройство с одним ключом ⇒ запас есть; общий ключ для всех
  пользователей бинаря ЗАПРЕЩЁН красной линией;
- `MaxTier: 0` из `GET /vpn/v2` — определяет фильтр серверов;
- полоса/длительность сессии — ограничений в коде референсов нет;
- reason-коды LA, которые важно знать заранее: 86101 cert expired, 86110-86115
  max sessions, 86100 guest session (существует, ванилью не обрабатывается).

---

## 2. Bootstrap-устойчивость (стек эскалации)

Живой факт Nova (generator-скрипт, P1/P3): из РФ `vpn-api.proton.me` закрыт на
транспортном уровне (имя резолвится, ICMP отвечает, TCP 443 не открывается), а на
запасных маршрутах Proton подвисает именно `/vpn/logicals` (отдаёт 8-21 КБ и обрывается).
Поэтому лестница обязательна, порядок эскалации (каждая ступень = полный цикл
регистрации до списка узлов):

1. **Direct**: `vpn-api.proton.me` → `api.protonvpn.ch` (различать «не достучались»
   от «ответили ошибкой» — на запасной маршрут уходим только в первом случае,
   ProtonApi.kt:95-100);
2. **DoH-зеркала Proton** (штатный обход самого Proton): TXT-запись
   `d<Base32RFC4648(хост)>.protonpro.xyz` через DoH-цепочку `dns.google/resolve` →
   `cloudflare-dns.com/dns-query` → `dns11.quad9.net/dns-query`
   (`Accept: application/dns-json`); кандидаты «имена раньше адресов»; запрос
   **напрямую по IP с заголовком Host** (обход SNI-блокировки), подлинность —
   SPKI-пиннингом, не цепочкой: у зеркал самоподписанный сертификат
   `CN=*.demo-wathever.net`, 4 опубликованных пина (ProtonDoh.kt:36-49):
   `EU6TS9MO0L/GsDHvVc9D5fChYLNy5JdGYpJw0ccgetM=`, `iKPIHPnDNqdkvOnTClQ8zQAIKG0XavaPkcEo0LBAABA=`,
   `MSlVrBCdL0hKyczvgYVSRNm88RicyY04Q2y5qrBt0xA=`, `C2UxW0T1Ckl9s+8cXfjXxlEqwAfPM4HiW2y3UdtBeCw=`;
   плюс 6 основных пинов Proton (NetworkConstants.kt:24-35) — берём все 10 в seed
   pin-store;
3. **Bootstrap-through-carrier** (домашний паттерн E-OPERA §2/E-FXVPN §5): вся
   контрольная плоскость через активный базовый туннель (MASQUE/WG) — у Nova для этого
   «туннель поднимается, чтобы достучаться до API Proton» (SettingsActivity
   PROTON_TUNNEL_WAIT), у нас носитель уже есть;
4. **Offline-актив**: встроенный `proton_nodes.json` (список не зависит от API; НО
   регистрация ключа всё ещё требует API — поэтому актив = «туннель поднимется на
   существующем ключе и сохранённых узлах», а не полный bootstrap с нуля);
5. Ручной прокси-кандидат из конфига (аналог api-proxy Opera; BYeDPI/собственный
   reverse-прокси Next'а — вне скопа, документируем как опцию).

TOFU-дисциплина (домашний паттерн opera/pin.go): pin-store коммитит SPKI при первом
успешном контакте, seed = 10 известных пинов; расхождение =
`proton-api-pin-mismatch` + fail-closed (переход на следующую ступень, никогда молча).

---

## 3. Обфускация и маскировка (требование владельца: «по примеру awg warp»)

### 3.1. Механика AWG v3 — что безопасно против vanilla-пира (по vendored исходнику)

Верифицировано по `src/vendor/github.com/amnezia-vpn/amneziawg-go/v3`:

- **I1–I5 (ipackets)**: произвольные датаграммы отправляются ПЕРЕД рукопожатием
  (send.go:146-156: sendBuffer = ipackets + junkPackets + initiation). Vanilla-пир их
  молча отбрасывает ⇒ безопасно. DPI видит первым пакетом потока то, что мы положим в I1.
- **Jc/Jmin/Jmax**: мусорные датаграммы случайной длины [jmin..jmax] вперёд
  рукопожатия (send.go:147) — та же безопасность «лишние датаграммы».
- **S1–S4 (paddings)**: случайные байты ВПЕРЕДИ реального сообщения
  (send.go:162-168: buf = [padding][packet]) — сдвигает контент, vanilla-пир НЕ
  распарсит ⇒ против Proton ЗАПРЕЩЕНО, всегда 0.
- **H1–H4 (headers)**: диапазоны, из которых ПИШЕТСЯ поле типа сообщения
  (send.go:606: `PutUint32(fieldType, headers.transport.PickOne())`), приём — XOR с
  typeHash (нули без header_protection_key ⇒ identity) и проверка принадлежности
  диапазону (receive.go:604-660). Дефолты устройства (device.go:344-351) —
  синглтоны [1,1]/[2,2]/[3,3]/[4,4] = **стандартные типы WG** ⇒ не задавая H вообще,
  получаем провод-стандартный заголовок. Nova пишет H1=1..H4=4 явно (защитный пиннинг
  дефолтов); наш Profile просто НЕ эмитит h1-h4 — и проходит существующий инвариант
  `VanillaSafe()` (validate.go:211-214) без правок валидатора.
- **header_protection_key**: XOR-шифрование заголовка — ломает vanilla ⇒ никогда.

Итоговая рамка: обфускация ТОЛЬКО «спереди потока» (I1 + Jc), сам WG-пакетник остаётся
эталонным. Это ровно семантика cf-warp-профиилей E-WG, поэтому весь существующий
механизм (каталог → валидатор VanillaSafe → IpcSet-whitelist-рендер) применим как есть.

### 3.2. Каталог профилей TargetProton

Новый `ProfileTarget` рядом с `TargetCfWarp` (profiles.go:43-50) — `TargetProton =
"proton"` с тем же инвариантом vanilla-safe (Build() отклоняет не-vanilla-safe).
Профили (значения Jc/Jmin/Jmax = дефолты сайта Amnezia, живьём проверены владельцем
Nova; I1-семейство — наша лестница):

```yaml
catalog_version: 2            # +1 к существующему
profiles:
  - id: proton-quic            # PREFERRED — живой референс Nova
    target: proton
    ports: [443, 88, 1224, 51820, 500, 4500]
    client_side: { jc: 3, jmin: 1, jmax: 3 }   # дефолты сайта Amnezia
    init_packets:
      i1: "<quic-initial sni=<from pool>>"     # генератор §3.3, 1250 Б
  - id: vanilla-off            # чистый WG-пир (последняя ступень лестницы)
    target: proton
  - id: proton-sip             # SIP-мимикрия (паттерн warp-семян Nova)
    init_packets:
      i1: "<b 0x494e56...>"    # INVITE, 348 Б
      i2: "<b 0x534950...>"    # SIP/2.0, 245 Б
  - id: proton-crlf            # переиспользуем crlf-light каталога (target cf-warp → добавить proton)
```

Существующие `quic-a/quic-b/sip-invite/crlf-*` не трогаем (они для CF-краёв);
Proton-семейство — отдельные записи с target=proton. MTU: 1420 (Nova, живьём);
SO_MARK/SO_BINDTODEVICE — через существующие SocketOptions как у прочих WG-сессий.

### 3.3. I1-генератор: настоящий QUIC Initial

Порт ProtonQuicInitial.kt (Nova) на Go, ~150 строк, ноль новых зависимостей
(x/crypto/hkdf + stdlib AES-GCM уже vendored):

1. DCID — 8 случайных байт (однобайтовый DCID — сам по себе примета,
   ProtonQuicInitial.kt:102);
2. ClientHello — минимальный: legacy_version 0x0303, 32 случайных байта random,
   session_id/ciphers/compression пустые, единственное расширение `server_name`
   (type 0x0000) с SNI из пула §3.4;
3. CRYPTO-фрейм (type 0x06, offset varInt(0));
4. набивка до **1250 Б** (RFC 9000 §14.1 требует ≥1200; первая версия Nova без
   набивки «выглядела мусором, который любой разборщик отбрасывает» — ProtonQuicInitial.kt:90-98);
5. заголовок: long header `0xC0|(pkn_size-1)`, версия `00 00 00 01` (QUIC v1),
   DCIL=8, пустые SCID/token, varInt-length, PKN 1 байт;
6. ключи RFC 9001: `initialSecret = HMAC-SHA256(QUIC_SALT, DCID)` (соль
   `38 76 2c f7 f5 59 34 b3 4d 17 9a e6 a4 c8 0c ad cc bb 7f 0a`), затем
   HKDF-Expand-Label `client in` → `quic key`(16)/`quic iv`(12)/`quic hp`(16);
7. шифрование AES-128-GCM (nonce = iv ⊕ pkn, AAD = заголовок), защита заголовка
   AES-ECB(hp, sample) + XOR маски;
8. вывод `<b 0x<hex>>` — грамматика amneziawg-go (уже есть парсер chain.go:59-140).

Тестовый вектор: первый байт `&0xC0==0xC0`, байты 2-9 = версия v1, байт 10 = 08
(ProtonHandshakeVectorTest.kt:71-73) + golden-блоб с фиксированным DCID/SNI/random
(детерминизм — crypto/rand заменяем интерфейсом).

### 3.4. SNI-пул и фоновая адаптация

Пул маскировочных имён — актив `white_sni.txt` в бинаре (embed): стартовый набор —
90 live-tested имён Nova (`assets/white.sni`: gosuslugi/sber/vtb/ozon/nspk/...),
формат — по имени на строку. Правила: (а) имя не должно быть Proton-доменом;
(б) ротация — случайный выбор на каждый выпуск профиля; (в) конфиг-override
`obfuscation.sni_pool` заменяет пул целиком (свои имена владельца). Фоновая адаптация
I1 (паттерн AwgI1Adaptation, Nova): когда профиль в degraded-качестве (TrustGate
провален/ротация) — перевыпуск I1 со следующим именем пула; шаг не чаще 30 минут,
только деградировавшие профили, рабочий профиль не трогаем.

### 3.5. Seek-лестница (переиспользование Seeker'а)

Существующий `Seeker` (seek.go:174,286) работает как есть — он параметризован
`Target ProfileTarget`, `Candidates []netip.AddrPort`, `LadderIDs []string`.
Для Proton:

- кандидаты: узлы выбранной локации (§5) × порты (round-robin); гейт
  «только из каталога» расширяется: Proton-каталог = узлы кэша/актива (InCatalog для
  Proton = принадлежность текущему списку узлов, не CF-диапазонам);
- лестница: `[last_good → proton-quic → vanilla-off → proton-sip → proton-crlf]`;
- критерий победителя — существующий: handshake + DATA GATE (2 DNS RTT) за бюджет;
  «handshake ok + tx растёт + rx нет» = сигнатура version-mismatch → следующий
  профиль (для Proton-семантика: «обфускация не та»);
- `LastGoodStore` персистит пару {endpoint, profile} — старт следующего раза с неё.

Замер кандидатов (превентивный, паттерн Nova): до установления сессии — легаси-проба
«I1+Jc+рукопожатие» чистым сокетом (порт ProtonCrypto-подхода: свой Noise-IK
initiation ~150 строк на blake2s/chacha20poly1305 — x/crypto уже vendored) ИЛИ
дёшево: только UDP-liveness (тип 2/3 в ответе). Решение MVP: без превентивного замера
— Seeker сам мериет полным рукопожатием с бюджетом 5 с/кандидат; превентивный RTT-замер
в отдельный этап PT6+ (ускорение выбора внутри локации).

---

## 4. Identity и хранилище

Новый слот по канону четырёх существующих (warp/wg/opera/fxvpn):

```
/opt/etc/b4/proton/identity.json       # 0600, tmp+fsync+rename, *.corrupt
/opt/etc/b4/proton/serverlist.json     # кэш списка узлов (ServerlistCache-паттерн)
/opt/etc/b4/proton/pins.json           # TOFU SPKI pin-store (seed 10 пинов)
```

`Identity` (format=1): `seed` (b64, 32 Б — ЕДИНСТВЕННЫЙ секрет; wg-приватник всегда
выводится на лету), `device_profile` (выдуманный кадр §1.3 — стабилен между
перерегистрациями), `uid`, `access_token`, `refresh_token`, `cert_expires_at`,
`cert_refresh_at` (unix sec), `registered_pubkey_pem`, `vpn_ipv4/ipv6/dns`
(опционально из ответа), `created_at/updated_at`. `Validate()`: seed 32 байта,
ed25519-публичник выводится и сверяется с `registered_pubkey_pem`, пере-вывод
x25519-приватника. `Redacted()`: токены/seed → `[redacted]`, наружу только
`pubkey_prefix(12)`, `cert_expires_at`, таймстемпы. Регистрация ключа — не чаще
раза на загрузку (урок Opera §4: «шум регистраций = риск бана»; re-issue того же
ключа дешёв — но тоже по явной надобности, не по циклу).

---

## 5. Локации (требование владельца «иметь возможность выбирать локацию»)

Модель — fxvpn-эталон end-to-end (config → resolve → API → GUI):

- Конфиг: `proton.location { mode: auto|country|host, country: "NL", host: "" }`;
- `auto` → все free-узлы, ранжирование по Load/Score из живого списка (или порядок
  актива при офлайне); `country` → узлы страны (валидация против кэша); `host` →
  точный узел (валидация InCatalog);
- PUT `/api/proton/location` → ValidateLocation (против кэша) → persist в b4.json →
  рестарт сессии с новой локацией (restartGuard применяется);
- exit-верификация: после DATA GATE — сквозная проба страны выхода (как fxvpn
  verifyExit): несовпадение = `proton_exit_mismatch` + пере-выбор узла внутри локации;
- очередь профилей: кандидаты локации в порядке Load↑ (живой) / интерливинг (актив),
  порты round-robin, ротация при N=2 подряд неудачах узла (паттерн Next IpRotationSelector:
  пул 5 наименее загруженных, случайный выбор; у нас проще — очередь + страйки).

---

## 6. Здоровье и жизненный цикл

Переиспользуем всё существующее, добавляя Proton-специфику:

- **TrustGate** (trustgate.go:91): 2 DNS RTT через туннель — готов; джейл-детект:
  handshake ok + гейт провален ×2 = `proton-jailed` → ротация профиля;
- **rx-stall watchdog** (watchdog.go:96): как есть (дефолты RXIdle 10 с /
  stall-окно 120 с);
- **restartGuard**: ≤6/час + cooldown 300 с (fxvpservice/service.go:73-113 канон);
- **Цикл обновления** (supervisor tick 30 с + timestamp-планировщик 10 с против
  clock-jump — ванильный scheduler-паттерн):
  - keep-alive сессии: `GET /core/v4/users` раз в 12 ч (Next SessionRefreshWorker);
  - refresh сессии: по 401 (force, debounce 60 с) + раз в 7 дней профилактически;
  - сертификат: при `now > cert_refresh_at` (серверский RefreshTime минус маржа
    30 дней для persistent) → re-issue того же ключа; WG-туннель НЕ рвётся
    (ключ производен от seed, §1.5); 401 на re-issue → сначала refresh сессии;
  - список узлов: TTL 3 ч ± 22% (полный) / 15 мин ± 22% (loads), 304-семантика,
    X-PM-netzone;
  - бэкофф ошибок: `1·2^n·(1±0.22)`, капы как в ванили.
- **Состояния**: idle → ntp-wait → registering → node-select → seeking →
  trust-gate → established → (renewing | rotating | backoff) — расширение
  SessionState-канвы; running/listening раздельно (listening = established).
- **Воскрешение после ребута**: гейт — `system.proton.enabled` (канон §2 хвостов WG:
  autostart = персистентный флаг конфига).

---

## 7. Интеграция в движок

- **Сервис**: `src/protonservice` (новый) — сборка по канону fxvpservice: Build (не
  стартует) → Start/Stop → Status/Locations/SetLocation/ValidateLocation/RestartNow;
  `Options{Carrier DialFunc}` — bootstrap-through-carrier §2;
- **Дата-плоскость**: `src/transport/wg.Session` как есть — `SessionConfig{Ident
  *wg.Identity, Profile, Endpoint, SockOpts, Tunnel, Health, MaxGenerations:1}`;
  Identity Proton-проекция: `wg_private_key` = вывод из seed, `wg_peer_public_key`
  = ключ узла, `cf_warp=false` ⇒ ReservedHook=nil (красная линия §11.3 E-WG:
  reserved-байты ТОЛЬКО для CF-пиров — у Proton нули на проводе);
- **Scoped-маршрутизация**: Proton = UDP full-scope носитель; направляемый трафик
  решает существующий scoped-маршрутизатор (как WG-WARP); AllowedIPs пира
  `0.0.0.0/0,::/0`, TUN — существующие режимы (kernel-TUN PBR основной путь роутера,
  netstack для проб/nested);
- **Антипетля**: `vpn-api.proton.me`, `api.protonvpn.ch`, `api.protonmail.ch`,
  `protonpro.xyz`, DoH-резолверы (`dns.google`, `cloudflare-dns.com`,
  `dns11.quad9.net`) — всегда DIRECT/bypass; IP текущего узла — bypass на время
  сессии (урок zapret-gui chain);
- **Wiring в main.go**: if-gate по образцу warp-блока (main.go:621-633) +
  `handler.SetProtonRuntime`; включение — только `system.proton.enabled=true`
  (дефолт false, как у fxvpn/opera — «валидировать и в выключенном состоянии»);
- **Приоритет**: ниже AWG-WARP/MASQUE/H3 во всех деревьях выбора; никогда не
  подменяет явно выбранный транспорт (RegionTransportPolicy-урок Nova I4: «молча
  выйти нельзя — иначе "Proton не подключился" выглядело бы как успех MASQUE»).

---

## 8. Наблюдаемость

Классы отказов (kebab-case — стиль opera/wg; события snake_case — стиль wg_/fxvpn_):

```
proton-api-refused            # 401/403/410 на регистрации — стоп, не ретраить
proton-api-throttled          # 429/5xx — backoff, капы
proton-api-pin-mismatch       # TOFU/SPKI расхождение — fail-closed
proton-captcha-required       # 9001/12087 — структурный отказ + событие владельцу
proton-scope-missing          # Scopes не содержит vpn
proton-session-refresh-failed # refresh 400/401/422 → перерегистрация (кап!)
proton-cert-expired           # нотАфтер прошёл, перевыпуск не удался
proton-no-nodes               # оба источника списка пусты
proton-jailed                 # handshake ok, данные не идут (тrust-gate ×2)
proton-exit-mismatch          # страна выхода ≠ локации
(transport-часть переиспользует wg-handshake-timeout / wg-stall-rx /
 awg-version-mismatch / awg-junk-profile-failed как есть)
```

События: `proton_registered`, `proton_session_refreshed`, `proton_cert_renewed`,
`proton_nodes_refreshed{source}`, `proton_profile_issued`, `proton_established`
(строго после DATA GATE — cutoff-правило камуфляжа), `proton_rotated`,
`proton_location_switched`, `proton_exit_mismatch`.

Метрики (observability/proton.go + экспорт в /metrics): `proton_dial_total{result}`,
`proton_handshake_total{result}`, `proton_profile_seek_total{profile,result}`,
`proton_nodes_source{source=live|asset}`, `proton_cert_valid_until_seconds`,
`proton_registration_total` (zero-tolerance: только boot + ручной reissue),
`proton_api_requests_total{endpoint,result}`, `proton_session_refresh_total{result}`.
Секреты (seed/токены/приватник) не покидают пакет — редац-правило программы;
в Summaries только `pubkey_prefix(12 hex)`.

---

## 9. Этапы PT1–PT7

| Этап | Содержимое | Верификация |
|---|---|---|
| PT1 | Пакет transport/proton: криптоядро (seed→ed25519 PEM→x25519 clamp), Identity слот 0600/quarantine, FailureClass-набор | golden-векторы против вывода Nova (ProtonHandshakeVectorTest-паттерн); юнит round-trip стора |
| PT2 | API-клиент: 4 шага регистрации + refresh + challenge-кадр + заголовки + пины + DoH-зеркала + bootstrap-through-carrier | фейк-Proton-API стенд (httptest): happy / refuse / throttle / captcha / scope-missing / already-tied / refresh-цепочка / pin-mismatch |
| PT3 | Каталог узлов: v2-логикалы + If-Modified-Since/Last-Modified + X-PM-netzone + loads-TTL + офлайн-актив (embed 50 узлов) + Location resolve/validate | фейк-логикалы (200/304/битый JSON/пустой free-тир); инварианты актива (поля, интерливинг, 4 страны в голове) |
| PT4 | Обфускация: I1 QUIC-генератор + TargetProton + профили каталога + лестница + SNI-пул + адаптация | golden-блоб I1 (фикс. DCID/SNI/rand); валидатор пропускает только vanilla-safe; интероп: AWG↔vanilla-WG genTestPair на профиле proton-quic |
| PT5 | Протон-сессия: сборка transportwg.Session + TrustGate + Seeker + watchdog + restartGuard + renew-циклы (keep-alive/refresh/cert/nodes) + состояния | матрица отказов фейк-edge: silent-drop / stall / джейл (handshake-ok-data-no) / cert-expiry на живой сессии / смена локации |
| PT6 | Интеграция: protonservice + config + HTTP API (status/locations/location/restart/reissue) + observability + main-wiring + антипетля + scoped-routing + ntp-wait гейт | handler-тесты (disabled-shape, валидация location против кэша); wiring-смоук с фейк-рuntimes; ноль горутин при enabled=false |
| PT7 | Финал: vet/test/race, полный ./..., отчёт, обновление NOTICE (аспекты лицензий — ноль новых зависимостей), бриф | полный суит зелёный; счётчики нулевых нарушений |

Оценка: PT1–PT3 ≈ один session-эквивалент, PT4–PT5 ≈ ещё один, PT6–PT7 — половина.
Живой смоук против настоящего Proton — отдельно, с разрешения владельца (правило
«без live-регистраций в тестах»).

---

## 10. Красные линии этапа

1. **Ноль новых зависимостей**: ed25519/AES-GCM — stdlib; curve25519/hkdf/blake2s/
   chacha20poly1305 — x/crypto v0.54.0 уже vendored; amneziawg-go v3 уже vendored.
2. Proton-профили — **только vanilla-safe** (S=0, H не заданы, hp-key пуст): инвариант
   `VanillaSafe()` в Build(); S/H-мутации против Proton-пира = сломанный туннель.
3. Reserved-байты — никогда (`cf_warp=false` ⇒ hook=nil): красная линия §11.3 E-WG.
4. Регистрация устройства — ≤1 на загрузку роутера; refresh вместо перерегистрации;
   никаких регистрационных петель; MaxConnect=2 ⇒ ключ всегда per-device, никаких
   общих ключей в бинаре/активе.
5. Капча/human-verification — структурный отказ `proton-captcha-required` + событие
   владельцу; НЕ автоматизируем (нет WebView на роутере и не должно быть).
6. Секреты (seed/токены/приватник) — только в identity-слоте 0600 атомарно, карантин
   битого, редац во всех логах/сводках; офлайн-актив — только публичные факты
   (server_name/country/city/entry_ip/peer_public_key).
7. TOFU/SPKI-пиннинг всех контрольных хостов обязателен; mismatch = fail-closed.
8. Живые запросы к Proton API из юнит-тестов запрещены — только фейк-стенды; поле —
   отдельно и явно с разрешения владельца.
9. Часы: NTP-wait перед первой регистрацией (notBefore сертификата); локальная
   проверка notBefore/notAfter до принятия сертификата.
10. Приоритет ниже AWG-WARP/MASQUE/H3 везде; никакой молчаливой подмены других
    транспортов и никакой подмены Proton другими (explicit-only в очереди Proton).
11. Не коммитить/не пушить без прямой просьбы владельца (AGENTS.md).

---

## 11. Открытые вопросы (решит поле)

1. Проходимость `vpn-api.proton.me` напрямую из РФ (факт Nova: TCP 443 закрыт) ⇒
   ожидаемо основная дорога — DoH-зеркала + bootstrap-through-carrier; замерить.
2. Реальный состав free-стран для credentialless-сессии (актив: NL/US/CA/NO;
   живой список исторически шире — JP/IT/SE...); обновление актива полем.
3. Фактическая длительность persistent-сертификата для credentialless (Nova
   наблюдала год) — подтвердить первым полем.
4. Терпимость Proton-края к увеличенным Jc (Nova проверила только 3/1/3; лестница
   Medium 10/50/100 — Next-пресет — кандидат на эксперимент).
5. Начнёт ли Proton джеилить credentialless-сессии без local agent (сейчас не
   джеилит — оба мода работают); детектор — proton-jailed, ответ — PT6+ LA-клиент.
6. Поведение зеркал protonpro.xyz на /vpn/logicals (Nova: подвисает) — v2-эндпоинт
   на зеркалах не проверялся никем; наша лестница это переживёт (v1 → v2 → актив).
7. Tor-over-AWG (референс ProtonVPN-Next): в скоп НЕ входит, композиция
   зафиксирована §12 как PT8+ — решение за полем (нужен ли `.onion`-egress).

---

## 12. Tor-over-AWG: зафиксированная будущая композиция (вне PT1–PT7)

Владельческий вопрос по итогам ревью v1. Фиксируем: что это, почему не сейчас,
как ляжет на каркас, если поле попросит. Живой референс — ProtonVPN-Next
(единственный из трёх реализует; в Nova и ванили Tor отсутствует).

### 12.1. Что это (по коду Next)

Tor-клиент живёт **на устройстве**, и все его соединения (directory, guard'ы,
relay-цепочки) едут внутри AWG-туннеля до узла Proton:

```
[apps] ─► scoped-router ─► Tor (3 хопа) ─► destination
                             │
                             └──(весь трафик Tor)──► AWG ─► Proton node ─► Tor network
```

Механика Next (файл:строка):

- Tor — **внешний бинарник**, зашитый в APK как native-либа `libtor.so`
  (app/build.gradle.kts:337; AmneziaVpnManager.kt:927
  `File(nativeLibraryDir, "libtor.so")` → поле `executable_path` конфига);
- sing-box outbound `type: "tor"` (пакет `protocol/tor` ядра amnezia-box) с
  `detour: proton-awg` — Tor-трафик заворачивается в AWG-endpoint
  (AwgBoxConfigGenerator.kt:113, 250-264);
- Tor-процесс: SOCKS5 на приватном unix-сокете `DataDir/socks`
  (`--SocksPort unix:...`, NoAutoSocksPort — патч awgbox-tor-android.patch),
  control-канал опрашивает `status/bootstrap-phase` до `PROGRESS=100`,
  бюджет бутстрапа 90 с, тик 250 мс (waitBootstrap);
- DNS: Tor DNSPort `127.0.0.1:19053`; `.onion` маппится в виртуальный диапазон
  `198.18.0.0/15` и маршрутизируется обратно в tor-outbound (сохранение
  внутренней hostname-карты); UDP режется — Tor TCP-only
  (AwgBoxConfigGenerator.kt:59-61, 206-264, 288-313);
- режим — **глобальный тумблер**: `tunnelOutbound = if (torModeEnabled) "tor"
  else "proton-awg"` — либо весь scoped-трафик через Tor, либо ничего.

Ценность в цензурной среде: прямой Tor в РФ блокируется на нескольких уровнях
(relay-IP, TLS-фингерпринт, directory authorities), Tor-внутри-туннеля не
нуждается в мостах/obfs4 — достижимость всей relay-сети решает носитель. DPI
видит один обфусцированный AWG-поток до Proton; Proton видит шифрованный
Tor-трафик; guard — exit-IP узла Proton; destination — Tor-exit.

### 12.2. Почему НЕ в текущем этапе

1. **Красная линия §10.1 (ноль новых зависимостей) нарушается фундаментально.**
   Tor не собирается из stdlib + vendored x/crypto. Варианты: (а) embed
   настоящего tor-бинарника — C-проект ~3–7 МБ, кросс-сборка под архитектуры
   роутера, сопровождение security-обновлений, torrc/data-dir-менеджмент,
   обновление NOTICE; (б) чистый Go (waytor и класс) — экспериментальные,
   сами авторы запрещают анонимность-чувствительное использование; (в) Arti
   через FFI — Rust-тулчейн в сборке. Любой вариант по объёму ≥ всего PT1–PT7.
2. **Роль не та.** E-PROTON — R-reserve-носитель (UDP full-scope, гео-выход).
   Tor — анонимностный оверлей поверх носителя: TCP-only, без выбора локации,
   медленный. Это **потребитель** резерва, а не ещё один резерв; подмешивание
   второй threat-модели (анонимность vs доступность/маскировка) разрастает
   скоп и поверхность риска.
3. **Производительность.** free-узел Proton + 3 хопа Tor = единицы Мбит/с и
   бутстрап до 90 с (и это на телефонном железе Next); как egress роутера —
   footgun. Осмысленно только как узкий per-scope egress, не как транспорт.
4. **Поверхность атаки и оптика.** tor-процесс в прошивке + Tor через
   credentialless-free — больше ToS-серой зоны и уязвимого кода, чем весь
   остальной дизайн этапа вместе.

### 12.3. Как ляжет на каркас b4x, если поле попросит (PT8+, отдельный этап)

Композиционный хук уже есть — ядро менять не придётся:

- **E-TOR как scoped-egress, не глобальный тумблер** — преимущества перед
  Next: наш scoped-маршрутизатор уже решает per-flow, поэтому Tor получает
  только выбранные scope'ы (`.onion` + явно назначенные владельцем), остальной
  трафик идёт напрямую через Proton; у Next «всё или ничего»;
- **carrier = proton-сессия**: тот же примитив, что bootstrap-through-carrier
  §2, перевёрнутый на всю дата-плоскость — `Options{Carrier DialFunc}` уже в
  интерфейсе сервиса (§7);
- **Tor-runtime-менеджер**: spawn/supervise бинарника, SOCKS5-listener на
  loopback, control-опрос бутстрапа с бюджетом 180 с (роутер слабее телефона),
  data-dir `/opt/etc/b4/tor` 0700, отдельный restartGuard-класс — падение Tor
  НЕ рвёт Proton-сессию;
- **DNS/`.onion`**: виртуальный диапазон + маршрутизация обратно в Tor
  (механика Next 1:1); UDP-scope через Tor запрещается на уровне
  scoped-маршрутизатора — честный отказ, не тихое падение;
- **инвариант непросачивания**: весь Tor-трафик только через carrier; смерть
  Proton-носителя = разрыв Tor-контуров, никакой автоматической утечки в
  прямую сеть (иначе вся затея анонимности ломается одним падением туннеля);
- **приоритет**: Tor-egress никогда не участвует в деревьях выбора
  транспортов — только явное назначение scope'а владельцем.

### 12.4. Условия включения

1. Устойчивая полевая потребность (`.onion`-доступ или анонимность-от-носителя)
   — job-to-be-done владельца, а не «крутая фича из Next».
2. Отдельное решение владельца по зависимости (embed tor / Go-порт / Arti) с
   явным исключением из красной линии §10.1 и обновлением NOTICE.
3. Отдельный этап PT8 со своим acceptance: бутстрап через carrier, инвариант
   «Tor не утекает мимо AWG» (фейк-носитель + счётчики), kill-семантика при
   падении носителя, метрики `tor_bootstrap_seconds` / `tor_circuits_alive`.

До тех пор: композиция зафиксирована здесь, код не пишем, каркас совместим by
design — ни одна правка PT1–PT7 этому не мешает.
