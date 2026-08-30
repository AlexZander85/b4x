# E-PROTON: патч-план для агента-реализатора (v1, 2026-08-30)

Дизайн-документ: `proton-awg-design.md` (обязателен к прочтению до начала —
этот план НЕ повторяет обоснования, только исполнение). Референсные исходники
и исследовательские отчёты — см. §0.2.

Формат плана: этапы PT1–PT7 строго по порядку; каждый этап = файлы (создать/изменить),
интерфейсы/скелеты, тесты, критерий готовности (DoD). Никакого кода «на будущее» —
каждый файл упоминается потому, что нужен этапу.

---

## 0. Дисциплина и входные материалы

### 0.1. Правила репозитория b4x (из AGENTS.md / PROJECT_DIRECTIVES.md — исполнять)

1. Прочитать `AGENTS.md`, `PROJECT_DIRECTIVES.md` (истина: стек, запреты, лестница).
2. Отвечать владельцу по-русски. Не коммитить и не пушить без прямой просьбы.
3. Один слой лестницы на сессию; задача — из `bd ready --json`, если задана.
4. **Живой роутер не трогать**; никаких деплоев в этом этапе — только код+тесты.
5. Тесты: `go vet ./... && go test ./... && go test -race ./...` зелёные; юнит-тесты
   **никогда** не ходят в живой Proton API (только httptest-стенды) — consent rule.
6. Ноль новых зависимостей: `go.mod`/`go.sum`/`vendor/` не меняются. Всё нужное
   vendored: `golang.org/x/crypto v0.54.0` (curve25519, hkdf, blake2s,
   chacha20poly1305), stdlib (crypto/ed25519, crypto/aes, crypto/cipher, crypto/sha512),
   `github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814`.
7. Секреты никогда не логируются; в status/summary — только редац-поля. Файлы секретов:
   0600, tmp+fsync+rename, карантин `*.corrupt`.
8. События/классы/метрики — префикс `proton` (классы kebab-case, события snake_case),
   канон таксономии программы.

### 0.2. Входные материалы (лежат рядом с этим планом)

| Файл | Что даёт |
|---|---|
| `proton-awg-design.md` | проектные решения — ИСТИНА при конфликте с этим планом |
| `research-b4x-arch.md` | карта b4x: какие сущности переиспользовать, file:line |
| `research-nova-proton.md` | первичный протокольный референс (константы, file:line Nova) |
| `research-protonvpn-next.md` | refresh, v2-логикалы, bypass-набор, SPKI-пины |
| `research-proton-vanilla.md` | жизненный цикл сертификата, кэш списка, LA-семантика |

При любом расхождении «план vs дизайн vs исходники» — остановиться и спросить
владельца, не improvising протокол.

### 0.3. Соглашения кода (по образцам fxvpn/opera/wg в b4x)

- Пакеты: `src/transport/proton` (control-plane, без горутин вне эксплицитных Run),
  `src/protonservice` (сборка/супервизия), `src/config`, `src/http/handler`,
  `src/observability`.
- Ошибки: sentinel + классификация (образец `fxvpn/classes.go`), обёртка
  `fmt.Errorf("proton: ...: %w", err)`.
- Время: везде injectable `now func() time.Time` (тесты); rand: injectable
  `io.Reader` (детерминированные golden-тесты).
- HTTP: инжектируемый `*http.Client` (никаких глобальных клиентов); пины — на
  уровне `http.Transport.DialTLSContext`/VerifyConnection (образец opera/pin.go).

---

## 1. Карта файлов

### 1.1. Создать

```
src/transport/proton/
  api.go            # клиент: 4 шага регистрации + refresh + логикалы v2/v1 + clientconfig
  challenge.go      # device-profile (выдуманный) + challenge-кадр
  crypto.go         # seed → ed25519 PEM → x25519 clamp; вывод WG-ключей
  doh.go            # DoH-резолверы + TXT-зеркала protonpro.xyz
  pins.go           # SPKI pin-store: seed 10 пинов + TOFU
  classes.go        # FailureClass + sentinel errors + Classify()
  identity.go       # Identity + IdentityStore (0600/quarantine/redacted)
  serverlist.go     # ServerlistCache: v2 + If-Modified-Since + loads-TTL + fallback на актив
  asset.go          # embed proton_nodes.json + парс + инварианты
  asset_test.go     # инварианты актива (поля/интерливинг/4 страны в голове)
  nodes.go          # Node/Candidate + free-фильтр + очередь профилей локации
  quici1.go         # генератор QUIC Initial (порт ProtonQuicInitial.kt)
  quici1_test.go    # golden-векторы (фикс. DCID/SNI/rand)
  profile.go        # ProtonProfile {Node, Port, ProfileID, I1} + сериализация
  api_test.go       # фейк-API стенд: все сценарии §4
  serverlist_test.go
  identity_test.go
  crypto_test.go
  assets/proton_nodes.json   # 50 узлов (копия актива Nova v1.31 — публичные факты)
  assets/white_sni.txt       # SNI-пул (90 имён из Nova white.sni)

src/protonservice/
  service.go        # Runtime: Build/Start/Stop/Status/Locations/SetLocation/Reissue
  service_test.go
  metrics.go        # экспорт метрик (observability-паттерн fxvpservice/metrics.go)

src/config/proton.go           # ProtonConfig + дефолты + Effective*()
src/observability/proton.go    # MetricProton* константы
src/http/handler/proton.go     # RegisterProtonApi + swagger-формы
```

### 1.2. Изменить (минимальные хирургические правки)

| Файл | Правка |
|---|---|
| `src/transport/wg/profiles.go` | + `TargetProton ProfileTarget = "proton"`; + 4 шаблона в `defaultCatalog()` (proton-quic/vanilla-off-для-proton/proton-sip/proton-crlf); + порядок лестницы `protonLadderOrder` (образец `cfWarpLadderOrder` profiles.go:193-195) |
| `src/transport/wg/seek.go` | гейт кандидатов: `InWGCatalog` → параметризовать «каталог пира» (новый интерфейс `CandidateSource`, существующее поведение CF не меняется) |
| `src/config/types.go` | + `Proton ProtonConfig` в `SystemConfig` (после FxVPN, types.go:326-343) |
| `src/config/validation.go` | + `validateProton` (выполнять и при enabled=false — канон validation.go:360) |
| `src/config/defaults.go` | дефолт путей при пустых значениях (в Build сервиса, как fxvpn) |
| `src/http/handler/common.go` | + `api.RegisterProtonApi()` в RegisterEndpoints (common.go:169-208) |
| `src/main.go` | + proton-блок if-gate по образцу warp (main.go:621-633) + `handler.SetProtonRuntime` + graceful stop |
| `src/http/handler/tests` | + proton-кейсы disabled-shape |

NE трогать: `confbridge.go` (whitelist-рендер уже умеет всё нужное), `validate.go`
(VanillaSafe уже пропускает профиль без S/H — verificated design §3.1),
`identity.go` transportwg (ReservedHook=nil при cf_warp=false уже работает),
`trustgate.go`/`watchdog.go`/`session.go` transportwg (переиспользуются как есть).

---

## 2. PT1 — криптоядро и identity

### 2.1. `src/transport/proton/crypto.go`

```go
package proton

// DeriveKeyPair выводит всё из одного seed (32 Б). Секрет на диске — только seed.
// Ed25519-pub → PEM SPKI (префикс MCowBQYDK2VwAyEA = 12 байт DER + 32 байта ключа).
// WG-priv = clamp(SHA-512(seed)[0:32]) — конверсия ed25519→x25519
// (crypto_sign_ed25519_sk_to_curve25519); WG-pub = curve25519.X25519(priv, basepoint).
type KeyPair struct {
    Seed         [32]byte // never leaves this package / identity store
    Ed25519PubPEM string  // → ClientPublicKey
    WGPrivateKeyB64 string // → wg config private_key
    WGPubKeyB64     string // диагностика
}
func DeriveKeyPair(seed [32]byte) KeyPair
func RandomSeed(r io.Reader) ([32]byte, error)
```

Реализация: `ed25519.NewKeyFromSeed` → `ed25519.PublicKey`; PEM руками
(`MCowBQYDK2VwAyEA` + base64, обёртки `-----BEGIN PUBLIC KEY-----`); WG-ключ —
`sha512.Sum512(seed[:])` → clamp `b[0]&=248; b[31]&=127; b[31]|=64` → base64.
Golden-тест: вектор из Nova ProtonCrypto.kt (первые 12 hex байт PEM-тела, вывод
x25519 по фикс. seed).

### 2.2. `src/transport/proton/identity.go`

Канон четырёх существующих сторов (wg/identity.go:206-288 — tmp `.proton-*.tmp`,
chmod 0600, fsync, rename, `Validate()`, `Quarantine()`):

```go
type Identity struct {
    Format            int    `json:"format"` // 1
    SeedB64           string `json:"seed"`           // СЕКРЕТ
    DeviceProfile     DeviceProfile `json:"device_profile"`
    UID               string `json:"uid,omitempty"`
    AccessToken       string `json:"access_token,omitempty"`   // СЕКРЕТ
    RefreshToken      string `json:"refresh_token,omitempty"`  // СЕКРЕТ
    RegisteredPubPEM  string `json:"registered_pub_pem"`
    CertExpiresAt     int64  `json:"cert_expires_at,omitempty"` // unix sec
    CertRefreshAt     int64  `json:"cert_refresh_at,omitempty"`
    VPNIv4, VPNIv6    string `json:"vpn_ipv4,omitempty", ...`
    VPNDNS            []string `json:"vpn_dns,omitempty"`
    CreatedAt, UpdatedAt int64
}
func (id *Identity) Validate() error   // seed=32Б; DeriveKeyPair(seed).Ed25519PubPEM == RegisteredPubPEM
func (id *Identity) Redacted() RedactedIdentity // токены/seed → "[redacted]"
type IdentityStore struct{ Path string } // Load/Save/Quarantine; sentinel Errs Absent/Corrupt/Invalid
```

### 2.3. `src/transport/proton/challenge.go`

DeviceProfile (фиксируется один раз, персистится): поля кадра Nova
(ProtonProfileStore.kt:296-324) — model/androidVersion/language/regionCode/timezone/
timezoneOffset/storageBytes/deviceNameHash/keyboards; генерация из injectable rand
(5 моделей × 5 локалей × 3 storage; `deviceNameHash ∈ [1e12, 9e15)`).
`func (p DeviceProfile) ChallengeFrame() map[string]any` — кадр §1.3 дизайна
(включая `v: "2.0.7"`, `isJailbreak: false`, `preferredContentSize: "1.0"`,
`isDarkmodeOn: true`). Тест: стабильность вывода (один профиль → один кадр),
соответствие схеме.

### 2.4. DoD PT1

`go test ./src/transport/proton/...` зелёный: crypto golden-векторы; identity
round-trip + карантин битого + редац; challenge-кадр стабилен. `go vet` чист.

---

## 3. PT2 — API-клиент и bootstrap-стек

### 3.1. `src/transport/proton/api.go`

```go
type Endpoints struct{ // лестница хостов, design §1.1/§2
    Direct  []string // ["https://vpn-api.proton.me", "https://api.protonvpn.ch"]
    MirrorHosts []string // динамически из DoH
}
type Client struct {
    HTTP     *http.Client    // инжект; nil => http.DefaultClient c pin-верификатором
    Pins     *PinStore
    DoH      *DoHResolver
    Carrier  DialFunc        // bootstrap-through-carrier (опц.)
    Now      func() time.Time
    UserAgent, AppVersion, APIVersion string // дефолты Nova, override из конфига
}
// Шаги:
func (c *Client) CreateSession(ctx, frame) (*Session, error)          // POST /auth/v4/sessions {}
func (c *Client) Credentialless(ctx, carrier *Session, frame) (*Session, error)
    // POST /auth/v4/credentialless; проверка Scopes∋"vpn"; retry-1 на "already tied"
func (c *Client) Refresh(ctx, id *Identity) (*Session, error)
    // POST /auth/v4/refresh {UID,RefreshToken,ResponseType:"token",GrantType:"refresh_token",RedirectURI:"http://protonmail.ch"}, БЕЗ Authorization
func (c *Client) FetchLogicals(ctx, sess, cacheHint) (*LogicalsResponse, error)
    // v2: /vpn/v2/logicals?WithEntriesForProtocols=wireguard&WithState=true
    //     + If-Modified-Since + X-PM-netzone; 304 => nil,nil (кэш валиден)
    // v1 fallback: /vpn/logicals?Tier=0 (ступень ниже)
func (c *Client) RegisterClientKey(ctx, sess, pubPEM) (*CertResponse, error)
    // POST /vpn/v1/certificate {ClientPublicKey, Mode:"persistent", DeviceName:"Nova"}
func (c *Client) UserKeepAlive(ctx, sess) error  // GET /core/v4/users
```

Заголовки (каждый запрос): `x-pm-appversion` (дефолт `android-vpn@5.4.44.0`),
`x-pm-apiversion` (дефолт `3`), `Accept: application/vnd.protonmail.v1+json`,
`User-Agent` (дефолт `ProtonVPN/5.4.44.0 (Android 13; Pixel 7)`); аутентифицированные:
`x-pm-uid`, `Authorization: Bearer`. Тело — JSON; ответы Proton: `{Code, Error?,
...}` — Code!=1000 => классификация.

`Classify(status int, code int, body string) FailureClass`:
401/403/410 → `proton-api-refused`; 429/5xx → `proton-api-throttled` (уважать
Retry-After, кап 30 с — канон enrollment.go:88-102); code 9001/12087 →
`proton-captcha-required`; ответ без scope vpn → `proton-scope-missing`;
"already tied" → sentinel (клиент сам делает retry-1, наружу не отдаёт).

Порядок обхода хостов (design §2): direct-хосты → DoH-зеркала (direct-IP + Host) →
carrier. Различать транспортный отказ (dial/TLS timeout) от HTTP-ошибки: на
следующую ступень — только транспортный.

### 3.2. `src/transport/proton/doh.go`

DoH-резолвер: GET `{resolver}/resolve?name=...&type=TXT` c
`Accept: application/dns-json`; цепочка `https://dns.google/resolve` →
`https://cloudflare-dns.com/dns-query` → `https://dns11.quad9.net/dns-query`.
Зеркала: имя `d<Base32RFC4648-без-паддинга(хост)>.protonpro.xyz`; ответ TXT →
кандидаты (имена раньше адресов). Base32 — алфавит RFC 4648
`ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`. Тест: golden base32 для `vpn-api.proton.me`
(сверить с DohClient.kt:59-61), парс TXT-ответов (кавычки/точки).

### 3.3. `src/transport/proton/pins.go`

PinStore (канон opera/pin.go): seed-пины = 6 основных Proton
(NetworkConstants.kt:24-35: `drtmcR2kFkM8qJClsuWgUzxgBkePfRCkRpqUesyDmeE=`,
`YRGlaY0jyJ4Jw2/4M8FIftwbDIQfh8Sdro96CeEel54=`,
`AfMENBVvOS8MnISprtvyPsjKlPooqh8nMB/pvCrpJpw=`,
`CT56BhOTmj5ZIPgb/xD5mH8rY3BLo/MlhP7oPyJUEDo=`,
`35Dx28/uzN3LeltkCBQ8RHK0tlNSa2kCpCRGNp34Gxc=`,
`qYIukVc63DEITct8sFT7ebIq5qsWmuscaIKeJx+5J5A=`)
+ 4 альтернативных (design §2). Поведение: хост из known-списка → сверка с seed-пинами
(любой из списка — Ok; эволюция пинов без релиза); незнакомый (зеркало) → TOFU
(первое касание коммитит, расхождение = `proton-api-pin-mismatch` fail-closed).
SPKI = SHA-256 SubjectPublicKeyInfo leaf-сертификата. Файл `pins.json` — sibling
identity (атомарно, 0644 допустимо — не секреты).

### 3.4. Фейк-API стенд и тесты (`api_test.go`)

httptest-серверы с таблицей сценариев (§5 матрица): happy-path полный цикл
(4 вызова, проверка тел/заголовков: Bearer шага 1 в шаге 2, Scopes, Mode persistent),
already-tied retry-1, captcha 9001, scope-missing, refused 401, throttled 429 +
Retry-After, refresh success/rotation/force-logout-400, pin-mismatch (подмена серта),
зеркальный маршрут (direct-IP + Host), 304 логикалов. Ноль внешних вызовов
(в тестах Client.HTTP всегда указывает на httptest).

### 3.5. DoD PT2

Все сценарии матрицы §5 зелёные; счётчик «регистраций на тест-прогон» инвариантен
(например, happy-сценарий = ровно 1 createSession + 1 credentialless).

---

## 4. PT3 — каталог узлов и локации

### 4.1. `src/transport/proton/serverlist.go` + `asset.go` + `nodes.go`

ServerlistCache (канон fxvpn/serverlist.go: TTL/Last-Modified/stale-but-present):
- `Get(ctx)`: fresh-в-памяти → API (v2 c If-Modified-Since; 304 → освежить метку) →
  при сетевой ошибке с кэшем → stale-but-present (лог + событие) → при полном
  отсутствии кэша → встроенный актив;
- TTL: полный 3 ч ± 22%, loads 15 мин ± 22% (эффективная = min); `X-PM-netzone` =
  текущий публичный IP/24 (получаем первый раз при старте, не в каждом запросе);
- парс: `LogicalServers[] → free: Tier==0 && Status==1`; physical: `Status==1 &&
  EntryIP!="" && X25519PublicKey!=""`; из физического берём ОДИН (Nova-правило
  «физические узлы одного логического делят и адрес, и ключ — берём один»);
- персист `serverlist.json` (atomic, sibling identity; битый → карантин + актив).

Актив `assets/proton_nodes.json`: embed, копия Nova v1.31 (50 узлов, схема — ровно
5 полей). Инвариант-тест (образец ProtonNodesAssetTest.kt): поля только из
allowed-набора; ≥40 узлов; ≥3 стран; первые 4 узла — разные страны; ноль ключей
аккаунта/приватников (grep-подобная проверка значений полей).

```go
type Node struct{ Name, Country, City, EntryIP, PeerPubKey string; Load int; Score float64 }
type Queue struct{ ... } // очередь кандидатов локации: Load↑ → интерливинг по странам (актив)
func (q *Queue) Candidates(loc Location) []Candidate // Candidate{Node, Port}
// порты round-robin: [443,88,1224,51820,500,4500] (конфиг-override одним значением)
```

Location (config): `{Mode: auto|country|host, Country, Host}`;
`ValidateLocation(loc, cache)` — режим-специфичные required + InCatalog-проверка
(канон fxvpservice/service.go:595-640).

### 4.2. DoD PT3

Фейк-логикалы: 200 с full-набором → кэш; 304 → переиспользование; пустой free-тир →
`proton-no-nodes`; битый JSON → карантин + актив; TTL-истечение → рефреш; offline с
кэшем → stale-but-present; offline без кэша → актив; очередь: интерливинг стран,
порты round-robin, выборка по country/host.

---

## 5. PT4 — обфускация: TargetProton, I1-генератор, лестница

### 5.1. `src/transport/wg/profiles.go` — правки

```go
const (
    TargetProton ProfileTarget = "proton" // vanilla WireGuard peer (Proton free edge)
)
// В defaultCatalog() добавить (в конец, после существующих):
//  proton-quic:  {Jc:3, JunkMin:1, JunkMax:3, InitPacket[0]: "<runtime: quic-initial>"}  — см. §5.3
//  proton-vanilla: {}                        // чистый WG
//  proton-sip:   {InitPacket: i1=INVITE 348Б, i2=Trying 245Б}  — константы из warp-семян
//  proton-crlf:  переиспользовать build crlf-light с target=proton (отдельная запись)
// protonLadderOrder = []string{"proton-quic", "proton-vanilla", "proton-sip", "proton-crlf"}
```

Важное: I1 для proton-quic — РАНТАЙМ-значение (генерится под SNI-пул на выпуск
профиля), а шаблон хранит маркер. Реализация: `Profile.InitPacket[0]` заполняется
сервисом перед IpcSet (механика уже есть — Profile строится в рантайме), шаблон
каталога отдаёт пустой I1 + флаг `NeedsI1 bool` в шаблоне (новое поле
`ProfileTemplate.RuntimeI1 bool`); Build() не валидирует пустой I1 у proton-quic
(поправка Validate: пустой InitPacket[0] допустим всегда — vanilla-профили тоже пусты).

### 5.2. `src/transport/proton/quici1.go`

Порт ProtonQuicInitial.kt (дизайн §3.3, 8 пунктов). Входы: `sni string, r io.Reader`.
Выход: `string` в грамматике `<b 0xHEX>`. Константы: `PAD_TO=1250`, `DCID_SIZE=8`,
соль RFC 9001 (20 байт), метки `client in/quic key/quic iv/quic hp`.
Зависимости: `golang.org/x/crypto/hkdf` (уже vendored), `crypto/aes`, `crypto/cipher`.
Тесты: fixed-DCID+SNI+rand → golden hex (первые 64 байта + длина 1250 + структурные
проверки: byte0&0xC0==0xC0, версия 00000001, DCIL=8); пустой SNI → "" (обфускации
нет, вызывающий трактует явно).

### 5.3. `src/transport/proton/profile.go`

```go
type ProtonProfile struct {
    Node      Node
    Port      uint16
    ProfileID string          // "proton-quic" | ...
    I1        string          // hex-chain для InitPacket[0]
    SNI       string          // имя пула, из которого собран I1
    IssuedAt  int64
}
func IssueProfiles(cands []Candidate, ladder []string, sniPool []string,
    r io.Reader, lastGood LastGood) []ProtonProfile
// по кандидату: порт round-robin, profile=лестница[0] (или last_good),
// I1 = quici1.Build(random(sniPool)) для профилей с RuntimeI1
```

SNI-пул: `assets/white_sni.txt` (embed; 90 имён Nova) + конфиг-override
(`obfuscation.sni_pool[]` заменяет при непустоте). Адаптация (design §3.4):
при деградации профиля — перевыпуск I1 со следующим именем, шаг ≥30 мин,
только деградировавшие (реализуется в PT5 health-цикле).

### 5.4. `src/transport/wg/seek.go` — правка гейта кандидатов

Сейчас Seeker отклоняет кандидатов вне WG-каталога CF (seek.go:128-130
AllowOutOfCatalog tests-only). Ввести:

```go
type CandidateSource interface{ Allowed(netip.AddrPort) bool }
// cfWarpSource — существующее поведение (endpoints.go InWGCatalog);
// protonSource — принадлежность текущему списку узлов (func-обёртка над Queue)
```

SeekerConfig: `Source CandidateSource` (nil => прежний CF-каталог — обратная
совместимость). Поведение/бюджеты/страйки не меняются.

### 5.5. DoD PT4

- `go test ./src/transport/wg/...` — новые шаблоны проходят Build+VanillaSafe;
  интероп-тест genTestPair-паттерна: AWG(proton-quic) ↔ vanillaWG — handshake и
  данные (I1/Jc-мусор не мешает vanilla-пиру); AWG(proton-quic без I1) ↔ AWG — не
  требуется (Proton-пир всегда vanilla);
- quici1 golden-тесты;
- Seeker: кандидат из protonSource допускается, вне — отклоняется; существующие
  CF-тесты не изменились (золотой прогон `go test ./src/transport/wg/...` до/после).

---

## 6. PT5 — сессия, здоровье, жизненный цикл

### 6.1. `src/protonservice/service.go`

Канон fxvpservice/service.go (798 строк — структура повторяется, механика своя):

```go
const (
    MaxRestartsPerHour = 6
    RestartCooldown    = 300 * time.Second
    superviseTick      = 30 * time.Second
    certRenewMarginSec = 30 * 24 * 3600 // persistent: за 30 дней
    sessionKeepAlive   = 12 * time.Hour // GET /core/v4/users
    sessionRefreshMaxAge = 7 * 24 * time.Hour
)
type Options struct{ Carrier DialFunc; Now func() time.Time; ExtraEvents func(ev Event) }
type Runtime struct{ /* cfg, client, idStore, listCache, queue, session *wg.Session,
     guard restartGuard, profiles []ProtonProfile, lastGood wg.LastGoodStore, ...*/ }
func Build(cfg *config.Config, opts Options) (*Runtime, error)
func (r *Runtime) Start(ctx) error / Stop() / Status() Status
func (r *Runtime) Locations(ctx) LocationsView
func (r *Runtime) SetLocation(loc) / ValidateLocation(ctx, loc)
func (r *Runtime) RestartNow(ctx) / Reissue(ctx) // ручной перевыпуск ключа/сертификата
```

Супервизорный цикл (tick 30 с + timestamp-планировщик против clock-jump):
1. `ensureIdentity`: identity есть? нет → NTP-wait гейт (см. §6.3) → регистрация
   §1.2 (ОДИН раз на загрузку: atomic flag `registeredThisBoot`);
2. `ensureServerlist`: кэш/актив → очередь профилей локации;
3. `ensureSession`: сессии нет → Seeker(лестница §5, кандидаты локации) →
   победитель → `wg.NewSession(SessionConfig{Ident: protonIdentity→wg.Identity{
   PrivateKey: вывод seed, PeerPublicKey: узел, CFWarp: false}, Profile: победитель,
   Endpoint: node:port, SockOpts, Tunnel, Health, MaxGenerations: 1})` →
   `session.Run` (TrustGate внутри) → established ⇒ listening=true;
4. `renew`: cert (`now > cert_refresh_at - margin` → re-issue того же ключа;
   WG-сессию НЕ рвать); session (keep-alive/refresh по §1.4; 401 → refresh force;
   refresh 400/401/422 → перерегистрация, гейт registeredThisBoot+владелец);
   nodes (TTL кэша);
5. `health`: trust-gate провал ×2 на established → `proton-jailed` → ротация
   профиля (следующий из очереди, страйки узла 2 → cooldown 300 с);
   rx-stall — отдаётся существующему watchdog'у сессии.

restartGuard — копия fxvpservice/service.go:73-113 (окно 1 ч + cooldown).

wg.Identity-проекция: новый хелпер в transport/proton
`func (id *Identity) WGIdentity(node Node) *wg.Identity` —
`{PrivateKey: DeriveKeyPair(seed).WGPrivateKey, PeerPublicKey: node.PeerPubKey,
CFWarp: false}`; AssignedV4/V6 — из identity (если API дал) либо константы
`10.2.0.2/32` + `2a07:b944::2:2/128` (design §1.8). EndpointHint не нужен.

### 6.2. Статусы

```go
type Status struct {
    Enabled, Running, Listening bool
    State string // idle|ntp-wait|registering|node-select|seeking|trust-gate|established|renewing|backoff
    RestartCapHit bool
    Location config.ProtonLocation
    ActiveProfile, ActiveNode, ActivePort, VerifiedExit string
    CertExpiresAt int64; SessionAge time.Duration
    ProfilesIssued, ProfilesLeft int
    LastFailure FailureView
    Events []Event // ring 32
}
```

`verifiedExit` — сквозная проба страны после established (fxvpn verifyExit-паттерн,
service.go:411-434): GET ip-инфо через туннель; mismatch → `proton_exit_mismatch` +
ротация внутри локации.

### 6.3. NTP-wait гейт

Перед ПЕРВОЙ регистрацией: если `cert notBefore`-риск (часы роутера без RTC) —
убедиться, что системное время свежее (b4x-инфраструктура: если в репо есть SNTP/
часовой сервис — использовать его событие; иначе ждать до первого успешного HTTPS-
ответа любого хоста с валидной датой — TLS NotAfter-vs-now уже даёт грубую проверку).
Минимум: `ntp-wait` состояние с таймаутом 120 с, затем попытка регистрации всё равно
(Proton ответит, сертификат не примем если notBefore в будущем — локальная проверка
X.509 перед записью в identity: notBefore > now+5 мин → остаться в ntp-wait).

### 6.4. Тесты PT5

Фейк-edge (существующий стенд-паттерн transportwg): матрица — silent-drop /
handshake-timeout / version-mismatch-сигнатура (tx↑ rx=0) / джейл (handshake ok,
данные нет ×2) / смена локации на живой сессии / cert-expiry при established
(проверить: туннель не рвётся, renew обновил identity) / исчерпание очереди профилей
→ честный статус. Инварианты: рестарты ≤6/час; registration_total за тест = 1 на
«загрузку»; ноль петель (timeout-границы на циклах).

---

## 7. PT6 — конфиг, HTTP API, observability, wiring

### 7.1. `src/config/proton.go`

```go
type ProtonLocation struct{ Mode, Country, Host string } // auto|country|host
type ProtonObfuscation struct {
    Enabled bool        // false => профиль proton-vanilla (чистый WG)
    PreferredProfile string // "" => proton-quic
    SNIPool []string    // override пула актива
    I1Adaptation bool   // фоновая смена SNI у деградировавших
}
type ProtonConfig struct {
    Enabled bool
    IdentityPath string   // дефолт /opt/etc/b4/proton/identity.json
    ServerlistPath string // дефолт .../serverlist.json
    Location ProtonLocation
    Obfuscation ProtonObfuscation
    Port uint16           // 0 => round-robin каталога
    MTU int               // 0 => 1420
    BootstrapThroughCarrier bool
    UserAgent, AppVersion, APIVersion string // "" => дефолты Nova
    MaxRestartsPerHour int // 0 => 6
}
```

`validateProton` (validation.go: канон validateOpera 384-407): mode∈{auto,country,host}
+ режим-специфичные required; пути абсолютные при enabled; SNIPool — валидные
имена хостов (не Proton-домены — проверка суффикс-чёрным списком); порт/MTU диапазоны;
валидировать ВСЕГДА (и при enabled=false).

### 7.2. `src/http/handler/proton.go`

Канон fxvpn.go (RegisterXxxApi + runtime-inject через atomic.Pointer +
swagger-аннотации + disabled-shape):

| Метод/путь | Назначение |
|---|---|
| GET /api/proton/status | Status (truthful disabled shape при выключенном) |
| GET /api/proton/locations | страны→города→узлы из кэша (+load, +free-пометка), fetched_at, source |
| PUT /api/proton/location | {mode,country,host} → ValidateLocation → SetLocation → persist (generic config API) → `go RestartNow` |
| POST /api/proton/restart | ручной рестарт (caps применяются) |
| POST /api/proton/reissue | ручной перевыпуск ключа/сертификата (регистрация по явному действию) |

Body-лимиты `http.MaxBytesReader` 4 KiB; ошибки `writeAPIError` c APIError.

### 7.3. `src/observability/proton.go` + `src/protonservice/metrics.go`

Константы метрик (дизайн §8) + экспорт: `recordDial/recordHandshake/recordSeek/
exportState` по образцу fxvpservice/metrics.go (включая нулевые ряды).

### 7.4. `src/main.go` — wiring

```go
// сразу после warp-блока (main.go:621-633), тем же if-gate-паттерном:
var protonEngine *protonservice.Runtime
if cfgPtr.Load().System.Proton.Enabled {
    rt, err := protonservice.Build(cfgPtr.Load(), protonservice.Options{
        Carrier: baseTunnelDial, // если wiring-хук существует; nil на первом этапе
    })
    // log/started/Start(appCtx) — по образцу warp
}
handler.SetProtonRuntime(protonEngine) // nil-safe
// graceful: в shutdown-цепочку (main.go:675-691) добавить protonEngine.Stop()
```

Ноль горутин при enabled=false (инвариант-тест wiring-смоука).

### 7.5. DoD PT6

Handler-тесты: disabled-shape нулевой; locations из фейк-кэша; PUT location
валидация (неизвестная страна → 400 с кодом); restart соблюдает caps; swagger-формы
в аннотациях. Config: validateProton покрывает кейсы. Observability: метрики
экспортируются (fake registry инкременты). Main: смоук-тест невозможен в юните —
проверка код-ревью + `go build ./...`.

---

## 8. PT7 — финал

1. `cd src && go vet ./... && go test ./... && go test -race ./...` — зелёные
   (включая существующие суиты: регресс transportwg/config/handler запрещён).
2. Полный отчёт: что сделано/отклонено/отложено; счётчики: новые файлы ~20,
   изменённые 7, ноль новых зависимостей (go.mod/go.sum/vendor — diff пуст).
3. NOTICE: аспект — assets/proton_nodes.json и white_sni.txt — публичные факты,
   источник Nova v1.31 (GPL-совместимость: это данные, не код — проверить LICENSE
   Nova и при сомнении перегенерировать актив своими полями с живого списка в поле).
4. Обновить бриф: `.ag/summaries/state_packet.md` — только если владелец скажет.
5. worklog: запись по канону (Task ID, этапы, решения).

---

## 9. Матрица фейк-API сценариев (PT2/PT3 — полная)

| # | Сценарий | Ожидание |
|---|---|---|
| 1 | happy: sessions→credentialless(scopes vpn)→logicals→certificate(год) | Identity сохранён; 1 регистрация; заголовки Bearer/uid корректны |
| 2 | credentialless: первый вызов «already tied» 400 | retry-1 с новой сессией-носителем → успех; наружу не видно |
| 3 | credentialless: scopes без vpn | proton-scope-missing; повтор с новой сессией НЕ выполняется |
| 4 | 401 на любом шаге | proton-api-refused; никакой авто-перерегистрации в этом цикле |
| 5 | 429 + Retry-After | proton-api-throttled; backoff по Retry-After (кап 30 с) |
| 6 | code 9001 | proton-captcha-required; стоп; событие |
| 7 | refresh: success + новый RefreshToken | токены заменены; debounce 60 с |
| 8 | refresh: 400 | перерегистрация (гейт 1/boot); событие |
| 9 | refresh: force после 401 | debounce обойдён |
| 10 | логикалы 304 | кэш переиспользован; fetched_at обновлён |
| 11 | логикалы: только платные Tier>0 | proton-no-nodes → актив |
| 12 | логикалы: битый JSON | карантин файла → актив |
| 13 | все хосты транспортно недоступны, зеркала дают IP | запрос direct-IP + Host; пин зеркала TOFU |
| 14 | подмена сертификата (pin-mismatch) | proton-api-pin-mismatch fail-closed; следующая ступень |
| 15 | certificate без ExpirationTime | proton-api-invalid; ключ НЕ считаться зарегистрированным |
| 16 | logicals v2 недоступен, v1 доступен | вторая ступень отработала; источник=v1 |

## 10. Acceptance-чеклист (весь этап)

- [ ] Ноль новых зависимостей (diff go.mod/go.sum/vendor пуст)
- [ ] Проявление дизайна: vanilla-safe инвариант на proton-профилях (тест Build())
- [ ] cf_warp=false у Proton-identity (тест: ReservedHook == nil)
- [ ] Регистрация ≤1/boot (инвариант тестов PT5)
- [ ] Секреты: редац-тест (Redacted() без seed/токенов), 0600, карантин
- [ ] Актив: только 5 публичных полей (инвариант-тест)
- [ ] Пины: TOFU + seed 10 пинов; mismatch fail-closed (сценарий 14)
- [ ] Живых вызовов Proton в тестах ноль (grep http:// вне httptest — пусто)
- [ ] Классы/события/метрики: префикс proton, канон имён
- [ ] vet/test/race зелёные; регресс существующих суит = 0
- [ ] enabled=false → ноль горутин, honest disabled shape API

## 11. Риски и откаты

| Риск | Митиг/откат |
|---|---|
| Proton поменяет challenge-схему (капча станет обязательной) | класс captcha-required уже честен; override версии клиента в конфиге; живой смоук владельцем |
| Зеркала protonpro.xyz умернут | лестница: direct→зеркала→carrier→актив; каждая ступень независимо тестируема |
| Proton начнёт джеилить без LA | детектор proton-jailed (trust-gate ×2) уже ротирует; задел LA-клиента — отдельный этап, НЕ в этом скопе |
| v2-логикалы на зеркалах виснут (факт Nova для v1) | ступень v1 + актив; таймауты 12/20/30 c (OkHttp-профиль Nova) |
| amneziaawg-go I1-цепочка не примет 1250-байтный блоб | парсер chain.go уже держит 4096-байтные элементы (maxChainElemLen); тест quici1→ParseChain round-trip |
| Актив Nova — лицензионная неоднозначность | актив = данные (публичные факты узлов); при сомнении владельца — регенерация с живого списка в поле, скелет asset_test уже не зависит от источника |
| Роутер без RTC: notBefore | ntp-wait гейт §6.3; поле подтверждает |
