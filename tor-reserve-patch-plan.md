# E-TOR: патч-план для агента-реализатора (v1, 2026-09-15)

Дизайн обязателен к прочтению: `tor-reserve-design.md` (далее «design §N»). При
конфликте дизайн — истина. Этапы **TT1–TT10 строго по порядку**; каждый этап =
файлы (создать/изменить), интерфейсы/скелеты, тесты, критерий готовности (DoD).
Никакого кода «на будущее».

## §0. Дисциплина и входные материалы

### 0.1 Правила (из AGENTS.md / PROJECT_DIRECTIVES.md — исполнять)

- Живой Keenetic: ошибочный деплой роняет YouTube владельца. Не деплоить ничего
  без отдельной команды; этот план — код в ветку + тесты, не поле.
- `go vet ./... && go test ./... && go test -race ./...` зелёные на каждом этапе;
  регресс существующих суит = 0.
- **Consent rule**: живые сетевые запросы из тестов запрещены — только httptest
  и фейк-стенды. Интеграционные тесты с реальным tor — за env-гейтом
  `B4X_TOR_INTEGRATION=<path-to-tor>`, по умолчанию skip с честным t.Skip.
- Зависимости: ровно перечень design §10 (goptlib, lyrebird, snowflake/v2-форк
  tools/snowflake + транзитивы). Любое иное добавление — стоп и вопрос владельцу.
  CGO_ENABLED=0 сохраняется. Сборка mips/mipsle/armv6 должна проходить
  (cross-compile smoke в Makefile остаётся).
- Таксономия: события snake_case (`tor_entry_won`), классы kebab-case
  (`tor-bridge-dead`), метрики с префиксом `tor_`; bounded всё.
- Секретов нет (design §7.1): bridges.json — публичные факты, но AtomicFile-канон
  (tmp+fsync+rename, *.corrupt) обязателен.
- Не коммитить/пушить без прямой просьбы (для этого этапа — уже дана владельцем
  в постановке задачи; работа идёт в отдельной ветке от
  agent/classifier-v2.3-capture-envelope).

### 0.2 Входные материалы

| Файл | Зачем |
|---|---|
| `tor-reserve-design.md` | истина архитектуры |
| `artifacts/tor-research/research-nova-tor.md` | канон PT-прокси, парсера, конвейера мостов, bootstrap-надзора (file:line Nova) |
| `artifacts/tor-research/research-tor-tooling.md` | канон глубокой пробы релея, control-протокола, torrc-валидации, snowflake client/lib |
| `artifacts/tor-research/research-rethink-singbox-rawa.md` | proxybridge-паттерн, failover-паттерны |
| `artifacts/tor-research/research-b4x-reserve-arch.md` | контракт резерва, эталон protonservice, примитивы b4x |
| `proton-awg-patch-plan.md` | формат и дисциплина этапов (образец) |

### 0.3 Соглашения кода

- Пакеты: `src/transport/tor/` (контрольная плоскость), `src/transport/torscan/`
  (сканер релеев — отдельный пакет, ноль зависимостей от тор-рантайма),
  `src/torservice/` (сборка). Инжектируемые `now func() time.Time`, `rand`,
  HTTP-клиенты, диалеры — как в protonservice.
- Sentinel-ошибки: `ErrTorBinaryMissing`, `ErrNotListening`, `ErrTorSelfLoop`,
  `ErrBridgeLineInvalid`, `ErrNoBridgesForEntry`, `ErrBootstrapTimeout`,
  `ErrTransportUnsupported`.
- Никаких горутин при `enabled=false`; все тикеры/серверы гаснут по ctx.

## §1. Карта файлов

### 1.1 Создать

```
src/config/tor.go                     # TorConfig + Effective* + константы
src/transport/tor/bridges.go          # тип Bridge, ParseBridgeLine, Explain, builtin snowflake
src/transport/tor/bridges_store.go    # bridges.json (AtomicFile) + EntryMemory (TTL 30м)
src/transport/tor/collector.go        # конвейер сбора (зеркала-гонка, Moat, пробы, trim)
src/transport/tor/probe.go            # пробы живости per-transport (TCP/WS-101/HTTP-any)
src/transport/tor/egress.go           # egress-диалер: policy, marks, self-loop, DoH, neg-cache
src/transport/tor/egress_bridge.go    # loopback SOCKS5-мост для Socks5Proxy tor
src/transport/tor/ptproxy.go          # loopback SOCKS5 PT-прокси + реестр фабрик
src/transport/tor/snowflake_adapter.go# адаптер snowflake/v2 client/lib (+кэш, крючки)
src/transport/tor/torrc.go            # рендер torrc (чистая функция) + валидация
src/transport/tor/control.go          # минимальный control-клиент (cookie, GETINFO, SIGNAL, SETCONF)
src/transport/tor/process.go          # spawn/supervise/pid+exe/owning-controller
src/transport/tor/bootstrap.go        # progress-вотчер (stall 150с/cap 180/300с, лог-дедуп)
src/transport/tor/events.go           # имена событий + классы (таксономия)
src/torservice/service.go             # Runtime, состояния, supervisor, лестница входов
src/torservice/carrier.go             # reserve.Carrier (Kind tor, TCP-only, self-loop)
src/torservice/status.go              # проекция статуса для API
src/torservice/metrics.go             # observability-экспорт
src/http/handler/tor.go               # SetTorRuntime + API
src/cmd/torctl/main.go                # CLI: status|entry|bridges|scan|test
src/transport/torscan/onionoo.go      # источники+фолбэки+кэш
src/transport/torscan/probe.go        # глубокая проба (TLS random SNI, VERSIONS/NETINFO/CREATE)
src/transport/torscan/scanner.go      # пул+deadline+goal+bandwidth-отбор
tools/snowflake/                      # форк snowflake v2.14.1 (2 патча, design §10)
tools/deps/patches/snowflake-b4x.patch
```

### 1.2 Изменить

| Файл | Правка |
|---|---|
| src/reserve/registry.go | `KindTor Kind = "tor"`, `PriorityTor = 5`, ветка в priorityOf (после proton-ветки) |
| src/packetmark/marks.go | `MarkTorEgress uint32 = 1 << 21` + комментарий (бит 21; 23=opera, 22=fxvpn) |
| src/config/types.go | поле `Tor TorConfig \`json:"tor"\`` в SystemConfig (после Proton) |
| src/config/validation.go | `validateTor(v)` + вызов в Validate() (всегда, не только enabled) |
| src/config/config.go (NewConfig) | дефолт DataPath (zero-value + Effective* допустимо — как proton) |
| src/http/handler/common.go | `api.RegisterTorApi()` |
| src/main.go | wiring-блок после fxvpn (design §9.3); shutdown: `Unregister(KindTor)` ДО `Stop()` |
| src/observability/tor.go (новый файл в существующем пакете) | метрики design §9.7 |
| changelog.md | секция [unreleased] — E-TOR (в конце, TT10) |
| Makefile / NOTICE / THIRD_PARTY_NOTICES | лицензии новых зависимостей (TT9/TT10) |
| src/go.mod, src/go.sum, src/vendor/ | только перечень design §10 (+replace tools/snowflake) |

### 1.3 НЕ трогать

`src/engine/`, `src/classifier/`, `src/action/`, `src/nfq/`, `src/tun/` (ядро
анти-DPI), `src/transport/wg/` (кроме чтения), `src/transport/proton/`,
`src/warpservice/`, `src/protonservice/`, `src/operaservice/`, `src/fxvpservice/`,
`src/socks5/` (только чтение/переиспользование), существующие миграции конфига
(новый ключ tor миграции не требует — design §9.4).

---

## §2. TT1 — конфиг, реестр, таксономия

### 2.1. src/config/tor.go — полный скелет design §9.4 (все структуры + константы
`TorEntryAuto/Webtunnel/Obfs4/Snowflake/Meek/Vanilla/Direct`, `TorEgressNone/Warp/
Masque/H3/Opera/Fxvpn/Proton/Auto`, `TorBaitNone/FirstFlight`, `TorPaddingReduced/
Full`, `TorConfluxAuto/Off/Throughput/Latency`, `TorIsolationNone/PerDestination`)
+ `Effective*()` для каждого 0/""-поля (BinaryPath автодетект: /opt/bin/tor →
/usr/sbin/tor; DataPath → /opt/etc/b4/tor; MaxRestartsPerHour → 6;
BootstrapTimeoutSec → 180; RecollectPauseSec → 300; SnowflakeMax → 2; Country → ru).

### 2.2. registry.go / packetmark / types.go / validation.go — правки §1.2.
`validateTor`: mode/through/bait/padding/conflux/isolation ∈ enum; SnowflakeMax
∈ 1..8; Bridges.Lines — каждая через `tor.ParseBridgeLine` (ошибка с индексом
строки); при enabled — BinaryPath абсолютный и (мягко, warning-статусом) существует;
DataPath абсолютный; CollectURLs — валидные https URL; Entry.RaceWindow ∈ 0..4.

### 2.3. src/transport/tor/events.go — константы событий/классов (design §9.7) +
`src/observability/tor.go` — метрики (инкременты заглушками пока не Used —
регистрация серий только при первом использовании, bounded).

### DoD TT1: конфиг-тесты (zero-value валиден, все перечисления, invalid-кейсы с
точными кодами `system.tor.<field>`), priorityOf(KindTor)=5, MarkTorEgress=1<<21,
vet/test/race зелёные, `b4.json` без ключа tor парсится как disabled.

---

## §3. TT2 — bridge-строки и хранилище

### 3.1. bridges.go — порт Nova TorBridge (research-nova-tor §D):

```go
type Bridge struct {
    Transport  string // webtunnel|obfs4|snowflake|meek_lite|vanilla
    Line       string // исходная строка целиком (юнит обмена)
    AddrPort   string // для PT-транспортов может быть заглушкой
    Fingerprint string // 40 hex, "" допустим
    Args       map[string]string
}
var SupportedTransports = []string{"obfs4","webtunnel","snowflake","meek_lite","vanilla"}
var KnownUnsupported = map[string]string{"obfs3":"…","scramblesuit":"…","meek":"…","conjure":"…","dnstt":"…"}
func ParseBridgeLine(line string) (Bridge, error)   // все правила design §1.5
func (b Bridge) DecorationAddr() bool               // RFC3849/5737/0.0.0.0/:: — «не набирать»
func (b Bridge) SocksArgs() (login, password string, err error) // ≤510 Б, экранирование '\'
```

Правила: ASCII-only; запрет ISO control (`unicode.IsControl`), `\`, `#`, `"`;
первый токен = транспорт (vanilla — строка начинается с адреса `[?addr]:port`);
fingerprint 40 hex (склеенные пробелами куски — склеить, как tor); k=v-токены
после fp; `sqsqueue|sqscreds` → ErrBridgeLineInvalid("sqs-rejected"); snowflake
`max` клэмп 1..8; `iat-mode` ∈ 0..2 (obfs4). `Explain()` — человекочитаемая
причина отказа (для API и лога).

### 3.2. bridges_store.go — `bridges.json` (AtomicFile: tmp 0600 → fsync → rename;
`*.corrupt` карантин; схема `{version:1, updated_at, source, bridges:[{transport,
line, endpoint, fingerprint}], last_error}`) + `EntryMemory` (entry_memory.txt:
строка 1 = epoch-ms метка, далее провалившиеся входы и победитель; TTL 30 мин;
протухшая запись читается как пустая и удаляется — Nova TorAutoEntryProgress).

### 3.3. builtin snowflake-наборы: CDN77 и AMP (строки актуальны для v2.14.1;
источник — client/torref собранной версии; константы + тест на синхронность с
go.sum-версией не нужен — фиксируем в комментарии).

### DoD TT2: таблица кейсов ≥30 (каждое правило парсера, инъекция `\n` → отказ,
бюджет 510 Б на границе, заглушки, sqs, max-клеймп, склеенный fingerprint);
roundtrip store (save/load/corrupt-quarantine); entry-memory TTL/очистка.

---

## §4. TT3 — egress-диалер и egress-мост

### 4.1. egress.go:

```go
type ConnClass string // "bridge-pt" | "bridge-vanilla" | "relay-dir" | "rendezvous" | "bootstrap-source"
type EgressPolicy struct { Through string; BaitProfile string; Now func() time.Time }
type Dialer struct { /* carrier lookup func(kind) (reserve.Entry, bool) — инъекция для тестов */ }
func (d *Dialer) Dial(ctx context.Context, class ConnClass, host string, port uint16) (net.Conn, error)
```

- direct: `net.Dialer` + `socks5.ApplyBypassMark(d, packetmark.MarkTorEgress)`.
- through:<kind>: `reserve.Lookup(kind).Carrier.DialStream(ctx, addr)` (kind =
  warp/masque/h3/opera/fxvpn/proton; TCP-only резервы ок — все соединения тор TCP).
- auto: failoverDial-канон operaservice (direct таймаут 5 с → негативный кэш 60 с
  после 2 фейлов → carrier-first, self-heal проба direct каждые 60 с).
- Self-loop: host:port ∈ {слушатели тор-рантайма (инъекция), активная сессия
  носителя} → `ErrTorSelfLoop` ДО диала.
- Hostname → IP через `dns/doh.go MarkedDoHClient` (кэш в памяти до рестарта);
  is_global-проверка (анти-SSRF).
- `rendezvous`/`bootstrap-source` — никогда через tor (by construction: их диалит
  наш код, не тор; инвариант тестом).

### 4.2. egress_bridge.go — loopback SOCKS5-сервер для `Socks5Proxy` tor:
слушает 127.0.0.1:0, креды randomHex(16)/randomHex(16) на старт (sing-box
proxybridge), handshake-код из src/socks5 (приватная переиспользуемая функция или
минимальная локальная копия — согласовать с фактическим API server.go; НЕ менять
публичный API socks5), CONNECT → Dialer.Dial(class=bridge-vanilla|relay-dir).
UserPass-auth обязательна; неверные креды → отказ (чужой локальный процесс не
проходит). Лимит соединений 512, half-close pipe (Nova `pipe`-канон).

### DoD TT3: fake-carrier (reserve.Entry с счётчиком диалов) — политика
direct/through/auto с переключением; негативный кэш; self-loop кейс; DoH-фейк
(httptest); egress-мост: RFC1929-кейсы, креды, лимит, half-close; goleak.

---

## §5. TT4 — конвейер сбора мостов

collector.go + probe.go (design §4.1–4.2): источники builtin→OnionHop(гонка
зеркал, cap 25 с)→Moat(POST country+transports, через egress.Dial(bootstrap-source))
→owner lines; свежесть 24 ч; пауза 300 с; неудачный прогон сохраняет старый
список; dedup `transport|fingerprint|endpoint`; trim-keeping-every-kind 40;
успех = ≥1 живой из сети. Пробы per-transport (TCP 6 с / WS-101 строго HTTP/1.1
ALPN / HTTP-any для рандеву; бюджеты 16/8/∞, общий 60 с, пул 8). Выбор snowflake-
набора CDN77→AMP с кэшированием вердикта на прогон и принудительным «жив» при
молчании обоих (G202-канон).

Moat-тип ответа и OnionHop-формат — фикстуры (research-nova-tor §F); всё через
httptest. `TorBridgesConfig.CollectURLs` — в начало списка зеркал.

### DoD TT4: сценарии — гонка (первый непустой побеждает; пустой 200 не
выигрывает), Moat-фейл → фолбэк, провал всего → старый список сохранён +
last_error, trim с сохранением редких видов, свежесть/пауза, WS-проба только
HTTP/1.1 (h2-ответ = не жив).

---

## §6. TT5 — PT-прокси in-process

### 6.1. ptproxy.go — порт Nova tor_obfs4.go на b4x-примитивы:

```go
type PTRegistry struct { /* map[string]TransportFactory */ }
type TransportFactory interface {
    Name() string
    ParseArgs(args map[string]string) (PTEndpoint, error)
}
type PTEndpoint interface { Dial(dial func(addr string) (net.Conn, error)) (net.Conn, error) }
```

Реестр: obfs4 (lyrebird), webtunnel (lyrebird), meek_lite (lyrebird), snowflake
(адаптер §6.2). Loopback SOCKS5 (127.0.0.1:0): CONNECT → ACL (только адреса
мостов СООТВЕТСТВУЮЩЕГО транспорта из активного набора) → ParseArgs(из
login/password RFC1929, снятие нулей с конца, обратное экранирование '\') →
endpoint.Dial(protectedDial) → pipe half-close. Отказы: ACL → код 0x02; дозвон →
0x04. Лимит 256 соединений. protectedDial = egress.Dialer.Dial(bridge-pt).

### 6.2. snowflake_adapter.go — порт Nova tor_snowflake.go: ParseArgs →
`sflib.ClientConfig{BrokerURL, AmpCacheURL, FrontDomains, ICEAddresses, Max,
UTLSClientID, UTLSRemoveSNI, BridgeFingerprint, CovertDTLSConfig}` (sqs-поля
игнорируются — форк без SQS, строка с ними уже отвергнута парсером); кэш клиентов
с ключом из сырых аргументов (≤16); ловушки NetWrapper/BrokerDialContext из
форка → protected-сеть (все pion-сокеты через egress.Dialer; fail-loud
`failingPionNet` — nil-сеть запрещена, G154).

### 6.3. tools/snowflake + patch: форк v2.14.1 с ровно 2 изменениями (design §10):
(1) ловушки NetWrapper/BrokerDialContext (порт Nova-патча); (2) удаление
rendezvous_sqs.go и aws-импортов (файл заменён заглушкой, возвращающей ошибку).
go.mod: replace-директива. Vendor-дерево после — проверить `go mod vendor`
(отсутствие aws-sdk-go-v2 — отдельным тестом-гейтом CI-скрипта сборки, не Go-тестом).

### DoD TT5: фабрики — ParseArgs кейсы всех поддерживаемых аргументов + отказы;
ACL (чужая цель → 0x02; мёртвый мост → 0x04); экранирование (cert с base64 `=`);
кэш-ключи снежинки; лимиты; half-close; integration-гейт: если
B4X_TOR_INTEGRATION задан — end-to-end obfs4/webtunnel против локального
фейк-моста НЕ требуется (нет моста) — вместо этого юнит-стенд фейк-PTEndpoint.
goleak.

---

## §7. TT6 — control-клиент, процесс, torrc, bootstrap

### 7.1. control.go — минимальный клиент (~300 строк, torware-канон):

```go
type ControlClient interface { // инъекция для тестов
    Authenticate(cookie []byte) error
    GetInfo(keys ...string) (map[string]string, error)
    Signal(s string) error            // NEWNYM|ACTIVE|SHUTDOWN
    SetConf(kv ...[2]string) error    // conflux opportunistic
    Close() error
}
func DialControl(ctx context.Context, network, addr string) (ControlClient, error) // unix:…|tcp 127.0.0.1:…
```

Парсер ответов: `250 key=value`, multiline `250-key=…`, `250 OK`, `5xx` → ошибка
с кодом. Cookie: чтение файла 0600 → hex → `AUTHENTICATE <hex>`.

### 7.2. process.go: spawn (`exec.Command`, argv-пути design §7.4, env-минимум,
DataDirectory 0700), pid-файл {pid, exe}; сверка `/proc/<pid>/exe` перед любым
kill; owning-controller (`__OwningControllerProcess`); остановка SHUTDOWN→3с→
SIGTERM→3с→SIGKILL; смерть-детект (`cmd.Wait` горутиной → событие); рестарты
только через restartGuard torservice.

### 7.3. torrc.go — рендер design §7.4 чистой функцией `(cfg RenderInput) string`
+ `ValidateRendered(s string) error` (CRLF-бан, `\#"`-бан, все Bridge-строки
через ParseBridgeLine, транспорт-токены = именам PT). GeoIP-строки только при
Speed.GeoIP. Socks5Proxy-строка только при vanilla/direct-наборах. PT-строки
только для PT-входов. Пустой DefaultsTorrcFile.

### 7.4. bootstrap.go — progress-вотчер: поллинг 1 с; stall 150 с (без роста
PROGRESS); cap: 180 с (snowflake-только вход — 300 с); «10 молчаливых опросов» —
отдельная причина; тэг-дедуп лога (смена тэга/+10%/30 с повтор). События
`tor_bootstrap_progress` (bounded — только смены).

### DoD TT6: транскрипт-тесты control-протокола (записанные сессии 250/5xx/
multiline); verify-config integration-гейт (`tor --verify-config -f <rendered>`,
skip без B4X_TOR_INTEGRATION); тайминги bootstrap на фейк-control (прогресс-лест-
ница 10→15→25→…→100, stall-кейсы, молчание); pid/exe-свёрка (фейк-процесс);
порядок остановки.

---

## §8. TT7 — torservice-сборка

service.go (design §8): Runtime + состояния (`idle, binary-missing, bridges-wait,
starting, bootstrapping, established, rotating, backoff`); supervisor tick 30 с
(ensure*: bridges→process→bootstrap→liveness→exit-probe(30м)→conflux→exportState);
`enabled=false` — no-op. Лестница входов: auto → mixed-set (RaceWindow голов,
design §2.1) → последовательный проход (память входа минус проваленные, исчерпание
→ сброс); пин одного входа — без лестницы. Liveness: SOCKS5 CONNECT через tor
60 с (через socks5.DialUpstream), 2 фейла → SIGNAL ACTIVE+NEWNYM; 4 фейла+30 с →
teardown+restart с последнего рабочего входа; restartGuard (6/ч+300с). Страйки
мостов (порог 2, cooldown 300 с) → ротация моста в наборе → исчерпание → след.
вход. Exit-проба: GET https://check.torproject.org/api/ip ЧЕРЕЗ tor (таймаут 15 с,
клиент с фиксированным UA), IsTor=false → событие tor_exit_mismatch (без strike —
информационно; mismatch ≠ jail). Carrier-composition: смерть носителя →
egress-диалер auto переключает; liveness подхватит. `winner` входа: bootstrap 100
→ GETINFO orconn-status/entry-guards → мост → транспорт → entry_memory.

Тесты: фейк-tor стенд (скрипт/Go-процесс, слушающий control-сокет и отвечающий
транскриптами; SOCKS-echo) — сценарии §12 (матрица). Инжекцируемые Now/диалеры;
goleak; FD-бюджеты.

### DoD TT7: state-машина сценарии (успех/бинарник отсутствует/нет мостов/
stall/молчание/liveness-фейлы→NEWNYM→teardown→restart-with-winner/restartCap);
честный no-op при disabled; события/метрики на месте.

---

## §9. TT8 — carrier, API, wiring, CLI

- carrier.go: Kind/SupportsUDP=false/DialStream → socks5.DialUpstream к tor SOCKS
  (hostname насквозь); ErrNotListening до established; self-loop guard (адрес =
  слушатель тор). Опциональный `HostCarrier`-интерфейс (design §9.1) — только
  объявление + реализация, потребителей нет (потребители scoped-роутера — вне
  скоупа, §13.6 дизайна).
- handler/tor.go + common.go: эндпоинты design §9.5 (4 КБ body-лимит, nil-safe
  disabled-шейпы, swagger-аннотации).
- main.go: wiring design §9.3 (после fxvpn); shutdown `Unregister(KindTor)` →
  `torEngine.Stop()` (порядок в gracefulShutdown зафиксировать).
- cmd/torctl: status|entry <mode>|bridges|scan|test (fxvpnctl-канон; test =
  liveness-проба + exit-проба по требованию).
- observability/tor.go: финальная проводка метрик.

### DoD TT8: handler-тесты (disabled-шейпы, валидации, рестарт-эндпоинт);
wiring-смоук (fake runtime); CLI smoke; vet/test/race; регресс 0.

---

## §10. TT9 — relay-scanner

torscan (design §4.3): onionoo.go (источники: пользовательские CollectURLs →
onionoo → CORS-прокси icors → GitHub-зеркало → Bitbucket → кэш-файл; поля
`fingerprint,or_addresses,country,observed_bandwidth`; фильтры страна/порты;
random shuffle). probe.go — глубокая проба (TLS CERT_NONE + случайный SNI
`www.<4-25 base32>.org`; VERSIONS-ячейка; NETINFO + N×CREATE; парсинг ответа
CREATED — байтовые константы из research-tor-tooling §1). scanner.go — пул
(конфигурируемый, default 24), deadline (default 90 с), goal (default 6),
проверка ВСЕХ or_addresses (не только [0] — фикс juev-бага), bandwidth-отбор
(top-квантиль observed_bandwidth), выход — []Bridge (vanilla) + метрики
tor_scan_relays_found. Запуск: фоновой из torservice (по расписанию: свежесть
кэша 6 ч) + по требованию (API/CLI), budget-bounded, egress.Dial(bootstrap-source)
для источников.

### DoD TT9: httptest-onionoo (все фолбэки по очереди; кэш-файл офлайн);
фейк-TLS-релей стенд (Go-сервер: TLS + VERSIONS/CREATED ответы — правильные и
неправильные); bandwidth-сортировка; бюджеты/раннее-завершение; конвертация в
bridge-строки.

---

## §11. TT10 — финал: полевой пакет, NOTICE, changelog

- `FIELD_TEST_TOR_PROMPT.md` (по образцу FIELD_TEST_PROTON_QUIC_PROMPT.md):
  pcap-доказательства (webtunnel CH = валидный HTTPS до живого сайта; obfs4 =
  случайный поток; vanilla = Tor-TLS только внутри носителя), инвариант «tor не
  утекает мимо носителя» (egress.through=proton: в pcap только AWG-пакеты к узлу
  proton при живом tor), kill-семантика (убить носитель → цепочки умерли →
  NEWNYM/rebuild; убить tor → носитель жив), FD-аудит (48 ч soak, ls /proc/<pid>/
  fd стабилен), скорость (tor_bootstrap_seconds, tor_first_stream_ttfb_ms,
  throughput по входам).
- NOTICE/THIRD_PARTY_NOTICES: goptlib (CC0), lyrebird (BSD-2), snowflake (BSD-3)
  + транзитивы pion/kcp-go/smux/covert-dtls/ptutil (MIT/BSD) — таблицей.
- changelog.md `[unreleased]`: ADDED (E-TOR): … по образцу.
- Makefile: сборка всех LINUX_ARCHS зелёная; размер бинаря до/после — в отчёт
  этапа (ожидание +3–6 МБ из-за pion-дерева; осознанное решение design §10).

### DoD TT10: все зелёное; полевой пакет написан и ждёт владельца; артефакты
этапа в worklog; версия дизайна/патч-плана не расходится с кодом.

---

## §12. Матрица фейк-сценариев (обязательные тесты)

| # | Сценарий | Ожидание |
|---|---|---|
| 1 | tor-бинарь отсутствует, enabled=true | state=binary-missing, событие tor_binary_missing, подсказка opkg; сетевой активности ноль |
| 2 | bridges.json отсутствует, вход obfs4, все зеркала недоступны | bridges-wait → fallback owner lines → если и их нет: честный no-bridges, не цикл |
| 3 | Строка моста с `\n` внутри | ErrBridgeLineInvalid на валидации конфига (не в рантайме) |
| 4 | Аргументы > 510 Б | Отказ парсера с указанием поля |
| 5 | snowflake строка с max=9 | Клеймп до 8 + событие-статус |
| 6 | snowflake строка с sqsqueue= | Отказ (sqs-rejected), клиент не создаётся |
| 7 | Moat вернул webtunnel+obfs4, оба живы, гонка зеркал выиграла пустой 200 | Пустой ответ не побеждает; Moat-набор принят |
| 8 | WS-проба webtunnel по h2 (нет 101) | Мост «не жив», из набора исключён |
| 9 | mixed-set: bootstrap дошёл до 100, orconn = obfs4-мост | entry_memory: winner=obfs4; событие tor_entry_won |
| 10 | mixed-set stall 150 с без роста | teardown → последовательный вход webtunnel (первый неотказанный) |
| 11 | Все входы провалены | entry_memory исчерпан → сброс → повтор круга; restartGuard держит 6/ч |
| 12 | liveness 2 фейла подряд | SIGNAL ACTIVE + NEWNYM, события |
| 13 | liveness 4 фейла + 30 с | teardown → restart с winner-входа |
| 14 | egress.through=proton, proton умер | цепочки умерли → диалер auto → следующий carrier → NEWNYM; tor не диалил в прямую (счётчик fake-direct) |
| 15 | egress.through=none (direct), ISP режет | bootstrap timeout → вход меняется, не виснет |
| 16 | Убить b4 (SIGTERM) | tor умер (owning controller); PT-прокси погашен; без сирот (ps-проверка в интеграционном тесте) |
| 17 | kill по имени процесса tor | Запрещён: только pid+exe-свёрка (тест на попытку чужого pid) |
| 18 | exit-проба IsTor=false | Событие tor_exit_mismatch; стрима нет; без strike/ротации |
| 19 | SETCONF ConfluxEnabled → 5xx | tor_conflux_unavailable, работа продолжается |
| 20 | enabled=false | Ноль горутин, ноль слушателей, ноль сетевых вызовов (goleak+nettrace-тест) |
| 21 | ACL PT-прокси: CONNECT к цели вне мостов | Код 0x02, в сеть ничего не ушло |
| 22 | PT-мост мёртв (dial timeout) | Код 0x04 tor'у; страйк моста |
| 23 | carrier.DialStream на слушатель тор- SOCKS | ErrTorSelfLoop |
| 24 | .onion-хост в DialStream | Уходит в tor SOCKS как atypDomain (нересолвленным), без локального DNS-запроса |

---

## §13. Acceptance-чеклист (финальный гейт этапа)

- [ ] Все TT1–TT10 DoD зелёные; vet/test/race; регресс 0; goleak во всех новых пакетах
- [ ] Зависимости = перечень design §10 (vendor без aws-sdk-go-v2 — скрипт-проверка)
- [ ] Конфиг валидируется в disabled-состоянии; zero-value = валидный disabled
- [ ] `b4.json` без ключа `tor` → программа стартует как раньше (нулевое влияние)
- [ ] Инварианты anti-loop: bootstrap-источники и рандеву никогда через tor
- [ ] Инвариант §12.4 proton-design: composed-mode утечек в прямую сеть нет (сценарий 14)
- [ ] UDP через tor — честный отказ (SupportsUDP=false + отказ в DialUDP-ветке тестом)
- [ ] Bait включается только явно; событие tor_bait_active/inactive честное
- [ ] Shutdown: Unregister до Stop; порядок обратен пуску; без сирот-процессов
- [ ] Метрики design §9.7 существуют и bounded; события snake_case/классы kebab
- [ ] NOTICE/лицензии обновлены; changelog дописан; Makefile все архитектуры зелёные
- [ ] Полевой пакет FIELD_TEST_TOR_PROMPT.md готов и НЕ запускается без владельца

## §14. Риски и откаты

| Риск | Митиг/откат |
|---|---|
| pion/webrtc тяжёл для MIPS (память/CPU) | snowflake — последний вход лестницы; на MIPS можно собрать без snowflake (build-tag `tor_snowflake`, регистрация пропускается, вход честно unsupported) — запасной план, согласовать с владельцем до TT5 |
| Форк snowflake разошёлся с upstream | Патч-файл минимален (2 изолированных изменения); обновление = переприменение патча; replace-директива локальная |
| Entware tor старой версии (без conflux/ControlSocket) | Всё опционально: SETCONF-мягкость, ControlPort-fallback; version-detect на старте |
| OnionHop-зеркала недоступны | Moat + owner lines + builtin snowflake; collector отчитывает source |
| Глубокая проба сканера триггерит IDS провайдера | Бюджеты (goal/interval), только по требованию/расписанию, порты 443; конфиг позволяет выключить relay_scan полностью |
| FD-утечка (история проекта) | Bounded-лимиты PT/egress; goleak; soak в полевом пакете |
| Регресс основного движка | Карта «НЕ трогать» §1.3; нулевой diff вне перечня §1.2 |
| Вендор-размер (+pion) | SQS-вырезание; MIPS-сборка-гейт в TT10; осознанно задокументировано |
| tor-процесс как root (Entware) | Документировано в §7 дизайна; опционально BinaryPath на кастомную сборку владельца (не в скоупе) |
| Возврат | E-TOR целиком за feature: удалить ветку/каталоги §1.1, откатить правки §1.2 (список исчерпывающий), vendor — `git checkout`; ядро не затрагивается |
