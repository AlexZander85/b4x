# E-TOR: ревью дизайна и реализации (v1, 2026-09-15)

Статус: независимое ревью HEAD `ea661ec53f19b62325caea54c5b11cbd41776e39` ветки `agent/e-tor-reserve` против `tor-reserve-design.md` (v1) и `tor-reserve-patch-plan.md` (v1). Объект: `src/transport/tor/`, `src/transport/torsnowflake/`, `src/transport/torscan/`, `src/torservice/`, `src/config/tor.go`, `src/http/handler/tor.go`, `src/reserve/registry.go`, `src/packetmark/marks.go`, `src/main.go`, `tools/snowflake/`, тесты и полевой пакет.

Режим ревью: только чтение и рассуждение. Код/дизайн не менялись; создан только этот отчёт. Живых сетевых запросов из b4x и деплоя на роутер не было.

> Ограничение верификации: GitHub connector не даёт исполнить локальные `go vet ./...`, `go test ./...`, `go test -race ./...` и cross-compile. Коммит TT10 заявляет зелёные vet/test/race и cross-compile на amd64/arm64/armv6/mips/mipsle/softfloat, но в ветке нет GitHub Actions run, поэтому в этом ревью это **заявление реализатора, а не независимо воспроизведённый результат**.

---

## 1. Вердикт

Архитектурное направление E-TOR в целом сильное. Внешний C-Tor из Entware, PT как in-process Go-библиотеки, отдельный reserve.Carrier, fail-closed named carrier, egress-policy, self-loop guards, bridge admission gate, bootstrap supervision и наблюдаемость хорошо укладываются в ограничения b4x. Особенно перспективна композиция vanilla Tor через существующий carrier: после исправления контрактов это может стать самым быстрым режимом Tor в проекте, потому что скрывает Tor-TLS внутри уже работающего резерва и не требует медленного PT на каждом соединении.

Однако **E-TOR сейчас не готов к полевому прогону `FIELD_TEST_TOR_PROMPT.md`**. Причина не в недостатке полировки: найдены несколько блокирующих ошибок протокольного уровня. Две torrc-директивы закодированы не по реальному синтаксису Tor (`ControlSocket`, `Socks5Proxy` credentials), relay-scanner основан на неверной/устаревшей интерпретации CREATE/CREATED и ждёт `0x04` как CREATED, хотя это DESTROY, а legacy CREATE/CREATED удалены в Tor 0.4.9.1-alpha. Кроме того, restart/teardown может потерять handle живого C-Tor и породить сироты.

Второй блок — обещанный инвариант `egress.through=<kind> => ноль утечки мимо carrier`. Для vanilla/TCP идея реализована правильно, но Snowflake сознательно открывает ICE/STUN UDP напрямую, а broker/front HTTPS классифицируется как rendezvous и принудительно получает direct-first `auto`. Значит, при `through=proton` или другом pinned carrier Snowflake может оставить прямые WAN-пакеты. Это CRITICAL именно потому, что дизайн и FIELD_TEST трактуют carrier как строгую оболочку E-TOR.

TT1–TT10 структурно реализованы почти полностью, но DoD нескольких этапов не выполняется по смыслу: TT6 должен был поймать неправильный torrc реальным `tor --verify-config`, TT7 не обеспечивает kill/restart invariant, TT9 не имеет корректной современной deep-probe семантики. Поэтому заявленный acceptance TT10 нельзя считать достаточным до закрытия P0 ниже.

| Область | Оценка |
|---|---|
| Дизайн-факты | **BLOCKED** — несколько внешних фактов о Tor неверны |
| Инновации | **PARTIAL** — идеи хорошие, 3 из 4 требуют усиления инвариантов |
| TT1 | готово по структуре |
| TT2 | частично: admission gate нормализует control chars до проверки |
| TT3 | частично: TCP egress хорош, но torrc proxy contract сломан |
| TT4 | в основном готово |
| TT5 | **BLOCKED** для strict carrier: Snowflake direct UDP/rendezvous |
| TT6 | **BLOCKED**: torrc syntax, control parser, process-start races |
| TT7 | **BLOCKED**: orphan-process restart path, winner attribution, grace |
| TT8 | в основном готово: carrier/API/wiring/shutdown финального Stop выглядят здраво |
| TT9 | **BLOCKED**: relay deep probe протокольно неверна |
| TT10 | документы готовы; acceptance не воспроизведён независимо, field packet неполон |
| Зависимости | в основном контролируемы; есть mismatch версии snowflake в go.mod |
| Платформа MIPS/32MB | не доказана; нужны low-memory/FD guards и поле после P0 |

### Ответ владельцу

**Нет, E-TOR пока не следует запускать по `FIELD_TEST_TOR_PROMPT.md`.** Сначала закрыть P0 из §5. После этого я бы разрешил короткий контролируемый field smoke, затем soak/скорость.

---

## 2. Карта покрытия (дизайн → реализация)

### 2.1 TT1–TT10

| Этап | Статус | DoD по ревью |
|---|---|---|
| TT1 config/registry/marks/taxonomy | реализован | в основном да |
| TT2 bridge parser/store | реализован | **частично**: raw control-char invariant нарушен, `obfs2` не в KnownUnsupported |
| TT3 egress + egress bridge | реализован | **частично**: policy хорош, но Tor не получит корректные SOCKS5 credentials |
| TT4 collector/probes | реализован | в основном да по статическому чтению/httptest |
| TT5 PT + Snowflake | реализован | **нет для strict through**: UDP/rendezvous bypass |
| TT6 control/process/torrc/bootstrap | реализован | **нет**: C2/C3/H1/H5/H8/H9 |
| TT7 runtime/supervisor | реализован | **нет**: C5/H2/H3/H6 |
| TT8 carrier/API/wiring/CLI | реализован | в основном да; финальный shutdown reverse-order корректен |
| TT9 relay scanner | реализован | **нет**: C1 делает deep-probe недостоверной |
| TT10 field/docs/licenses | реализован | документы есть; запуск acceptance не воспроизведён; field matrix надо расширить |

### 2.2 Выборочная перепроверка внешних фактов (A.1, >=10)

Авторитет для внешних фактов: актуальные Tor Specifications (`spec.torproject.org`) и torrc(5) Debian testing/trixie-backports. Research-файлы использованы как traceability, но при конфликте с Tor spec приоритет у Tor spec.

| # | Утверждение | Результат |
|---|---|---|
| 1 | Nova UI имеет auto/webtunnel/obfs4/snowflake/vanilla/direct | подтверждено research-nova; E-TOR покрывает эти режимы |
| 2 | Nova auto идёт webtunnel→obfs4→snowflake→vanilla | подтверждено research-nova |
| 3 | RFC1929 даёт 255 Б username + 255 Б password = 510 Б | подтверждено; parser budget разумен |
| 4 | SQS-аргументы Snowflake опасны/ненужны для b4x | подтверждено research; ранний reject оправдан |
| 5 | uTLS v1.8.2 — актуальная зависимость Snowflake-стека | подтверждено research и `src/go.mod` |
| 6 | VERSIONS — variable cell command 7 | подтверждено Tor spec |
| 7 | Fixed cell body = 509 Б, при link v>=4 total = 514 Б | подтверждено Tor spec |
| 8 | `0x04` — CREATED | **ОШИБКА**: command 4 = DESTROY; CREATED = 2 (legacy), CREATED2 = 11 |
| 9 | Legacy CREATE/CREATED можно использовать как современную deep probe | **ОШИБКА**: obsolete; support removed entirely in Tor 0.4.9.1-alpha |
| 10 | `Socks5Proxy user:pass@host:port` — валидный torrc | **ОШИБКА**: host:port отдельно, credentials через `Socks5ProxyUsername/Password` |
| 11 | `ControlSocket unix:/path` — валидный `ControlSocket` | **ОШИБКА**: `ControlSocket Path`; `unix:path` относится к форме `ControlPort` |
| 12 | Socks5Proxy покрывает OR-connections | подтверждено torrc(5); современные клиенты получают directory docs через OR-connections |
| 13 | GETINFO multiline: `250+key=`, body, `.`, затем другие ReplyLine и финальный `250 OK` | подтверждено control-spec; текущий parser теряет terminator |
| 14 | Bridge transport token означает PT и должен соответствовать ClientTransportPlugin | подтверждено torrc(5); literal `vanilla` как transport без plugin неверен |
| 15 | Conflux имеет throughput/latency | подтверждено; дополнительно актуальный Tor имеет `throughput_lowmem`/`latency_lowmem` |
| 16 | Snowflake/WebRTC использует UDP ICE/STUN | подтверждено самим snowflake/Pion стеком и текущим adapter; strict TCP carrier не может «магически» скрыть этот UDP |

### 2.3 Матрица §12 patch-plan (24 сценария)

Обозначения: PASS = есть правдоподобная unit/static реализация; PARTIAL = часть инварианта есть, но acceptance неполон; FAIL = код противоречит ожидаемому поведению. Это не результат повторного запуска тестов.

| # | Статус | Комментарий |
|---|---|---|
| 1 binary missing | PASS | честное состояние присутствует |
| 2 no bridges/fallback | PARTIAL | collector/fallback есть, end-to-end no-loop не воспроизведён |
| 3 bridge `\n` | **FAIL** | `strings.Fields(raw)` выполняется до control-char проверки |
| 4 args >510 | PASS | admission gate есть |
| 5 snowflake max=9 clamp | PASS | notice/clamp реализованы |
| 6 sqs reject | PASS | parser + adapter double-check |
| 7 empty 200 mirror | PASS | collector tests/logic предусматривают non-empty winner |
| 8 webtunnel h2/no101 | PASS | отдельная probe semantics есть |
| 9 mixed winner=obfs4 | PARTIAL | scripted case возможен, но real GETINFO parser/fallback attribution ненадёжны |
| 10 mixed stall→sequential | **FAIL invariant** | переход есть, но старый C-Tor может остаться жив |
| 11 all entries fail/restartGuard | PARTIAL | cap есть, lifecycle leak остаётся |
| 12 liveness2→ACTIVE+NEWNYM | PASS | реализовано |
| 13 liveness4+30s→restart | **FAIL** | 30s grace фактически не реализован; process не Stop перед handle drop |
| 14 pinned proton dies | **SPEC CONFLICT** | код pinned fail-closed, matrix ожидает auto-next-carrier; выбрать одну семантику |
| 15 direct ISP cut | PARTIAL | bootstrap timeout/ladder есть, real Tor не проверен |
| 16 kill b4→no orphan | PARTIAL | final Stop хорош, но mid-runtime restart уже может породить сироту |
| 17 no kill-by-name | PARTIAL | `OwnsPID` есть, но Stop не использует guard перед TERM/KILL |
| 18 IsTor=false | PASS | event without strike |
| 19 Conflux 5xx | PASS | graceful degradation |
| 20 enabled=false | PASS по wiring | main не Build/Start при disabled; runtime Build fail-loud |
| 21 PT ACL foreign | PASS | fail-closed ACL path |
| 22 PT dead→0x04 | PASS | error mapping есть |
| 23 carrier self-loop | PASS | guard присутствует |
| 24 .onion unresolved | PASS | SOCKS hostname path предусмотрен |

---

## 3. Находки

### CRITICAL

#### C1 — relay-scanner построен на неверном/устаревшем Tor wire contract

**Где:** `tor-reserve-design.md` §1.6, §4.3; `artifacts/tor-research/research-tor-tooling.md` §1; `src/transport/torscan/probe.go:28-145`.

Дизайн называет ответ `00 00 00 05 04` CREATED. В актуальном Tor spec command 4 = **DESTROY**, legacy CREATED = 2, modern CREATED2 = 11. Более того, legacy CREATE/CREATED support удалён целиком в Tor 0.4.9.1-alpha. Текущий probe также формирует NETINFO не как полный fixed cell и не проходит современную channel handshake последовательность CERTS/AUTH_CHALLENGE/NETINFO.

**Почему важно:** scanner не доказывает то, что обещает. На современном Tor он либо систематически отвергнет живые релеи, либо неправильно интерпретирует поток. Это делает vanilla-scanner фундаментально ненадёжным и нарушает A.1: дизайн опирается на неверный внешний факт.

**Фикс:** перепроектировать probe. Минимальный безопасный v2: TLS → VERSIONS → корректно распарсить link handshake relay → корректно отправить NETINFO → признать успешную современную OR channel handshake доказательством «Tor endpoint + DPI пропустил application stage». Не пытаться строить фиктивный circuit без корректного CREATE2/ntor материала. Если нужен более глубокий тест — отдельный modern CREATE2 только после получения нужных ключей/descriptor, с очень малым budget. Обновить research/design/tests одновременно.

#### C2 — неправильный torrc `ControlSocket`

**Где:** `tor-reserve-design.md` §1.3/§7.4; `src/transport/tor/torrc.go:45-104`; `src/torservice/supervisor.go:220-247`; `src/transport/tor/control_test.go` torrc golden tests.

Код генерирует `ControlSocket unix:/opt/.../control.sock`. torrc(5) определяет `ControlSocket Path`; форма `unix:path` относится к `ControlPort [address:]port|unix:path|auto`.

**Почему важно:** control socket может не создаться, после чего bootstrap supervision, GETINFO, NEWNYM, shutdown и winner attribution не работают.

**Фикс:** либо `ControlSocket /opt/.../control.sock`, либо `ControlPort unix:/opt/.../control.sock`; выбрать один канон и согласовать `connectControl`. Добавить реальный `tor --verify-config` gate.

#### C3 — неправильный torrc `Socks5Proxy` credentials

**Где:** `tor-reserve-design.md` §1.8/§3/§7.4; `src/transport/tor/torrc.go:48-122`; `src/torservice/supervisor.go:220-247`.

Код формирует `Socks5Proxy user:pass@127.0.0.1:port`. Реальный Tor требует:

```text
Socks5Proxy 127.0.0.1:port
Socks5ProxyUsername user
Socks5ProxyPassword pass
```

**Почему важно:** vanilla/direct/vanilla-through-carrier могут не стартовать или не аутентифицироваться к egress bridge. Это ломает главную инновацию дизайна.

**Фикс:** разделить address/user/password в `TorrcInput`, рендерить три директивы. Обязательный verify-config test + маленький integration smoke до создания control socket.

#### C4 — Snowflake нарушает строгий `through=<carrier>` и может выйти напрямую

**Где:** `tor-reserve-design.md` §3.2/§3.3/§12.8; `src/transport/torsnowflake/protected_net.go:1-125`; `src/transport/torsnowflake/adapter.go:1-65`; `src/transport/tor/egress.go:185-215,360-410`; `FIELD_TEST_TOR_PROMPT.md` шаг 2.

Два обхода:

1. Pion UDP (`ListenUDP`, `DialUDP`, `ListenPacket`) всегда direct + SO_MARK.
2. Snowflake broker/front идёт как `ClassRendezvous`; `effectivePolicy` принудительно делает его `auto`, а `auto` direct-first, даже если оператор выбрал `through=proton`.

**Почему важно:** дизайн обещает carrier как оболочку Tor. Прямой STUN/ICE/DTLS/HTTPS при pinned carrier — утечка транспортного профиля и нарушение review red line. Текущий FIELD_TEST проверяет strict-carrier только на vanilla и поэтому этот дефект может не увидеть.

**Фикс:** развести классы `bootstrap-source` и активный `pt-rendezvous`. Активный Snowflake rendezvous должен наследовать pinned policy. Для UDP сейчас нет честного stream-only carrier пути: при named `through` Snowflake должен **fail closed / исключаться из ladder**, пока не появится существующий packet-capable carrier API. Никакого silent direct fallback. FIELD_TEST дополнить Snowflake+pinned-carrier pcap: ноль прямых broker/ICE/STUN/DTLS пакетов.

#### C5 — teardown теряет handle живого C-Tor и способен копить сироты

**Где:** `src/torservice/supervisor.go:353-428,500-526,570-610`; `src/torservice/service.go:420-468`.

`teardown()` закрывает control и делает `r.proc=nil`, но сам процесс не останавливает; комментарий предполагает, что process «already dead or stopped by caller». Это неверно для bootstrap failure, liveness restart, manual restart/entry change. Owning controller = PID b4, а b4 продолжает жить, поэтому старый Tor не обязан умереть. Следующий ensure может spawn новый Tor.

**Почему важно:** на роутере это RSS/FD leak, сетевые сироты, конфликт data/control paths и нарушение kill-инварианта.

**Фикс:** единая функция `retireCurrentProcess(reason)` — atomically capture proc+ctl, graded `Stop()`/wait, только после подтверждённого retirement очистить handle/state. Использовать для bootstrap fail, liveness restart, RestartNow, entry change и final Stop. `handleDeath` оставить отдельным для уже умершего процесса. Тест: счётчик fake Stop + запрет нового Spawn до retirement.

#### C6 — parser допускает literal transport `vanilla`, который Tor трактует как PT

**Где:** `tor-reserve-design.md` §1.5; `src/transport/tor/bridges.go:36-48,91-125`; `src/transport/tor/torrc.go:116-135`; `src/transport/tor/control_test.go` vanilla torrc golden.

`SupportedTransports` включает `vanilla`; parser сохраняет `vanilla 5.6.7.8:9001 ...`; renderer пишет это как `Bridge vanilla ...`, но для Tor transport token означает имя pluggable transport и должен соответствовать `ClientTransportPlugin`. Plugin `vanilla` не существует. Scanner-generated address-first line может быть валидной, owner line с explicit `vanilla` — нет.

**Фикс:** internal `Bridge.Transport="vanilla"`, но canonical torrc line для vanilla всегда `IP:ORPort FINGERPRINT` без transport token. Либо explicit `vanilla` во входной строке отвергать и документировать address-first форму. Verify-config fixture обязателен.

### HIGH

#### H1 — GETINFO multiline parser теряет `.` и может поглотить следующие keys

**Где:** `src/transport/tor/control.go:99-145,183-240`.

`roundtrip()` читает body `250+key=` до точки, но точку не сохраняет в block. `GetInfo()` затем повторно пытается искать `.` в уже собранных lines и способен присоединить следующие `250-key=...` / `250 OK` к первому значению.

**Фикс:** парсить reply один раз в structured representation либо сохранять multiline terminator/границы. Добавить fixture: `250+keyA`, body, `.`, `250-keyB=value`, `250 OK`.

#### H2 — mixed-set winner при неизвестной атрибуции выдумывается

**Где:** `src/torservice/supervisor.go:620-690` (`winningTransport`).

Если GETINFO не дал однозначный match, код возвращает `set[0].Transport`, а при пустом set — webtunnel. Это превращает отсутствие доказательства в «победителя», пишет ложь в EntryMemory и меняет будущую ladder.

**Фикс:** winner может быть `unknown`. Не обновлять memory без однозначного bridge/fingerprint match; emit `tor_entry_attribution_unknown`. Для нескольких активных ORConn хранить фактический selected guard/bridge, а не первый транспорт.

#### H3 — mixed-set молча включает meek_lite, хотя design исключает meek из auto

**Где:** `tor-reserve-design.md` §2; `src/torservice/supervisor.go:80-110`.

`assembleSet(auto-mixed)` перебирает `webtunnel, obfs4, snowflake, meek_lite`. В design meek_lite owner-only/manual и в auto не участвует.

**Фикс:** убрать meek_lite из auto либо явно изменить design отдельным owner decision.

#### H4 — control chars проверяются после нормализации

**Где:** `src/transport/tor/bridges.go:91-106`.

`strings.Fields(raw)` уничтожает `\n/\r/\t` до `isASCII`/control check. Поэтому admission gate не гарантирует обещанное «raw control char => reject».

**Фикс:** сначала пройти исходную строку byte/rune-wise и reject control/CR/LF/backslash/#/quote, только потом trim/split/normalize.

#### H5 — race при старте `torrc-defaults` и двойной владелец pid-файла

**Где:** `src/transport/tor/process.go:62-112`.

Tor запускается с `--DefaultsTorrcFile <.../torrc-defaults>`, а пустой файл создаётся **после `cmd.Start()`**. Это race. Одновременно `--PidFile tor.pid` отдаётся Tor, после чего b4 пишет в тот же файл собственный формат `{pid,exe}`.

**Фикс:** создать/fsync defaults до Start. Не делить pid-file между Tor и b4: отдельный Tor PidFile и `b4-tor-owner` metadata либо только ProcessHandle + отдельный ownership record.

#### H6 — заявленные 30 секунд grace после 4 liveness failures отсутствуют

**Где:** `src/torservice/supervisor.go:353-428`.

Блок с `ctx.Deadline()` ничего не ждёт и не сравнивает `deadSince`; при `fails>=4` teardown выполняется сразу.

**Фикс:** `livenessDeadSince` на injected `Now`; teardown только если failures продолжаются и прошло >=30s; reset при success.

#### H7 — scenario #14 противоречит реализации и безопасной pinned-семантике

**Где:** `tor-reserve-patch-plan.md` §12 scenario 14; design §3.3; `src/transport/tor/egress.go:168-215,360-410`.

Matrix ожидает: `through=proton`, proton умер → next carrier. Код pinned `proton` честно пробует только proton; fallback есть только у `auto`.

**Рекомендация:** оставить более безопасную реализацию и исправить спецификацию: named carrier = sticky/fail-closed, `auto` = availability mode. Никогда молча не превращать pinned policy в auto/direct.

#### H8 — отсутствует обязательный real `tor --verify-config` gate

**Где:** `tor-reserve-patch-plan.md` TT6 DoD; `src/transport/tor/control_test.go`.

Patch-plan прямо требует integration test за `B4X_TOR_INTEGRATION`. В текущем TT6 tests есть только собственный `ValidateRendered`, который как раз golden-тестами закрепил C2/C3/C6.

**Фикс:** gated test для direct, vanilla, PT, mixed-set через реальный `tor --verify-config -f`; дополнительный startup smoke до появления control socket.

#### H9 — pid+exe guard реализован, но escalation Stop его не использует

**Где:** `src/transport/tor/process.go:120-190`.

`OwnsPID()` существует и дизайн требует сверку перед любым kill, но `Stop()` посылает SIGTERM/SIGKILL через `proc` без вызова `OwnsPID`. Это расходится с собственным safety contract.

**Фикс:** перед TERM/KILL: сначала проверить, не завершён ли child; затем `OwnsPID(pid, expectedBinary)`. При mismatch — отказ от signal + событие безопасности. Контрольный `SIGNAL SHUTDOWN` не требует pid kill guard.

### MEDIUM

#### M1 — RaceWindow фактически умножается на транспорты

**Где:** `src/torservice/supervisor.go:80-110`.

`RaceWindow=2` означает до 2 мостов **каждого** транспорта плюс builtin snowflake, а не «2 головы». Это увеличивает одновременные sockets/CPU/RSS на MIPS.

**Фикс:** определить семантику явно. Для роутера разумнее фиксированные малые quota: WT 2 + obfs4 2 + snowflake 1, либо общий global budget.

#### M2 — bandwidth ranking relay-scanner затем уничтожается полным shuffle

**Где:** `src/transport/torscan/onionoo.go:180-215`; `src/transport/torscan/scanner.go:70-125`.

Сначала relays сортируются по observed_bandwidth, затем весь список shuffle. В итоге цель «быстрые guards» размывается.

**Фикс:** rank → взять top cohort/quantile → shuffle только внутри cohort. Сохранять jitter/randomness, но не выбрасывать скоростной сигнал.

#### M3 — версия Snowflake в root go.mod расходится с design

**Где:** `tor-reserve-design.md` §10; `src/go.mod:70-94`.

Design говорит fork v2.14.1, require записан `snowflake/v2 v2.11.0` при local replace на `../tools/snowflake`. Код берётся из local fork, но provenance/SBOM вводит в заблуждение.

**Фикс:** синхронизировать require-version с fork provenance; отдельно tidy tools module, чтобы AWS metadata не жила там без нужды.

#### M4 — KnownUnsupported не содержит obfs2

**Где:** design §14; `src/transport/tor/bridges.go:36-48`.

Design обещает распознавать obfs2/obfs3/...; map начинается с obfs3.

**Фикс:** добавить honest unsupported reason для obfs2.

#### M5 — HostCarrier semantics для обычных hostname расходится с принципом Tor SOCKS hostname-through

**Где:** design §9.1; `src/torservice/carrier.go` (`DialStreamHost`).

`.onion` передаётся unresolved, обычный hostname предварительно резолвится DoH. Для доступности это не фатально, но Tor способен принять обычный hostname через SOCKS сам.

**Фикс:** по возможности передавать все hostnames в Tor SOCKS unresolved; local DoH оставить для endpoint-ов собственного egress/PT.

#### M6 — не используются low-memory Conflux UX

**Где:** design §6/§13; `src/torservice/supervisor.go` `ensureConflux`.

Актуальный Tor имеет `throughput_lowmem` и `latency_lowmem`, специально уменьшающие queue memory. При GOMEMLIMIT от 32 МБ это естественный профиль для слабых роутеров.

**Фикс:** добавить существующий enum/profile без новых deps; по умолчанию выбирать lowmem только на явно low-memory platform/profile, а не угадывать silently.

#### M7 — не зафиксирован Tor `ConnLimit`/FD preflight

**Где:** design §8.4/§13.

Tor default ConnLimit=1000 и может отказаться стартовать, если hard FD limit ниже. b4 ограничивает PT/egress соединения, но внешний C-Tor остаётся отдельным FD-потребителем.

**Фикс:** до spawn логировать RLIMIT_NOFILE, Tor ConnLimit expectation и RSS/FD status; после field измерений выбрать conservative explicit ConnLimit, если Keenetic требует.

#### M8 — MIPS Snowflake остаётся недоказанным риском

**Где:** design §13.2; Pion/KCP/smux tree.

Это честно признано design, но TT10 формулировка acceptance может создать впечатление platform-ready. Cross-compile != runtime feasibility.

**Фикс:** field telemetry: RSS, heap, GC pauses, goroutines, FD, CPU, throughput. Если Snowflake не помещается — build/capability gate `tor_snowflake` или runtime disable на конкретном low-memory profile.

#### M9 — «все виды входов» надо формулировать точнее

**Где:** design §0/§2/§14.

E-TOR покрывает все UI entry modes Nova и добавляет meek_lite manual. Но conjure/dnstt/full meek сознательно не подключаются.

**Фикс:** release wording: «all Nova UI entry modes + manual meek_lite». Если владелец требует conjure/dnstt — это отдельный future stage, не скрытый gap.

### LOW

#### L1 — TT10 acceptance provenance надо машинно закрепить

**Где:** commit TT10 / CI.

Сейчас зелёный acceptance описан в commit message; GitHub Actions run для ветки нет.

**Улучшение:** добавить существующий CI/smoke target (без новых deps), который сохраняет vet/test/race/crosscompile + `tor --verify-config` при доступном бинаре.

#### L2 — exception вне Tor scope стоит явно отметить в интеграции

**Где:** diff после `3525acf`: удалён `src/transport/proton/service_extras.go`.

Коммит `4313bba` объясняет это как baseline compile-fix дублирующих declarations, а не E-TOR feature. Это выглядит обоснованно, но patch-plan говорил не трогать proton.

**Улучшение:** зафиксировать как отдельный documented baseline exception при merge, чтобы Tor review не маскировал чужое изменение.

---

## 4. Стресс-тест инноваций

### 4.1 Mixed-set racing — **идея держит, текущая реализация нет**

Плюс: один Tor process с несколькими мостами действительно потенциально убирает последовательные минуты bootstrap. Fallback на последовательную ladder — правильная страховка.

Слабые места: winner может быть fabricated (`set[0]`), control multiline parser ненадёжен, meek_lite просачивается в auto, RaceWindow раздувает set per transport. При нескольких мостах одного транспорта событие хранит только transport, а не bridge identity, поэтому диагностика/обучение грубые.

**Условие устойчивости:** winner записывается только по доказанному bridge identity/fingerprint; unknown не обучает; mixed quota глобально bounded; meek manual-only.

### 4.2 Egress-мост — **держит для TCP vanilla/direct, не держит как «единая точка всего Tor»**

Socks5Proxy для OR traffic — хороший механизм, PT-proxy через тот же policy Dialer — тоже. Bootstrap-source anti-loop разумен. Но Snowflake создаёт отдельный UDP dataplane, а rendezvous принудительно direct-first. Поэтому утверждение «весь egress tor сходится в одной policy» сейчас неверно.

**Условие устойчивости:** описывать архитектуру как TCP egress hub + отдельный explicitly governed packet plane; pinned carrier обязан fail-closed на неподдерживаемом UDP.

### 4.3 Vanilla-through-carrier — **самая сильная инновация, но сейчас заблокирована torrc/lifecycle**

С точки зрения архитектуры идея хороша: Tor OR traffic идёт в локальный SOCKS5 proxy, затем через reserve.Carrier; pinned carrier code не делает direct fallback. Это именно то, что нужно для «Tor невидим для ISP» и высокой скорости релеев.

Слом сейчас: неправильный Socks5Proxy syntax и process retirement. После фикса это первый режим, который я бы проверял в поле.

**Self-loop:** kind `tor` исключён из auto carriers и отсутствует в enum `through`; это хороший by-construction guard. Дополнительно listener loop set защищает локальные сокеты.

### 4.4 Relay-scanner — **текущий вариант не держит**

Главная проблема — не IDS risk, а неверный wire protocol C1. Даже после исправления глубокий active scan CREATE2-подобными circuit handshakes будет дорог и заметен.

**Лучший вариант:** двухступенчатая модель: дешёвая modern OR-channel handshake для большего пула → глубокая проверка лишь малой top-bandwidth выборки, если действительно нужна. Persistent cooldown per relay, jitter и hard daily/hourly budget. Это уменьшит abuse signature и CPU/network cost на роутере.

---

## 5. План доработок и улучшений

### P0 — без этого FIELD_TEST запрещён

| Что | Где | Критерий готовности | Объём |
|---|---|---|---|
| Переписать relay probe под современный Tor link protocol | design §1.6/§4.3, `torscan/probe.go` | fixtures по Tor spec; живой modern Tor integration gate за env; больше нет legacy CREATED=0x04 | M/L |
| Исправить ControlSocket | design + `torrc.go`, supervisor | `tor --verify-config` + startup control socket smoke | S |
| Исправить Socks5Proxy credentials | design + `torrc.go`, supervisor | 3 корректных directives; egress bridge auth проходит | S |
| Canonical vanilla bridge line | `bridges.go`, torrc tests | vanilla torrc без PT token; verify-config green | S |
| Сделать process retirement обязательным перед restart | supervisor/service | ни один restart не spawn новый Tor до Stop old; no-orphan fake/integration tests | M |
| Закрыть Snowflake bypass при pinned carrier | torsnowflake + egress policy | named through => ноль direct broker/ICE/STUN/DTLS; unsupported packet path fail-closed | M |
| Исправить GETINFO multiline + winner unknown | `control.go`, supervisor | multi-key multiline fixtures; no fabricated winner | M |
| Raw control-char reject до normalization | `bridges.go` | valid-looking line с embedded CR/LF/TAB всегда ErrBridgeLineInvalid | S |
| Убрать process start races | `process.go` | defaults exists before Start; separate pid ownership; pid+exe guard enforced | M |
| Реализовать реальный TT6 integration gate | tests | direct/vanilla/PT/mixed `--verify-config`; default skip без env | M |
| Расширить FIELD_TEST | `FIELD_TEST_TOR_PROMPT.md` | отдельный Snowflake+pinned-carrier pcap + no-orphan after forced runtime restart | S |

### P1 — до релиза

| Что | Критерий | Объём |
|---|---|---|
| Убрать meek_lite из auto или изменить design явно | design/code совпадают | S |
| Сделать RaceWindow глобально понятным и bounded | status показывает реальный set; FD budget предсказуем | S/M |
| Зафиксировать semantics named carrier vs auto | pinned=strict fail-closed; auto=availability | S |
| Исправить 30s liveness grace | fake clock tests 4 fails + <30s/no teardown, >=30s/teardown | S |
| Relay ranking top-cohort then shuffle | быстрые relays реально имеют приоритет | S |
| Persistent relay-scan cooldown/rate budget | повторный scan не зондирует тот же relay агрессивно | M |
| Lowmem Conflux + FD/RLIMIT preflight | low-memory profile наблюдаем и управляем | M |
| Синхронизировать snowflake provenance version | go.mod/design/NOTICE согласованы | S |

### P2 — улучшения сверх дизайна

1. **Двухступенчатый scanner:** modern channel handshake как cheap proof, глубокая проверка только top-K. Это и быстрее, и менее похоже на активное сканирование.
2. **Strict vs availability egress profiles:** `strict-through:<kind>` для privacy/no-leak и `auto` для максимальной доступности. Named carrier уже почти ведёт себя как strict — надо сделать это официальным контрактом.
3. **Bridge-level learning:** хранить не только transport winner, но stable bridge identity/fingerprint + reason/latency. Тогда mixed-set реально обучается, а не просто переставляет transport.
4. **Platform capability envelope:** в status вывести `rss`, `fd_used/fd_limit`, `snowflake_available`, effective Conflux UX. На MIPS можно честно отключать Snowflake без разрушения остальных входов.
5. **Tor queue memory profile:** рассмотреть `ConfluxClientUX=throughput_lowmem` и после field — аккуратный `MaxMemInQueues`/ConnLimit, но только по измерениям, не угадывая значения.
6. **Conjure/dnstt как отдельная фаза:** только если владелец считает их обязательными. Не добавлять зависимости в текущий E-TOR без отдельного решения.

---

## 6. Риски для полевого этапа

До включения на живом роутере проверить после P0:

- `tor --verify-config` на **фактическом Entware Tor**, а не только renderer unit tests;
- какой Tor version установлен; legacy scanner assumptions больше нигде не остались;
- hard `ulimit -n`, реальный Tor ConnLimit, FD baseline b4 + Tor + PT;
- RSS/CPU Snowflake на MIPS/ARM при GOMEMLIMIT 32–64 МБ; KCP/smux/Pion могут быть существенно тяжелее compile smoke;
- pcap strict carrier отдельно для vanilla **и Snowflake**;
- forced restart во время bootstrap и после liveness death: одновременно существует ровно один owned Tor process;
- kill b4: owned Tor исчезает, PT/egress listeners закрыты, системный Entware Tor не затронут;
- mixed-set: unknown winner не записывается как webtunnel по умолчанию;
- relay scanner: rate budget, traffic volume и отсутствие burst к десяткам чужих ORPort;
- flash wear: data path `/opt`, EntryMemory/store writes bounded; Tor `AvoidDiskWrites 1` не отменяет наши собственные state writes.

### Рекомендуемый порядок поля после P0

1. `entry=direct`/minimal local verify только чтобы доказать process/control lifecycle без цензурной логики.
2. pinned `vanilla + through=proton/warp`: доказать главный no-leak invariant и скорость.
3. webtunnel/obfs4 direct с bait=none.
4. Snowflake direct, измерить RSS/CPU/UDP profile.
5. Snowflake + pinned carrier: либо честный fail-closed, либо только если реализован packet-capable carrier path.
6. auto mixed-set + winner learning.
7. только после этого 24–48h soak/FD.

---

## Итоговый gate

**FIELD_TEST_TOR_PROMPT.md: NOT READY.**

Минимальный путь к READY: закрыть C1–C6, H1/H2/H5/H8/H9 и strict-carrier часть C4, добавить real Tor verify-config/startup gate и Snowflake carrier pcap. Остальные H/M можно разделить между «до первого smoke» и «до релиза», но перечисленные P0 нельзя переносить в поле: иначе полевой прогон смешает ошибки протокола/жизненного цикла с реальной цензурой и даст недостоверный диагноз.

### Внешние источники, перепроверенные независимо

- Tor Specifications — Cell packet format: `https://spec.torproject.org/tor-spec/cell-packet-format`
- Tor Specifications — Creating and extending circuits: `https://spec.torproject.org/tor-spec/create-created-cells.html`
- Tor Specifications — Obsolete circuit extension handshakes: `https://spec.torproject.org/tor-spec/obsolete-circuit-extension.html`
- Tor Specifications — Control protocol / GETINFO: `https://spec.torproject.org/control-spec/commands.html`
- Debian torrc(5), testing/trixie-backports — `ControlSocket`, `Socks5Proxy*`, `ConfluxClientUX`, `ConnLimit`.
