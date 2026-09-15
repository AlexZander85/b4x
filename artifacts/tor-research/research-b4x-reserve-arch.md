# Research: архитектура резервных туннелей b4x (branch agent/classifier-v2.3-capture-envelope, HEAD adbecc2)

Дата: 2026-09-15. Внутренний отчёт по собственному коду — входные данные для дизайна E-TOR.

## A. Интеграционный контракт резервного туннеля (канон)

Каждый туннель = два Go-пакета + пять точек врезки:

1. **transport-пакет** (`src/transport/<svc>/`) — контрольная плоскость и движок (протокол, bootstrap, обфускация).
2. **service-пакет** (`src/<svc>service/`) — тонкая сборка: `Build(cfg, Options) (*Runtime, error)` → `Start(ctx)` → supervisor tick 30 с → `Stop()`. Никакой сети в Build.
3. **`src/reserve/registry.go`**: `Kind` (kebab-case) + `Priority` + `Carrier`-интерфейс:
   ```go
   type Carrier interface {
       Kind() Kind
       DialStream(ctx, addr netip.AddrPort) (net.Conn, error)
       SupportsUDP() bool
       DialUDP(ctx, addr netip.AddrPort) (net.Conn, error) // только если SupportsUDP
   }
   ```
   Приоритеты: warp 60, masque 50, h3 40, opera 30, fxvpn 20, proton 10 (строго ниже базовых; «никакой молчаливой подмены транспортов» — урок Nova I4 RegionTransportPolicy).
4. **`src/config/<svc>.go`**: `XxxConfig` с json-тегами + `Effective*()` (0/"" = дефолт) + поле в `SystemConfig` (types.go) + `validateXxx(v)` в validation.go (**валидация ВСЕГДА, даже при enabled=false**).
5. **`src/http/handler/<svc>.go`**: `SetXxxRuntime` (atomic.Pointer, nil-safe), `RegisterXxxApi()` в RegisterEndpoints (common.go). Body-лимит 4 КБ, swagger-аннотации.

Wiring в `src/main.go` (блок после warp; для proton — main.go:648-668): if-gate `System.X.Enabled` → Build → Start → `reserve.Register(rt)`; shutdown (main.go:761+): `reserve.Unregister(kind)` **ДО** `Stop()`. Текущий gap: opera/fxvpn отсутствуют в shutdown-цепочке — новый туннель обязан делать правильно.

## B. Анатомия protonservice (эталон, src/protonservice/)

- `service.go` (1209): Runtime, состояния `idle → ntp-wait → registering → node-select → seeking → trust-gate → established → (renewing|backoff)`; `running/listening` отчитываются отдельно.
- Дисциплины: `MaxRestartsPerHour=6`, `RestartCooldown=300s`, `superviseTick=30s`, `eventsRingCap=32`; `restartGuard` (rolling 1h окно, канон fxvpservice); `registeredThisBoot atomic.Bool` (≤1 регистрация на boot); `jailedStrikes=2` (handshake ok + data gate failed ×2 → ротация профиля + strike узла 300 с).
- Анти-петля: `BypassSuffixes` (контрольные хосты + DoH — всегда DIRECT) + self-loop guard в `carrierSession` (dial на entry-IP активного узла → отказ ДО state-чека).
- `carrier.go`: Kind/SupportsUDP/DialStream/DialUDP через `tun.Netstack.DialContextTCPAddrPort`; honest refusal `ErrNotListening`.
- `exitprobe.go`: TLS+HTTP/1.1 к `www.cloudflare.com/cdn-cgi/trace` ЧЕРЕЗ netstack (системный DNS не участвует); один probe за раз; country-mismatch → strike + retire.
- `kernelroute.go`: PBR `fwmark 0xB4B4/table 5182/priority`, `ip route get ... fwmark` verify, fail-closed rollback, Assert каждый tick.
- Метрики (observability/proton.go): `proton_dial_total{result}`, `proton_handshake_total`, `proton_profile_seek_total`, `proton_registration_total` и т.д. События: snake_case имена, kebab-case классы (`proton-jailed`, `proton-exit-mismatch`).

## C. Конфиг-паттерн

`ProtonConfig` (src/config/proton.go): Enabled, IdentityPath, Location{Mode,Country,Host}, Obfuscation{Enabled,PreferredProfile,SNIPool,I1Adaptation}, Port (0→round-robin [443,88,1224,51820,500,4500]), MTU (0→1420), BootstrapThroughCarrier, UserAgent/AppVersion/APIVersion, MaxRestartsPerHour (0→6), TunnelMode (netstack|kernel), KernelDevice (""→b4proton0), RouteMark (0→0xB4B4), RouteTable (0→5182).

- Миграции НЕ нужны для новой подсистемы: новый json-ключ unmarshal'ится в zero value = disabled (`CurrentConfigVersion=53` не растёт).
- `NewConfig()` задаёт явные дефолты; `ApplyConfigDefaults` — рефлексивное заполнение нулей.
- Ошибки валидации: `v.addf("system.proton.<field>", "invalid_value", map[string]any{...})`.

## D. Переиспользуемые примитивы

| Примитив | Путь | Значение для E-TOR |
|---|---|---|
| SOCKS5 сервер | src/socks5/server.go (main.go:561) | RFC1928/1929, CONNECT+UDP ASSOCIATE, maxConnections 1024, `SetRouteDecisions(*routing.DecisionStore)` — шов скоупинга |
| SOCKS5 клиент | src/socks5/client.go: `DialUpstream(ctx, cfg, targetHost, targetPort)` — **поддерживает hostname (atypDomain)** | DialStream к tor SOCKS; `.onion` передаётся нересолвленным |
| SO_MARK bypass | socks5/client.go `ApplyBypassMark(d, mark)` | маркировка egress-сокетов |
| WG/AWG движок | src/transport/wg/ | Session/Seeker/TrustGate/Watchdog — паттерны, не код |
| StrikeState / FileLastGood | src/transport/wg/seek.go, lastgood.go | страйки мостов (addr+threshold+cooldown), last-good файл (atomic 0600, *.corrupt) |
| restartGuard | fxvpservice (канон) / protonservice | как есть |
| failoverDial | operaservice/service.go:204-302 | direct 5s → негативный кэш 60s (2 фейла) → carrier + self-heal проба |
| DoH с mark | src/dns/doh.go `MarkedDoHClient` | резолв хостнеймов мостов без утечек в ISP DNS |
| NFQ bait | packetmark/marks.go `MarkOperaEgress 1<<23`, `MarkFxvpnEgress 1<<22` + operaservice/nfqbait.go + tables.ApplyOperaBaitOnly | паттерн: SO_MARK egress + OUTPUT mangle → action queue → fakedsplit/fakeddisorder. **Следующий свободный бит: 1<<21** |
| uTLS | src/transport/opera/utfingerprint.go, fxvpn; quic-go b4x-fork `Config.UTLSClientHelloID` | фингерпринты TLS (v1.8.2 — та же версия, что у snowflake!) |
| Observability | src/observability/ (bounded 1024 серий), handler.GetMetricsCollector().RecordEvent | метрики/события |
| crossservice | src/crossservice/validation.go | изоляция сервисов |
| CLI-паттерн | src/cmd/fxvpnctl, warpenroll | `b4 torctl` |
| Мультиплекс/quic | src/quic/ (initial keys, sniff), quici1.go | QUIC-маскировка (не для tor, но рядом) |

## E. Зависимости (go.mod)

amneziawg-go/v3 v3.1.20260814, quic-go v0.61.0 (**b4x-fork** AlexZander85/quic-go v0.61.0-b4x.2 с uTLS-швом), utls v1.8.2, go-nfqueue v1.3.2, netlink v1.7.2, cobra v1.10.1, gorilla/websocket v1.5.3, gvisor 2023-12-02, x/crypto v0.54.0. **Tor-библиотек нет**; CGO_ENABLED=0 всегда; LINUX_ARCHS включает mips/mipsle/mips64 + softfloat, armv5-7, riscv64 и др.

## F. Формат дизайн-документа и патч-плана (по proton-awg-design/patch-plan)

Дизайн: заголовок `# E-X: ... — дизайн (vN, дата)`, Статус: ПРОЕКТ; позиция/роль; родительские слои; таблица Источников (research-файлы). Разделы: §0 роль и честные границы → §1 протокол (факты по референсам, file:line) → §2 bootstrap-устойчивость → §3 обфускация → §4 identity/хранилище → §5 локации → §6 здоровье/жизненный цикл → §7 интеграция → §8 наблюдаемость → §9 этапы (таблица Этап|Содержимое|Верификация) → §10 красные линии → §11 открытые вопросы → §12+ зафиксированные будущие композиции.

Патч-план: §0 дисциплина (правила репо, consent rule, ноль зависимостей, таксономия) → §1 карта файлов (создать/изменить/НЕ трогать) → §2..§N этапы PTn (сигнатуры в Go-блоках, DoD PTn) → матрица фейк-сценариев → acceptance-чеклист → риски и откаты. «Никакого кода на будущее»; vet/test/race зелёные; регресс = 0.

Review-формат (opera/fxvpn/proton-reserve-review.md): вердикт → карта покрытия по слоям → находки CRITICAL→HIGH→MEDIUM→LOW с file:line → рекомендации → глава «Маскировка».

## G. Красные линии (для туннелей)

1. **Ноль новых зависимостей** — go.mod/vendor не меняются (ИСКЛЮЧЕНИЕ для Tor санкционировано владельцем в рамках этой задачи — дизайн E-TOR §12 фиксирует точный перечень).
2. Конфиг валидируется и в выключенном состоянии.
3. Секреты 0600 tmp+fsync+rename, карантин *.corrupt, Redacted() наружу.
4. Живые API-запросы из юнит-тестов запрещены (только httptest); поле — с разрешения владельца.
5. События snake_case, классы kebab-case, метрики с префиксом подсистемы.
6. Приоритет ниже базовых; никакой молчаливой подмены.
7. Anti-loop: bypass-суффиксы + in-code self-loop отказ.
8. UDP-scope никогда в TCP-only резерв (fail-closed, честный tcp-only).
9. Маскировка не ослабляет верификацию; nesting/bait никогда не включаются молча.
10. go vet && go test && go test -race зелёные; ноль горутин при enabled=false.
11. «Не коммитить и не пушить без прямой просьбы» (AGENTS.md) — для E-TOR пуш санкционирован владельцем в постановке задачи.

## H. Ограничения платформы

Keenetic/Entware — основная платформа; ~15 LINUX_ARCHS (mips first-class) → только чистый Go; CGO_ENABLED=0; память: GOMEMLIMIT от 32 МБ floor, /tmp tmpfs ~243 МБ; роутер без RTC (ntpWaitBudget 120 с + notBefore-slack 5 мин); PPE offload может обходить netfilter (mark-контракт); сборка arm64 только docker CGO_ENABLED=0; живой Keenetic — ошибочный деплой роняет YouTube владельца.

## I. Зафиксированная композиция Tor (proton-awg-design §12 — родитель этого дизайна)

§12.3: E-TOR как scoped-egress (не глобальный тумблер, в отличие от ProtonVPN-Next): scoped-маршрутизатор даёт Tor только выбранные scope'ы (.onion + явно назначенные); carrier = сессия резерва (`Options{Carrier DialFunc}`); Tor-runtime-менеджер: spawn/supervise, SOCKS на loopback, control-опрос с бюджетом 180 с (роутер слабее телефона), data-dir /opt/etc/b4/tor 0700, отдельный restartGuard — падение Tor НЕ рвёт носитель; DNS/.onion: виртуальный диапазон 198.18.0.0/15 + маршрутизация обратно в Tor; UDP через Tor запрещён на уровне scoped-маршрутизатора; метрики tor_bootstrap_seconds / tor_circuits_alive; инвариант «Tor не утекает мимо носителя» (фейк-носитель + счётчики); kill-семантика при падении носителя.

§12.4: условия включения (устойчивая полевая потребность; отдельное решение владельца по зависимости с явным исключением из красной линии §10.1 + NOTICE; отдельный этап со своим acceptance) — **все три условия выполнены в рамках задачи E-TOR (решение владельца от 2026-09-15)**.
