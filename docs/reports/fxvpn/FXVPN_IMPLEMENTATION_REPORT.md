# E-FXVPN — IMPLEMENTATION REPORT (Firefox VPN reserve transport, FX1–FX5)

Дата сдачи: 2026-08-25. Ветка: `agent/classifier-v2.3-capture-envelope`.
Серия коммитов этапа: f9f3eadc (FX1+FX2, control+data plane) → cccc974e (FX3, pool)
→ 76d76dd5 (FX4, config+service+handlers) → FX5 (этот запуск: метрики, CLI, доки).
Дизайн: `.ag/research/fxvpn-reserve-design.md`. Карта слоя для ревьювера:
`docs/reports/warp/WARP_V2_REVIEW_BRIEF.md`, Часть III, секция E-FXVPN.
Ревью делает владелец у ревьювера — этот отчёт фиксирует факты и отклонения.

## 1. Карта пакета (построчно)

### src/transport/fxvpn — движок

| Файл | Содержание |
|---|---|
| classes.go | FailureClass fxvpn-* константы; QuotaError{RetryAfter}/TokenInvalidError/GuardianHTTPError/FxAError{errno}; Classify() |
| privatefile.go | saveAtomic 0600 (tmp+fsync+rename) + карантин *.corrupt; ErrStoreAbsent/ErrStoreCorrupt |
| pin.go | TOFU SPKI pins.json: первый контакт пишет пин, mismatch = ErrPinMismatch fail-closed |
| fxa.go | authPW через stdlib crypto/pbkdf2+hkdf; Hawk; login email-2fa + errno107 fallback ×2; VerifySession; OAuth client_id 5882386c6d801776; refresh сохраняет старый RT при отсутствии нового |
| guardian.go | /fpn/token\|status\|activate; JWT без проверки подписи (пиннинг); claim-time offset детект; X-Quota-*; Retry-After |
| fastly.go | PoW 62², PAT-fallback, clientmetrics; exit-IP-привязка cookie ⇒ общий transport+jar challenge/API; per-client сериализация |
| serverlist.go | Remote Settings ETag/TTL кэш; bare=default connect :2499; protocols[].name==connect override; masque игнорируется (задел); quarantined исключены; stale-fallback; corrupt→карантин |
| store.go | accounts.json v1 {email,label,password?,refresh_token?}; Validate; Redacted() |
| varint.go / h3qpack.go / h3wire.go | QPACK RFC 9204 + фреймы RFC 9114 (перенос проверенного кодека E-H1, префиксы fxvpn:) |
| dialpolicy.go (+_linux/_other) / dialudp.go | SO_MARK/SO_BINDTODEVICE до bind; RequireMark fail-closed; Dialer() для TCP-H2; ListenUDP 8MB |
| tunnel.go | TunnelOpener контракт; ConnectRejectedError.IsQuota(); failureTracker ≥3 РАЗНЫХ authority timeout/502 ⇒ unhealthy |
| h2tunnel.go | tls ALPN h2 → http2.ClientConn; PING keepalive 10s/budget15s; CONNECT authority+Bearer; ring-buffer 1MB; half-close контракт (CloseWrite обязателен) |
| h3tunnel.go | рукописный H3 поверх quic-go: InitialPacketSize=1200, ALPN строгий, establishment deadline с обязательным сбросом после 2xx, DATA-relay, classifyH3HandshakeFailure |
| ladder.go | PreferH3: switch только по подтверждённым классам (udp-egress-blocked/h3-negotiation-failed); один эпизод = один switch; cooldown возврата 300s молча; account-level 407/429/502 не переключают |
| exitprobe.go | CONNECT→TLS внутри релея→cdn-cgi trace→ip=/loc=; auto/match/mismatch классы |
| pool.go | жизненный цикл II.2.1 (8 состояний), pre-emptive ротация (<15% или reset-lead) с прогревом ДО swap; reset-aware recycling; бан-лестница 3 strike + backoff+jitter; BLOCKED одно событие/эпизод |

Тесты движка: 30+ сценариев против фейков FxA/Guardian/RemoteSettings/challenge/TLS
(уникальные self-signed серты) и fake H2/H3 edges; матрицы happy/502/silent-drop/
teardown/hang/wrong-JWT/quota/pin-mismatch/blackhole; лестница и exit-probe таблицами.

### src/fxvpservice — сборка и супервизия

| Файл | Содержание |
|---|---|
| service.go | Build без I/O; Runtime{pool,cp,sl,preferH3,guard}; tick 30s: RecycleDue→RenewActivePassIfNeeded→ensureSession→exportPoolMetrics; ensureSession: RotateIfDue→ActiveBearer→guard.allowed→resolveLocation→dialSession(лестница)→атомарный swap→verifyExit; restartGuard ≤6/час sliding + cooldown 300s; антипетля BypassSuffixes+активная нода; DialStream TCP-only; Status JSON Дополнения 3; Locations/SetLocation/ValidateLocation/TestAccount |
| metrics.go (FX5b) | recordDial: атомик + реестр синхронно; exportPoolMetrics: fxvpn_pool_state (все 8 состояний, нули включительно) + fxvpn_quota_remaining_bytes (только известное значение); точки обновления — тик и пул-события |
| service_test.go | guard капы/cooldown/sliding-window, bypass-таблица, classify, disabled-smoke+lifecycle |

### src/http/handler/fxvpn.go — API surface

Маршруты Дополнения 3 + seam SetFxvpnRuntime (паттерн SetClientHelloSessionController);
честный minimal shape при enabled-but-unwired; порядок decode-vs-runtime в accounts/test
зафиксирован тестом. Swagger-аннотации краткие.

### Прочее

| Файл | Содержание |
|---|---|
| src/config/fxvpn.go | system.fxvpn схема off-by-default + EffectiveRotateThreshold |
| src/observability/fxvpn.go | имена метрик таксономии |
| src/observability/observability.go (FX5b) | минимальная gauge-поддержка: MetricsRegistry.Set() (replace, не accumulate; общий maxSeries; nil-safe), Gauges в MetricsSnapshot, сортировка, Reset |
| src/http/handler/prometheus.go (FX5b) | рендер gauges: # HELP/# TYPE gauge/значение |
| src/cmd/fxvpnctl/main.go (FX5c) | L0 CLI: login/import/list/test; exit 3=needs_code; env B4_FXVPN_PASSWORD; секреты не печатаются |

## 2. Верификация сдачи (исполненные команды, docker golang:1.25.3-alpine,
свежий контейнер b4x-agent; дерево = git archive HEAD + файлы FX5 + gitignored
src/http/ui/dist; скелет /repo/artifacts/remediation/logs)

```text
A0 базовая линия (чистый HEAD):
  go vet ./...                                   → RC=0, чисто
  go test ./... -count=1                          → все ok, 0 FAIL

A1 финал (HEAD + файлы FX5):
  go build ./...                                  → OK
  go vet ./...                                    → RC=0, чисто
  go test ./... -count=1                          → все ok, 0 FAIL
  CGO_ENABLED=1 go test -race ./transport/fxvpn/... ./fxvpservice/... → ok (обязательный)
  CGO_ENABLED=1 go test -race ./...               → 3 pre-existing FAIL, см. ниже
  gofmt -l ./observability/ ./http/handler/prometheus.go ./fxvpservice/ ./cmd/fxvpnctl/
                                                  → пусто (мои файлы)
CLI смоук (офлайн-пути): usage / import → redacted вывод / list → OK
```

Полный -race ./... — три FAIL, ВСЕ pre-existing (A/B доказан прогоном тех же команд
на чистом HEAD в том же контейнере, воспроизведение 1:1):

| Пакет | Тест | Статус |
|---|---|---|
| transport/wg | TestSeekVanillaFailsAgainstAwgEdge | известен: amneziawg-go timers.go race, bd b4x-1v2 |
| capture/ppe | TestAutoEnableRollbackOnSelfTestFailure | чужая зона, падает на HEAD без моих файлов |
| lab | TestSessionControllerCapturesHelloAndPublishesResult | чужая зона, падает на HEAD без моих файлов |

Дозорные пункты (не мои регрессы, зафиксированы фактами):
- handler TestTestSessionLifecycleRequiresHeadersAndIsIdempotent флапает ТОЛЬКО при
  -count≥2 в одном процессе ("systemd-run not found") — воспроизведён и на чистом HEAD;
  при штатном -count=1 полный суит зелёный дважды (A0 и A1).
- gofmt -l: observability/warp.go не-gofmt-нут УЖЕ на HEAD (файл не трогался).

## 3. Self-report: план-отклонения от промптов FX1–FX4/FX5

1. **x/net/http3 отсутствовал** — промпт FX2 предполагал готовый http3-пакет; в vendor
   только http2+hpack. Решение владельца: рукописный минимальный H3 поверх сырого
   vendored quic-go (вариант «а»), переиспользование кодека E-H1. Ноль новых deps.
2. **operaservice-паттерн вместо немедленной проводки в демон** — runtime собирается и
   тестируется как сервис, но main.go демона fxvpn не стартует (аналог opera до b4x-6da).
   Проводка — отдельный follow-up; handlers отвечают честным «unwired» shape.
3. **Persist location через общий config-API** — PUT /api/fxvpn/location применяет
   локацию in-memory и kick'ает цикл; запись b4.json остаётся за generic config-API GUI.
   Задокументировано в handler-комментарии.
4. **Gauge-поддержка реестра добавлена (решение владельца, вариант А)** — промпт FX5b
   требовал gauge-метрики, реестр имел только counters/histograms. Добавлен минимальный
   аддитивный Set()+Gauges+# TYPE gauge (~30 строк, чужая логика Inc/Observe не тронута);
   тесты gauges_test.go фиксируют replace-семантику, maxSeries, изоляцию namespace.
5. **cmd/fxvpnctl включён в объём явным словом владельца** в этом запуске (промпт
   допускал опциональность). Реализованы login/import/list/test; EnterVerificationCode
   путь = --code у login/test (exit 3 = needs_code).
6. **Квота-gauge обновляется дискретно** (тик 30s + события пула), а не на каждый байт —
   X-Quota-* приходит от Guardian, локального байтового счётчика сессии нет (в отличие
   от дизайна §3 «локальный счётчик»: решено опираться на серверные заголовки как на
   единственный источник истины; уточнить на поле).

## 4. Ограничения (честно)

1. **Живого контакта с Mozilla/Fastly НЕ БЫЛО** (consent rule): вся верификация протокола
   против фейковых стендов + верифицированных констант референса firefox-vpn-client и
   mozilla-central. Полевая сессия — отдельно и явно (доступности FxA/Guardian из РФ,
   частота Fastly-challenge, поведение X-Quota-Reset).
2. Masque/RFC 9298 (UDP-эгресс) — задел: продакшн serverlist сегодня несёт bare connect;
   ветка включится серверным переключением protocols[].
3. L1 авто-регистрация не реализована вовсе (красная линия II.4 №9): только L0 вручную.
4. Метрики fxvpn появляются в /metrics только когда runtime собран и экспортировал хотя
   бы раз (Build+tick/событие); при невключённом транспорте серий нет — честное отсутствие.
5. Проводка в демон, scoped-маршрутизация kind:fxvpn на живом роутере, GUI-панель — вне
   этапа (follow-up'ы).

## 5. Как проверить (владельцу)

```bash
docker run -d --name b4x-agent golang:1.25.3-alpine sleep 14400
docker exec b4x-agent apk add --no-cache gcc musl-dev
git archive HEAD --format=tar -o /tmp/fx5.tar && mkdir -p /tmp/fx5src && tar -xf /tmp/fx5.tar -C /tmp/fx5src
docker cp /tmp/fx5src b4x-agent:/repo
docker cp <host>/src/http/ui/dist b4x-agent:/repo/src/http/ui/dist     # gitignored, embed!
# ...скопировать файлы FX5 поверх (или коммит, когда будет дано слово)
docker exec b4x-agent sh -c 'cd /repo/src && go build ./... && go vet ./... && go test ./... -count=1'
```
