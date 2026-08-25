# WARP H3 IMPLEMENTATION REPORT — этапы EH3/EH4/EH5 (продолжение E-H3)

**Дата:** 2026-08-25. **База:** fb43e8b0 (EH1+EH2). **bd:** b4x-qkr.
**Промпт:** `.ag/prompts/E-H3_CONT_AGENT_PROMPT.md`. **Дизайн:** `.ag/research/eh3-design.md` §6/§8/§10.

## Что изменилось (полный периметр сессии)

Новые файлы `src/transport/warp/`:
- `ladder.go` — контракт `packetTransport` (*Session и *H3Session удовлетворяют,
  compile-time assertions); `TransportDialer{Dial, ObserveValidation}`;
  `H3FirstDialer` (лестница H3→H2 с анти-осцилляционным гейтом);
  `ProbeUDPReachability` + `classifyProbeError` (три класса);
  `LadderMetrics` (h3_dial_total{result}, h3_fallback_to_h2_total).
- `ladder_test.go`, `discovery_h3_test.go`, `cover_test.go` — тесты.

Изменённые:
- `supervisor.go` — `SupervisorConfig.Dialer` (nil ⇒ прежнее поведение
  байт-в-байт; существующие H2-тесты зелёные без правок); `cur` →
  `packetTransport`; `healthLoop` принимает localV4 параметром; события
  `warp_transport_switched` / `warp_h3_negotiated`; `Status.LastTransport`;
  masque_connected несёт Detail `transport=h2|h3`.
- `discovery.go` — `H3VerifyConfig` (QUIC-ветка скана: probe → DialH3Session +
  trust gate → durability burst); QUIC-first порядок кандидатов;
  `EndpointScore.Transport`; burstReader переведён на интерфейс.
- `catalog.go` — `QuicCatalogCandidates()`: 6 адресов × 7 портов (42, v4-first),
  turbo = 1 seed. Версия карты НЕ менялась (CatalogVersion=1), SeedEndpoints не
  тронут (тест len==2 жив) — §34-гейт сохранён.
- `nfqwiring.go` — FakeQUICCover (EH5): профиль Nova + Arm/Release lifecycle.
- `docs/reports/warp/WARP_V2_REVIEW_BRIEF.md` — Часть III: секция E-H3 (карта
  файлов, режимы h2/h3, лестница), список тестов, ограничение №3 снято с учёта.

НЕ моё (параллельная сессия b4x-9aa, в верификацию не входило):
`netstack.go`/`netstack_test.go`, правки `supervisor_test.go`,
`config/warp.go`, `warpservice/service.go`.

## Вердикты по этапам

### EH3 — discovery и лестница H3→H2: **DONE**
- Лестница на уровне инстанса через `TransportDialer`. Подтверждённые классы
  переключения: `udp-egress-blocked`, `tls-alert` (+ `validation-timeout` как §6
  «handshake-ok-but-silent» через ObserveValidation). **tls-pin-mismatch
  исключён** — fail-closed, H2 того же endpoint умрёт идентично; маскирование
  пин-верdict'а запрещено. Согласовано с владельцем на старте («старт» без
  возражений на предложенные дефолты).
- Анти-осцилляция: гейт `h3BlockedUntil` (300 s, выровнен с RestartCooldown).
  Приёмочный тест `TestSupervisorLadderNoOscillationAcrossTicks`: 5 тиков при
  живом H2 (fakeserver) и мёртвом H3 (инжектированный udp-egress-blocked) →
  ровно ОДИН transport_switched, 5 masque_connected, H3-контакт ровно 1,
  LastTransport=h2.
- Cooldown-return: после истечения окна следующая генерация снова пробует H3
  (тест с управляемыми часами, сдвиг +301 s).
- Discovery: QUIC-кандидаты только из версии карты (юнит-гейт 42/турбо-1);
  быстрая UDP-reachability проба (бюджет 1.5 s default) различает
  reachable / udp-refused / udp-blackhole — blackhole = egress-block verdict,
  кандидат умирает на скорости пробы без прожига полных сессионных бюджетов
  (тест <4 s). Reachable → полная верификация DialH3Session+burst.
- Классификация пробы построена на верифицированных типах vendor quic-go v0.61
  (`internal/qerr/errors.go:86–127`: VersionNegotiation/StatelessReset =
  edge ответил; IdleTimeout/HandshakeTimeout = тишина).

### EH4 — наблюдаемость: **DONE**
- События: `warp_h3_negotiated` (с colo/status/duration),
  `warp_transport_switched` (FailureClass=reason, Detail from=/to=/reason=).
  Идут единственным путём Sink супервизора → warpwire (P1 default),
  payload-ключи failure_class/detail/colo — без правок warpwire.
- Colo: путь H3ConnectResult.Colo → единый TransportAttempt.Result →
  EvMasqueConnected.Colo → payload["colo"] проверен тестом
  `TestSupervisorH3ColoFlowsToTraceEvent` (TST доходит до события и Status.LastColo).
- Метрики: LadderMetrics.H3DialTotal[result] ("ok"/класс отказа),
  FallbackToH2, Switches, H3Blocked; покрыты тестами лестницы.

### EH5 — прикрытие bootstrap и финал: **DONE**
- `FakeQUICCover` в nfqwiring.go по дисциплине ControlFlowGuard: движок без
  netfilter, `CoverApplier` биндится полевым слоем. Профиль Nova:
  ipset CF-v4+v6 из версии карты (162.159.198.0/24+199.0/24, 103::/48+104::/48),
  порты ровно каталоговые 7, fake-bin repeats×6, autottl — `Validate()` отвергает
  любой дрейф (юнит соответствия без реального NFQ: `cover_test.go`).
- Жизненный цикл: Arm строго перед H3-диалом; Release на каждом терминальном
  исходе; при успехе — ТОЛЬКО после trust gate (ObserveValidation(success) —
  §C.4 cutoff). Отказ Arm = fail-closed к H2 на генерацию БЕЗ отравления гейта
  (локальная проблема ≠ сетевой вердикт; следующий цикл повторяет H3).
- Интеграция с лестницей — через `BootstrapCover` в LadderConfig.Cover
  (`TestLadderCoverIntegration`). В warpservice composition НЕ подключён —
  это слой E7/field (честно: компонент готов, сборка — отдельная задача).

## Верификация (выполнено, воспроизводимо)

Контейнер golang:1.25.3-alpine `b4x-eh3-deps`, код ТОЛЬКО docker cp:

```sh
docker exec b4x-eh3-deps sh -c 'cd /repo/src && go vet ./transport/... && go test ./transport/... -count=1'
docker exec b4x-eh3-deps sh -c 'cd /repo/src && go test ./... -count=1'          # полный суит
docker exec b4x-eh3-deps sh -c 'cd /repo/src && CGO_ENABLED=1 go test ./transport/warp/ -count=1 -race'
```

Результаты на изолированном дереве «baseline fb43e8b0 + ровно файлы этой сессии»:
- vet ./transport/... — чисто;
- полный суит: **56 ok / 0 FAIL**;
- `-race ./transport/warp`: **ok** (~29 s);
- новые тесты лестницы/discovery/cover — все PASS (см. листинг прогона в чате сессии).

go.mod/go.sum/vendor: изменений зависимостей НЕТ (источник истины остаётся на диске;
обратное копирование не требуется).

## Честные ограничения и риски

1. **Authority открытый вопрос** (владелец решает перед полем): extended CONNECT
   шлёт `:authority IP:port` по мандату; pinned-usque шлёт домен шаблона;
   «домен=403» доказан только для plain CONNECT (warp-socks). Переключение — одна
   строка в `dialH3Once`.
2. **Live-CF нет** (consent rule): всё против loopback-стендов; полевые UDP-VN
   данные field1 (16/16 на {443,500,1701,4500}×{198.1,.2}) поддерживают
   предположения о живости QUIC-ветки, но e2e H3-диалект в поле не проверялся.
3. **Сессия vs проба**: EH2-классификатор диала (`classifyH3HandshakeError`)
   отображает таймауты в udp-egress-blocked; различение refused/blackhole есть
   на уровне ПРОБы discovery, сессионный диал его не различает. Осознанный
   компромисс (лестнице достаточно подтверждённости класса).
4. **Пре-существующая гонка vendor amneziawg-go**: полный `-race ./transport/wg`
   падает (Timer.Del vs NewTimer.func1, timers.go) И НА БАЗЛАЙНЕ fb43e8b0 —
   A/B-проверка worktree'ом. Вне скоупа («чужие пакеты не трогаешь»), фиксация
   здесь для будущего тикета.
5. **Параллельная сессия**: netstack-WIP (b4x-9aa) не компилируется и НЕ входит
   в этот периметр; финальный гейт снят на чистом дереве базлайн+мои файлы.
6. warpwire `priorityFor`: новые события — P1 default; в
   RequiredPromotionEvents НЕ добавлены (осознанно: promotion-контракт §62.5
   не расширялся).
7. Метрики — внутренние счётчики движка; экспорт в реестр src/warp — слой
   интеграции.
