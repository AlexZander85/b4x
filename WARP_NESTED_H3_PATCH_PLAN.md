# ПАТЧ-ПЛАН — цикл исправлений по итогам ревью Фазы 3

**Проект:** b4x WARP-слой — Nested Matrix (E-NM) + HTTP/3 Transport (E-H3)
**Источник:** отчёт ревью `WARP_NESTED_H3_REVIEW_REPORT` (Фаза 3 из 3, 2026-08-27, вердикт **agree-with-changes**)
**База для патчей:** снапшот `b4x-agent-classifier-v2.3-capture-envelope` (пакеты `src/transport/nested`, `src/transport/wg`, `src/transport/warp`; vendored `src/vendor/github.com/amnezia-vpn/amneziawg-go/v3`)
**Исполнитель:** агент-имплементатор. Документ самодостаточен: все находки ревью развёрнуты ниже, обращение к отчёту не требуется.

---

## 0. Контракт для исполнителя (обязателен к прочтению перед стартом)

### 0.1. Нумерация и источники

Находки ревью цитируются по стабильным идентификаторам: `MAJOR-1…MAJOR-5`, `M-1…M-18` (MINOR), `N-1…N-8` (NIT). Нумерация MINOR — по порядку появления в отчёте ревью; обратите внимание: сводная таблица отчёта декларировала «17 MINOR», но фактический список содержит **18** записей — настоящий план покрывает все 18 (расхождение учтено в матрице трассировки §12). Каждый патч ниже содержит ссылку `Источник:` — по ней находка восстанавливается однозначно.

### 0.2. Порядок исполнения

1. Патчи исполняются **батчами 1 → 8** (§1). Внутри батча порядок свободен, кроме явно указанных зависимостей.
2. **Один патч = один коммит.** Формат сообщения: `fix(<scope>): PATCH-XX — <суть>` (scope ∈ `warp | nested | wg | vendor | tests | docs | ci`).
3. Каждый коммит обязан оставлять ветку зелёной: минимальный прогон — `go vet ./transport/... && go test ./transport/... -count=1`; полные ворота — §11.
4. Тесты пишутся **в том же коммите**, что и изменение. Патч без теста не принимается, если в спеке указан хоть один тест.
5. По завершении батча — запись в `changelog.md` (дисциплина репозитория) одной строкой на патч.

### 0.3. Жёсткие ограничения

- **Не менять публичные API**, если спека патча явно этого не требует (единственные запланированные расширения API: `H3SessionConfig.ResponseBudget`, `H3SessionConfig.E2EProbe`, `*Config.Metrics`, `StatusDetailed()` — все добавляющие, не ломающие).
- Не рефакторить соседний код «заодно»; диффы минимальные.
- **Vendored-код** (`src/vendor/...`) правится только по процедуре `wg/NOTICE.md` (Modifications-запись + re-pin hash) — см. PATCH-03; больше никаких правок вендора в этом цикле нет.
- Все новые тайминги/бюджеты — только через конфиг-поля с дефолтами и именованными константами; никаких магических чисел в теле функций.
- Комментарии/идентификаторы в коде — на английском (стиль кодовой базы); классы событий — snake_case, новые классы согласованы с таксономией design §5 (см. PATCH-07).
- Структурный класс вместо сравнения строк — везде, где добавляется новая классификация (паттерн уже принят в кодовой базе).

### 0.4. Окружение

Go 1.25.3, vendor-режим, офлайн (все тесты на фейк-стендах: `fakeh3_test.go`, `fakeserver_test.go`, fake `RouteRunner`, `masque_awg_e2e_test.go`). Команды сборки/тестов выполняются из `src/`.

### 0.5. Соглашения о размере работ

S — до ~30 строк диффа; M — 30–150; L — 150+ или затрагивает конфиг-схему/несколько пакетов. Оценки даны для планирования, не для торга.

---

## 1. Карта патчей, батчи и граф зависимостей

### 1.1. Сводная таблица

| ID | Источник | Приоритет | Основные файлы | Суть | Размер |
|---|---|---|---|---|---|
| PATCH-01 | MAJOR-1 | **P0** | warp/ladder.go, warp/h3session.go | silent-after-handshake → switch-класс H2 | M |
| PATCH-02 | MAJOR-2 | **P0** | warp/h3session.go | раздельные бюджеты dial/response | M |
| PATCH-03 | MAJOR-4 | **P0** | vendor/…/timers.go, wg/NOTICE.md | data race в amneziawg-go + re-pin | S |
| PATCH-04 | MAJOR-3 | **P1** | nested/wgmasque.go | teardown старого KernelRouteCarrier | M |
| PATCH-05 | M-12 | P1 | nested/wgmasque.go | watch от производного ctx, Stop ждёт done | S |
| PATCH-06 | M-3 | P1 | nested/kernelroute_ops.go | дедуп route-lost по эпизоду | S |
| PATCH-07 | M-14 | P1 | nested/matrix.go, nested/wgmasque.go, nested/metrics.go | таксономия child-start-failed / child-invalidated | S |
| PATCH-08 | M-18 | P1 | nested/masque_awg_e2e_test.go | e2e kill-inner / kill-WAN для M+W и W+M | M |
| PATCH-09 | MAJOR-5 | **P1** | nested/matrix.go, nested/wgmasque.go, wg/nested_runtime.go | врезка ObserveGate в три рантайма | M |
| PATCH-10 | M-5 | P2 | warp/h3session.go | classifyUDPListenError: локальные ошибки ≠ сетевой вердикт | S |
| PATCH-11 | M-6 | P2 | warp/h3session.go | errors.Is → errors.As для quic-типов | S |
| PATCH-12 | M-17 | P2 | warp/h3session.go | CRYPTO_ERROR 0x131 → FailureTLSPin | S |
| PATCH-13 | M-16 | P2 | warp/h3session.go | дефолт HandshakeBudget 20с → 10с | S |
| PATCH-14 | M-1 | P2 | nested/kernelroute.go | порядок пина add→replace-fallback | S |
| PATCH-15 | M-2 | P2 | nested/kernelroute.go, nested/matrix.go, nested/wgmasque.go | AttemptV6: реализовать двухсемейственный пин | M |
| PATCH-16 | M-11 | P2 | nested/masque_carrier.go | proof-гейт на запись в masque-плейн | S |
| PATCH-17 | M-4 | P2 | nested/matrix.go, nested/wgmasque.go | post-connect сверка edge-IP/colo | M |
| PATCH-18 | M-7 | P3 | warp/pump.go | ICMPv6 Packet-Too-Big | M |
| PATCH-19 | M-8 | P3 | warp/h3session.go | ironclad-lite: слот E2EProbe | S |
| PATCH-20 | M-9 | P3 | docs (отчёт реализации) | InitialPacketSize — фиксация ограничения | S |
| PATCH-21 | M-13 | P3 | warp/h3session.go | sync.Pool для WrapH3Datagram | M |
| PATCH-22 | M-10 | P3 | warp/discovery.go | резерв слотов H2 в шейпе скана | S |
| PATCH-23 | M-15 | P3 | warp/nfqwiring.go | retry/эскалация Release | M |
| PATCH-24 | N-1 | P3 | warp/h3session.go | cf-warp-colo lowercase-сравнение | S |
| PATCH-25 | N-2 | P3 | nested/masque_carrier.go | коллизия random sport | S |
| PATCH-26 | N-3 | P3 | nested/masque_carrier.go | flowConn.Read: ErrShortBuffer | S |
| PATCH-27 | N-4 | P3 | warp/h3frame.go | acceptControlStreams → тестовый хелпер | S |
| PATCH-28 | N-5 | P3 | nested/matrix.go, nested/wgmasque.go, wg/nested_runtime.go | StatusDetailed: per-layer handshake/RX/TX | M |
| PATCH-29 | N-6 | P3 | docs (шпаргалка брифа) | согласование 600/700 мс | S |
| PATCH-30 | N-7 | P3 | warp/h3session.go | ReadPacket: guard zero-value | S |
| PATCH-31 | N-8 | P3 | warp/dialudp.go, warp/dialpolicy*.go | ручка DisableUDPFragment | S |
| PATCH-32 | §8.1 отчёта | процесс | docs (ADR-апдендум) | путь B + cf-connect-proto вердикт | M |
| PATCH-33 | §7 отчёта | процесс | docs (карта сдачи) | фиксация структурных отклонений | M |
| PATCH-34 | §8.2 отчёта | процесс | CI | wg -race -count=3 в CI | S |

### 1.2. Граф зависимостей

```text
PATCH-02 ──► PATCH-01        (сначала независимое окно детекции, затем switch-класс;
                              допустимо одним PR двумя коммитами)
PATCH-02 ──► PATCH-13        (оба трогают дефолты H3SessionConfig; порядок 02 → 13)
PATCH-04 ──► PATCH-06        (teardown карриера гасит дубли route-lost; дедуп
                              проверяется уже без шума от утечки)
PATCH-07 ──► PATCH-09        (события/счётчики таксономии до врезки метрик)
PATCH-04, PATCH-05 ──► PATCH-08 (e2e-сценарии опираются на починенный lifecycle)
PATCH-03 — независим (исполнять первым в батче 1, чтобы race-ворота работали
           для всех последующих прогонов)
Все остальные патчи независимы.
```

### 1.3. Что сознательно ВНЕ скоупа этого цикла

- **A9 (НЕ РФ дерево §7.5)** — селектор путей живёт в интеграционном/serviceprofile-слое при сборке `TransportService`, не в transport-срезе. Требуется отдельный план проводки дерева; здесь только фиксация в карте сдачи (PATCH-33).
- **A10 (gVisor-буферы ≥256KiB)** — не верифицируем в этом срезе (стек amnezia-модуля, дефолты); фиксация в отчёте реализации (PATCH-33).
- **A3 (интеграция re-assert в тик супервизора)** — ревью требует зафиксировать отклонение, не обязательно устранять; опция нормализации описана в PATCH-33, решение за владельцем.
- **InitialPacketSize 1350/1242** — quic-go не экспонирует управление начальным размером пакета; только документация (PATCH-20).
- Увеличение каналов первичника до ~64 (замечание A10 про очереди) — не входит: требует ревизии дизайн-числа, вынесено в PATCH-33 как вопрос владельцу.

---

## 2. Батч 1 (P0) — главный целевой сценарий и ворота сдачи

Три патча этого батча закрывают функциональный пробел, ради которого лестница H3→H2 существует (DPI-сценарий РФ: QUIC-handshake проходит, данные молча режутся), и делают детерминированными ворота приёмки N5/EH5.

### PATCH-01 [MAJOR-1] Лестница: silent-after-handshake на фазе ответа CONNECT → switch-класс H2

**Источник:** MAJOR-1 ревью; `src/transport/warp/ladder.go:326-333` (`isLadderSwitchClass`), `src/transport/warp/h3session.go:304-308, 261-269`.

**Проблема (развёрнуто).** Лестница переключает H3→H2 только для switch-классов отказов. Сейчас это `FailureUDPEgressBlocked` (молчание на диале) и `FailureTLSAlert`. Третий заявленный дизайн-класс — «handshake прошёл, ответ на extended CONNECT молчит» — классифицируется как `FailureConnectTimeo` (`h3session.go:308`, а также `:267` при истечении общего бюджета в фазе open_bi), и этот класс **не входит** в `isLadderSwitchClass`. Следствие: генерация падает с H3-вердиктом, гейт H3 не блокируется, H2 не пробуется — цикл «H3-бэкофф-H3» продолжается бесконечно. Это прямо противоречит design §6 («handshake-ok-but-silent ⇒ H2 + пометка») и оставляет главный РФ-ДПИ-сценарий незакрытым. Реализация ловит лишь два из трёх silent-классов: udp-blocked (диал) и validation-timeout (после 200 OK).

**Предварительное условие:** PATCH-02 (окно детекции молчания не должно зависеть от остатка dial-бюджета — иначе switch-вердикт станет ложным для медленных, но живых рёбер).

**Изменения.**

1. `ladder.go`, `isLadderSwitchClass` — добавить класс:

```go
func isLadderSwitchClass(class string) bool {
        switch class {
        case FailureUDPEgressBlocked, FailureTLSAlert, FailureConnectTimeo:
                return true
        default:
                return false
        }
}
```

Обновить doc-комментарий функции: перечень классов = «confirmed network verdicts» — udp-молчание на диале, TLS-отказ, молчание ответа после handshake.

2. **Обязательный guard (без него патч некорректен):** класс `FailureConnectTimeo` должен порождаться только сетевым молчанием, не отменой родительского контекста. Сейчас в `h3session.go:261-269` (фаза open_bi) таймаут `osCtx` при отменённом **родительском** ctx даёт `FailureConnectTimeo` — после включения класса в switch-семейство teardown-гонка супервизора ложно закрывала бы гейт H3 на 300 с. Привести классификацию к виду:

```go
stream, err := conn.OpenStreamSync(osCtx)
osCancel()
if err != nil {
        class := FailureQUICStreamQuotaHang
        switch {
        case ctx.Err() != nil: // parent cancelled — never a network verdict
                class = FailureSessionAborted
        case hsCtx.Err() != nil:
                class = FailureConnectTimeo
        }
        return abandon(class, err)
}
```

3. Убедиться, что `FailureSessionAborted` остаётся вне switch-классов (это уже так — default), и что `FailureConnectTimeo` не входит в retriable-семейство `isRetriableH3Failure` (это так: обёрнут `context.DeadlineExceeded`, не проходит ни одну ветку) — молчание подтверждает вердикт, ретраев быть не должно; добавить эти два утверждения комментариями в соответствующих местах.

4. Событие: механика уже есть — `switchedEvent(TransportH3, TransportH2, FailureConnectTimeo)` с `reason=connect-ip-timeout`; «пометка кандидата» = закрытие гейта на `H3ReturnCooldown` (300 с) и счётчик `fallbackH2N` — ничего нового вводить не нужно, только убедиться, что событие несёт `DurationMS`.

**Тесты (ladder_test.go, по образцу существующих switch-тестов; фейк-стенд уже имеет режим `hangConnect` — fakeh3_test.go:32, «accept the CONNECT stream but never answer it»).**

- `TestLadderSwitchesToH2OnHangConnectAfterHandshake`: фейк `hangConnect=true`, реальный `DialH3Session` через seam `LadderConfig.DialH3`, фейковый `DialH2` (success). Утверждения: (а) результат попытки — транспорт H2; (б) ровно одно событие `EvTransportSwitched` с `FailureClass == FailureConnectTimeo` и `Detail` «from=h3 to=h2»; (в) `Metrics().H3Blocked == true`; (г) повторный `Dial` в пределах cooldown не делает ни одного H3-контакта (счётчик `h3Dials` не растёт), идёт сразу в H2.
- `TestLadderNoSwitchOnParentCancelDuringOpenBI`: edge-случай из guard-пункта 2 — отмена родительского ctx в фазе open_bi (маленький `OpenStreamBudet` + внешний cancel): класс `FailureSessionAborted`, гейт НЕ закрыт, событий switch нет. Реализация через seam-диалер, контролирующий момент отмены.
- Регресс: `TestNoOscillationAcrossTicks` и соседние должны остаться зелёными без правок (если правки нужны — это сигнал, что семантика изменилась, остановиться и перепроверить).

**Критерии приёмки.** Три silent-класса дизайна (dial-молчание, response-молчание, validation-молчание) переводят транспорт на H2 с гейтом 300 с и ровно одним switch-событием; отмена родителя не влияет на гейт.

**Риски.** Ложные switch-вердикты для медленных рёбер — закрывается PATCH-02; двойная задержка (H3-попытка целиком + H2-диал в той же генерации) — приемлемо, бюджет генерации это допускает (H2-диал в той же `Dial`-вызове уже реализован).

**Размер:** M.

### PATCH-02 [MAJOR-2] Раздельные бюджеты: dial/handshake ≠ окно ожидания ответа CONNECT

**Источник:** MAJOR-2 ревью (нарушение B-H4 «два таймера зависаний раздельны»); `src/transport/warp/h3session.go:241, 304-308`, конфиг `:98`.

**Проблема (развёрнуто).** Требование B-H4 — два независимых таймера зависаний: один на dial+handshake, второй на ожидание первого ответа. В реализации оба делят один контекст `hsCtx` (`context.WithTimeout(ctx, cfg.HandshakeBudget)`, :241): `tr.Dial` (:243), open_bi (:261 — свой `osCtx`, но классификация смотрит `hsCtx.Err()`), и select ожидания ответа (`case <-hsCtx.Done()` :306). Следствие: медленный handshake (например, 17 с из бюджета 20 с) съедает окно детекции молчания до 3 с — «окно» response-фазы становится случайной величиной, зависящей от скорости handshake: (а) для живого, но медленно отвечающего рёбра вердикт «молчит» может прозвучать преждевременно; (б) в связке с PATCH-01 преждевременный `FailureConnectTimeo` — это ложный switch H3→H2. Классификация лестницы не должна зависеть от того, сколько секунд ушло на handshake.

**Изменения.**

1. `H3SessionConfig` — новое поле и константа:

```go
// ResponseBudget bounds the wait for the first extended-CONNECT response
// after the request is written. It is measured from the moment the CONNECT
// is sent and never inherits the handshake budget remainder (design B-H4:
// two independent stall timers).
ResponseBudget time.Duration // default DefaultH3ResponseBudget
```

```go
const DefaultH3ResponseBudget = 10 * time.Second
```

`fillDefaults()` — заполнение по нулевому значению. Значение 10 с: верхняя граница рекомендованной ревью вилки 10–15 с, консервативно к живым рёбрам (реальные ответы WARP — первые сотни мс; RTT-хвост до ~3 с покрывается с трёхкратным запасом).

2. `dialH3Once`, фаза ответа — независимый контекст, производный от **parent**, не от `hsCtx`:

```go
// Response window is independent of the dial budget remainder (B-H4):
// a slow handshake must not shrink the silence-detection window.
rspCtx, rspCancel := context.WithTimeout(parent, cfg.ResponseBudget)
defer rspCancel()
…
select {
case rsp = <-rspCh:
case <-rspCtx.Done():
        stream.CancelRead(quic.StreamErrorCode(0))
        return abandon(FailureConnectTimeo, fmt.Errorf("response window: %w", rspCtx.Err()))
case <-hsCtx.Done(): // overall attempt budget still applies
        stream.CancelRead(quic.StreamErrorCode(0))
        return abandon(FailureConnectTimeo, fmt.Errorf("attempt budget: %w", hsCtx.Err()))
case <-parent.Done():
        return abandon(FailureSessionAborted, parent.Err())
}
```

Оба таймаута дают один и тот же класс `FailureConnectTimeo` (switch-семантика PATCH-01 едина), но с разным `reason` в обёртке ошибки — это различимо в трейсе.

3. Классификация open_bi — уже исправлена в PATCH-01 (guard-пункт 2); здесь только проверить, что после настоящего патча в фазе после handshake `hsCtx` используется исключительно как общий бюджет попытки, а не как окно детекции.

4. `HandshakeIdleTimeout` в `quic.Config` остаётся равным `cfg.HandshakeBudget` — это фаза dial, изменений нет. Прокинуть `ResponseBudget` из `SessionConfig`, если там есть соответствующее поле — иначе только `H3SessionConfig` + `h3ConfigFromSession` не трогаем (лестница не задаёт его; работает дефолт).

**Тесты (h3session_test.go).**

- `TestH3ResponseBudgetNotInheritedFromHandshakeRemainder` — ключевой тест независимости: фейк-эдж с быстрым handshake и `hangConnect`; `cfg.HandshakeBudget = 2s`, `cfg.ResponseBudget = 5s`. Утверждения: класс `FailureConnectTimeo`; `res.DurationMS` ≥ ~5 с (окно полноразмерное; до фикса таймаут срабатывал бы по `hsCtx` на 2-й секунде). Тест подтверждает, что окно детекции молчания отсчитывается от отправки CONNECT, а не от старта попытки.
- `TestH3ResponseBudgetDeadlineThenLateAnswer`: `hangConnect=false`, но ответ задерживается больше `ResponseBudget` → `FailureConnectTimeo` (не udp-класс), при этом handshake успел — проверка, что класс не «сползает» в handshake-семейство.
- Существующий `TestH3SessionHangConnectBudgetFires` — обновить: он фиксировал поведение «общий бюджет»; теперь ожидание — `ResponseBudget`.

**Критерии приёмки.** Окно детекции молчания фиксировано конфигом и не зависит от остатка dial-бюджета; медленный handshake + молчание → стабильный `FailureConnectTimeo`; B-H4 восстановлен.

**Риски.** Совокупное время неудачной H3-попытки растёт до `HandshakeBudget + ResponseBudget` в худшем случае (was: один общий) — приемлемо: генерация не блокируется параллельным H2-фоллбэком; отметить в changelog.

**Размер:** M.

### PATCH-03 [MAJOR-4] Data race в vendored amneziawg-go (timers.go) — патч вендора + re-pin

**Источник:** MAJOR-4 ревью (ворота сдачи N5/EH5); `src/vendor/github.com/amnezia-vpn/amneziawg-go/v3/device/timers.go:41` vs `:58`.

**Проблема (развёрнуто).** Колбэк таймера пишет `timer.duration = 0` **после** снятия `modifyingLock` (:40 снят, :41 запись), а `Timer.Del()` пишет ту же ячейку **под** `modifyingLock` (:58). Триггер: `Session.teardown → Device.Down → Peer.Stop` (session.go:520). Подтверждено прогоном: `go test ./transport/wg/ -race` падает в `TestSeekVanillaFailsAgainstAwgEdge` в 3 из 4 полных прогонов (изолированно зелёный — гонка load-зависимая). Ворота приёмки брифа объективно красные; продовые seek-циклы дёргают teardown постоянно, т.е. риск не ограничен тестами.

**Изменения.**

1. `src/vendor/github.com/amnezia-vpn/amneziawg-go/v3/device/timers.go`, функция `NewTimer` — перенести обнуление под лок:

```go
timer.Timer = time.AfterFunc(time.Hour, func() {
        timer.runningLock.Lock()
        defer timer.runningLock.Unlock()

        timer.modifyingLock.Lock()
        if timer.duration == 0 {
                timer.modifyingLock.Unlock()
                return
        }
        duration := timer.duration
        timer.duration = 0
        timer.modifyingLock.Unlock()

        expirationFunction(peer, duration)
})
```

Семантика сохранена дословно: нулевая длительность → не стрелять; стрельба — после снятия лока (чтобы `expirationFunction` не выполнялся под `modifyingLock`, как и раньше); `Del`/`DelSync`/`Mod`/`IsPending` не меняются.

2. `src/transport/wg/NOTICE.md` — добавить запись в раздел Modifications: файл, суть (one-line: «timers.go: move timer.duration reset under modifyingLock to fix data race between timer callback and Timer.Del»), и пересчитать re-pin hash по процедуре, уже описанной в NOTICE (hash по содержимому вендорной директории; команда — из NOTICE).

3. **Upstream-репорт:** завести issue в `amnezia-vpn/amneziawg-go` с текстом гонки (две стек-трейса из ревью-прогона), минимальным патчем и ссылкой на NOTICE-запись. Номер issue зафиксировать в NOTICE. Если репозиторий недоступен из окружения — подготовить текст issue файлом `docs/upstream/amneziawg-timers-race-issue.md` (черновик приложить к коммиту) и пометить как pending.

**Тесты.** Нового тест-кода нет (гонка в vendored-пути воспроизводится только серийными прогонами). Верификация:

```bash
cd src
go test ./transport/wg/ -race -count=5        # серия: все зелёные
go test ./transport/... -count=1              # регресс всей транспортной зоны
go vet ./transport/...
```

`-count=5` обязателен: одиночный прогон недостаточен (гонка load-зависимая).

**Критерии приёмки.** `go test ./transport/wg/ -race -count=5` стабильно зелёный в ≥ 3 независимых сериях на разных уровнях загрузки; NOTICE обновлён (запись + hash); upstream-issue создан или черновик сохранён.

**Риски.** Вендорный патч девиатирует от апстрима — именно поэтому обязательна Modifications-запись (процедура уже принята проектом для amneziawg-go). Поведенческих изменений нет: перестановка записи под уже удерживаемый лок не меняет порядок событий.

**Размер:** S.

---

## 3. Батч 2 (P1) — жизненный цикл W+M runtime и гигиена событий

### PATCH-04 [MAJOR-3] WgMasqueRuntime: teardown старого KernelRouteCarrier при новой генерации outer

**Источник:** MAJOR-3 ревью; `src/transport/nested/wgmasque.go:232-241, 284-301` (`onParentUp`/`buildCarrier`).

**Проблема (развёрнуто).** Каждый успешный реконнект outer-WG вызывает `onParentUp` → `buildCarrier`, который в kernel-режиме создаёт **новый** `KernelRouteCarrier` и запускает `RunAssertionLoop` (30-секундный тикер), не останавливая предыдущий. Последствия, нарастающие с каждым реконнектом: (а) живёт вечная горутина assertion-loop с мёртвым owned-состоянием; (б) старые и новый карриеры конкурируют за один и тот же пин `/32` (assert старого может репинить маршрут и снимать proof нового); (в) события `carrier-route-lost` / `pin-restored` дублируются от двух карриеров — диагностика route-инцидентов шумит; (г) нарушены B-N2/B-N6 «каждая owned-сущность имеет terminal-record»: старый карриер не получает терминальной записи. Дополнительно: prev-снимок чужого маршрута первого поколения теряется — при финальном `Stop` restore вернёт пин первого карриера вместо исходного чужого маршрута.

**Изменения.**

1. `wgmasque.go`, `onParentUp` — перед построением нового карриера полный teardown старого (kernel-режим):

```go
func (r *WgMasqueRuntime) onParentUp() {
        gen := r.bumpGen()

        // Carrier lifecycle (B-N2/N6): exactly one kernel carrier may be
        // alive per runtime. Teardown the previous generation BEFORE building
        // the next one: Restore() returns the foreign prev-route, so the new
        // Setup() snapshots the TRUE foreign state and the final Stop()
        // restores it (first-generation prev survives across generations).
        r.mu.Lock()
        oldKernel := r.kernel
        r.carrier, r.kernel = nil, nil
        r.mu.Unlock()
        if oldKernel != nil {
                oldKernel.StopAssertionLoop()
                oldKernel.Restore(context.Background())
                oldKernel.Close()
                r.emit(Event{Class: "wg_nested_carrier_replaced",
                        Reason: fmt.Sprintf("gen=%d carrier torn down before rebuild", gen)})
        }

        carrier, krc, cerr := r.buildCarrier(gen)
        … // далее без изменений
```

Порядок «teardown → build» существенен по причине, раскрытой в комментарии: `Restore()` возвращает чужой маршрут в таблицу, поэтому `pinFamily` нового карриера делает prev-снимок **истинного** чужого маршрута — так prev-снимок первого поколения переживает любое число реконнектов без дополнительных механизмов.

2. Путь отказа: если `buildCarrier`/`Setup` нового карриера упал — состояние уже консистентно (чужой маршрут восстановлен, старого карриера нет, runtime в `child-invalidated` через `setInvalidated`). Убедиться, что `setInvalidated` используется и для ошибки teardown старого (обернуть teardown в ошибку? — нет: teardown идемпотентен и не должен фейлить установку нового; ошибки не возвращаются).

3. `Stop()` (:191-212) — не меняется: он уже делает корректный teardown текущего карриера; после настоящего патча «текущий» всегда единственный.

**Тесты (wgmasque_test.go или новый lifecycle-тест на fake `RouteRunner`; паттерн fake-раннера уже есть в kernelroute_test.go).**

- `TestWgMasqueCarrierTornDownAcrossGenerations`: два цикла `onParentUp` (эмуляция реконнекта outer). Fake `RouteRunner` пишет журнал операций. Утверждения: (а) после второй генерации assertion-вызовы (`route show`) идут только от нового карриера (различаются по `Device` — конфиг второй генерации с другим именем устройства, либо по счётчику: после teardown счётчик старого замирает — подождать один тик интервала, уменьшенного в тесте до 50 мс); (б) в конце (`Stop`) таблица содержит **исходный** чужой маршрут (тот, что был до первого пина), а не наш пин и не «dev ourDevice».
- `TestWgMasqueNoDuplicateRouteLostAfterReconnect`: после установления второй генерации сымитировать wipe маршрута; assertion-loop должен дать **ровно один** `carrier-route-lost` (нет дублей от мёртвого карриера первого поколения) и затем `pin-restored`.
- Обновить существующие тесты, если они строили несколько генераций и не ожидали событие `wg_nested_carrier_replaced`.

**Критерии приёмки.** Число живых assertion-горутин ≤ 1 в любой момент времени; route-lost/pin-restored не дублируются между генерациями; финальный restore возвращает чужой маршрут первого поколения; событие `wg_nested_carrier_replaced` — терминальная запись старого карриера.

**Риски.** Окно между teardown старого и Setup нового (маршрут временно = чужой) — допустимо: inner в этот момент ещё не поднят (child-first), outer только что установился; на данные это окно не влияет. `closeOnce(c.stopCh)` в `StopAssertionLoop` и `Close` — двойной вызов безопасен (idempotent).

**Размер:** M.

### PATCH-05 [M-12] watch-горутина: производный контекст и закрытие done при Stop

**Источник:** M-12 ревью; `src/transport/nested/wgmasque.go:224-227, 191-212`.

**Проблема (развёрнуто).** `watch(parent)` ждёт только `parent.Done()` — контекст, переданный в `Start` вызывающим кодом, а не собственный `cancel` рантайма. После `Stop()` (который вызывает `r.cancel()`, но родителя не трогает) горутина продолжает жить до отмены родительского контекста, а `r.done` не закрывается — `Start` в другом месте может ждать `done` вечно. Утечка горутины на каждый цикл start/stop.

**Изменения.**

1. `watch` ждёт производный контекст рантайма:

```go
func (r *WgMasqueRuntime) watch() {
        defer close(r.done)
        r.mu.Lock()
        ctx := r.cancelCtx
        r.mu.Unlock()
        if ctx == nil {
                return
        }
        <-ctx.Done()
}
```

Вызов в `Start`: `go r.watch()` (контекст уже сохранён в `r.cancelCtx` до запуска горутины — см. `Start:125-129`).

2. `Stop()` — после teardown дождаться закрытия `done` (bounded-wait, чтобы не завесить вызывающего на негодном колбэке):

```go
select {
case <-r.done:
case <-time.After(2 * time.Second): // bounded: never hang Stop on a stuck watcher
}
```

Учесть: ранние пути ошибки в `Start` уже закрывают `done` вручную — сохранить (watch в них не запускается).

**Тесты.**

- `TestWgMasqueStopClosesWatchWithoutParentCancel`: `Start(parent)` с долгоживущим parent, затем `Stop()`; утверждается, что `done` закрывается в пределах 2 с **без** отмены parent (до фикса — не закрывался вовсе); повторный `Stop` идемпотентен.

**Критерии приёмки.** После `Stop` горутина watch мертва (проверяется закрытием `done`); родительский контекст не требуется.

**Размер:** S.

### PATCH-06 [M-3] Дедуп событий carrier-route-lost: один эпизод — одно событие

**Источник:** M-3 ревью (нарушение B-N2 «route-lost ровно один раз на эпизод»); `src/transport/nested/kernelroute_ops.go:26-35` (`Assert`).

**Проблема (развёрнуто).** При неремонтируемом пине `Assert` эмитит `ClassCarrierRouteLost` **каждый тик** (30 с), пока ремонт не удастся. Один инцидент размазывается на серию событий; в связке с багом PATCH-04 дублировался ещё и от утекших карриеров. B-N2 требует семантику «ровно один раз на эпизод».

**Изменения.**

1. `kernelroute.go`, структура `pinnedRoute` — добавить флаг эпизода (доступ под `c.mu`, как остальные поля owned-состояния):

```go
type pinnedRoute struct {
        …
        lostActive bool // route-lost episode in progress (B-N2: one event per episode)
}
```

2. `kernelroute_ops.go`, `Assert` — эмитить только на переходе:

```go
for _, r := range owned {
        if err := c.verifyRoute(ctx, r.family, r.dst); err != nil {
                lastErr = err
                if !r.lostActive {
                        c.emit(Event{Class: ClassCarrierRouteLost, Reason: err.Error()})
                        r.lostActive = true // episode opened; no re-emit until repaired
                }
                if perr := c.repairPin(ctx, r); perr != nil {
                        c.proofOK.Store(false)
                        return perr
                }
                repaired = true
        }
}
```

После успешного `repairPin` — закрывать эпизод (сброс `lostActive` для отремонтированного маршрута) до эмита `ClassPinRestored`; `PinRestored` остаётся единственным сигналом закрытия эпизода. Аккуратно с копией слайса `owned`: флаг менять в оригинальных записях под `c.mu` (сейчас `owned := c.ownedList()` возвращает копии — либо мутабельный обход под локом, либо set-хелпер `c.setLostActive(dst, bool)`).

**Тесты.**

- `TestAssertEmitsRouteLostOncePerEpisode`: fake-раннер, маршрут снесён перманентно (ремонт всегда фейлится — тогда Assert возвращает ошибку после первой итерации; тогда проверять на тик-уровне: три вызова `Assert` → ровно один route-lost). Вариант B: ремонт успешен со второй попытки → события: 1 × route-lost, 1 × pin-restored, и после нового wipe — снова route-lost (новый эпизод).

**Критерии приёмки.** Один инцидент (wipe → repair) даёт ровно один route-lost и один pin-restored; повторный инцидент — снова ровно один.

**Риски.** Минимальные; семантика событий сужается — обновить тесты, которые считали повторы (в т.ч. тест из PATCH-04, он должен остаться зелёным).

**Размер:** S.

### PATCH-07 [M-14] Таксономия: классы nested/child-start-failed и nested/child-invalidated вместо чужого ClassCarrierRouteLost

**Источник:** M-14 ревью; `src/transport/nested/matrix.go:392-399` (`setInvalidated` в MasqueAwgRuntime), `src/transport/nested/wgmasque.go:351-357` (`setInvalidated` в WgMasqueRuntime).

**Проблема (развёрнуто).** `ClassCarrierRouteLost` («nested/carrier-route-lost») используется как класс для событий, не имеющих отношения к потере маршрута: провал построения карриера, провал старта inner-супервизора, провал inner-старта. Таксономия design §5 размывается: потребитель метрик/событий не может отличить настоящий route-инцидент от детской ошибки старта; диагностика route-инцидентов шумит (усугубляется счётчиком `RouteLostTotal` в `Metrics.Observe`, который считает и эти события).

**Изменения.**

1. `carrier.go` (или doc.go, где живут классы) — новые константы:

```go
// ClassChildStartFailed: the inner layer failed to start (carrier build,
// supervisor construction or first start). Not a route incident.
ClassChildStartFailed = "nested/child-start-failed"
// ClassChildInvalidated: the inner layer was invalidated (parent loss or
// start failure aftermath). Not a route incident.
ClassChildInvalidated = "nested/child-invalidated"
```

2. `matrix.go` `setInvalidated` и `wgmasque.go` `setInvalidated`: для причин «start failed» — `ClassChildStartFailed`; для инвалидации по parent-lost — `ClassChildInvalidated` (в `wgmasque.go:280` уже эмитится строковый класс `"wg_nested_child_invalidated"` — заменить на константу, значение оставить прежним, чтобы не ломать внешних потребителей: значение константы `ClassChildInvalidated` взять равным `"wg_nested_child_invalidated"`, а `ClassChildStartFailed = "wg_nested_child_start_failed"` — префикс сохранён, таксономия целостна).
3. `ClassCarrierRouteLost` остаётся строго для потери kernel-маршрута (emit в `kernelroute*.go` и `Setup` optional-family warning — пересмотреть: optional-family warning тоже не route-lost, перевести на `ClassChildStartFailed` с reason «optional-family …» либо отдельный warn-класс — взять `ClassChildStartFailed`, причина сборки карриера).
4. `metrics.go` `Observe` — новые счётчики:

```go
ChildStartFailedTotal atomic.Uint64
ChildInvalidatedTotal atomic.Uint64
// switch: case ClassChildStartFailed: m.ChildStartFailedTotal.Add(1)
//         case ClassChildInvalidated: m.ChildInvalidatedTotal.Add(1)
```

`RouteLostTotal` после этого считает только настоящие route-инциденты.

**Тесты.**

- Обновить тесты, ожидавшие `ClassCarrierRouteLost` от путей старта (wgmasque_test, matrix_test, masque_runtime_test).
- Новые: провал `buildCarrier` (fake-раннер, replace падает) → событие `nested/child-start-failed`; `onParentLost` → `nested/child-invalidated`; wipe маршрута → по-прежнему `nested/carrier-route-lost`; `Metrics`: соответствующие счётчики инкрементируются раздельно.

**Критерии приёмки.** Класс `ClassCarrierRouteLost` эмитится только из kernelroute-кода потери маршрута; счётчики метрик разделены.

**Размер:** S.

### PATCH-08 [M-18] e2e: kill-inner и kill-WAN сценарии для M+W и W+M

**Источник:** M-18 ревью; `src/transport/nested/masque_awg_e2e_test.go`.

**Проблема (развёрнуто).** E2E-стенд покрывает happy-path двойного гейта; матрица отказов пар покрыта точечно: W+W kill-outer ✓, M+W teardown-mid-stream ✓. Отсутствуют интеграционные сценарии инвалидации **каждого отдельного слоя** для M+W и W+M: kill-inner (падение внутреннего слоя при живом внешнем) и kill-WAN (потеря внешнего при живом внутреннем). Контракт parent-link (B-N5) требует «мгновенной инвалидации child при потере parent» и «child-first teardown» — для W+M обе ветки не покрыты интеграционно.

**Изменения** (только тестовый файл; харнес — существующие фейки стенда).

Новые сценарии, по два на каждый рантайм:

1. `TestE2EMasqueAwgKillInner`: M+W поднят (двойной гейт прошёл) → убить inner-AWG (стоп inner-сессии через тестовый хук / сделать inner-endpoint недостижимым) → утверждения: runtime отразил инвалидацию child (`Status().childRunning == false`, link перешёл из `up`), события `nested/child-*`; outer-плейн жив; восстановление inner при следующем цикле (если рантайм предусматривает revalidation — утвердить переход обратно в up).
2. `TestE2EMasqueAwgKillWAN`: уронить внешний MASQUE-плейн (`RouteHeld → false` через хук плейна) → child-first: сначала останавливается inner, затем плейн; события в правильном порядке (`child_invalidated` раньше teardown плейна).
3. `TestE2EWgMasqueKillInner`: W+M поднят → inner-супервизор падает (диал через карриер фейлится — хук fake-карриера/эндпоинта) → `nested/child-start-failed`/`invalidated`, outer-сессия продолжает жить, повторный onParentUp строит всё заново.
4. `TestE2EWgMasqueKillWAN`: уронить outer-WG (`OnLost` через тестовый хук сессии) → `onParentLost` → child остановлен до того, как outer полностью погашен (порядок событий), события `wg_nested_parent_lost` + `nested/child-invalidated`; восстановление: новый outer-establishment поднимает свежий карриер и inner (регрессия для PATCH-04/05: ровно один карриер после восстановления).

**Критерии приёмки.** Все четыре сценария зелёные стабильно (прогон ×3), включая `-race` (nested-пакет).

**Размер:** M.

---

## 4. Батч 3 (P1) — honest observability (KPI-4)

### PATCH-09 [MAJOR-5] Врезка per-layer gate latency (ObserveGate) во все три рантайма

**Источник:** MAJOR-5 ревью (plan-deviation; KPI-4 «honest observability», design §5, N4-контракт); `src/transport/nested/metrics.go:46` (`ObserveGate` — сейчас вызывается только тестом wgmasque_test.go:127), рантаймы: `nested/matrix.go` `MasqueAwgRuntime`, `nested/wgmasque.go` `WgMasqueRuntime`, `wg/nested_runtime.go` `NestedWgRuntime`.

**Проблема (развёрнуто).** Метрическая структура (`OuterGateMS`/`InnerGateMS`), экспорт (`ExportLoop`, `Snapshot`) и метод `ObserveGate` готовы, но **ни один прод-рантайм не замеряет длительность trust gate слоёв**. Дизайн §5 формулирует жёстко: «замер TTFB каждого слоя отдельно — без него никаких заявлений о цене вложенности». KPI-4 честной наблюдаемости не выполняется: серии пустые, wiring-слой экспортирует нули.

**Изменения.**

Общий принцип точки замера: **от старта установления слоя до подтверждения гейта слоя** (TrustGate-validate / RouteHeld / OnEstablished — в зависимости от рантайма). nil-безопасность уже есть (`ObserveGate` nil-safe) — конфиг-поле опциональное, при nil поведение рантаймов не меняется.

1. `Metrics *Metrics` — новое поле в трёх конфигах: `MasqueAwgConfig` (matrix.go), `WgMasqueConfig` (wgmasque.go), `NestedWgOptions` (wg/nested_runtime.go).

2. `MasqueAwgRuntime` (matrix.go):
   - **outer:** в `run(ctx)` — `tOuter := time.Now()` на старте цикла наблюдения; при первом переходе `RouteHeld == true` (пик poll-цикла :319) — `m.ObserveGate("outer", time.Since(tOuter))` (замер повторяется на каждую новую генерацию: tOuter сбрасывается при потере RouteHeld).
   - **inner:** в `startChild(gen)` (:340) — обернуть установку: от входа до успеха `sess.Start()` (:367) — `m.ObserveGate("inner", elapsed)`; на ошибке — не замеряем (гейт не пройден — честно: только успешные gate-прохождения).

3. `WgMasqueRuntime` (wgmasque.go):
   - **outer:** `tOuter` фиксируется в `Start` перед `sess.Start()`; в `onParentUp` первым действием — `ObserveGate("outer", time.Since(tOuter))` (OnEstablished = гейт outer пройден).
   - **inner:** в `onParentUp` вокруг `sup.Start` + переход `link = "up"` — от вызова `sup.Start` до присвоения `link="up"` (:265) — `ObserveGate("inner", elapsed)`.

4. `NestedWgRuntime` (wg/nested_runtime.go):
   - **outer:** tOuter в `Start` (:109), замер в `onParentEstablished` (:164).
   - **inner:** `establishChild()` (:199) — длительность успешного установления.

5. Экспорт wiring-слоя не трогаем: `Snapshot()` уже забирает оба поля (`metrics_pipeline.go`).

**Тесты.**

- Расширить существующие рантайм-тесты (fake-слои): после bring-up `Metrics.Snapshot()` содержит `OuterGateMS > 0` и `InnerGateMS > 0` (через `ExportLoop`/`Snapshot` — проверить имена серий: «outer_gate_ms», «inner_gate_ms» по metrics_pipeline).
- Негативный: nil `Metrics` — рантаймы работают, паник нет.

**Критерии приёмки.** Во всех трёх рантаймах серии `OuterGateMS`/`InnerGateMS` наполняются реальными длительностями на каждой генерации; KPI-4 выполнен; никакого влияния на поведение при nil-конфиге.

**Риски.** Дополнительный вызов time.Now на генерацию — пренебрежимо. Не путать «gate latency» с «establishment latency»: замер от старта установления слоя до гейта — именно так формулирует дизайн («TTFB каждого слоя»); при спорной интерпретации фиксируй в комментарии выбранную точку.

**Размер:** M.

---

## 5. Батч 4 (P2) — корректность классификации отказов H3

### PATCH-10 [M-5] classifyUDPListenError: локальные ошибки сокета ≠ сетевой вердикт

**Источник:** M-5 ревью; `src/transport/warp/h3session.go:588-590`.

**Проблема (развёрнуто).** `classifyUDPListenError` безусловно возвращает `FailureUDPEgressBlocked`. Локальные ошибки сокета — `EPERM` (нет прав на bind с mark), `EACCES`, `EADDRNOTAVAIL` (нет запрошенного локального адреса), `EADDRINUSE`, `EAFNOSUPPORT` — замываются в сетевой вердикт лестницы: H3 блокируется на 300 с, H2-фоллбэк маскирует **локальную** проблему оператора (например, слетевший маршрутный mark), и вместо чинить локально — агент переключает транспорт. Диагностика деградирует.

**Изменения.**

1. Новый класс (рядом с `FailureSessionAborted`, h3session.go:642-644):

```go
// FailureLocalSocket covers local socket setup failures (bind/mark/addr).
// Never a network verdict: the ladder must not degrade transport on it.
const FailureLocalSocket = "local-socket-error"
```

2. `classifyUDPListenError` — разделение:

```go
func classifyUDPListenError(err error) string {
        var opErr *net.OpError
        if errors.As(err, &opErr) {
                var sysErr *os.SyscallError
                if errors.As(opErr.Err, &sysErr) {
                        switch sysErr.Err {
                        case syscall.EPERM, syscall.EACCES, syscall.EADDRNOTAVAIL,
                                syscall.EADDRINUSE, syscall.EAFNOSUPPORT:
                                return FailureLocalSocket
                        }
                }
        }
        return FailureUDPEgressBlocked
}
```

( набор кодов — linux-типовые; на не-linux платформах компилируется через `syscall`-пакет, где перечисленные константы есть на всех целевых платформах проекта; при проблемах — обёртка в `errors.Is(err, syscall.EPERM)`-цепочку.)

3. Лестница: `FailureLocalSocket` **не** входит в `isLadderSwitchClass` (default-false — уже так) и не является retriable — генерация падает с локальным вердиктом, супервизорный бэкофф применяется, гейт не отравляется. Убедиться, что `h3Dials[class]` счётчик получает `local-socket-error` (автоматически — `countH3(res.FailureClass)` в `Dial`).

**Тесты.**

- Табличный unit-тест `TestClassifyUDPListenError`: сконструированные ошибки `&net.OpError{Op:"listen", Err: &os.SyscallError{Syscall:"socket", Err: syscall.EPERM}}` (и остальные коды) → `FailureLocalSocket`; произвольная другая ошибка → `FailureUDPEgressBlocked`.
- Лестничный мини-тест: DialH3-seam возвращает `FailureLocalSocket` → попытка падает с H3-вердиктом, гейт НЕ закрыт, событий switch нет (по образцу guard-теста PATCH-01).

**Критерии приёмки.** Локальные ошибки сокета никогда не блокируют H3 на cooldown и не эмитят switch-событий.

**Размер:** S.

### PATCH-11 [M-6] errors.Is с указателями quic-типов → errors.As

**Источник:** M-6 ревью; `src/transport/warp/h3session.go:562-586` (`isRetriableH3Failure`), `:606-613` (`classifyH3HandshakeError`), `:632` (`classifyH3ResponseError`).

**Проблема (развёрнуто).** Проверки вида `errors.Is(err, &quic.IdleTimeoutError{})` и `errors.Is(err, &quic.StatelessResetError{})` — мёртвые: quic-go error-типы не реализуют метод `Is()`, поэтому `errors.Is` сводится к сравнению указателей с только что созданным экземпляром и **никогда** не истинен. Код работает случайно: `IdleTimeout`/`HandshakeTimeout`/`StatelessReset` разворачиваются (`Unwrap`) в `net.ErrClosed`, который ловится соседней строкой. Хрупко и вводит в заблуждение (выглядит как осмысленная проверка, но таковой не является). При смене поведения `Unwrap` в quic-go классификация молча изменится.

**Изменения.** Заменить все указательные `errors.Is` на канонический `errors.As`-паттерн (как уже корректно сделано в `ladder.go` `classifyProbeError:455-457`):

```go
var idleTO *quic.IdleTimeoutError
var hsTO *quic.HandshakeTimeoutError
var ssErr *quic.StatelessResetError
if errors.As(err, &idleTO) || errors.As(err, &hsTO) || errors.As(err, &ssErr) ||
        errors.Is(err, net.ErrClosed) {
        return true // / FailureUDPEgressBlocked / FailureQUICProtocolViolation — по контексту
}
```

Три места: `isRetriableH3Failure` (:581), `classifyH3HandshakeError` (:606), `classifyH3ResponseError` (:632). Строковые fallback-проверки (`strings.Contains(msg, "timeout")` и т.п.) сохранить как есть — они покрывают обёрнутые варианты.

**Тесты.**

- `TestClassifyQuicErrorTypes`: для каждого типа (`&quic.IdleTimeoutError{}`, `&quic.HandshakeTimeoutError{}`, `&quic.StatelessResetError{}`), обёрнутого `fmt.Errorf("dial: %w", …)`: assert ожидаемый класс в трёх функциях. До фикса эти проверки провалились бы (мёртвые ветки), после — детерминированно проходят.

**Критерии приёмки.** Ни одного `errors.Is(err, &…)` на quic-типах в пакете (grep-чек в CI-скрипте необязателен, но локальная проверка обязательна); классификация типов прямая, не зависящая от `Unwrap`-случайности.

**Размер:** S.

### PATCH-12 [M-17] CRYPTO_ERROR 0x131 / TLS alert 49 (access denied) → FailureTLSPin

**Источник:** M-17 ревью; `src/transport/warp/h3session.go:595-614` (`classifyH3HandshakeError`), дизайн §4 («fail-closed: чужой ключ»).

**Проблема (развёрнуто).** QUIC CRYPTO_ERROR 0x131 (TLS alert 49, access_denied) означает «сертификат клиента отвергнут» — вердикт **идентичности**, а не сети. Сейчас remote TransportError с этим кодом падает в default-ветку → `udp-egress-blocked`/handshake-fail → лестница переключает на H2, маскируя проблему ключей под сетевую блокировку. Design §4 требует fail-closed: пин-вердикты никогда не деградируют транспорт.

**Изменения.**

1. `classifyH3HandshakeError` — до строковых проверок:

```go
var te *quic.TransportError
if errors.As(err, &te) && te.Remote {
        // CRYPTO_ERROR 0x131 = TLS alert 49 (access_denied): the edge
        // rejected the client identity — fail-closed, never a transport
        // downgrade (design §4).
        if uint64(te.ErrorCode) == 0x131 {
                return FailureTLSPin
        }
}
```

2. `FailureTLSPin` уже не входит в switch-классы (fail-closed, never masked) — верно, не трогать. В `isRetriableH3Failure` этот путь не retriable (TransportError с чужим кодом → `return false` после switch по NoError/ProtocolViolation — уже так).

**Тесты.**

- `TestHandshakeCryptoAccessDeniedIsPinVerdict`: `classifyH3HandshakeError(fmt.Errorf("dial: %w", &quic.TransportError{ErrorCode: quic.TransportErrorCode(0x131), Remote: true}))` → `FailureTLSPin`. И контрпример: локальный (не remote) TransportError 0x131 → обычная ветка (локальные crypto-проблемы — не вердикт идентичности).

**Критерии приёмки.** Remote 0x131 классифицируется как пин-вердикт; лестница на нём не переключает транспорт (assert в мини-лестничном тесте: класс не switch).

**Размер:** S.

### PATCH-13 [M-16] Дефолт HandshakeBudget: 20 с → 10 с

**Источник:** M-16 ревью (plan-deviation); `src/transport/warp/h3session.go:98, 115-117`.

**Проблема (развёрнуто).** KPI дизайна: «handshake-бюджет кандидата 5–8 с», per-candidate dial timeout 8 с (design §6). Дефолт реализации — 20 с, мягче KPI в 2,5 раза. С учётом PATCH-02 (появляется независимый `ResponseBudget`) общий верхний кошмар-кейс попытки = HandshakeBudget + ResponseBudget; смягчение dial-бюджета согласуется с KPI и дисциплинирует общее время генерации. В discovery окно `echoWait = 2 с` уже честное — не трогать.

**Изменения.**

1. `fillDefaults`: `DefaultHandshakeBudget = 10 * time.Second` (именованная константа; магическое число убрать), комментарий: «KPI design §6: candidate handshake budget 5–8 s; 10 s = upper bound with margin; per-candidate scan timeouts stay tighter in discovery».
2. Решение зафиксировать в changelog и карте сдачи (PATCH-33). Опция владельца «оставить 20 с с обоснованием» — отклонена по умолчанию, но явно упомянута в changelog-строке.

**Тесты.**

- Прогнать пакет warp: тесты, не задающие бюджет явно и полагающиеся на 20 с (например, тесты с медленными handshake-сценариями на фейке), при необходимости получить явный `HandshakeBudget` в конфиге (это правильно: тесты не должны зависеть от дефолта).
- `TestH3Defaults`: `fillDefaults` устанавливает `HandshakeBudget == DefaultHandshakeBudget` и `ResponseBudget == DefaultH3ResponseBudget` (PATCH-02).

**Критерии приёмки.** Дефолты соответствуют KPI; ни один тест не полагается на неявные 20 с.

**Риски.** Медленные, но живые рёбра теперь укладываются в tighter-бюджет: handshake-таймаут классифицируется `udp-egress-blocked` → switch на H2 — это корректное поведение лестницы для рёбер, не укладывающихся в KPI-бюджет (H2-фоллбэк для них предпочтителен), отметить в changelog.

**Размер:** S.

---

## 6. Батч 5 (P2) — семантика carrier-слоя nested

### PATCH-14 [M-1] KernelRouteCarrier: порядок пина add → replace-fallback (B-N1)

**Источник:** M-1 ревью; `src/transport/nested/kernelroute.go:151-166` (`pinFamily`).

**Проблема (развёрнуто).** Спецификация B-N1 (и эталон zapret-gui :175) требует порядок **add → replace-fallback**. Реализация делает `replace` → (при ошибке) `del` → `replace`-ретрай. Два дефекта: (а) ветка `del` может транзиентно снести **чужой** `/32` до повторного replace (prev-снимок смягчает, но окно уязвимости есть — между del и replace маршрут отсутствует); (б) ветка почти мёртвая — `ip route replace` в реальности не фейлится EEXIST (replace семантически idempotent), т.е. код нарощен под несуществующий случай.

**Изменения.**

`pinFamily` — привести к специфицированному порядку:

```go
// B-N1 pin discipline (zapret-gui :175): add first — clean case, no
// foreign route is ever transiently removed; on conflict fall back to a
// single replace (idempotent, never EEXIST).
out, err := c.cfg.Runner(ctx, fam, "route", "add", dst.String()+"/"+plen, "dev", c.cfg.Device)
if err != nil {
        if _, rerr := c.cfg.Runner(ctx, fam, "route", "replace", dst.String()+"/"+plen, "dev", c.cfg.Device); rerr == nil {
                err = nil
                out = ""
        } else {
                err = rerr
        }
}
if err != nil {
        return fmt.Errorf("pin %s: %v (%s)", dst, err, strings.TrimSpace(out))
}
```

Ветку `del` удалить полностью. Обновить комментарий блока.

**Тесты.**

- Обновить `kernelroute_test.go` (существующие тесты считают replace-вызовы — fresh-pin теперь `add`): (а) чистый пин → ровно один `add`, ни одного `del`/`replace`; (б) конфликт (fake-раннер фейлит `add` EEXIST-подобной ошибкой) → `add` + `replace`, успех; (в) обе операции падают → ошибка пина, rollback-путь не меняется; (г) во **всех** сценариях ни одного `route del` от `pinFamily` (del остаётся только в `Restore`).

**Критерии приёмки.** Порядок соответствует B-N1; `del` в пути пинирования отсутствует; транзитное исчезновение чужого маршрута невозможно.

**Размер:** S.

### PATCH-15 [M-2] AttemptV6: реализовать двухсемейственное покрытие (v4 mandatory + v6 warn)

**Источник:** M-2 ревью; `src/transport/nested/carrier.go:92-93` (`AttemptV6` — мёртвое поле), `src/transport/nested/kernelroute.go:109-134` (`Setup`/`coverageOK`), design §1.1, zapret-gui :296-330.

**Проблема (развёрнуто).** `FamilyPolicy.AttemptV6` объявлен, но не используется нигде (grep: только декларация). `Setup` пинит семейство единственного `Endpoint`; комбинированная семантика «v4 обязательный + v6 предупредительный» невыразима. `coverageOK` проверяет только v4 — `_routes_cover` вырожден: система заявляет политику семейств, но не способна её исполнить. Для W+M-пары с v6-эджем каталога (discovery отдаёт v6-пары) inner-контроль по v6 шёл бы мимо пина.

**Изменения** (вариант A — реализация; альтернатива B «удалить поле» — только по явному решению владельца, см. PATCH-33).

1. `KernelRouteCarrierConfig` — расширение:

```go
type KernelRouteCarrierConfig struct {
        …
        Endpoint  netip.AddrPort // primary (v4) endpoint pin — mandatory per policy
        EndpointV6 netip.AddrPort // optional v6 endpoint pin — warn-only (AttemptV6)
}
```

2. `Setup` — цикл по обоим семействам: primary (v4) — mandatory (фейл → полный rollback, как сейчас); v6 — при `EndpointV6.IsValid() && policy.AttemptV6`: пин, фейл → warn-событие (класс по таксономии PATCH-07 — не route-lost), продолжение. Порядок: сначала v4 (успех обязателен), затем v6.
3. `coverageOK` — проверяет v4-пин всегда; v6-пин — если заявлен (не warn-фейл).
4. `Assert`/`repairPin`/`Restore` работают по `owned` —_records обоих семейств автоматически (данные уже в owned-структуре); `ProofSnapshot` перечисляет оба пина.
5. Прокидывание конфига: `WgMasqueConfig.InnerEndpointV6 netip.AddrPort` (optional; валидация в `Validate`: должен быть валидным v6-адресом либо нулевым; передаётся в `buildCarrier` → `KernelRouteCarrierConfig`). `PairConfig` не расширять (endpoint-пары остаются одиночными; v6 — транспортная опция карриера, не топология пары).
6. Семейная асимметрия остаётся в `isMandatoryFamily` — v6 никогда не mandatory (по конструкции политики).

**Тесты.**

- `TestSetupDualFamilyV4MandatoryV6Warn`: fake-раннер: v4-add ок, v6-add фейлит → Setup успех, warn-событие, owned = {v4}, coverage ok.
- `TestSetupDualFamilyV6PinOwned`: оба add ок → owned = {v4, v6}, ProofSnapshot перечисляет оба; wipe v6-маршрута → assertion repin-ит (route-lost + pin-restored по эпизоду PATCH-06).
- `TestSetupV4FailRollsBackBoth`: v4 фейл при живом v6-пине → полный rollback (v6-пин тоже снят/восстановлен).
- Валидация конфига: `InnerEndpointV6` задан с v4-адресом → ошибка валидации.

**Критерии приёмки.** Поле `AttemptV6` живое: либо оба пина в proof, либо задокументированный warn; `coverageOK` отражает заявленные семейства.

**Риски.** Конфиг-расширение — добавляющее, не ломающее (нулевое значение = прежнее поведение). Если владелец выберет вариант B (удаление поля) — патч сжимается до удаления `AttemptV6` + фиксации ограничения в отчёте; решение зафиксировать до старта батча 5.

**Размер:** M.

### PATCH-16 [M-11] MasqueDatagramCarrier: proof-гейт на запись в плейн

**Источник:** M-11 ревью; `src/transport/nested/masque_carrier.go:154-170` (`writeDatagram`), `:243-253` (`flowConn.Write`).

**Проблема (развёрнуто).** Асимметрия fail-closed: `KernelRouteCarrier.DialUDPThrough/DialTCPThrough` отказывают без proof (`ErrCarrierUnproven`), а masque-карриер пишет в плейн при **любом** его состоянии — `writeDatagram` проверяет только `closed` и MTU. Если supervisor уже отпустил маршрут (`RouteHeld == false` — fail-open release при stall), карриер продолжает инжектить датаграммы в мёртвый/чужой плейн. Красная линия #1/#2 (fail-closed без proof) нарушена для этого карриера.

**Изменения.**

`writeDatagram` — гейт перед построением пакета:

```go
func (c *MasqueDatagramCarrier) writeDatagram(dst netip.AddrPort, sport uint16, payload []byte) error {
        if c.closed.Load() {
                return ErrCarrierClosed
        }
        // Fail-closed parity with kernel/netstack carriers: no datagram
        // leaves through an unproven plane (red line #1/#2).
        if !c.cfg.Plane.Snapshot().RouteHeld {
                return fmt.Errorf("%w: masque plane route not held", ErrCarrierUnproven)
        }
        …
}
```

(Прямая проверка `Plane.Snapshot().RouteHeld` вместо обходного `ProofSnapshot()` — тот уже делает то же самое (:179-187), но возвращает строку; выбрать один путь и переиспользовать: допустимо `if _, ok := c.ProofSnapshot(); !ok { return ErrCarrierUnproven }` — идентично и короче. В спеке предпочтителен вариант через `ProofSnapshot` — единая точка истины.)

**Тесты.**

- `TestMasqueCarrierWriteFailsClosedWithoutProof` (masque_carrier_test.go): плейн с `RouteHeld=false` → `flowConn.Write`/`writeDatagram` → `errors.Is(err, ErrCarrierUnproven)`; `RouteHeld=true` → запись проходит (fake-плейн считает пакеты).

**Критерии приёмки.** Все три карриера отказывают без proof одинаково; тест на асимметрию добавлен.

**Риски.** Поведение ужесточается: клиенты, писавшие в отпущенный плейн, получат ошибку — это и требовалось (сейчас они молча теряли данные).

**Размер:** S.

### PATCH-17 [M-4] Edge-collision: post-connect факт-сверка edge-IP/colo обоих слоёв

**Источник:** M-4 ревью (B-N3); `src/transport/nested/matrix.go:103-105` (config-проверка), рантаймы; A4-вердикт ревью.

**Проблема (развёрнуто).** Edge-collision (обе стороны вложенности terminate на одном и том же physical edge) проверяется только на этапе конфигурации — сравнением заявленных IP. Сверка **факта** подключения (какой edge/colo реально обслуживает каждый слой) отсутствует, при том что данные уже собираются: colo-телеметрия тянется в события обоих слоёв (H3/H2-ответы несут `cf-warp-colo`; endpoint-IP известны рантаймам). Чеклист B-N3 прямо требует факт-сверку; для числовых endpoint'ов из каталога риск низкий, но необнаруженная коллизия = вложенность в саму себя (петля, деградация MTU, странные фейлы гейтов).

**Изменения.**

1. Малый тип-свидетель (matrix.go или events):

```go
// edgeWitness captures which physical edge each layer actually landed on
// (post-connect facts, not config declarations).
type edgeWitness struct {
        ip   string // numeric endpoint the layer connected to
        colo string // cf-warp-colo when the layer reports one
}
```

2. Каждый рантайм фиксирует свидетеля слоя при его установлении:
   - `MasqueAwgRuntime`: outer — endpoint + colo из событий внешнего MASQUE-слоя; inner — `startChild`: endpoint inner-AWG + colo недоступен (AWG без colo) → только ip.
   - `WgMasqueRuntime`: outer — endpoint outer-WG (ip); inner — supervisor-события (`InnerSink`): colo + endpoint из `SupervisorEvent`/попыток.
   - Свидетели пишутся под `mu` рядом с полями генерации.
3. Функция сверки — вызывается при установлении **второго** слоя (оба свидетеля ненулевые):

```go
func edgeCollision(outer, inner edgeWitness) bool {
        if outer.ip != "" && outer.ip == inner.ip { return true }
        if outer.colo != "" && outer.colo == inner.colo { return true }
        return false
}
```

При коллизии — событие `ClassEdgeCollision` с reason-префиксом `post-connect:` (класс уже существует и считается в `EdgeCollisionTotal`; конфиг-реджект и факт-сверка теперь различимы по префиксу причины).

**Тесты.**

- `TestEdgeCollisionPostConnectDetected`: fake-слои, у обоих свидетелей одинаковый colo (или ip) → событие с `post-connect:`-префиксом; разные свидетели → события нет. Юнит на `edgeCollision` + интеграционная врезка в один рантайм (W+M — там оба свидетеля доступны из событий).

**Критерии приёмки.** Факт-сверка выполняется в рантаймах обоих W-моделей; коллизия эмитится отдельным событием и считается счётчиком `EdgeCollisionTotal`.

**Риски.** Ложные срабатывания при общем colo для разных edge (кластер) — принять: событие носит информационный характер (не блокирует пару), формат причины оставляет место для уточнения политикой владельца.

**Размер:** M.

---

## 7. Батч 6 (P3) — функциональные пробелы H3-слоя

### PATCH-18 [M-7] ICMPv6 Packet-Too-Big (тип 2) — дописать v6-рецепт

**Источник:** M-7 ревью (B-H6/A8); `src/transport/warp/pump.go:201-236` (`BuildICMPTooBig` — v4-only).

**Проблема (развёрнуто).** ICMP TooBig синтезируется только для IPv4 (type 3/code 4; рецепт корректен и протестирован). Для IPv6 `BuildICMPTooBig` возвращает nil — oversized v6-пакеты не получают ICMPv6 PTB, отправитель не узнаёт о фрагментации. Учитывая v4-only scope туннеля (addendum §46) — латентная проблема, но чеклист B-H6 требует явного рецепта (type 2, pseudo-header checksum, данные ≤ 1232, MTU 1232).

**Изменения.**

Новая функция рядом с v4 (v4-функцию не менять):

```go
// BuildICMPv6TooBig synthesizes an ICMPv6 Packet Too Big message (type 2)
// advertising mtu (≤1232 per QUIC v6 floor), embedding the original IPv6
// header plus the first 8 payload bytes. Checksum is computed over the
// IPv6 pseudo-header (src, dst, upper-layer packet length, next header 58).
// Returns nil for non-IPv6 or truncated input.
func BuildICMPv6TooBig(orig []byte, mtu int) []byte
```

Ключевые элементы рецепта: (а) внешний IPv6-заголовок 40 байт (next header 58, hop limit 64, src ← original dst, dst ← original src); (б) ICMPv6-сообщение: type 2, code 0, checksum (псевдозаголовок: src 16 + dst 16 + length 4 + zeros 3 + nexthdr 58), MTU-поле 32-бита; (в) embedded-данные: original IPv6-заголовок + 8 байт payload, суммарный ICMPv6-пакет ≤ 1280 (данные ≤ 1232); (г) вызов из точки, где сейчас v4-вызов возвращает nil для не-v4 — заменить на диспетчеризацию по версии пакета.

Если туннельный scope гарантированно v4 (addendum §46) и владелец предпочитает не расширять поверхность — допустим альтернативный вариант B: **не** добавлять v6-рецепт, а зафиксировать осознанное ограничение в отчёте реализации (PATCH-33) с одной строкой «BuildICMPTooBig: v4-only by tunnel scope, v6 recipe intentionally absent». Решение (A/B) фиксируется до старта патча; по умолчанию — A.

**Тесты.**

- Векторный: сконструированный v6-пакет → `BuildICMPv6TooBig` → разбор полей (type/code/MTU/embedded), пересчёт checksum независимо (тест-хелпер), недопустимые входы (короткий пакет, v4-пакет) → nil.
- Round-trip с существующим парсером тестов v4 (если обобщается).

**Критерии приёмки.** B-H6 закрыт либо кодом (A), либо явной записью ограничения (B) — отсутствие Handler'а больше не «немая дыра».

**Размер:** M (вариант A).

### PATCH-19 [M-8] ironclad-lite: слот E2EProbe в H3SessionConfig

**Источник:** M-8 ревью (B-H3); `src/transport/warp/h3session.go` (пакет), образец `transportwg.TrustGate.E2EProbe`, дизайн §5 (паттерн Aether tunnelping).

**Проблема (развёрнуто).** B-H3 требует ironclad-lite «отключена по умолчанию, но присутствует интерфейсом». В H3-сессии нет даже интерфейсного хука — будущую E2E-проверку некуда врезать без новой волны рефакторинга, и чеклист формально не выполнен.

**Изменения.**

1. `H3SessionConfig`:

```go
// E2EProbe optionally validates the inner path end-to-end right after the
// data-plane comes up (ironclad-lite pattern, design §5). nil = disabled
// (default). When set, a probe failure fails the validation with the
// probe's error class — the session never reports healthy on a silent path.
E2EProbe func(ctx context.Context, sess *H3Session) error
```

2. Точка вызова: `ValidateDataPlane` (h3session.go:399+) — до вынесения вердикта; probe-ошибка маппится в существующий класс validation-семейства (FailureValidation или класс пробы, если она структурный класс возвращает). `ctx` — контекст валидации с её окном.
3. Дефолт nil — нулевое поведение, никаких новых таймеров/пакетов.

**Тесты.**

- `TestE2EProbeSlotFailsValidation`: конфиг с зондом, возвращающим ошибку → валидация падает; nil-зонд → поведение идентично текущему (существующие тесты зелёные без правок).

**Критерии приёмки.** Слот существует, отключён по умолчанию, задокументирован; B-H3 «интерфейсом присутствует» выполнен.

**Размер:** S.

### PATCH-20 [M-9] InitialPacketSize 1350/1242 — зафиксировать отклонение

**Источник:** M-9 ревью (plan-deviation); `src/transport/warp/h3session.go:239` (`DisablePathMTUDiscovery: false // PMTUD auto per design §1`).

**Проблема.** Шпаргалка брифа и дизайн §1 предписывают пресет initial packet size 1350 с fallback 1242; реализация использует авточисловой старт quic-go + PMTUD (публичного поля `InitialPacketSize` в `quic.Config` quic-go v0.61 нет). Отклонение разумно, но не задокументировано — следующий ревьюер потратит таксон на его переоткрытие.

**Изменения.** Docs-only: раздел «Принятые отклонения» отчёта реализации (PATCH-33): формулировка «initial packet size: quic-go auto + PMTUD (пресеты 1350/1242 не экспонируются quic-go v0.61 API; частично доступно через quic.Transport — принято решение не бороться с библиотекой; эффект — не более одного лишнего PMTUD-цикла на кандидате)».

**Критерии приёмки.** Запись присутствует в отчёте реализации; в коде — только уточнённый комментарий у `DisablePathMTUDiscovery`, если уместно.

**Размер:** S.

### PATCH-21 [M-13] sync.Pool для H3-датаграмм (uplink)

**Источник:** M-13 ревью; `src/transport/warp/h3session.go:342-364` (`WritePacket`/`WrapH3Datagram`), дизайн §3 «пул буферов MTU+1», KPI zero-copy.

**Проблема (развёрнуто).** Каждый исходящий IP-пакет аллоцирует свежий слайс под H3-датаграмму (`WrapH3Datagram(nil, …)` в `WritePacket:351`) — на потоке 10–50k pps это постоянный GC-pressure. Дизайн требует пул буферов MTU+1; в H2-ветке headroom-трюк уже реализован — H3-ветка отстаёт.

**Изменения.**

1. Пул на сессию (не глобальный — MTU конфиг-зависим):

```go
// h3FramePool recycles datagram buffers sized MTU + varint headroom.
// quic-go SendDatagram copies the frame before returning, so the buffer
// is reusable immediately after the call.
```

`sync.Pool` с `New: func() any { b := make([]byte, 0, s.cfg.MTU+16); return &b }` (указатель на слайс — канонический паттерн против аллокации интерфейса).
2. `WritePacket`: `bufp := pool.Get(); frame := appendVarintHeader(*bufp, qsid, ctxID); copy(frame[n:], pkt); SendDatagram(frame); *bufp = frame[:0]; pool.Put(bufp)`. Headroom 16 байт в начале: varint(qsid) ≤ 8 байт + varint(0) = 1 байт — писать заголовок «вперёд» от основания, чтобы copy не двигался.
3. **Обязательная проверка перед реализацией:** убедиться по коду/докам quic-go v0.61, что `SendDatagram` действительно копирует буфер до возврата (это так: датаграмма сериализуется в соединение синхронно). Если вдруг нет — пул запрещён (use-after-put), оставить как есть и записать в отчёт.

**Тесты.**

- `TestWritePacketPoolRoundTrip`: N=1000 последовательных `WritePacket` на фейк-эдже (эхо датаграмм) — все пакеты дошли байт-в-байт; `-race` зелёный; (опционально) аллокации в профиле упали (testing.AllocsPerRun — только если стабильно).

**Критерии приёмки.** Uplink без per-packet аллокаций (кроме growth-случаев), корректность подтверждена эхо-тестом и race-прогоном.

**Размер:** M.

### PATCH-22 [M-10] Discovery: резерв слотов H2 в шейпе скана

**Источник:** M-10 ревью; `src/transport/warp/discovery.go:321-361` (`selectCandidates`).

**Проблема (развёрнуто).** При включённой H3-ветке QUIC-кандидаты (6 адресов × 7 портов = 42) попадают в шейп **первыми** и при `maxTargets=12` (balanced) вытесняют H2-эндпоинты целиком: первые раунды H2 вообще не верифицируется, до самоисцеления через strikes/cooldown проходят 2 полных раунда (~минуты). turbo+H3 не содержит ни одного H2-кандидата. Лестница H3-first опирается на живой H2-фоллбэк — а он не проверен сканом.

**Изменения.**

`selectCandidates` — квота для H2 при наличии обоих списков:

```go
// Mixed-shape fairness: QUIC candidates must not starve H2 verification —
// the H3-first ladder depends on a verified H2 fallback. Reserve half the
// slots for H2 when both candidate lists are non-empty.
h2Quota := 0
if len(h2) > 0 && len(quic) > 0 {
        h2Quota = maxTargets / 2
        if h2Quota == 0 {
                h2Quota = 1
        }
}
```

Порядок заполнения: QUIC первыми до `maxTargets - h2Quota`, затем H2 до лимита. При `maxTargets == 1` (turbo): чередование по раундам — добавить в `Discoverer` поле `round uint64` (инкремент в scan-цикле): нечётный раунд — H3-кандидат, чётный — H2 (устойчивая справедливость вместо вечного H3). Cooldown-исключения (`excluded`) применяются как сейчас — пропуск не занимает слот.

**Тесты.**

- `TestSelectCandidatesReservesH2Slots` (discovery_h3_test.go): balanced, 42 QUIC + ≥1 H2 → в шейпе ≥ `maxTargets/2` H2-кандидатов; все QUIC-слоты ≤ половины.
- `TestTurboAlternatesH2H3`: два последовательных вызова с maxTargets=1 → первый H3, второй H2, третий H3 (проверка чередования раундов).
- Обновить существующие тесты шейпа, если они фиксировали старый порядок.

**Критерии приёмки.** Ни один раунд balanced-скана не остаётся без H2-кандидатов при их наличии в каталоге; turbo чередует транспорты.

**Риски.** Скорость нахождения H3-кандидата в balanced падает (меньше слотов) — приемлемо: назначение скана — верификация обоих путей.

**Размер:** S.

### PATCH-23 [M-15] FakeQUICCover.Release: retry и эскалация

**Источник:** M-15 ревью; `src/transport/warp/nfqwiring.go:519-539` (`Release`), риск §C.4.

**Проблема (развёрнуто).** При неудачном `Deactivate` (сеты nftables не очистились) Release просто считает `applyErrors` — самоисцеления нет: правила продолжают матчить fake-QUIC-обстрел **установленной** сессии (риск §C.4: ненужный шум у DPI после установления), состояние видимо только через `Status`. Один единственный шанс очистки.

**Изменения.**

1. Фоновая пере-попытка по образцу reassert-цикла `ControlFlowGuard` (паттерн уже в кодовой базе): при фейле `Deactivate` — запустить (одну) фоновую горутину retry: попытки каждые 5 с, до 3 попыток, затем переход на разряженный каденс 60 с; успех или новый `Arm()` (ре-arm перекрывает и отменяет retry-контекст) — остановка.
2. Эскалация событием: `GuardEvent{Name: EvFakeQUICCoverReleaseFailed, Detail: reason=… attempt=N err=…}` — на первую неудачу и далее на каждом 60-секундном каденсе (не спамить: между эскалациями ≥ 60 с).
3. `FakeQUICCoverStatus` — новое поле `ReleaseRetries uint64`; `Release` остаётся неблокирующим (retry в горутине, `sync.Once`-подобная защита от дублей retry-цикла).

**Тесты.**

- `TestReleaseRetriesUntilSuccess`: fake-аплайнер, Deactivate падает 2 раза, затем успех → Status: `Releases == 1`, `ReleaseRetries == 2`, событий эскалации 1, финальный вызов Deactivate успешен.
- `TestReleaseEscalatesWhenPersistent`: перманентный фейл → события эскалации с каденсом (fake-часы или короткие интервалы через конфиг-поля); `Arm()` во время retry отменяет retry без утечки горутины.
- `-race` на оба.

**Критерии приёмки.** Неудачный релиз самоисцеляется или громко эскалируется; после успеха обстрел установленной сессии гарантированно прекращён.

**Размер:** M.

---

## 8. Батч 7 (P3) — NIT-чистка (8 патчей)

Мелкие правки; каждая — отдельный коммит `fix(...)`. Тесты обязательны там, где меняется поведение (24, 25, 26, 30, 31); для 27, 28 — тесты на новый статус/структуру; 29 — docs-only.

### PATCH-24 [N-1] cf-warp-colo: регистронезависимое сравнение имени поля

**Источник:** N-1 ревью (B-H7); `src/transport/warp/h3session.go:324`.

H3 обязывает lowercase-имена полей заголовков, но строгое равенство `kv[0] == "cf-warp-colo"` хрупко (нестандартный сервер, прокси-нормализация). Заменить на `strings.EqualFold(kv[0], "cf-warp-colo")`. Тест: декодировать ответ с полем `CF-WARP-COLO` → `res.Colo` заполнен. **Размер:** S.

### PATCH-25 [N-2] randomSport: коллизия больше не «молча перезаписывает flow»

**Источник:** N-2 ревью; `src/transport/nested/masque_carrier.go:222-230` (комментарий «the demux rejects duplicates anyway» — не соответствует коду).

Коллизия случайного порта молча перезаписывает flow в карте: первый клиент орфанится без ошибки. Исправить код до соответствия комментарию (не наоборот): при занятом ключе — до 3 попыток перегенерации порта, затем детерминированный сдвиг (+1 по модулю диапазона); обновить комментарий. Тест: внедрить seam `randomPortFn` (package-level var, тест подменяет) → принудительная коллизия → второй flow получает другой порт, первый жив. **Размер:** S.

### PATCH-26 [N-3] flowConn.Read: короткий буфер читателя — ошибка, не тихая обрезка

**Источник:** N-3 ревью; `src/transport/nested/masque_carrier.go:255-266`.

`n := copy(b, pkt); return n, nil` молча обрезает пакет при `len(b) < len(pkt)` — нарушение контракта `net.Conn` и потеря данных без сигнала. Заменить на семантику `net.UDPConn`: если `len(pkt) > len(b)` — вернуть `n, io.ErrShortBuffer` (пакет при этом потреблён, как в UDP). Тест: буфер короче пакета → `errors.Is(err, io.ErrShortBuffer)`; достаточный буфер — полный пакет. **Размер:** S.

### PATCH-27 [N-4] acceptControlStreams — из прод-кода в тестовый хелпер

**Источник:** N-4 ревью; `src/transport/warp/h3frame.go:161`.

Функция вызывается только тестами — мёртвый прод-код. Перенести в тестовый файл (`h3frame_test.go` или `fakeh3_test.go`), при переносе переименовать с префиксом/суффиксом, принятым в кодовой базе для тестовых хелперов (см. существующие seam'ы `DialH3`, `RouteRunner` — они помечены TEST-ONLY контрактом в доке). Прод-файл h3frame.go теряет функцию. **Размер:** S.

### PATCH-28 [N-5] StatusDetailed: per-peer handshake/RX/TX обоих слоёв одним вызовом

**Источник:** N-5 ревью; `src/transport/nested/matrix.go:291-296` (`MasqueAwgRuntime.Status`), `wgmasque.go:179-187`, дизайн §1.2 (состав Status zapret-gui).

Текущий Status пар возвращает только `(link, gen, childRunning)`. Добавить расширенный снимок, не ломая существующий вызов:

```go
// PairStatus is one snapshot of both composed layers (design §1.2).
type PairStatus struct {
        Link          string
        ParentGen     uint64
        ChildRunning  bool
        Outer         LayerStatus
        Inner         LayerStatus
}
// LayerStatus: last handshake age (or "never"), RX/TX byte+packet counters
// of the layer's own session.
type LayerStatus struct {
        HandshakeMS   int64 // -1 = never established
        RXBytes, TXBytes uint64
        RXPackets, TXPackets uint64
}
```

- `StatusDetailed() PairStatus` на обоих runtime'ах (источники: outer — снапшот сессии `twg.Session`/плейна; inner — снапшот супервизора/forwarder'а; поля уже экспортируются сессиями обоих движков).
- Существующий `Status()` оставить как деградированную обёртку (не ломать вызывающих).
- Для W+W (`NestedWgStatus`) — расширить ту же структуру по месту (там уже частично есть).

Тесты: после bring-up — обе секции заполнены (handshake ≥ 0, RX/TX растут после трафика на фейке). **Размер:** M.

### PATCH-29 [N-6] Шпаргалка брифа: 600 мс vs 700 мс

**Источник:** N-6 ревью; шпаргалка брифа против кода (warp-гейт — пробы каждые 700 мс, H2-наследие; 600 мс — gap WG-гейта `transportwg/trustgate.go`).

Docs-only: исправить формулировку шпаргалки брифа: «warp-гейт: пробы каждые 700 мс (H2-наследие); WG-гейт: интервал 600 мс» — развести величины по владельцам. Код не менять (значения честные и осознанные). Попутно — в ADR PATCH-32 упомянуть наследование параметров 1:1 от H2 (вердикт A7 ревью). **Размер:** S.

### PATCH-30 [N-7] ReadPacket: guard от zero-value закрытого канала

**Источник:** N-7 ревью; `src/transport/warp/h3session.go:368-387`.

После `close(s.packets)` чтение из закрытого канала отдаёт zero-value `packetMsg{nil, nil}` — «пустой пакет без ошибки» в 250-мс окне done-ветки. Гард в начале и в done-ветке:

```go
if m.data == nil && m.err == nil {
        return nil, ErrSessionClosed
}
```

Тест: закрыть done при пустом канале пакетов → `ErrSessionClosed`, не nil-пакет. **Размер:** S.

### PATCH-31 [N-8] Ручка DisableUDPFragment (IP_PMTUDISC_DO)

**Источник:** N-8 ревью; `src/transport/warp/dialudp.go`, дизайн §7.

Дефолт sing-box-совместимый (fragment разрешён) — правильный, но ручки нет. Добавить поле `DisableUDPFragment bool` в политику диал-конфига; в `Control`-цепочке (linux — dialpolicy_linux.go) при `true`: `syscall.SetsockoptInt(fd, syscall.IPP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)` (для v4-сокета; для v6 — `IPV6_MTU_DISCOVER`/`IPV6_PMTUDISC_DO`). Не-linux: no-op + предупреждение в доке поля. Дефолт false — поведение не меняется. Тест по образцу `dialudp_probe_linux_test.go` (assert значения опции сокета; skipped на не-linux). **Размер:** S.

---

## 9. Батч 8 (процесс) — документация, ADR, CI

### PATCH-32 [PT-процесс] ADR-апдендум: путь B и cf-connect-proto на H3

**Источник:** §8.1 отчёта ревью (немые развороты дизайн-решений); карта EH3 (`session_h3.go`), design §2.1.

**Проблема.** Код самосогласованно отходит от брифа в двух местах: (1) реализован **путь B** (рукописный минимальный H3 поверх quic-go Transport) вместо заявленного пути A (quic-go/http3) — разворот дизайн-решения §2.1; обоснование в коде есть (wire-форма сверена с pinned usque-клоном), но владельцем не подписано; (2) заголовки `cf-connect-proto` / `pq-enabled` на H3 не отправляются — код обосновывает их отсутствием в H3-ветке usque, но карта брифа их требует. Оба пункта — организационные дыры: следующий ревьюер обязан трактовать их как несоответствие.

**Изменения.** Одностраничный ADR-апдендум к `eh3-design.md` (§2.1):

1. **Заголовок:** «ADR: H3 реализация — путь B (минимальный рукописный H3 поверх quic.Transport)».
2. **Контекст:** решение §2.1 предписывало путь A; при реализации выявлены ограничения http3.Transport для диалекта CF (extended CONNECT capsule-семантика, контроль control-stream преамбулы, qpack-минимум).
3. **Решение:** путь B; владение диалектом осознанно принимается (trade-off: поддержка QPACK-минимума и wire-дисциплины на нас, зато полный контроль — и это сверено с pinned usque-клоном и реальными векторами warp-socks).
4. **Вердикт по cf-connect-proto/pq-enabled на H3:** рекомендация — **не отправлять** (паритет с H3-веткой usque; расхождение с шпаргалкой брифа признаётся и закрывается этой записью); если владелец решит иначе — отдельный маленький патч на добавление заголовков в qpackWriter (`encodeLiteralNameLine`, по образцу `:protocol`).
5. **Последствия:** шпаргалка брифа обновляется по этим двум пунктам (вместе с PATCH-29).

**Критерии приёмки.** ADR слит в репозиторий рядом с eh3-design.md; оба отклонения имеют письменный вердикт владельца. **Размер:** M (документ).

### PATCH-33 [PT-процесс] Карта сдачи: зафиксировать структурные отклонения Части III

**Источник:** §7 отчёта ревью (plan-deviation по картам N1–N5, EH1–EH5); top-5 п.5.

**Изменения.** Обновить карту сдачи (Часть III) фактическими решениями, каждое с одной строкой обоснования:

1. Пакет `src/transport/nested` вместо заявленного `src/transport/wg` — причина: import-cycle wg↔warp (matrix импортирует оба движка).
2. `reassert` — собственный 30-с тикер карриера, а не тик супервизора (карта N1 требует интеграцию в тик супервизора). Опция нормализации: передать `Assert` колбэком в тик супервизора — решение владельца; по умолчанию фиксируем отклонение (изоляция жизненного цикла карриера).
3. InitialPacketSize — quic-go auto + PMTUD (см. PATCH-20).
4. HandshakeBudget дефолт 10 с (PATCH-13), ResponseBudget 10 с (PATCH-02).
5. AttemptV6 — вариант A/B PATCH-15 с итогом.
6. ICMPv6 — вариант A/B PATCH-18 с итогом.
7. A9/A10-оговорки: дерево НЕ РФ — вне transport-среза (требуется отдельная проводка при сборке TransportService); gVisor-буферы — вне среза, дефолты amnezia-стека; каналы первичника — вопрос владельцу о дизайн-числе ~64.

**Критерии приёмки.** Следующая фаза ревью не тратит таксон на структурные сюрпризы: всё перечисленное — подписанные записи. **Размер:** M (документ).

### PATCH-34 [PT-процесс] CI: серийные race-прогоны wg

**Источник:** §8.2 отчёта ревью (флаки выявляется только серийными прогонами полного пакета).

**Изменения.** CI-джоба: `go test ./transport/wg/ -race -count=3` (после PATCH-03 — стабильно зелёная; count=3 держит регрессию под нагрузкой CI). Опционально: тот же count для warp/nested, если время джобы позволяет. Зафиксировать в README/verification-разделе карты сдачи команду как обязательные ворота. **Размер:** S.

---

## 10. Вне скоупа (не делать в этом цикле)

- **A9, дерево НЕ РФ §7.5** — интеграционный слой (`TransportService`/serviceprofile), не transport-срез; нужен отдельный план проводки (упомянуто в PATCH-33 п.7).
- **A10, gVisor TCP-буферы ≥ 256KiB** — не конфигурируются из этого среза; только оговорка в карте сдачи.
- **Расширение каналов первичника до ~64** — вопрос дизайн-числа владельцу (PATCH-33 п.7), менять без его вердикта нельзя.
- **M+M (потоковый relay поверх датаграмм)** — A1-вердикт: структурная блокировка `ErrNoTCPCarrier` корректна до появления M+M-требования; ничего не делать.
- Любые правки вендора кроме PATCH-03.

---

## 11. Ворота приёмки цикла (финальные, все — из `src/`)

```bash
go vet ./transport/...                                  # чисто
go test ./transport/... -count=1                        # 10/10 пакетов зелёные
go test ./transport/warp/    -race -count=1             # зелёный
go test ./transport/nested/  -race -count=1             # зелёный
go test ./transport/wg/      -race -count=5             # СЕРИЯ: стабильно зелёный (PATCH-03)
go build ./...                                          # вся сборка
```

Дополнительно к командам:

- Ни одного нового vet/staticcheck-предупреждения.
- `changelog.md`: по строке на патч; ADR и карта сдачи обновлены (PATCH-32/33).
- Все тесты, добавленные этим циклом, идемпотентны и не flaky: контрольный прогон полного сьюта ×3.
- Батч 1 считается принятым только при зелёных воротах **полным набором** (включая wg-серию); для остальных батчей достаточно минимального прогона с финальным полным в конце цикла.

## 12. Матрица трассировки: находка ревью → патч

| Находка ревью | Патч | Батч |
|---|---|---|
| MAJOR-1 (лестница не ловит silent-after-handshake) | PATCH-01 (+02 guard) | 1 |
| MAJOR-2 (один общий бюджет вместо двух таймеров) | PATCH-02 | 1 |
| MAJOR-3 (утечка KernelRouteCarrier) | PATCH-04 | 2 |
| MAJOR-4 (data race vendored amneziawg-go) | PATCH-03 | 1 |
| MAJOR-5 (per-layer gate latency не врезана) | PATCH-09 | 3 |
| M-1 (replace→del→replace) | PATCH-14 | 5 |
| M-2 (AttemptV6 мёртвое поле) | PATCH-15 | 5 |
| M-3 (route-lost дубли) | PATCH-06 | 2 |
| M-4 (edge-collision без факт-сверки) | PATCH-17 | 5 |
| M-5 (classifyUDPListenError) | PATCH-10 | 4 |
| M-6 (мёртвые errors.Is) | PATCH-11 | 4 |
| M-7 (ICMPv6 отсутствует) | PATCH-18 | 6 |
| M-8 (ironclad-lite отсутствует) | PATCH-19 | 6 |
| M-9 (InitialPacketSize не задокументирован) | PATCH-20 | 6 |
| M-10 (QUIC вытесняет H2 из скана) | PATCH-22 | 6 |
| M-11 (writeDatagram без proof) | PATCH-16 | 5 |
| M-12 (watch только parent.Done) | PATCH-05 | 2 |
| M-13 (нет буферного пула) | PATCH-21 | 6 |
| M-14 (таксономия route-lost) | PATCH-07 | 2 |
| M-15 (Release без retry) | PATCH-23 | 6 |
| M-16 (HandshakeBudget 20 с) | PATCH-13 | 4 |
| M-17 (CRYPTO_ERROR 0x131) | PATCH-12 | 4 |
| M-18 (нет kill-inner/WAN e2e) | PATCH-08 | 2 |
| N-1 (colo lowercase) | PATCH-24 | 7 |
| N-2 (randomSport коллизия) | PATCH-25 | 7 |
| N-3 (flowConn.Read обрезка) | PATCH-26 | 7 |
| N-4 (acceptControlStreams мёртвый) | PATCH-27 | 7 |
| N-5 (Status без per-layer) | PATCH-28 | 7 |
| N-6 (600/700 мс шпаргалка) | PATCH-29 | 7 |
| N-7 (ReadPacket zero-value) | PATCH-30 | 7 |
| N-8 (DisableUDPFragment) | PATCH-31 | 7 |
| §8.1 (ADR: путь B, cf-connect-proto) | PATCH-32 | 8 |
| §7 (карта сдачи: отклонения) | PATCH-33 | 8 |
| §8.2 (CI серийные race) | PATCH-34 | 8 |

**Покрытие:** 5/5 MAJOR, 18/18 MINOR, 8/8 NIT, 3 процессных пункта — все находки ревью развёрнуты в патчи. Точки принятия решений владельцем (до старта соответствующих батчей): вариант A/B PATCH-15 и PATCH-18; cf-connect-proto вердикт PATCH-32; нормализация reassert-тика PATCH-33 п.2.


# Четыре решения владельца — рекомендации с обоснованием

Разбираю каждый пункт: вердикт, обоснование из базы проекта, риск/условие пересмотра и готовая формулировка для фиксации (ADR / карта сдачи). Все четыре решения взаимосвязаны общей логикой — она в конце.

* * *

## 1\. AttemptV6 (PATCH-15) → **Вариант B: удалить мёртвое поле**

**Контекст:** `FamilyPolicy.AttemptV6` объявлен, но не используется; семантика «v4 mandatory + v6 warn» невыразима. План предлагает либо реализовать двухсемейственный пин (A), либо удалить поле (B).

**Почему B, а не A (вопреки дефолтному уклону плана):**

1.  **Нормативный scope — v4-only.** Аддендум §46 и дизайн §7 прямо говорят: «IPv6 disabled для scope до отдельной валидации». Пинить нечего: ни один живой путь сейчас не может предъявить v6-endpoint.
2.  **Неверифицируемо.** В отличие от чистых функций, v6-пиннинг требует живой v6-маршрутизации и v6-эджмейтов — это ровно та зона, где у проекта стоит `BLOCKED_TARGET_VALIDATION`. Отгрузить непроверенный v6-путь = нарушить принцип «доверие доказывается трафиком».
3.  **Обратимо без долга.** Когда IPv6-scope будет открыт отдельным решением, двухсемейственный пин добавится одним осмысленным этапом с полевыми тестами — сейчас для этого будет больше контекста (карта пул↔colo, поведение NDMS с v6), чем сегодня.
4.  Удаление чище, чем «консервация»: мёртвое поле в конфиг-схеме — постоянный магнит для ложных ожиданий у следующего читателя.

**Когда передумать:** если открытие IPv6-scope запланировано в следующем релизном цикле — тогда дешевле сделать A сейчас.

**Формулировка для карты сдачи:**

> «`AttemptV6` удалён как мёртвое поле. Двухсемейственный пин (v4 mandatory + v6 warn, design §1.1 / zapret-gui :296-330) сознательно не реализуется: аддендум §46 фиксирует v4-only scope до отдельной валидации; непроверенные пути не отгружаются. Восстановление — отдельным этапом при открытии IPv6-scope, с полевыми тестами».

* * *

## 2\. ICMPv6 Packet-Too-Big (PATCH-18) → **Вариант A: реализовать рецепт**

**Почему A, и почему это не противоречит решению №1:**

Ключевая асимметрия: конструктор `BuildICMPv6TooBig` — **чистая функция над байтами**, полностью тестируемая офлайн (векторные тесты: поля, pseudo-header checksum, embedded-данные, недопустимые входы). Ей не нужен живой v6-трафик. Аргумент «неверифицируемо», который лёг в основу решения по AttemptV6, здесь не работает.

1.  **Дизайн уже предписал рецепт.** `eh3-design.md` §3 содержит полный v6-рецепт (type 2, данные ≤1232, MTU 1232, pseudo-header checksum, swap адресов, TTL 64) — реализация закрывает расхождение код↔дизайн.
2.  **Чеклист B-H6 требует явно** оба варианта; «осознанное отсутствие» — допустимый, но более слабый ответ, чем проверенный код.
3.  **Дёшево и изолированно:** одна функция рядом с существующей v4 (её не трогаем) + векторные тесты; без изменений конфиг-схемы.
4.  Когда IPv6-scope откроется (см. решение №1), рецепт уже будет написан и покрыт тестами — реинтеграция станет механической.

**Формулировка:** в коде — комментарий по рецепту из `eh3-design.md` §3; в отчёте реализации: «B-H6 закрыт кодом: v4 + v6 варианты, векторные тесты checksum; v4-only scope туннеля делает v6-ветку латентной до открытия IPv6 — статус честный».

* * *

## 3\. cf-connect-proto / pq-enabled на H3 (PATCH-32) → **Не отправлять; закрыть ADR-апдендумом**

**Почему:**

1.  **Принцип проекта — паритет wire-формы с доказанными в проде реализациями.** Обе продакшн-проверенные ветки против реального CF — H3-ветка usque и минимальный H3 warp-socks — эти заголовки на H3 **не шлют**. Отправка была бы отклонением от доказанной wire-формы с неизвестным риском отказа эджа.
2.  **Механизм уже покрыт стандартом.** На H3 роль `cf-connect-proto` выполняет штатный псевдозаголовок `:protocol = connect-ip` extended-CONNECT — он в коде уже кодируется. `cf-connect-proto` — проприетарный механизм H2-эпохи CF; на H3 он избыточен.
3.  **Спека Пути B в самом `eh3-design.md` §2** перечисляет ровно три QPACK-поля (`0xCF` CONNECT, authority, never-indexed authorization) — без `cf-connect-proto`. То есть реализация следует букве Пути B; расходится она только с картой брифа, унаследовавшей H2-заголовки.
4.  **Добавление потребовало бы живой проверки против CF**, которая запрещена consent-правилом (BLOCKED\_TARGET\_VALIDATION) — значит, отгрузили бы непроверенное отклонение.

**Условие пересмотра (записать в ADR):** если полевая сессия с консентом покажет отказы H3-CONNECT, которых нет на H2, — добавление заголовков (`encodeLiteralNameLine`, по образцу `:protocol`) — первая гипотеза для проверки; патч малый.

**Формулировка:** одностраничный ADR-апдендум по структуре PATCH-32 (контекст → решение Путь B → вердикт по заголовкам → последствия) + правка шпаргалки брифа (в связке с PATCH-29).

* * *

## 4\. Reassert-тик (PATCH-33, п.2) → **Оставить собственный 30-секундный тикер карриера; зафиксировать отклонение**

**Почему не нормализовать в тик супервизора:**

1.  **Функциональная цель N1 достигнута и доказана тестами:** автоматический repin после потери (фикс задокументированного бага zapret-gui), wipe→tick→repin+pin-restored. Ревьювер A3 подтвердил: бюджет достаточен, идемпотентность есть, джиттер не нужен. Претензия — только к точке интеграции, не к поведению.
2.  **Размерность жизненных циклов разная.** Карриер — per-generation сущность (пересоздаётся на каждый реконнект outer), супервизор — instance-level. Встраивание per-generation сущности в instance-level тик требует register/unregister на каждой генерации — это ровно та гоночная поверхность, которую **только что устранили** патчи PATCH-04/05/06 (утёкшие карриеры, конкурирующие за пин и дублирующие события). Нормализация рискует вернуть класс проблем, который закрыт.
3.  **После батча 2 состояние образцовое:** ровно один живой карриер, ровно один assertion-луп, дедуп событий по эпизоду, терминальные записи. Менять это на текстовое соответствие карте — churn без находки.
4.  Изоляция даёт корректное поведение бесплатно: утверждение не зависит от занятости супервизора (скан/диал) и гарантированно останавливается при teardown.

**Когда передумать:** если для Low-тира (Keenetic) появится требование единого heartbeat-дисциплины (минимум независимых таймеров) — тогда перенос в тик супервизора становится осмысленным; до этого — вопрос владельцу из карты сдачи, а не дефолт.

**Формулировка для карты сдачи:**

> «Re-assert пина: собственный 30-сек тикер карриера (`RunAssertionLoop`), а не тик супервизора (карта N1). Обоснование: пер-generation lifecycle карриера изолирован от instance-level супервизора; после PATCH-04/06 — ровно один карриер/луп, события дедуплены по эпизоду; функциональная цель N1 (автовосстановление пина, фикс бага zapret-gui) выполнена и покрыта тестами. Пересмотр — при требовании единого heartbeat на Low-тире».

* * *

## Сводка и согласованность

| 
#

 | 

Вопрос

 | 

Вердикт

 | 

Одна строка

 |
| --- | --- | --- | --- |
| 

1

 | 

AttemptV6

 | 

**B — удалить**

 | 

v6-scope нормативно выключен; непроверяемые пути не отгружаем

 |
| 

2

 | 

ICMPv6

 | 

**A — реализовать**

 | 

Чистая функция, офлайн-тестируема; рецепт предписан дизайном

 |
| 

3

 | 

cf-connect-proto на H3

 | 

**Не отправлять + ADR**

 | 

Паритет с usque-H3/warp-socks; `:protocol` уже есть

 |
| 

4

 | 

Reassert-тик

 | 

**Оставить свой тикер**

 | 

Цель N1 достигнута; нормализация вернёт гонки, которые закрыты

 |

Общая логика, которую стоит отразить в отчёте: **по каждому пункту выбран вариант, минимизирующий непроверенную поверхность** — удаляем то, что нельзя проверить в текущем scope (AttemptV6), реализуем то, что проверяется полностью офлайн (ICMPv6), держим wire-паритет с доказанными референсами (H3-заголовки) и не трогаем работающий lifecycle ради текстового соответствия (reassert).

Тайминг: решения 1 и 2 фиксируются **до старта батча 5** (они определяют объём PATCH-15/18); решения 3 и 4 — до батча 8 (это документы), но принять их лучше сейчас, чтобы PATCH-32/33 писались сразу начисто.


