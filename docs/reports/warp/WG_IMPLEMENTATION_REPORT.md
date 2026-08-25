# E-WG IMPLEMENTATION REPORT — WireGuard/AWG transport layer (WG1–WG7)

**Дата сдачи:** 2026-08-24. **Ветка:** `agent/classifier-v2.3-capture-envelope`.
**Пакет:** `src/transport/wg` (`github.com/daniellavrushin/b4/transport/wg`).
**Зависимости:** ровно одна новая — `github.com/amnezia-vpn/amneziawg-go/v3 v3.1.20260814`
(MIT, pin; NOTICE.md с полным текстом и sha256-pin лицензии, тест-хеш).
**Бриф ревьювера:** `docs/reports/warp/WARP_WG_REVIEW_BRIEF.md` (карта файлов Части III
актуализирована фактическими именами). Дизайн: `.ag/research/wg-layer-design.md`.

---

## 1. Коммиты этапов

| Этап | Коммит | Тема |
|---|---|---|
| WG1 | a4ab0e89 | embedded AWG core, scoped bind with reserved seam, IPC config bridge |
| WG2 | 251b9d10 | wg identity v2, CF reserved-bytes hook and gate, fake-edge routing matrix |
| WG3 | e0f96eb3 | data-plane trust gate, stall watchdog, session supervisor with bootstrap-probe |
| WG4 | 5f960b68 | versioned AWG profile catalog, seek ladder with strike/cooldown and last-good persistence |
| WG5 | 70036617 | measured endpoint catalog with §34-gate, regional pools and Happy Eyeballs runner |
| WG6 | 6f57ce0c | nested R3 composition: Backend-B loopback carrier, parent-link controller, two-device gool e2e |
| WG7 | (документы) | финальный полный прогон, отчёт, актуализация карты брифа |

## 2. Карта пакета (факт)

Производственный код:

| Файл | Строк | Назначение |
|---|---|---|
| bind.go | 246 | кастомный conn.Bind: SO_MARK/SO_BINDTODEVICE fail-closed, DatagramHook seam, idempotent Close/Open-циклы |
| socket_linux.go / socket_other.go | 74/27 | apply-or-fail применение mark/bind-device по платформам |
| tun.go (+tun_kernel_linux/_stub) | 121 | ModeNetstack (gVisor) / ModeKernel (/dev/net/tun, compile-gated); DefaultMTU 1280 / InnerMTU 1200 |
| chain.go | 180 | строгий парсер AWG chain-DSL (пробел; arity; 0..4096; ≤16 элементов; канонический round-trip) |
| validate.go | 211 | pre-IpcSet валидатор профилей (jc/jmin/jmax, H-интервалы, HP⇒S≥12, VanillaSafe()) |
| confbridge.go | 204 | whitelist-рендер IpcSet; J1–J3/Itime хранятся, никогда не рендерятся |
| logger.go | 23 | DeviceLogger(nil-safe), DiscardLogf дефолт |
| identity.go | 266 | Identity v2 + IdentityStore (atomic 0600, карантин *.corrupt) + ReservedHook/DatagramHookOrNil (только cf_warp) |
| failures.go | 58 | структурные FailureClass: wg-handshake-timeout, wg-stall-rx, awg-version-mismatch, awg-param-rejected, awg-junk-profile-failed, reserved-bytes-invalid |
| trustgate.go | 299 | trust gate: 2×DNS round-trip, гэп, окно; RawTUN + NetstackRoundTripper; retry 700 мс |
| watchdog.go | 164 | rx-idle ИЛИ rolling-window «tx≥MinTX @ Δrx≤MaxRX» сигнатура; injectable Now/Tick |
| session.go | 491+10 | Session: assemble→IpcSet→Up→bootstrap-probe→handshake→gate→Established→watchdog→restart; MaxGenerations; Tunnel() accessor; nsUDPDial seam |
| profiles.go | 202 | CatalogVersion=1: vanilla-off/quic-a/quic-b/sip-invite/crlf-light/crlf-aggressive (все cf-warp=VanillaSafe) + awg-sh-a; LadderFor |
| seek.go | 386 | Seeker: бюджеты HS/gate/attempt/total/cooldown/strikes; классификация winner/mismatch/stall; StrikeState shared; TunnelFactory hook |
| lastgood.go | 106 | Attempt + LastGoodStore (Memory|File atomic, corrupt→*.corrupt, version-guard) |
| endpoints.go | 385 | EndpointCatalogVersion=1: CorePorts{2408,500,1701,4500}+ExtendedPorts×50 (provenance: Aether wireguard.rs == warpscout == Nova ⊆-проверка), §34-гейт InCatalog, RegionPool с Verified/VerifyMeta, ScanStrategy капы, builtinSeedPool, SeedEndpointsV6 |
| happyeyeballs.go | 118 | интерлив v4/v6, стаггер, потолок |
| nested.go | 179 | NestedWgConfig: ТРИ адресных роли (OuterEdge публичный / InnerEdge сквозной / InnerDial loopback); Validate gool-правил (identity, адреса, edge-IP, MTU-градиент, obf ON на outer, ka 5≠20, ErrInnerNotLoopback) |
| forwarder.go | 214 | LoopbackForwarder: host-loopback ↔ gonet connected conn через dial-seam; last-writer-wins; closeOnce+Wait |
| nested_runtime.go | 288 | NestedWgRuntime: колбэк-driven parent-link контроллер; child-first teardown; пересоздание форвардера на netstack каждой генерации outer; статусы waiting-parent/up/child-invalidated; события wg_nested_* |

Тесты: **85 тест-функций** в 17 файлах (вкл. fake CF/AWG-edge стенд на реальном amneziawg
Device, chanTUN-фикстуры, interop triple vanilla↔vanilla / AWG↔AWG / AWG↔vanilla,
junk-client↔vanilla-edge acceptance).

## 3. Верификация сдачи (все строки — исполненные команды, docker golang:1.25.3-alpine)

```text
gofmt -l ./transport/wg/                     → пусто
go build ./...                               → ok
go vet ./...                                 → ok (clean)
go test ./transport/wg/ -count=2             → ok (~59 s)
CGO_ENABLED=1 go test -race ./transport/wg/ -run '<unit-filter>' -count=2 → ok
go test ./... -count=1                       → 0 FAIL; 53 packages ok (WG6) → 57 ok (WG7 сдача,
                                               +4 пакета параллельной работы владельца вне слоя wg)
```

Юнит-фильтр race (device-lifecycle исключён — известная гонка апстрима device/timers.go,
задокументирована с WG1): TestChain|TestIPCString|TestParseKey|TestParseRange|TestProfile|
TestReserved|TestDatagramHook|TestIdentity|TestSetMark|TestNilHook|TestOpenTwice|TestWatchdog|
TestLicense|TestEndpoint|TestRace|TestNestedWg|TestForwarder.

## 4. Отклонения от буквы плана (self-report plan-deviation)

1. **Имена файлов**: плановые config_bridge/logger_bridge/identity_wg/reserved/stall/
   supervisor_hooks/profiles_catalog/endpoints_wg/happy_eyeballs/nested_wg реализованы как
   confbridge+chain+validate / logger / identity(+ReservedHook внутри) / watchdog /
   (супервизор в session.go) / profiles / endpoints / happyeyeballs / nested+forwarder+
   nested_runtime. Карта Части III брифа обновлена фактическими именами.
2. **Контроллер WG6 колбэк-driven**, а не poll-тикером как warp E5: у Session есть честные
   OnEstablished/OnLost переходы; контракты parent-link (child-first, инвалидация, gen++,
   revalidation) сохранены.
3. **E2E gool**: внешний фейк-эдж — существующий startFakeEdge (уже на канальном TUN) без
   отдельной фикстуры; форвардинг расшифрованных UDP к внутреннему эджу делает harness-pump;
   цель форвардера в тестах — TEST-NET 198.51.100.x с трансляцией на реальный loopback
   внутреннего эджа (иначе gVisor доставляет пакет локально себе).
4. **MaxGenerations пробрасывается только во inner-сессию** (решение владельца): outer живёт
   до Stop, его жизненный цикл — зона ответственности надстройки.
5. **CI-окна таймингов** через опциональные хуки OuterHealth/InnerHealth (production = числа
   дизайна).
6. **JUNK-FIRST дефолт лестницы cf-warp** (решение владельца 24.08, посмертное изменение
   плана §5 дизайна): порядок `[quic-a → quic-b → sip-invite → crlf-light → crlf-aggressive
   → vanilla-off]` вместо `[vanilla-off → …]`. Обоснование: джанк живёт только на фазе
   handshake (I-пакеты до инициации + Jc вокруг handshake-сообщений; транспорт без джанка),
   поэтому дефолт почти ничего не стоит в steady-state, зато убирает сигнатуру
   WG-establishment (148Б init / type-byte) с первого датаграммы — против DPI-детекта
   классического WireGuard. Ваниль остаётся последним fallback'ом, last-good запоминает
   победителя, seek автоматически эскалирует вниз при провале gate. Красная линия §11.4 не
   тронута: против CF по-прежнему только VanillaSafe client-side семейства. Acceptance-гэп
   «junk-клиент ↔ ванильный эдж» закрыт тестом `TestJunkClientAgainstVanillaEdge`
   (реальный vanilla amneziawg Device + полный CF reserved-дисциплин: junk доходит как
   rxUnknown и отбрасывается routing-discipline, protocol-датаграммы остаются
   зарезервированными, handshake+gate проходят).

## 5. Известные ограничения

Полный список — в брифе (Часть III «Известные ограничения», пункты 1–9). Ключевые:
живой Cloudflare-WG edge не прогонялся (consent rule); kernel-TUN/PBR — полевой слой;
`TestSeekVersionMismatchMovesToNextProfile` = SKIP (KNOWN-ISSUE: второй последовательный
netstack-session к тому же инстансу эджа не двигает данные — подозрение на roaming/replay-state
края; все прочие сценарии спроектированы «один netstack-session на инстанс эджа»);
repo-wide `gofmt -l .` имеет исторические замечания вне слоя wg.

## 6. Готовность к ревью

Код закоммичен и запушен (HEAD = 6f57ce0c). Бриф актуализирован (карта файлов, статусы,
команда верификации с race-политикой, ограничения 7–9). Материалы ревьювера: этот отчёт +
`WARP_WG_REVIEW_BRIEF.md` + дизайн + исследование + код пакета.
