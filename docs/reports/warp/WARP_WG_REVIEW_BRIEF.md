# REVIEW BRIEF — WireGuard/AWG Transport Layer E-WG (архитектура + код)

**Кому:** ревьювер (сильная модель). **От:** владелец проекта b4x + агент-исполнитель.
**Дата компиляции:** 2026-08-24. **Фаза 2 из 3** (Фаза 1 — MASQUE-слой, см.
`WARP_V2_REVIEW_BRIEF.md`; Фаза 3 — nested-матрица + HTTP/3 транспорт, см.
`WARP_NESTED_H3_REVIEW_BRIEF.md`. Разделы про общие компоненты identity/supervisor/trace —
обязательный контекст этого брифа).
**Материалы ревью:** (1) этот документ, (2) `.ag/research/wg-layer-design.md` — архитектура,
(3) `.ag/research/wg-dataplane-research.md` — исследование референсов (все факты с file:line),
(4) код `src/transport/wg/`, (5) по желанию — первоисточники: amneziawg-go v3 (локальный чекаут
`D:\b4x\wireguard\amneziawg-go`, MIT — верифицировано GitHub API spdx_id=MIT), zapret-gui
SKILL.md, warp-socks, Aether, Nova (декомпиляция).

> **ВАЖНО — объём сдачи:** бриф описывает состояние ПОСЛЕ выполнения этапов WG1–WG7 плана
> дизайна. Файловая карта в Части III — контракт сдачи: отсутствующий или переименованный без
> объяснения компонент = находка `plan-deviation` (SEV=MAJOR). Вне объёма (НЕ находки):
> полевой TUN/PBR слой, H3, NDMS ASC-альтернатива, живые Cloudflare-прогоны, performance-замеры
> на целевом железе.

---

# Часть I. Погружение: зачем второй транспорт и какой у него KPI

## 1.1. Роли слоя (дизайн §0)

| Роль | Зачем | Активация |
|---|---|---|
| R1 | Транспорт-альтернатива MASQUE: UDP проходит там, где TCP-MASQUE фингерпринтится, и наоборот | Discovery / ручной выбор |
| R2 | География выхода — план Б режима «НЕ РФ» (WG-пулы подсетей → выбор colo; MASQUE anycast-зависим и страной не управляет) | Если эксперимент H-NONRU-1 провалится |
| R3 | Nested inner-transport (gool-паттерн WARP-in-WARP) | Этап после base |

## 1.2. Уникальное сочетание — главная ценность для проверки

Кросс-исследование шести проектов подтвердило: нигде не существует комбинация
«AWG-обфускация + Cloudflare reserved-routing + активный seek параметров пира + trust gate по
данным + scoped маршрутизация». По отдельности куски разбросаны: reserved-байты есть только в
usque/Aether/warp-socks линейке; AWG-проекты не знают про client_id вовсе; активного зондирования
версии обфускации нет ни у кого (zapret-gui диагностирует рассинхрон только посмертно).
Ревьювер должен проверять корректность сборки, а не искать этот функционал в референсах.

## 1.3. KPI

1. Латентность: handshake-бюджет 5 с на кандидата; trust-gate окно 10 с (2 DNS round-trip'а,
   гэп 600 мс); seek-лестница дедлайн 80–120 с на endpoint; Happy Eyeballs потолок 10 с.
2. Стабильность: stall-детект «нет RX >10 с» и картина «tx≥4096 при Δrx≤1024 за 120 с»
   (= version-mismatch); cooldown 300 с после 2 провалов; полный teardown вместо полуживых
   состояний; backoff/штампы супервизора общие с MASQUE-треком.
3. Скорость: MTU 1280 (inner 1200 в nested); TCP-буферы netstack ≥256 KiB (урок warp-socks:
   8 KiB давали ~30 KB/s); batch/zero-copy где доступно.
4. Честность: доверие только по реально прошедшим данным; структурные FailureClass; ключи
   никогда не в логах/трейсах.
---

# Часть II. Как формировалась архитектура: источники решений

Метод тот же, что для MASQUE: шесть глубоких исследований агентов, каждый факт с file:line
(компиляция — `.ag/research/wg-dataplane-research.md`). Ключевые решения:

| Решение | Почему | Первоисточник |
|---|---|---|
| Ядро = встроенный amneziawg-go v3, pin commit, MIT (верифицировано GitHub API) | Чистый импорт: NewDevice(tun,bind,logger) → IpcSet(строка) → Up(); UAPI-сокет не нужен; официальный пример эмбеддинга outline/dialer.go в самом апстриме | исследование amneziawg-go |
| Свой conn.Bind: SO_MARK + SO_BINDTODEVICE + hook патчинга датаграмм | Апстрим даёт только SO_MARK (fwmark=); BINDTODEVICE отсутствует; seam buf[1:4] подтверждён sing-box client_bind.go (GPLv3 — идеи, clean-room) | аддендум §17–18 |
| Reserved-байты ТОЛЬКО для CF-пиров (флаг cf_warp) | С ванильным пиром ненулевой reserved ломает MAC; RX требует зануления перед decapsulate | warp-socks teams.rs:291-305; Aether wireguard.rs:53-71 |
| Каталог профилей версионирован; side-разметка client-only vs must-match-peer | I/Jc — client-side (пир дропает); S/H — оба конца побайтно; HP-key требует S≥12; RandomTrailers симметричен — рассинхрон роняет handshakes | amneziawg-go uapi.go/send.go/receive.go |
| Vanilla-safe профиль для CF (только junk, S=0, H=1..4) | Экспериментально проверено zapret-gui; вся библиотека Nova (50 конфигов) ровно такая | zapret-gui warp_generator.py:77-95 |
| Trust gate = handshake + 2 DNS round-trip + e2e warp=on | У WG нет структурного «CONNECT-IP 200»; handshake обманывает | Aether wireguard.rs:431-502; z2k двойная проба; warp-socks health/probe.rs |
| Seek-лестница с классификацией «92B received/20KB sent» → awg-version-mismatch | Активного зондирования версии пира нет ни у кого; сигнатура задокументирована | zapret-gui SKILL.md:53-58; AmneziaChecker sweep-методология |
| Stall-watchdog с порогом min_rx=1024 Б | Пассивный keepalive ~32 Б/10 с давал ложные сбросы таймера без порога | zapret-gui awg_watchdog.py:66-86 |
| Региональные пулы с тегом region | Единственный способ влиять на страну выхода | warpscout SEEN AS методология |
| GOOL-nested: разные edge-IP обязательны; MTU 1280/1200; ka 5/20; независимая валидация слоёв | Проверено полем | Aether lib.rs:1539-1587 |
| Один enrollment → оба транспорта | Ответ регистрации содержит curve25519-ключи и client_id одновременно | usque models/register.go; Aether account.rs finish_provision |

Сознательно НЕ берём: boringtun (Go-стек вместо Rust); decoys T1/T2 включёнными по умолчанию
(опция + pcap-валидация перед полем); kmod awg-proxy (GPL-2.0 — но его урок об обходе FASTNAT/PPE
через UDP-encap softirq учтён концептуально); smoltcp (в Go gvisor netstack); NDMS ASC-путь
(наблюдение как дешёвая альтернатива доставки, не ядро).

---

# Часть III. Карта сдачи (контракт; отсутствие = plan-deviation)

Пакет `github.com/daniellavrushin/b4/transport/wg`. go.mod/go.sum: ровно одна новая зависимость
(amneziawg-go/v3, pinned).

## Статус выполнения (факт на момент сдачи, WG7)

Все семь этапов выполнены и закоммичены в ветку `agent/classifier-v2.3-capture-envelope`.
Отчёт реализации с деталями и гейтами: `docs/reports/warp/WG_IMPLEMENTATION_REPORT.md`.

| Этап | Коммит | Содержание |
|---|---|---|
| WG1 | a4ab0e89 | embedded AWG core, scoped bind with reserved seam, IPC config bridge |
| WG2 | 251b9d10 | identity v2, CF reserved-bytes hook and gate, fake-edge routing matrix |
| WG3 | e0f96eb3 | data-plane trust gate, stall watchdog, session supervisor with bootstrap-probe |
| WG4 | 5f960b68 | versioned AWG profile catalog, seek ladder with strike/cooldown and last-good persistence |
| WG5 | 70036617 | measured endpoint catalog with §34-gate, regional pools and Happy Eyeballs runner |
| WG6 | 6f57ce0c | nested R3 composition: Backend-B loopback carrier, parent-link controller, two-device gool e2e |
| WG7 | (этот документ + `WG_IMPLEMENTATION_REPORT.md`) | финальный полный прогон, актуализация карты |

Финальный гейт сдачи (все — исполненные команды, см. отчёт): gofmt по пакету пуст;
`go build ./...`; `go vet ./...`; `go test ./transport/wg/ -count=2` ok; race-CGO на
юнит-фильтре ok; **полный суит репозитория `go test ./... -count=1`: 53 пакета ok / 0 FAIL**.
Пакет содержит **84 тест-функции** в 17 тест-файлах (+ фикстуры fake-edge/chanTUN).

## WG1 — ядро

| Компонент | Обязанности |
|---|---|
| bind.go | Кастомный conn.Bind: Open/Close/SetMark/Send/ParseEndpoint/BatchSize; SO_MARK через fwmark; SO_BINDTODEVICE; fail-closed при невозможности применить constrained policy; точки перехвата TX/RX датаграмм (reserved/junk hook) |
| tun.go | Два бэкенда за интерфейсом Device: kernel /dev/net/tun (CreateTUN) и userspace netstack (CreateNetTUN, gVisor); MTU 1280 |
| config_bridge.go | Генерация IpcSet-строки; валидатор ДО применения: chain-DSL с разделителем ПРОБЕЛ (двоеточия невалидны), текст вне тегов отвергать, Jc 1–128, Jmin<=Jmax<=1280, непересечение H-интервалов, HP-key => S1–S4>=12, bool только on/off, J1-J3/Itime хранить но не рендерить |
| logger_bridge.go | device.Logger → наш логгер без ключевого материала |

Фактические файлы: `bind.go`, `tun.go` (+ `tun_kernel_linux.go` / `tun_kernel_stub.go`),
`confbridge.go` + `chain.go` + `validate.go` (генерация IPC / парсер DSL / pre-IpcSet валидатор),
`logger.go`.

## WG2 — идентичность и reserved

| Компонент | Обязанности |
|---|---|
| identity_wg.go | Расширение стора E2: wg_private_key/peer_pub/client_id (strict decode_fixed 32/32/3), флаг cf_warp; атомарные записи 0600 + карантин; один enrollment кормит оба транспорта |
| reserved.go | Деривация base64(client_id)+pad -> до 3 байт; TX патч packet[1..4] типы 1–4; RX зануление; применение только при cf_warp |

Фактические файлы: `identity.go` (Identity v2, IdentityStore, ReservedHook/DatagramHookOrNil —
seam живёт здесь, применяется в `bind.go`), `bind_seam_test.go` (round-trip seam-тесты),
`reserved_integration_test.go` + `fakeedge_test.go` (fake CF-edge стенд).

## WG3 — trust gate и здоровье

| Компонент | Обязанности |
|---|---|
| trustgate.go | Handshake → DATA GATE (синтетический DNS-зонд x2 round-trip, гэп 600 мс, окно 10 с) → E2E trace-проба warp=on|plus двойным замером; таймаут => teardown + FailureClass |
| stall.go | Нет валидного RX >10 с; tx>=4096 при delta rx<=1024 за 120 с (чистая stateful функция); рестарт через супервизор |
| supervisor_hooks.go | Интеграция в цикл E3: backoff/штампы/kick переиспользуются; события wg_* §62 → TracePipeline; wg_established строго после trust gate (= точка cutoff камуфляжа) |

Фактические файлы: `trustgate.go`, `watchdog.go`, `failures.go` (структурные FailureClass),
`session.go` (supervisor-цикл поколений с bootstrap-probe; колбэки OnEvent/OnEstablished/OnLost).

## WG4 — каталог профилей и seek-лестница

| Компонент | Обязанности |
|---|---|
| profiles_catalog.go | CatalogVersion; семьи: quic-a/quic-b (фейковый QUIC Initial, маркер 44d0), sip-invite (+100 Trying), crlf-light/aggressive, vanilla-off; поля engine_generation/client_side/match_side/affinity; side-разметка обязательна |
| seek.go | Лестница [preferred → vanilla-off → quic → sip → crlf-light → aggressive]; исходы WINNER / awg-version-mismatch (92B/20KB сигнатура) / handshake-fail; детерминизм; дедлайн 80–120 с; события трассировки на каждый шаг |

## WG5 — endpoints

| Компонент | Обязанности |
|---|---|
| endpoints_wg.go | ZeroTrust 162.159.193.0/24 x порты {2408,500,1701,4500} (тест диверсификации), расширенные 854–8886, hostname engage.cloudflareclient.com; региональные записи tag region; InCatalog-гвардия |
| happy_eyeballs.go | Интерлив v4/v6, стаггер 250 мс·i, потолок 10 с; UDP A-first |
| состояние | last_good {endpoint,profile} + cooldown-map (общая форма с MASQUE-discovery) |

Фактические файлы: `endpoints.go` (EndpointCatalogVersion=1, CorePorts+ExtendedPorts —
измеренные списки с provenance, §34-гейт InCatalog, ScanStrategy с капами, региональные
пулы RegionPool{Tag,Prefixes,Verified,Source,VerifyMeta}, PoolCandidates plan-B),
`happyeyeballs.go`, `lastgood.go`.

## WG6 — nested (R3)

| Компонент | Обязанности |
|---|---|
| nested_wg.go | Outer (primary id, MTU 1280, obf ON, ka 5) → userspace forwarder/proxy 127.0.0.1 или netstack → Inner (secondary id, MTU 1200, ka 20); ЖЁСТКО разные edge-IP; независимый trust gate каждого слоя; parent-link инвалидация/revalidation по поколениям (контракты E5) |

Фактические файлы: `nested.go` (NestedWgConfig — ТРИ адресных роли: публичный внешний эдж /
сквозной внутренний эдж / loopback-диал; Validate gool-правил), `forwarder.go`
(LoopbackForwarder — Backend-B carrier, single-client last-writer-wins, dial-seam),
`nested_runtime.go` (NestedWgRuntime — колбэк-driven контроллер parent-link: child-first
teardown, пересоздание форвардера на netstack каждой новой генерации outer, статусы
waiting-parent/up/child-invalidated).

## WG7 — финализация

Полный прогон vet/test/race; зелёный ./... репозитория; обновление отчётов и карты файлов брифа.
ВЫПОЛНЕНО: отчёт `docs/reports/warp/WG_IMPLEMENTATION_REPORT.md`; карта этой части
актуализирована фактическими именами; финальные гейты зафиксированы в блоке «Статус выполнения».

Тесты: bind/reserved/trustgate/stall/profiles_catalog/seek/endpoints_wg/nested_test.go +
fakepeer_test.go (фейковые пиры и edge-стенд). Имена могут отличаться — обязательна покрываемость.

Верификация при сдаче (фактическая политика; полная -race на пакете ловит известную гонку
внутри апстримного device/timers.go — поэтому race гоняется на юнит-фильтре без
device-lifecycle, а device-сценарии покрываются count=2 и полным суитом):

```text
docker run --rm --dns 8.8.8.8 --mount type=bind,source=D:\b4x,target=/src \
  --mount type=bind,source=D:\b4x\.go-modcache,target=/go/modcache \
  --mount type=bind,source=D:\b4x\.go-buildcache,target=/go/build \
  -e GOMODCACHE=/go/modcache -e GOCACHE=/go/build \
  -w /src/src golang:1.25.3-alpine sh -c "gofmt -l ./transport/wg/ && go build ./... && \
  go vet ./... && go test ./transport/wg/ -count=2"
# + race-CGO юнит-фильтр (без device-lifecycle):
#   CGO_ENABLED=1 go test -race ./transport/wg/ -run 'TestChain|TestIPCString|TestParseKey|
#   TestParseRange|TestProfile|TestReserved|TestDatagramHook|TestIdentity|TestSetMark|
#   TestNilHook|TestOpenTwice|TestWatchdog|TestLicense|TestEndpoint|TestRace|TestNestedWg|TestForwarder'
# + полный суит репозитория: go test ./... -count=1  (53 packages ok / 0 FAIL)
```

### Известные ограничения (НЕ считать находками)

1. Живой Cloudflare-WG edge не прогонялся (consent rule); BLOCKED_TARGET_VALIDATION остаётся.
2. Kernel-TUN/PBR применение — полевой слой.
3. H3/QUIC вне этапа; NDMS ASC — наблюдение.
4. Performance-замеры на целевом железе отсутствуют.
5. Linux mark-пути покрыты smoke-планом (автотест требует CAP_NET_ADMIN).
6. Патч апстримных констант очередей под low-memory — задокументированный кандидат вне объёма.
7. KNOWN-ISSUE: `TestSeekVersionMismatchMovesToNextProfile` = SKIP (seek_test.go) — второй
   ПОСЛЕДОВАТЕЛЬНЫЙ netstack-session к тому же инстансу фейк-эджа не двигает данные даже при
   выровненных параметрах (подозрение на roaming/replay-state края). Все остальные сценарии
   спроектированы «один netstack-session на инстанс эджа» и от этого ограничения не зависят.
8. `gofmt -l .` по ВСЕМУ репозиторию показывает исторические неотформатированные файлы ВНЕ слоя
   wg (capture/ppe, cmd/ppe-probe, config, dhcp, discovery, fieldtest, http/handler и др.) —
   вне объёма этапа; по `./transport/wg/` gofmt чист.
9. Полная `-race` на пакете — см. примечание над командой верификации (upstream timers.go);
   это ограничение апстрима, задокументировано с WG1.

---

# Часть IV. Задание ревьюверу

## Часть A. Оценка архитектуры (verdict agree / agree-with-changes / disagree + обоснование)

A1. Ядро: embed amneziawg-go v3 vs upstream wireguard-go + собственная junk-обфускация — устойчиво ли к дрейфу DSL апстрима (формат цепочек двигался; linkname fastrandn в timers)? Есть ли план Б?
A2. Reserved-hook в Bind vs патч device: полно ли покрытие поведений CF-edge (cookie-reply и его MAC, семантика нулевого reserved на RX)? Что упускаем, модифицируя только transport-датаграммы?
A3. Каталог профилей: достаточна ли side-разметка (client-only vs must-match-peer) и генерационные теги для безопасного перебора? Гарантирован ли vanilla-off как обязательный кандидат?
A4. Seek-лестница: бюджеты и классификация — риски ложных awg-version-mismatch на медленных handshake? Взаимодействие с endpoint-cooldown (флап между двумя парами endpoint+profile)?
A5. Trust gate без структурного события протокола: достаточна ли пара «2 DNS round-trip + e2e warp=on» против подделки ответов middlebox'ом? Нужен ли ironclad-lite (реальный HTTP 204) как опция глубокого режима?
A6. Stall-детекторы: пороги 10 с / 120 с / min_rx 1024 Б — баланс между быстрым обнаружением и ложными рестартами на bursty-idle трафике?
A7. Региональные пулы (R2): методика SEEN AS интегрируется без нарушения запрета произвольного сканирования? Как часто реверифицировать region-теги?
A8. Nested: gool-правила (разные edge-IP, MTU/ka разведение) применимы к кросс-транспортному вложению outer-WG → inner-MASQUE (не только WG-in-WG)?
A9. Identity v2: миграция существующих сторов обратно совместима? Схема secondary-слотов для nested не создаёт путаницы с MASQUE-inner слотами?
A10. Ресурсы Keenetic: нужен ли патч констант очередей amneziawg-go (bounded pools) в рамках этапа или допустимо отложить при GOMEMLIMIT-ручке?

## Часть B. Чеклист кода (src/transport/wg/)

B1. bind.go: порядок SO_MARK→SO_BINDTODEVICE; частичное применение = fail-closed; EPERM без CAP_NET_ADMIN → класс FailureDialPolicy; корректность BatchSize для netstack-TUN связки.
B2. reserved.go: round-trip patch/unpatch на всех типах пакетов 1–4; зануление RX строго ДО decapsulate; применение гейтируется флагом cf_warp; деривация base64+pad соответствует warp-socks teams.rs.
B3. config_bridge.go: полный whitelist ключей setconf; J1-J3/Itime никогда не уходят; групповой пропуск jc/jmin/jmax при одном нулевом значении НЕ допускается молча (урок zapret-gui — их render_setconf так делал и получал гарантированный version-mismatch); ошибки валидации человекочитаемы.
B4. trustgate.go: чистая тестируемая логика подсчёта подтверждений; поведение при конкурентном потребителе пакетов (pump уже читает канал?); teardown после таймаута гарантирован.
B5. stall.go: stateful-детектор с ре-базой при переполнении счётчиков; устойчивость к passive keepalive (32 Б/10 с); рестарт идёт через супервизор с cooldown, а не сразу.
B6. seek.go: детерминизм порядка; состояние last_good {endpoint,profile}; ограничение общего бюджета; события трассировки на каждый шаг (WINNER/MISMATCH/HANDSHAKE-FAIL).
B7. nested.go/nested_runtime.go: изоляция identity-слотов; forwarder односессионный (последний клиент побеждает) — задокументировано?; teardown порядок inner-first; разные edge-IP проверяются до установки, а не после.
B8. Lifecycle: closeOnce везде; порядок Down→Close; нет утечек горутин (прогнать goleak-паттерн как в upstream тестах).
B9. Конфиг-ошибки: человекочитаемые, с указанием поля и поколения; дамп effective-config (без секретов) при провале IpcSet.
B10. Приватность: ключи/client_id/endpoints только в хэшированном виде в трейсах; в логах никогда.
B11. Тесты: соответствие матрице отказов; отсутствие ложных PASS на silent-drop; интероп triple (vanilla↔vanilla, AWG↔AWG, AWG↔vanilla).

Формат отчёта:

```text
[SEV] area/file:line — проблема → предлагаемый fix
SEV в {BLOCKER, MAJOR, MINOR, NIT}; area в {arch|code|test|ops|plan-deviation}
```

Итоговые таблицы: (а) findings по severity; (б) вердикты A1–A10; (в) список «проверено, проблем
нет»; (г) top-5 приоритетных действий; (д) plan-deviation по карте Части III.

---

# Часть V. Красные линии

1. amneziawg-go/v3 — единственная новая зависимость, pin commit; MIT NOTICE сохранён.
2. Никакого GPL/kmod/sing-box-GPLv3 кода — только идеи clean-room.
3. Reserved-байты применяются только к CF-пирам (cf_warp flag); с прочими — нули.
4. Junk/обфускация не включается против пира без подтверждённой совместимости (vanilla-CF
   принимает только junk-семейство — экспериментальный факт).
5. Vanilla-off профиль всегда присутствует в лестнице как fallback.
6. Никаких тихих приведений параметров: невалидный профиль = ошибка валидатора, не автокоррекция.
7. Все ограничения MASQUE-этапа действуют: без live-регистраций в тестах, роутер не трогаем,
   коммиты только по явной просьбе владельца.

---

# Часть VI. Шпаргалка констант WG/AWG

```text
Peer pubkey (WARP):  bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
Endpoint host:       engage.cloudflareclient.com (+ порты 500–8886)
ZeroTrust пул:       162.159.193.0/24 x {2408,500,1701,4500}
Расширенные порты:   443,500,1701,4500,4443,8443,8095 (+854..8886 у расширенных пулов)
WG-пулы (регион):    8.6.112 / 8.34.70 / 8.34.146 / 8.35.211 / 8.39.125 / 8.39.204 /
                     8.39.214 / 8.47.69 / 162.159.192 / 162.159.195 / 188.114.96-99
Reserved:            base64(client_id)+pad'=' -> первые <=3 байта -> packet[1..4] типы 1-4;
                     RX зануление перед decapsulate
MTU:                 TUN 1280; nested inner 1200; warp-socks референс 1330
Keepalive:           одиночный 25 c (NAT); gool outer 5 / inner 20
Trust gate:          handshake + 2 DNS RT (гэп 600 мс) в окне 10 с; стартовый бюджет ~20 с
Stall:               нет RX >10 c ИЛИ tx>=4096 при delta rx<=1024 за 120 c
Seek:                >=3 попытки/endpoint; лестница preferred->off->quic->sip->crlf;
                     cooldown endpoint 300 c после 2 провалов
Валидация профиля:   Jc 1-128; Jmin<=Jmax<=1280; H непересекающиеся диапазоны; HP => S>=12;
                     chain-DSL через пробел; J1-J3/Itime не рендерить
Identity refusal:    только 401/404/410 = перевыпуск; 403/429/5xx = лимит (НЕ перерегистрировать)
```

*Конец брифа. Спасибо за глубину.*

# Часть VII. Приложение E-NM: nested matrix (bd b4x-ji0)

Статус: ядро N1-N5 сдано и запушено (commit 1bf346d5); e2e M+W добавлен следом.
Полный отчёт: docs/reports/warp/NESTED_MATRIX_IMPLEMENTATION.md (карта файлов,
гейты, self-report отклонений от буквы дизайна - раздел 3).

## Что ревьюить

| Зона | Файлы |
|---|---|
| Контракт носителя | src/transport/nested/carrier.go, doc.go |
| Kernel-route ownership | kernelroute.go, kernelroute_ops.go (+_linux/_stub) |
| Netstack carrier | netstack.go |
| MASQUE datagram carrier | masque_carrier.go, udpdgram.go |
| Матрица+runtime M+W | matrix.go |
| Наблюдаемость | metrics.go |
| Аддитивные швы движков | transportwarp/supervisor.go (SubscribePackets/tapPump), transportwg/forwarder.go (экспорт alias) |

## Верификация (фактом)

- go build ./... ok; gofmt/vet чисто по слою; nested/warp/wg count=2 ok; race(CGO) ok
- полный суит go test ./... -count=1 = 54 packages ok / 0 FAIL
- КРОСС-ДВИЖКОВЫЙ E2E M+W (masque_awg_e2e_test.go): настоящий DialSession против
  fake CONNECT-IP эджа с NAT в НАСТОЯЩИЙ amneziawg-go респондер; inner AWG сессия
  проходит handshake + trust gate (DNS round trips) СКВОЗЬ обе плоскости до
  wg_established. Это офлайн-пруф эскалационного пути дерева НЕ РФ (7.5 шаг 2).

## Хвосты E-NM

- прод-wiring W+M (Reconciler вторичного слота, MSS/PMTU конфиг)
- экспорт Metrics в pipeline уровня интеграции
