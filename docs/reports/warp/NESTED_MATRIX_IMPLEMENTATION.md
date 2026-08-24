# E-NM — WARP Nested Matrix: Implementation Report (N1–N5)

Дата: 2026-08-24 (вечер, обновлено). База: `6f57ce0c` (WG6), ветка `agent/classifier-v2.3-capture-envelope`.
Тикет: bd `b4x-ji0`. Дизайн: `.ag/research/warp-nested-matrix-design.md`.
Коммиты: `1bf346d5` feat(nested) N1–N5 ядро; e2e M+W + brief-sync — следующим коммитом по команде владельца.

## 1. Карта пакета `src/transport/nested` (11 файлов, ~1459 строк; тесты 6 файлов, ~907)

| Файл | Содержимое |
|---|---|
| `doc.go` | Контракт пакета, матрица комбинаций M+W / W+W / W+M, красные линии §8 |
| `carrier.go` | `NestedCarrier` (InjectUDPDatagram / DialTCPThrough / ProofSnapshot) ровно по дизайну §1; расширение `UDPSessionCarrier.DialUDPThrough` → `UDPSession` для релейного шва; классы событий §5 (`nested/carrier-route-lost`, `nested/pin-restored`, `nested/edge-collision`, `nested/inner-version-mismatch`); структурные ошибки `ErrCarrierUnproven/ErrCarrierClosed/ErrNoTCPCarrier`; `FamilyPolicy` |
| `kernelroute.go` | KernelRouteCarrier ч.1: ownership-цикл zapret-gui — snapshot prev-route → идемпотентный pin `/32`(/128) через outer dev → верификация чтением `route get` (не кодов выхода); self-clean при провале верификации (del своего пина + verbatim-рестор чужого); v4-fail = rollback, v6-fail = warning |
| `kernelroute_ops.go` | ч.2: `Assert()` — тик супервизора (фикс задокументированного гэпа zapret-gui «restart теряет пин»: lost → auto-repin → события carrier-route-lost + pin-restored); `RunAssertionLoop`; `Restore()` — teardown восстанавливает ПРЕЖНИЙ маршрут дословно (token-split replace), foreign не трогается; `DialUDPThrough/DialTCPThrough` fail-closed по proofOK |
| `kernelroute_linux.go/_stub.go` | Прод-ranner `IPRouteRunner` (iproute2 exec, house style src/tun/route.go) / fail-closed заглушка вне linux |
| `netstack.go` | NetstackCarrier над `*netstack.Net` (тот же хендл, что WG6 LoopbackForwarder): UDP/TCP gonet-диалы, proof `netstack:<gen>`; ноль новых зависимостей |
| `udpdgram.go` | Крафт/парс IPv4+UDP с полными чексуммами (математика = probe.go) для датаграмной плоскости MASQUE; `ErrNotV4` по scope §46 |
| `masque_carrier.go` | MasqueDatagramCarrier: Write = крафт + supervisor.WritePacket; Read = тап-насос + tuple-demux на per-flow UDPSession (без loopback-шим, drop-instead-of-block); DialTCPThrough = `ErrNoTCPCarrier` (BLOCKED_CARRIER семантика bd b4x-9aa); ProofSnapshot = RouteHeld |
| `matrix.go` | Схема §6: Kind/LayerSpec/PairConfig.Validate (kind-pair {awg,masque-h2}², inner slot = secondary, edge-collision, MTU-cap 1200, failure_mode только fail-closed-scoped); ResolveCarrier auto (по режиму дата-плоскости OUTER'а); швы `ForwarderSeam` (carrier→LoopbackForwarder dial-seam) и `CarrierDialFunc` (carrier→transportwarp SessionConfig.DialFunc); **MasqueAwgRuntime** — полный M+W runtime: parent-link poll (E5-контракт), child-first teardown, gen++ на каждый held-переход |
| `metrics.go` | N4-наблюдаемость: PairActive/RepinTotal/RouteLostTotal/EdgeCollisionTotal + per-layer OuterGateMS/InnerGateMS (атрибуция §62.9); `CountingEvents` |

Аддитивные правки существующих пакетов:
- `transportwarp/supervisor.go` (+80): `SubscribePackets()` — тапы входящих DATAGRAM уровня супервизора, переживающие поколения; `tapPump` на каждое поколение (спавн после EvMasqueConnected); `closeTaps` на выходе цикла. Diff чисто аддитивный, поведение прежних путей не тронуто.
- `transportwg/forwarder.go` (+13): экспорт шва `UDPConn`/`DialUDPFunc` (type alias) — внешние композиции адаптируют носители к реле без дублирования насосов.

## 2. Верификация (все — исполненными командами в docker)

| Гейт | Команда | Результат |
|---|---|---|
| Build | `go build ./...` | ok |
| gofmt | `gofmt -l ./transport/nested/` | пусто |
| vet | `go vet ./transport/{nested,warp,wg}/` | clean |
| Тесты новых | `go test ./transport/nested/ -count=2` | ok (24 теста ×2) |
| Тесты warp/wg | `go test ./transport/warp/ ./transport/wg/ -count=2` | ok / ok |
| Race (CGO) | `-race`: nested count=2; warp -run TestSubscribePackets count=2 | ok / ok |
| ПОЛНЫЙ суит | `go test ./... -count=1` (корень репо с artifacts/+specs/) | **54 packages ok / 0 FAIL** |

gofmt-замечания `transport/warp/{fakeserver_test,probe,probe_test,varint}.go` — ПРЕДСУЩЕСТВУЮЩИЕ (known-issue из WG7-брифа, вне этого слоя).

## 3. Self-report: отклонения от буквы дизайна

1. **N2/gVisor-решение**: NetstackCarrier реализован БЕЗ нового решения по зависимостям — gVisor уже прямая зависимость транспортного слоя (amneziawg-go tun/netstack, импорт в transportwg/tun.go). Дефер bd b4x-9aa касается ТОЛЬКО userspace-TCP-носителя поверх MASQUE и остаётся в силе.
2. **UDPSession как расширение контракта**: интерфейс NestedCarrier держит ровно 3 метода дизайна; двунаправленный релей вынесен в опциональный `UDPSessionCarrier` — kernel/netstack реализуют реальными connected-сокетами, MASQUE — tuple-demux. Причина: LoopbackForwarder требует Read, которого нет в минимальном контракте.
3. **FamilyPolicy без silent-default**: нулевое значение = ни одна семья не обязательна (явный opt-in), вместо автофлипа RequireV4=true. Безопасность держит proofOK-гейт диалов (нет верифицированного пина — нет Dial*).
4. **W+W не переписывался**: матрица делегирует зелёному `transportwg.NestedWgRuntime`; e2e двух устройств уже покрыт WG6. Улучшение «инжект без loopback-шим» реализовано там, где оно ново — в MasqueDatagramCarrier.
5. **TCP-dial сквозь gVisor игнорирует ctx во время хендшейка** (пин gvisor 2023-12-01f7806d) — та же категория ограничения, что задокументирована в transportwg/trustgate.go; юнит-тест заменён детерминированным closed-carrier контрактом, e2e-случай отнесён к интеграционному стенду.

## 4. Хвосты (follow-up, в bd)

- ~~E2E M+W целиком~~ **ЗАКРЫТО**: `masque_awg_e2e_test.go` — настоящий
  `twarp.DialSession` против fake CONNECT-IP эджа (капсульный NAT) в НАСТОЯЩИЙ
  amneziawg-go респондер; inner AWG проходит handshake + trust gate до
  `wg_established` сквозь обе плоскости (~3.5s, count=2 стабильно). Попутно
  `MasqueAwgConfig.Supervisor` → `Plane CapsulePlane` (DI для e2e без зачисления).
- прод-wiring W+M: Reconciler/identity вторичного слота + MSS/PMTU-параметры конфигурации.
- Экспорт метрик Metrics наружу (pipeline-адаптер уровня интеграции).

## 5. Уроки e2e (для будущих фикстур)

- varint капсул — QUIC/RFC9000 §16 (2-битный префикс длины), НЕ LEB128;
  эталон — transportwarp/varint.go AppendVarint.
- tun.Device.Read возвращает ЧИСЛО БУФЕРОВ, байты — sizes[0].
- порт эджа брать только из bind.ActualPort() ПОСЛЕ Up(), не из пробной сокеты.
- gVisor этого пина: TCP-connect игнорирует ctx при хендшейке; UDP/IP чексуммы
  на входе netstack валидируются строго.
- NAT-фикстура: clientSport по «последний писатель побеждает» — самозаживление
  между поколениями inner-сессии.
