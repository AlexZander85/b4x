# E-NM: построчный разбор + полный патч-план (E-WG + E-NM)

**Ревьювер:** независимая сильная модель (агент-ревьювер).
**Дата:** 2026-08-29. **Материалы:** архив `b4x-agent-classifier-v2.3-capture-envelope (3).zip`,
слой `src/transport/nested/` (16 прод-файлов, ~1550 строк + 8 тест-файлов, ~1000 строк),
швы `src/transport/warp/supervisor.go` и `src/transport/wg/{forwarder.go, session.go, tun.go, nested.go}`,
предыдущий отчёт `WG_LAYER_REVIEW_REPORT.md` (WG1–WG7, 22 findings), бриф
`docs/reports/warp/WARP_WG_REVIEW_BRIEF.md` (Часть VII: E-NM), отчёт
`docs/reports/warp/NESTED_MATRIX_IMPLEMENTATION.md`, дизайн `.ag/research/warp-nested-matrix-design.md`
(цитируется по коду/отчёту).

**Метод.** Построчное чтение всего производственного кода E-NM и обоих аддитивных швов;
сверка каждого пункта карты Части VII и каждого self-report-отклонения из
NESTED_MATRIX_IMPLEMENTATION §3–§4; трассировка жизненного цикла обоих рантаймов
(M+W, W+M) по поколениям с опорой на фактическую семантику коллбеков
`transportwg.Session` (`OnEstablished`/`OnLost` из session.go:190–240, 353–360) и
`TunnelConfig.InterfaceName` (tun.go:69 — «kernel mode hint; empty = kernel picks»);
проверка тестовой матрицы на ложные уверенности (какие ветки кода тесты не видят).
Инструментальные гейты (`go build/vet/test`) не исполнялись — Go-тулчейна в среде
ревьювера нет (ограничение унаследовано из WG-отчёта, §«Ограничения верификации»).
Все выводы ниже — чтение кода, а не отчёта исполнителя.

**Итог углубления.** Предыдущий «лёгкий» проход дал E-NM чистую бумагу. Построчный
разбор эту оценку снимает: **3 MAJOR** (детерминированная утечка kernel-пина при
teardown; утечка KernelRouteCarrier на каждое поколение outer с потерей провенанса
foreign-маршрута; рассинхрон имени TUN-устройства и пина в kernel-режиме W+M),
**12 MINOR** (включая отсутствие ретрая мёртвого child при живом parent в M+W —
тот же класс, что WG MINOR 13, но с более жёстким условием), **8 NIT**. Критично:
находки E-WG не изолированы от E-NM — rx-idle 10 с против keepalive 5/20 с
(WG MAJOR 4) **гарантированно** индуцирует рестарт-циклы во вложенных парах, а в
kernel-режиме W+M каждый такой рестарт течёт носителем (E-NM E2). Архитектура
при этом остаётся добротной: контракт носителя, гейт-дисциплина fail-closed,
кросс-движковый e2e — настоящие; чинить нужно жизненный цикл, а не замысел.

---

## Часть I. Построчный разбор E-NM (`src/transport/nested`)

Формат находок: `[SEV] файл:строки — проблема → fix`. Идентификаторы `E1…E23` —
новые находки этого прохода; ссылки `WG-#` — на находки предыдущего отчёта
(WG_LAYER_REVIEW_REPORT.md, §1). Строки — по текущему коду архива.

### I.1 `doc.go` + `carrier.go` — контракт пакета

- `doc.go:1–27`: матрица M+W / W+W / W+M, правило «data-plane режим outer решает
  носитель», красные линии §8 (обе стороны гейтов, no silent fallback, one CF device
  per layer, foreign routes never deleted). Декларации соответствуют коду, кроме
  последней красной линии — см. E1/E6 (foreign-маршрут можно потерять на teardown).
- `carrier.go:24–28` `NestedCarrier`: три метода дизайна §1 — ровно, без лишнего.
- `carrier.go:30–45` `UDPSession`/`UDPSessionCarrier`: расширение вынесено из
  минимального контракта — грамотно (LoopbackForwarder требует Read, которого в
  дизайне нет); саморасширение задокументировано в self-report §3.2.
- `carrier.go:50–55` классы событий: **`ClassInnerVersionMismatch` не имеет ни
  одного продьюсера в пакете** (см. E12/г) — объявленный дизайн §5-класс мёртв.
- `carrier.go:67–81` структурные ошибки: `ErrFamilyUnsupported` **недостижим** —
  ни один носитель его не возвращает (см. E14): FamilyPolicy работает не так,
  как задокументировано.
- `carrier.go:83–94` `FamilyPolicy`: нулевое значение = явный opt-in (без
  silent-default) — соответствует self-report §3.3. Но `AttemptV6` — мёртвое поле
  (E14): `Setup` пинит только семейство Endpoint, вторую семью не пробует никогда.

**Контрактная часть чистая; два мёртвых элемента API — E12(г), E14.**

### I.2 `kernelroute.go` + `kernelroute_ops.go` + `_linux/_stub` — kernel-route ownership

Построчно (139 строк kernelroute.go, 207 строк kernelroute_ops.go):

- `kernelroute.go:109–134` `Setup`: пин → verify чтением `route get` → coverage-gate →
  proofOK. Роллбек обязательной семьи корректен: `Restore` + ошибка. Замечание: строка
  123–124 `restCtx := ctx` — мёртвый алиас (E16).
- `kernelroute.go:139–182` `pinFamily`: идемпотентность (147: «уже наш и owned»),
  replace с fallback del→replace (151–166), verify-fail → self-clean **del нашего
  пина + verbatim-restore prev** (172–177) — эта ветка делает ОБА действия, в отличие
  от `Restore` (E1). Три дефекта:
  - **E5 [MINOR]** `144`: `prevRaw, _ := Runner(route show …)` — ошибка show
    проигнорирована. Транзиентный провал show → prev="" → на teardown foreign-маршрут
    не восстановится (fail-open против красной линии «foreign routes never lost»).
    Fix: ошибка show = отказ пина (fail-closed) либо ретрай.
  - **E6 [MINOR]** `151–166`: fallback-ветка при повторном провале replace
    **оставляет удалённый del-ем foreign-маршрут без восстановления**: prev здесь
    не ресторится (recordOwned не вызван, Setup-роллбек ресторит только owned).
    Сценарий: replace упал (EEXIST-класс с чужим маршрутом другого типа) → del прошёл
    (чужой маршрут удалён) → retry replace упал → чужой маршрут потерян навсегда.
    Fix: в ветке повторного провала — verbatim-restore prev (как в 173–177).
  - **E7 [MINOR]** `147, 174` и `kernelroute_ops.go:99`, `kernelroute.go:191`:
    матчинг устройства подстрокой `strings.Contains(line, "dev "+Device)` —
    префиксные коллизии имён (`dev wg0` матчится в `dev wg01`) дают ложное «уже
    наш»/«verify ok». Fix: токенный матчинг (следующий токен после `dev` == Device).
- `kernelroute.go:186–196` `verifyRoute`: чтение эффективного маршрута — правильная
  дисциплина (не коды выхода); но см. E7 про подстроку.
- `kernelroute_ops.go:18–47` `Assert`: тик супервизора; при провале ремонта —
  proofOK=false и ранний return (30–33) — остальные owned не проверяются до
  следующего тика (терпимо, тик 30 с). Строка 37–39: proofOK=true при непустом
  owned и coverageOK — корректно после успешного ремонта.
- `kernelroute_ops.go:50–56` `repairPin`: replace + verify — ок; **но не проверяет
  closed перед повторным пином** (E8): Assert, зашедший до `Close`/`Restore`, может
  пере-пинить маршрут ПОСЛЕ teardown.
- `kernelroute_ops.go:60–82` `RunAssertionLoop`: тикер, ctx/stopCh — ок; таймаут
  тика 5 с — ок.
- `kernelroute_ops.go:85` `StopAssertionLoop`: `closeOnce(stopCh)` — **не ждёт
  loopWg** (E8): `Close` (166–169) тоже. Окно гонки: in-flight Assert + параллельный
  `Restore` → повторный пин после рестора. Fix: `loopWg.Wait()` в Close +
  closed-гейт в repairPin.
- `kernelroute_ops.go:90–108` `Restore` — **E1 [MAJOR]**: при успехе
  verbatim-restore prev ветка `continue` (101–103) **пропускает удаление нашего
  пина**. Корректно ТОЛЬКО если prev — чужой маршрут с тем же префиксом (replace
  перезаписывает наш /32). Но типичный prev из `ip route show <dst>` —
  **покрывающий** маршрут (`default via … dev eth0`): `route replace default …`
  не трогает наш /32 → **пин переживает полный teardown** — детерминированно, в
  самом частом случае. Трафик к inner-edge уходит в мёртвый девайс до ручной
  чистки. Док-комментарий «Restore tears down ALL owned pins» ложен. Тест
  `TestKernelRestoreDeletesOwnedPinOnly` не ловит: prev там пустой (см. I.11).
  Многострочный prev даёт мусорную команду replace → err → fallthrough на del —
  «случайно правильно». Fix см. PATCH-06.
- `kernelroute_ops.go:110–123` `DialUDPThrough`: fail-closed по proofOK — ок;
  `context.Background()` в `InjectUDPDatagram` (129) — E17 [NIT].
- `kernelroute_ops.go:140–148` `DialTCPThrough`: fail-closed — ок.
- `kernelroute_ops.go:150–161` `ProofSnapshot`: «pins:…@dev» — ок.
- `kernelroute_ops.go:166–169` `Close`: closed + stopCh — без Wait (E8).
- `kernelroute_linux.go:17–32` `IPRouteRunner`: exec `ip`, таймаут 5 с, stderr в
  ошибку — ок; `kernelroute_stub.go` fail-closed вне linux — ок.
- Семантика v6 (kernelroute_ops.go:173–193): v6-Endpoint при `RequireV4=true`
  даёт coverage-gate-отказ (232: `v4 || !RequireV4`) — согласуется с «v4 mandatory»;
  но `AttemptV6` при v4-Endpoint не делает НИЧЕГО (E14).

### I.3 `netstack.go` — gVisor-носитель

- `36–41`: nil-гейт конструктора — ок. `81–86` `ProofSnapshot`: живой стек = пруф —
  семантика дизайна; `c.ns == nil` в 82 — мёртвая проверка (E22 [NIT]).
- `44–78`: диалы через `ns.DialContext` — ок; ограничение «TCP-connect игнорирует
  ctx во время хендшейка» (пин gvisor) задокументировано в self-report §3.5 —
  принято как известное.
- `56–64` `InjectUDPDatagram` — `context.Background()` (E17 [NIT], тот же класс).
- Носитель не владеет стеком (Close = флаг) — владение у outer-сессии — ок.

**Файл чистый, кроме двух NIT.**

### I.4 `udpdgram.go` — крафт/парс IPv4+UDP

- `31–71` `BuildUDPDatagram`: полные чексуммы (псевдозаголовок UDP, заголовок IP),
  DF, TTL 64, диапазон total ≤ 0xffff — корректно; тест TestUDPDatagramChecksumsValid
  перепроверяет обе — ок.
- `81–105` `SplitUDPDatagram`: структурные проверки (версия/IHL, proto, tot, ulen) —
  два замечания: **E20 [NIT]** (а) `101`: ulen сверяется с `len(pkt)`, а не с `tot` —
  при паддинге за tot полезная нагрузка может «расшириться» в паддинг (демукс по
  кортежу это переживает, но строгости ради — сверять с tot); (б) инбаунд-чексуммы
  не верифицируются — оправдано QUIC-AEAD внешней плоскости, но нигде не
  задокументировано. Фрагментированные IPv4 (MF/offset) парсятся как «первый
  фрагмент» — мусор отсекается демуксом по кортежу; для WG-трафика <1200 неактуально.
- `109–125` sum32/finalize — идентичны probe.go (один факт, один источник) — ок.

### I.5 `masque_carrier.go` — датаграммная плоскость MASQUE

- `74–88` конструктор: nil-plane/unspecified-LocalV4 — fail-closed; OuterMTU →
  `twarp.DefaultMTU` (1280). См. E13 (MTU не пробрасывается рантаймом).
- `92–100` `StartPumping` (pumpOnce): **не проверяет closed** (E21 [NIT]) —
  StartPumping после Close подписывается и качает вечно (до закрытия плоскости).
- `102–126` `pump`: split → демукс по `flowKey{peer,peerPort,localPort}` →
  приватная копия payload → drop-instead-of-block (ch 32) — дисциплина правильная;
  счётчики matched/unknown/dropped — N4-наблюдаемость — ок.
- `129–131` `InjectUDPDatagram`: случайный sport на каждый вызов — контракт
  «fire-and-forget» (ответы уйдут в unknown); реальный релейный путь идёт через
  `DialUDPThrough` — соответствует дизайну, но в док-комментарии carrier.go:17–18
  «WG/AWG handshake and transport traffic» вводит в заблуждение (через Inject
  handshake-ответы НЕ возвращаются) — отметить в патч-плане (PATCH-25, дока).
- `134–152` `DialUDPThrough` — **E11 [MINOR]**: `c.flows[key] = f` молча
  перезаписывает существующий flow при коллизии sport (комментарий 222–224
  «the demux rejects duplicates anyway» — **неверен**: демукс не отвергает, а
  подменяет). Осиротевший старый flowConn остаётся у владельца (Read навсегда
  пуст), а его `Close()` делает `removeFlow(key)` — **удаляет НОВУЮ регистрацию**.
  Вероятность мала (40000 sport), но контракт сломан. Fix: при существующем ключе —
  перевыбор sport (цикл) или ошибка.
- `154–170` `writeDatagram`: MTU-гейт — ок; `Plane.WritePacket` — wake-up-семантика
  супервизора (буферизация при мёртвой сессии) — осознанный «мягкий» гейтинг
  против жёсткого proofOK у kernel-носителя: допустимо (plane-уровень владеет
  дисциплиной), но асимметрия постур носителей стоит строки в доке (PATCH-25).
- `179–187` `ProofSnapshot`: RouteHeld плоскости — ок (fail-open супервизора
  корректно отражается в ok=false).
- `199–214` `Close`: swap-idempotent, отписка, закрытие всех flow — ок;
  `closeNow` не removeFlow (карта уже пересоздана) — ок.
- `255–266` `flowConn.Read`: после Close select между буферным ch и done —
  недетерминирован (пакет или ErrCarrierClosed) — семантически терпимо для
  teardown; `copy(b, pkt)` молча усекает — как настоящий UDP — ок.

### I.6 `matrix.go` — схема §6 + M+W рантайм

- `86–122` `PairConfig.Validate`: kind-pair, слоты primary/secondary, профиль-ID,
  endpoint'ы, edge-collision (по Addr — правильно, правило про IP), MTU-cap 1200,
  carrier-режимы, failure_mode — всё по дизайну §2/§6. `ResolveCarrier` (127–146)
  принимает `CarrierDatagram`, который `Validate` (113–117) отвергает как
  «not declarable» — рассинхрон контрактов (E18 [NIT]); безвредно (Resolve после
  Validate), но запутывает.
- `153–179` швы `ForwarderSeam`/`CarrierDialFunc`: строгий network-гейт
  (udp-only / tcp-only), ParseAddrPort — ок; возвращают ошибки, не паники — ок.
- `186–205` `MasqueAwgConfig`; `229–259` `NewMasqueAwgRuntime`: Validate + kind-пары
  + Plane/Ident обязательны; PollInterval 20 мс; DNS-дефолт 8.8.8.8.
  **E10 [MINOR]**: `InnerIdent` проверяется только на nil; `AssignedV4` НЕ
  валидируется → `innerTunnel()` (401–412) вызывает `mustAddr(AssignedV4)`
  (432: `netip.MustParseAddr`) **в горутине run()→startChild** → нулевой
  `Identity{}` (который передаёт сам тест, masque_runtime_test.go:40!) роняет
  процесс. Тот же класс, что WG MAJOR 2. Fix: ParseAddr при construction → ошибка.
- `262–275` `Start`: startOnce, cancel, pump, run — ок.
- `279–288` `Stop` — **E15 [MINOR]**: `<-r.done` при никогда не стартовавшем run()
  **блокирует навсегда** (done закрывает только run). Стоп-до-Старта = дедлок.
  Симметричная дыра у обоих рантаймов: Start-после-Stop работает, но второй Stop —
  уже no-op (stopOnce потрачен) → рантайм-зомби. Fix: стейт-флаг (atomic) или
  закрывать done в Stop при не-started-рантайме.
- `308–338` `run` — **E3 [MINOR]**: цикл parent-link. Ветка
  `case nowHeld && !held:` при провале `startChild` делает
  `setLink("child-invalidated")` + `break`, после чего `held = nowHeld` (336)
  становится **true**. Все следующие тики: nowHeld=true, held=true → ни одна ветка
  не выполняется → **мёртвый child при живом parent не ретраится до следующего
  флапа parent**. Тот же класс, что WG MINOR 13 (nested_runtime.go:199–246), но
  условие жёстче: локальный `held` делает это свойством цикла, а не только
  отсутствием таймера. Fix см. PATCH-08.
- `340–377` `startChild`: fwd.Start → NewSession → Start; частичные отказы закрывают
  fwd — ок; Session.Start не «частично» стартует (session.go:157–169) — утечек нет.
  `348`: `fwd.Start(context.Background())` — ок (Close в stopChild). `359`:
  `Health: {KeepaliveSec: NestedInnerKeepaliveSec (=20 с)}` — watchdog-дефолты
  (RXIdle 10 с) применяются к inner-сессии → см. I.14 (rx-idle × nested).
- `379–390` `stopChild`: child-first, swap под mu — ок; гонка Stop vs startChild
  ограничена (после `<-r.done` новых startChild нет).
- `401–412` `innerTunnel`: ModeNetstack + mustAddr (см. E10) + MTU-cap — ок.
- `246–249`: конструирует carrier без OuterMTU — **E13 [MINOR]**: фактический MTU
  внешней плоскости не пробрасывается (всегда 1280); при plane-MTU < 1228 все
  inner-датаграммы отклоняются локально → «up»-чёрная дыра. Fix: проброс MTU из
  Pair.Outer.MTU/Plane + инвариант InnerMTU+28 ≤ OuterMTU в Validate.

### I.7 `wgmasque.go` — W+M рантайм

- `56–78` `Validate`: kind-пара, outer-ident, kernel-поля строго парные,
  secondary-слот обязателен (красная линия #3) — хорошо.
- `123–176` `Start` — **E4 [MAJOR]** (составная часть): `TunnelConfig` (139–144)
  **не задаёт `InterfaceName`** → kernel-режим создаёт TUN с именем, выбранным
  ядром («empty = kernel picks», tun.go:69), а `buildCarrier` (286–293) пинит в
  `Device: r.cfg.KernelDevice`. Имя пина и имя реально созданного устройства
  **никак не связаны** — совпадение возможно только случайно (первый свободный
  `tun%d`). Пин либо в никуда, либо в чужой интерфейс → kernel-режим W+M
  неработоспособен по построению (кроме счастливого tun0). Path никогда не
  e2e-ился («полный e2e W+M — интеграционный стенд/поле», self-report §4) —
  потому и не поймано. Fix: `InterfaceName: r.cfg.KernelDevice` в TunnelConfig ИЛИ
  брать фактическое имя из `outer.Tunnel().Device.Name()` после OnEstablished.
- `141`: `netip.MustParseAddr(r.cfg.OuterIdent.AssignedV4)` — **E10 [MINOR]**
  (вторая половина): panic при пустом/битом AssignedV4; `Validate` проверяет
  только nil. Тест сам передаёт `&twg.Identity{}` (wgmasque_test.go:31, 86).
- `191–212` `Stop`: cancel → stopInner → kernel- teardown (StopAssertionLoop +
  Restore + Close) → outer.Stop — порядок child-first — ок. Замечания: (а) Restore
  здесь зависит от корректности E1-фикса; (б) см. E2 про старые kernel-носители.
- `224–227` `watch(parent)` — **E9 [MINOR]**: горутина ждёт ТОЛЬКО `parent.Done()`;
  `Stop()` будит `r.cancel` (потомок parent) — watch не просыпается, `r.done` не
  закрывается, горутина живёт до смерти parent-ctx. Фикс: select на cancelCtx
  (или отдельный stop-канал).
- `232–270` `onParentUp` — **E2 [MAJOR]**: на КАЖДОЕ поколение outer строится
  СВЕЖИЙ KernelRouteCarrier (`buildCarrier`, 284–315: New + `Setup` +
  `RunAssertionLoop(context.Background(), 30s)`), а старый (r.kernel) **просто
  перезаписывается (240–242) без StopAssertionLoop/Restore/Close**; `onParentLost`
  (274–281) kernel-носитель тоже не трогает. Следствия в kernel-режиме:
  1. **Утечка горутины assert-цикла + `ip route get` каждые 30 с на каждое
     поколение outer** — цикл на `context.Background()`, stopCh никогда не
     закрывается. Рестарты outer — штатный сценарий (watchdog; и WG MAJOR 3/4
     гарантируют их частоту), утечка накапливается.
  2. **Потеря провенанса foreign-маршрута**: K2.Setup видит в `route show` уже
     пин K1 (`... dev wgX`) → prev-запись K2 = наш собственный пин, а не исходный
     foreign-маршрут; финальный Restore (при E1-баге и без него) уже не восстановит
     исходный маршрут. K1.Restore никто не вызовет никогда.
  3. K1 и K2 спорят об ownership одной записи (одинаково безвредно, но
     наблюдаемость событий удваивается).
  Fix: носитель kernel-режима должен быть **один на весь рантайм** (это и есть его
  дизайн: assert-цикл чинит пины через воссоздания устройства — «закрытие
  zapret-gui-гэпа»), свежими должны быть только netstack-носители. См. PATCH-07.
- `244–251` `NewSupervisor(Reconciler{InnerEnroll, IdentityStore{InnerSlotPath}})`:
  вторичный слот структурно обязателен — красная линия #3 соблюдена.
- `256–261`: `ictx` от cancelCtx; провал `sup.Start` → icancel + setInvalidated —
  без ретрая (тот же класс E3; для W+M ретрай придёт только со следующим
  поколением outer — соотв. WG MINOR 13).
- `284–315` `buildCarrier`: kernel-ветка см. E2/E4; netstack-ветка: `Tunnel()` →
  `Netstack` nil → `ErrCarrierUnproven` — fail-closed — ок; label «gen=N» — ок.
- `317–327` `innerTemplate`: MTU-cap, DialFunc через носитель — ок; MSS-клоб
  только kernel-носителю (tcp_mss.go) — соотв. дизайну §3.3.
- `329–342` `stopInner`: swap под одним локом (inner + innerCancel) — TOCTOU нет;
  рекомендация прошлого отчёта «смотреть гонки innerCancel/inner в stopInner» —
  снята: сама пара атомарна; реальная гонка была в другом месте (Stop vs
  поздний onParentUp — mitigated через cancelCtx, и watch-утечка E9).
- `344–383`: bumpGen/setInvalidated/emit/proofText — ок.

### I.8 `tcp_mss.go` + `_linux/_other`

- `22–50` `DialerWithMSS`: копия диалера, ControlContext-обёртка, сохранение
  prev-Control (MSS → потом prev) — корректно; off-linux no-op задокументирован.
- `_linux`: `SetsockoptInt(IPPROTO_TCP, TCP_MAXSEG)` — ок. **Файл чистый.**

### I.9 `metrics.go` + `metrics_pipeline.go`

- **E12 [MINOR]** — наблюдаемость N4 частично мертва:
  - (а) `PairActive` (metrics.go:16) **никто не пишет**: ни один рантайм не делает
    `Store(1/0)` на up/down; серия `nested_pair_active` всегда 0 (читается только
    Snapshot'ом). Хвост «экспорт Metrics» закрыт наполовину — экспорт есть,
    источник gauge отсутствует.
  - (б) `ObserveGate` (metrics.go:46) **не вызывается ни одним прод-путём**:
    `nested_layer_gate_duration_seconds` навсегда 0. «Per-layer gate latency
    capture points» (комментарий) — точки захвата есть, захвата нет.
  - (в) `metrics_pipeline.go:43,47`: `v >= 0` — gate-серии экспортируются ВСЕГДА,
    даже до первого наблюдения (0.000 с — ложные данные в серии).
  - (г) `ClassInnerVersionMismatch` без продьюсера (см. I.1).
  Fix: PATCH-20 — wiring PairActive в оба рантайма, ObserveGate вокруг
  trust-gate (inner — по событиям сессии; outer — в WgMasqueRuntime), sentinel
  −1 + пропуск ненаблюденных, продьюсер класса или удаление.
- `ExportLoop`: ctx-гёрoutine, тикер — ок; первый экспорт только после интервала —
  приемлемо (дока: «call from integration tickers»).

### I.10 Швы с движками

**`transport/warp/supervisor.go` (аддитивный патч):**

- `335–352` `SubscribePackets`: регистрация в pktSubs, cancel закрывает канал
  ровно один раз — ок; **переживает поколения** (подписка на уровне супервизора) —
  как заявлено.
- `358–374` `guardTapPump`/`failSafePanic`: recover + EvEnginePanic + operator-pause
  на PanicLimit — дисциплина M3-07 сохранена — ок.
- `406–419` `tapPump`: один насос на поколение, выход по закрытию сессионного
  канала/ctx — ок.
- `421–431` `fanOutTaps` — **E19 [NIT]**: один и тот же слайс отдаётся всем
  supervisor-подписчикам БЕЗ копии, тогда как сессионный уровень даёт private copy
  каждому (session.go:585–598, контракт M-30). Текущий единственный потребитель
  (masque_carrier.pump) не мутирует и копирует payload сам — безопасно сегодня,
  но контракт над supervisor-уровнем не задокументирован и не защищён: будущий
  мутирующий подписчик молча испортит данные другим. Fix: копия в fanOutTaps
  (дёшево: 1 копия на подписчика, как в session) либо явный док-контракт.
- `433–444` `closeTaps`: закрытие всех каналов на выходе цикла — pump
  MasqueDatagramCarrier корректно завершается (`for range ch`) — утечки насоса нет.
- `546` `defer s.closeTaps()` в run — ок.

**`transport/wg/forwarder.go` (экспорт шва +13 строк):**

- `37–40`: `UDPConn`/`DialUDPFunc` — type alias, ровно для внешних композиций — ок.
- `80–121` `Start`: dial → listen 127.0.0.1:0 → два насоса; ошибки закрывают
  частично созданное — ок.
- `140–155` `Close` + `160–167` `stopped` + насосы `170–223`: last-writer-wins
  задокументирован; Write-ошибка upstream гасит forwarder (self-healing через
  рестарт inner-сессии) — ок.
- `236–239` `udpAddrPortOf` — **E23 [NIT]**: `ap.Addr().As4()` паникует на v6;
  латентно (листенер 127.0.0.1 → клиент всегда v4). Fix: `Is4()`-гейт.

### I.11 Тестовая матрица E-NM: что покрыто и где ложные уверенности

33 тест-функции (8 kernelroute + 6 masque_carrier + 3 masque_runtime + 4 matrix +
3 netstack + 3 udpdgram + 5 wgmasque + 1 e2e). Числа согласуются с self-report
(«24 теста» — до закрытия хвостов; +9 из wgmasque/masque_runtime/e2e = 33).

Сильное (проверено, ложно-положительных PASS не вижу):

- **e2e M+W** (`TestMasqueAwgE2EHandshakeAndGateThroughBothPlanes`): настоящий
  `twarp.DialSession` → fake CONNECT-IP edge (TLS+h2, NAT капсул) → настоящий
  amneziawg-go респондер; критерий — `wg_established` (handshake + два DNS
  round-trip сквозь обе плоскости) + handshakeSeen на респондере. Диагностическая
  деградация Fail-сообщения образцовая (caps/sport/fwd/repRead/demux). Это
  реальный офлайн-пруф эскалационного пути, не соломенный.
- kernelroute: idempotent-Setup (replace==1), rollback-on-verify-fail с
  verbatim-restore, Assert-репарация + событие, assert-цикл на живом тикере,
  fail-closed TCP-диал до Setup, v6 warn-only.
- masque_carrier: крафт (тройная проверка заголовков), oversize, демукс
  туда-обратно, мусор не блокирует насос, proof трекает RouteHeld, TCP
  структурно ErrNoTCPCarrier.
- matrix: таблица Validate, авто-резолв носителя, оба шва (udp-only/tcp-only).
- Проверка чексумм в udpdgram — независимая перепроверка обеих.

Ложные уверенности / дыры покрытия (каждая соответствует найденному дефекту):

1. `TestKernelRestoreDeletesOwnedPinOnly` (kernelroute_test.go:312–326): prev
   пустой → ветка verbatim-restore/E1 **не выполняется ни разу во всём суите**.
   Добавление одной строки `fr.showPre["9.9.9.9"] = "default via 10.1.1.1 dev wan0"`
   делает тест падающим СЕГОДНЯ (fakeRoutes честно моделирует разные ключи «default»
   и «9.9.9.9/32») — репродукция E1 в три строки.
2. Нулевые Identity: `masque_runtime_test.go:40` и `wgmasque_test.go:31,86`
   передают `&twg.Identity{}` — тесты «зелёные» именно потому, что E10 не
   проверяется (и если бы plane держал route — panic в run()).
3. `TestWgMasqueRuntimeConstruction` **не вызывает Start** (комментарий честен:
   нужен живой edge) → все пути onParentUp/buildCarrier/watch/Stop без юнит-покрытия:
   E2, E4, E9 невидимы для CI. Нужен fake-outer (fakeedge_test.go из E-WG уже умеет
   настоящий vanilla-device — реюз для W+M-рантайма).
4. Нет теста Stop-до-Start (E15 — нельзя написать без фикса: он висит).
5. Нет теста ретрая child после провала startChild (E3).
6. Нет теста коллизии sport (E11) и StartPumping-после-Close (E21).
7. Metrics: `ObserveGate` дёргается только руками в тесте — прод-проводки нет
   (E12) — тест маскирует мёртвую серию.

### I.12 Сводная таблица новых находок E-NM

| # | SEV | файл:строки | суть |
|---|-----|-------------|------|
| E1 | MAJOR | kernelroute_ops.go:90–108 | Restore: при покрывающем prev `continue` пропускает del нашего пина → детерминированная утечка /32 после teardown (частый случай: prev = default) |
| E2 | MAJOR | wgmasque.go:232–270, 284–315 | KernelRouteCarrier на каждое поколение outer; старый не закрывается: вечный assert-цикл (goroutine + `ip route get`/30с) и потеря prev-провенанса foreign-маршрута |
| E4 | MAJOR | wgmasque.go:139–144 + 286–293 + tun.go:69 | kernel-режим W+M: InterfaceName не пробрасывается → имя пина (cfg.KernelDevice) не связано с фактическим TUN-устройством (ядро выбирает имя само) → пин в неправильный девайс |
| E3 | MINOR | matrix.go:308–338 | M+W: после провала startChild `held=true` → мёртвый child без ретрая до флапа parent (класс WG MINOR 13, условие жёстче) |
| E5 | MINOR | kernelroute.go:144 | ошибка `route show` игнорируется → prev-снапшот потерян → foreign-маршрут не восстановится |
| E6 | MINOR | kernelroute.go:151–166 | del→replace fallback: при повторном провале replace удалённый foreign-маршрут не ресторится |
| E7 | MINOR | kernelroute.go:147,174,191; ops:99 | матчинг устройства подстрокой → ложные «уже наш»/«verify ok» при префиксных именах девайсов |
| E8 | MINOR | kernelroute_ops.go:85,166–169,50–56 | Close не ждёт loopWg; Assert не гейтится closed перед repairPin → повторный пин после Restore (гонка teardown) |
| E9 | MINOR | wgmasque.go:224–227 | watch(parent) не будится Stop'ом → горутина-утечка до смерти parent-ctx |
| E10 | MINOR | matrix.go:408,432 + wgmasque.go:141 | MustParse на AssignedV4 (в горутине у M+W) → паника процесса на невалидном Identity; construction не валидирует |
| E11 | MINOR | masque_carrier.go:141–151,216–220,268–274 | коллизия sport: молчаливая перезапись flow; Close старого flow удаляет НОВЫЙ из демукса; комментарий «demux rejects duplicates» ложен |
| E12 | MINOR | metrics.go:14–28,45–56; metrics_pipeline.go:43–50 | PairActive никто не пишет; ObserveGate никто не вызывает; gate-серии экспортируются ненаблюденными (0.000); ClassInnerVersionMismatch без продьюсера |
| E13 | MINOR | matrix.go:246–249 | OuterMTU не пробрасывается носителю (дефолт 1280); нет инварианта InnerMTU+28 ≤ OuterMTU |
| E14 | MINOR | carrier.go:89–94,80; kernelroute.go:109–134 | AttemptV6 мёртв (Setup пинит одну семью); ErrFamilyUnsupported недостижим |
| E15 | MINOR | matrix.go:279–288 (+ оба рантайма) | MasqueAwgRuntime.Stop без Start — дедлок на `<-r.done`; Start-after-Stop → зомби (второй Stop no-op) |
| E16 | NIT | kernelroute.go:123–125 | мёртвый `restCtx := ctx` |
| E17 | NIT | kernelroute.go:129; netstack.go:57 | InjectUDPDatagram на context.Background() (контракт без ctx — зафиксировать) |
| E18 | NIT | matrix.go:127–146 vs 113–117 | ResolveCarrier принимает CarrierDatagram, который Validate отвергает |
| E19 | NIT | supervisor.go:421–431 | fanOutTaps шарит слайс между подписчиками (M-27 контрадикция с M-30 сессионного уровня) |
| E20 | NIT | udpdgram.go:100–104 | ulen против len(pkt) вместо tot; инбаунд-чексуммы не верифицируются (оправдано QUIC-AEAD, не задокументировано) |
| E21 | NIT | masque_carrier.go:92–100 | StartPumping после Close — вечная подписка |
| E22 | NIT | netstack.go:82 | мёртвая nil-проверка в ProofSnapshot |
| E23 | NIT | forwarder.go:236–239 | udpAddrPortOf: As4() паникует на v6 (латентно) |

**Пересчёт итога E-WG + E-NM:** 1 BLOCKER + 7 MAJOR + 22 MINOR + 15 NIT = 45 findings.

### I.13 Проверено, проблем нет (E-NM, построчно)

1. **Контракт носителя** (carrier.go): минимальные 3 метода ровно по дизайну §1;
   расширение UDPSession вынесено отдельно и задокументировано; все ошибки
   структурные (`errors.Is`), ни одного строкочного матчинга в потребителях.
2. **Fail-closed постура носителей**: kernel — proofOK-гейт на оба диала +
   coverage-gate в Setup; masque — ErrNoTCPCarrier для TCP (BLOCKED_CARRIER,
   bd b4x-9aa — осознанный дефер), MTU-гейт на запись; netstack — живой стек как
   пруф. Противоречий с красными линиями §8 (кроме teardown-цикла — E1/E2/E6).
3. **Матрица-валидация** (matrix.go PairConfig.Validate + WgMasqueConfig.Validate):
   слоты, edge-collision, MTU-cap, обязательность secondary-enrollment — правила
   gool применены к кросс-транспортным парам (подтверждает вердикт A8).
4. **М+W data plane**: craft/parse математически корректны (обе чексуммы
   перепроверены тестом независимо); демукс — приватная копия payload,
   drop-instead-of-block, счётчики matched/unknown; wake-up-семантика
   supervisor.WritePacket не ломает carrier-записи.
5. **Порядок teardown**: оба рантайма child-first; stopChild/stopInner — swap под
   одним локом (TOCTOU нет); MasqueAwgRuntime.Stop ждёт done перед stopChild
   (нет гонки «стартующий child»); WgMasqueRuntime останавливает поздний child
   через смерть cancelCtx.
6. **SubscribePackets/tapPump**: подписка переживает поколения; cancel идемпотентен;
  closeTaps на выходе цикла; recover-рамка M3-07 не ослаблена; утечек насосов нет.
7. **forwarder-экспорт**: type alias без дублирования насосов; насосы
   last-writer-wins соответствуют задокументированной односессионности.
8. **e2e M+W** — настоящий кросс-движковый пруф (реальный H2/TLS + реальный AWG
   респондер + NAT-фикстура); уроки §5 (varint RFC9000, sizes[0], ActualPort,
   checksums gVisor) — качественные.
9. **Лицензионная гигиена**: gVisor — уже существующая зависимость (amneziawg-go),
   новых зависимостей E-NM не вводит; «Modifications: none» в NOTICE не затронут.

### I.14 Взаимодействия находок E-NM с находками E-WG (важно для приоритизации)

1. **rx-idle (WG MAJOR 4) бьёт по вложенным парам гарантированно, а не гипотетически.**
   Watchdog-дефолт `DefaultRXIdle=10 с` (watchdog.go:23) применяется к ЛЮБОЙ
   WG-сессии с нулевым Health.Watchdog. Вложенные конфиги задают только keepalive:
   W+M outer — `NestedOuterKeepaliveSec=5 с` (wgmasque.go:145), M+W inner —
   `NestedInnerKeepaliveSec=20 с` (matrix.go:359). Наш keepalive — исходящий, ответа
   WireGuard-пир не шлёт; значит при простое rx не растёт: **обе вложенные
   WG-сессии обязаны рестартнуться по триггеру 1 через ≤10–20 с после последнего
   входящего**, если edge не шлёт входящий с каденсом <10 с. Без фикса WG MAJOR 4
   любая вложенная пара в простое циклирует (handshake → gate → 10–20 с покоя →
   рестарт), генерируя поколения — а каждое поколение в kernel-режиме W+M
   течёт носителем (E2). **PATCH-04 обязан покрыть и вложенные keepalive, не
   только дефолт 25 с.**
2. **BLOCKER 1 (мёртвый триггер 2) действует и внутри вложенных пар** — внутренние
   AWG-сессии используют тот же watchdog; фикс PATCH-01 лечит их автоматически
   (одна точка — watchdog.go).
3. **WG MAJOR 3 (нет капа рестартов) × E2**: без капа рестарт-цикл из (1) —
   бесконечный источник утечек носителей в kernel-режиме W+M. PATCH-03 снижает
   частоту, PATCH-07 устраняет саму утечку — нужны оба.
4. **WG MAJOR 2 (паника hostname-endpoint) × E10**: класс «паника на
   конфигурационных входах» должен закрываться одним патчем по всему стеку
   (NewSession + оба nested-конструктора), иначе латентные горутинные паники
   останутся в M+W (matrix.go:432 — худший случай: паника в run()).

---

## Часть II. Патч-план по всем найденным проблемам

Адресат плана — агент-исполнитель. Патчи атомарны (один патч = одна ветка =
один пул-запрос), каждый содержит: проблему (file:line), точные изменения,
тесты приёмки, риски. Оценки: S ≤ 0.5 дня, M 0.5–2 дня, L > 2 дней.
Приоритеты: **P0** — до любого полевого выезда; **P1** — до поля желательно
(мажоры); **P2** — следующая итерация; **P3** — гигиена, по касанию.

Общие для всех патчей гейты (исполнить в docker, как в NESTED_MATRIX_IMPLEMENTATION §2):

```
gofmt -l ./transport/{nested,wg,warp}/   # пусто
go vet ./transport/{nested,wg,warp}/     # clean
go build ./...
go test ./transport/... -count=1
go test -race ./transport/{nested,wg}/ -count=2   # CGO-пин как в отчёте исполнителя
```

### II.1 Карта findings → патчи

| Патч | Приоритет | Закрывает findings | Оценка |
|------|-----------|--------------------|--------|
| PATCH-01 | P0 | WG BLOCKER 1 | S |
| PATCH-02 | P0 | WG MAJOR 2 + E10 | M |
| PATCH-03 | P1 | WG MAJOR 3 (хвосты 1–2) | M |
| PATCH-04 | P1 | WG MAJOR 4 + вложенные keepalive (I.14.1) | M |
| PATCH-05 | P1 | WG MAJOR 5 (сид-профили) | M–L |
| PATCH-06 | P1 | E1 + E5, E6, E7, E8 (kernelroute teardown-пакет) | M |
| PATCH-07 | P1 | E2 + E4 + E9 (kernel W+M жизненный цикл) | M |
| PATCH-08 | P1 | E3 + WG MINOR 13 (child-retry) | M |
| PATCH-09 | P2 | WG MINOR 6 (netstack-ретрансляция гейта) | S |
| PATCH-10 | P2 | WG MINOR 14 / A5 (E2EProbe wiring) | M |
| PATCH-11 | P2 | WG MINOR 15 / B9 (дамп effective-config) | S |
| PATCH-12 | P2 | WG MINOR 7 (seek per-endpoint дедлайн) | S |
| PATCH-13 | P2 | WG MINOR 8 (дубль-тег unassigned) | S |
| PATCH-14 | P2 | WG MINOR 9 / B10 (IPCSnapshot скраб) | S |
| PATCH-15 | P2 | WG MINOR 10 / B1 (dial-policy класс) | S |
| PATCH-16 | P2 | WG MINOR 11 / B8 (goleak) | S |
| PATCH-17 | P2 | WG MINOR 12 (engine_generation) | S |
| PATCH-18 | P2 | E13 + E11 (MTU-инвариант, sport-коллизия) | S |
| PATCH-19 | P2 | E15 + E21 (контракт Start/Stop, pump-after-close) | S |
| PATCH-20 | P2 | E12 (метрики: PairActive, ObserveGate, серии) | M |
| PATCH-21 | P2 | E14 (AttemptV6: реализовать или убрать) | S |
| PATCH-22 | P2 | WG MINOR (endpoints TTL VerifyMeta — рекомендация A7) | S |
| PATCH-23 | P3 | WG NIT-пакет (7 нит) | S |
| PATCH-24 | P3 | E-NM NIT-пакет (E16–E23, кроме закрытых выше) | S |
| PATCH-25 | P3 | Док-контракты (carrier Inject, постура носителей, M-30 supervisor) | S |

Порядок исполнения внутри волн: PATCH-06 → PATCH-07 (повторное использование
носителя опирается на корректный Restore); PATCH-01 → PATCH-04; PATCH-03 →
PATCH-04 (бэкофф из капа переиспользуется); остальное параллелится.

---

### II.2 Волна P0 — блокер и паники

#### PATCH-01. Оживить watchdog-триггер 2 (version-mismatch)

**Приоритет:** P0. **Оценка:** S. **Файлы:** `transport/wg/watchdog.go`, `transport/wg/watchdog_test.go`.
**Закрывает:** WG BLOCKER 1 (watchdog.go:116–137; эвишн [now−Window; now] против
требования span ≥ Window ⇒ равенство с наносекундной точностью ⇒ недостижимо на
реальных часах; тест зелёный только на мок-сетке).

**Изменения:**

1. Эвишн с запасом (рекомендуемый вариант «а» брифа):
   ```go
   // watchdog.go, в функции эвишна сэмплов:
   cut := now.Add(-w.cfg.Window - 2*w.cfg.Tick) // запас ≥ 2 тиков против джиттера пробуждения
   ```
   Требование `span >= Window` (132–133) остаётся без изменений. Итог: окно
   [now−Window−2Tick; now] допускает сэмплы с фактическим span ∈ [Window−ε;
   Window+2Tick], где ε — джиттер тикера; условие достижимо.
   Альтернативы (если владелец предпочитает): (б) armTime-штамп
   (`armed := now; … now.Sub(armed) >= Window` без span-проверки) или (в)
   ослабление до `span >= Window - 2*Tick`. Выбрать ОДНУ; вариант «а» —
   минимальный дифф и сохраняет семантику «полного окна».
2. Документировать инвариант в комментарии к структуре: `eviction window` обязан
   быть шире `span window` — иначе триггер 2 мёртв (добавить one-line-комментарий,
   чтобы регрессия не вернулась).

**Тесты приёмки (обязательные, новые):**

- `TestWatchdogVersionMismatchSignatureJittered`: та же сетка t0+i·1с, но чётные
  сэмплы сдвинуты на +10…+50 мс (несколько прогонов с разными сдвигами). До фикса
  тест красный; после — зелёный при любом сдвиге ≤ 2·Tick.
- `TestWatchdogEvictionMarginProperty`: сэмпл со штампом ровно now−Window должен
  ДОЖИВАТЬ до оценки (не эвиктиться) — пин запаса.
- Прогнать весь watchdog-суит с мок-часами И с реальным тикером
  (`TestWatchdogRealTickerSmoke`, 3–5 с): подтверждение, что эвишн не съедает окно.

**Риски:** запас 2·Tick увеличивает эффективное окно триггера 2 до ~Window+2Tick —
несущественно (каденс оценки не меняется, меняется лишь достижимость). Взаимодействие
с PATCH-04: после гейтинга rx-idle по tx триггеры становятся ортогональными.

---

#### PATCH-02. Убрать паники MustParse* из конфигурационных входов (весь стек)

**Приоритет:** P0. **Оценка:** M. **Файлы:** `transport/wg/session.go`,
`transport/nested/matrix.go`, `transport/nested/wgmasque.go` (+ их тесты).
**Закрывает:** WG MAJOR 2 (session.go:385 buildIPC — MustParseAddrPort на
непроверенном Endpoint; NewSession проверяет только непустоту) + E10
(matrix.go:432 mustAddr(AssignedV4) — паника в горутине run(); wgmasque.go:141
MustParseAddr(OuterIdent.AssignedV4)).

**Изменения:**

1. `transport/wg/session.go`, `NewSession` (~116–127): после проверки непустоты —
   ```go
   ap, err := netip.ParseAddrPort(strings.TrimSpace(cfg.Endpoint))
   if err != nil {
           return nil, newFailure(ClassParamRejected, "endpoint", fmt.Errorf(
                   "endpoint %q is not ip:port (hostnames must be resolved by the caller): %w", cfg.Endpoint, err))
   }
   ```
   Сохранить `ap` в Session (`s.endpointAP`); `buildIPC` (385) использует
   `s.endpointAP.String()`, больше не парсит. Hostname (в т.ч. каталоговный
   `engage.cloudflareclient.com:2408`) теперь даёт структурный отказ, а не панику
   процесса; резолв hostname — зона точек вызова (endpoints.go уже умеет), НЕ слоя.
2. `transport/nested/matrix.go`, `NewMasqueAwgRuntime` (~229–259): после nil-гейтов —
   ```go
   if _, err := netip.ParseAddr(cfg.InnerIdent.AssignedV4); err != nil {
           return nil, fmt.Errorf("nested: inner identity AssignedV4 %q invalid: %w",
                   cfg.InnerIdent.AssignedV4, err)
   }
   ```
   `innerTunnel()` (401–412): заменить `mustAddr(...)` на сохранённый при
   construction `netip.Addr` (поле рантайма). Функцию `mustAddr` удалить.
3. `transport/nested/wgmasque.go`, `WgMasqueConfig.Validate` (~56–78): добавить
   ```go
   if _, err := netip.ParseAddr(c.OuterIdent.AssignedV4); err != nil { return fmt.Errorf(...) }
   ```
   `Start` (141): использовать предвычисленный Addr (или локальный ParseAddr с
   возвратом `startErr` вместо паники — вариант «а» проще: ParseAddr в Start, при
   ошибке `startErr` + close(done), по образцу существующих веток 152–158).

**Тесты приёмки:**

- WG: `TestNewSessionRejectsHostnameEndpoint` (endpoint «engage.cloudflareclient.com:2408»
  → ClassParamRejected, не паника) + `TestNewSessionRejectsGarbageEndpoint` («1.2.3:80»).
- M+W: `TestMasqueAwgRuntimeRejectsZeroIdentity` (`&twg.Identity{}` → construction-ошибка).
  существующий `TestMasqueAwgRuntimeWaitingParentAndCleanStop` должен перейти на
  валидный Identity (сгенерировать через `twg.NewIdentity`, как в e2e).
- W+M: `TestWgMasqueValidateRejectsZeroAssignedV4`.
- Сквозная проверка: `grep -rn "MustParse" transport/wg/*.go transport/nested/*.go | grep -v _test`
  → только в тестах/фикстурах.

**Риски:** смена типа ошибки для hostname-endpoint — поведенческое изменение
публичного API (раньше паника/«работало» при AddrPort). Коллеры слоя (Seeker,
nested, E-NM) передают AddrPort — по коду не задет никто; сверить grep'ом точки
конструкции SessionConfig по репо.

---

### II.3 Волна P1 — мажоры

#### PATCH-03. Хвосты дизайна: кап рестартов + экспоненциальный бэкофф + autostart-флаг

**Приоритет:** P1. **Оценка:** M. **Файлы:** `transport/wg/session.go`,
`transport/wg/identity.go` (или `lastgood.go`), события/метрики слоя.
**Закрывает:** WG MAJOR 3 (дизайн §10: оба хвоста обязательны к закрытию; сейчас
MaxGenerations=0 = бесконечные рестарты с фиксированным бэкоффом 1 с — конструкция
рестарт-шторма ~10–11 с/цикл; autostart-флага нет нигде в слое).

**Изменения:**

1. `HealthConfig` + `RestartCapConfig`:
   ```go
   type RestartCapConfig struct {
           MaxPerHour int           // default 6 (дизайн §10); 0 = default; -1 = явный off (тесты)
           Window     time.Duration // default 1h
           OnExhausted func(gen uint64) // структурное уведомление (событие+метрика)
   }
   ```
   `fillDefaults` — по образцу существующих.
2. `run()` (~191–241): вместо `time.After(s.cfg.Health.RestartBackoff)` —
   экспоненциальный бэкофф: `base=RestartBackoff (1 с)`, ×2 на каждый подряд идущий
   провал, потолок 60 с, jitter ±20% (`base + rand(±20%)`); сброс к base при
   достижении established (успешное поколение). Скользящее окно рестартов:
   кольцевой буфер штампов (емкость MaxPerHour+1); перед очередным рестартом —
   если за Window уже MaxPerHour рестартов: событие `wg_restart_cap_exhausted`
   (ClassStallRX-независимый класс! — отдельный `ClassRestartCapExhausted = "restart-cap-exhausted"`,
   см. также WG NIT про all-candidates-cooling), метрика `wg_restart_total`,
   `wg_restart_backoff_seconds`, переход в терминальное состояние `StateClosed`
   с финальным OnLost(ClassRestartCapExhausted).
3. Autostart: поле `Autostart bool` в `Identity` (identity.go:38–59) с миграцией
   по умолчанию false (строгая валидация формата уже есть — поле просто
   добавляется к JSON); точка потребления — E8 (вне пакета): задокументировать в
   док-комментарии Identity, где читается флаг. (Альтернатива — отдельный
   state-файл слота; выбрать по консистентности с Reconciler MASQUE-слотов.)

**Тесты приёмки:**

- `TestSessionRestartCapExhausted`: мок-туннель, всегда падающий на handshake;
  MaxPerHour=3, Window=1h → ровно 3 рестарта → терминальное состояние, событие
  wg_restart_cap_exhausted, done закрыт, горутин не осталось (NumGoroutine-дельта).
- `TestSessionBackoffExponentialWithJitter`: фиксация мок-времени; ряд задержек
  [1,2,4,8…]±20% до потолка; сброс после успешного поколения.
- `TestIdentityAutostartRoundTrip`: JSON round-trip с флагом; старый файл без
  поля → false, ошибок нет.

**Риски:** терминальное состояние по капу меняет контракт «Session перезапускается
вечно» — сверить потребителей (seek использует MaxGenerations=1 — не задет;
nested runtimes реагируют на OnLost — получат структурный класс). Jitter —
детерминизм тестов обеспечивается инжектируемым rand (как часы в watchdog).

---

#### PATCH-04. rx-idle против keepalive: tx-гейтинг + производный RXIdle + лайвнесс

**Приоритет:** P1 (усилен I.14.1 — вложенные пары циклируют гарантированно).
**Оценка:** M. **Файлы:** `transport/wg/watchdog.go`, `watchdog_test.go`,
`session.go` (fillDefaults), `transport/nested/{matrix.go,wgmasque.go}`.
**Закрывает:** WG MAJOR 4 (rx-idle 10 с vs keepalive 25 с: наш keepalive исходящий,
ответа нет ⇒ rx в простое растёт только от входящих edge; каденс CF не обмерен;
нет self-liveness) + расширение на вложенные keepalive 5 с (W+M outer) / 20 с
(M+W inner).

**Изменения (минимальный согласованный пакет из трёх мер):**

1. **Tx-гейтинг триггера 1** (главное): rx-idle считается ТОЛЬКО при наличии
   исходящей активности в том же окне:
   ```go
   // watchdog.go, оценка триггера 1:
   if now.Sub(w.lastRx) > w.cfg.RXIdle && txGrowthSince(lastRx) > 0 {
           // тихий-простой без исходящих — НЕ stall: NAT-keepalive не требует ответа
   ```
   Реализация: держать `lastTx` рядом с `lastRx` (сэмпл уже содержит tx);
   условие: `now.Sub(w.lastRx) > RXIdle && w.lastTx.After(w.lastRx)`.
   Тихий-простой (нет tx) — не рестарт.
2. **Производный RXIdle**: в `HealthConfig.fillDefaults` (session.go:60–70):
   ```go
   if h.Watchdog.RXIdle == 0 {
           h.Watchdog.RXIdle = max(30*time.Second, 3*time.Duration(h.KeepaliveSec)*time.Second)
   }
   ```
   Дефолт для 25 с → 75 с (вместо 10 с); вложенные: 5 с → 30 с, 20 с → 60 с.
   Явный RXIdle в конфиге по-прежнему уважается (seek-пути и тесты).
3. **Self-liveness-проба (слоя)**: не вводить в этом патче (дизайн-вопрос полевой
   валидации); вместо этого — задокументировать в watchdog.go требование полевого
   обмера: «первый field-smoke обязан замерить фактический каденс входящих CF-WG
  (события на сэмплере) до включения агрессивных RXIdle» + тумблер
   `HealthConfig.Watchdog.LivenessProbe` (зарезервированный интерфейс, nil по
   умолчанию) для будущего DNS-RT-зонда < RXIdle.

**Тесты приёмки:**

- `TestWatchdogQuietIdleWithoutTxIsNotStall`: rx заморожен 60 с, tx тоже
  заморожен → НЕТ триггера 1 (сейчас — рестарт).
- `TestWatchdogIdleWithTxAndDeadRxFires`: rx заморожен, tx растёт → триггер 1
  срабатывает (старое поведение для реально мёртвого туннеля сохранено).
- `TestNestedKeepaliveDerivesRXIdle`: для KeepaliveSec 5/20/25 → RXIdle 30/60/75 с
  (юнит на fillDefaults).
- Обновить `TestWatchdogQuietKeepsAlive` под новую семантику (сейчас он кодирует
  предположение «~32 Б каждые 10 с» — после tx-гейтинга кейс «тихий edge + наш
  keepalive» не должен стрелять вообще).

**Риски:** удлинение RXIdle откладывает детект реально мёртвого туннеля при
наличии tx (с 10 с до 30–75 с). Компенсация: (а) триггер 2 (после PATCH-01)
ловит «пишем-не-читаем» за 120 с; (б) liveness-проба (п.3) закроет остаток на
полевом этапе. Согласовать с владельцем KPI «детект stall» (§1.3): сейчас
KPI фактически не выполняется (ложные срабатывания), после фикса — выполняется
с другой константой.

---

#### PATCH-05. Сид-профили: полевые блобы или загрузчик (CatalogVersion=2)

**Приоритет:** P1. **Оценка:** M–L. **Файлы:** `transport/wg/profiles.go`,
`profiles_test.go`, новый `profiles_loader.go` (опционально).
**Закрывает:** WG MAJOR 5 (сид-профили — плейсхолдеры: нет маркера 44d0;
quic-блобы 17–29 Б против ≥1200 Б RFC 9000 §14; chain.go:28–29 ссылается на
Nova ~1252 Б — данные были известны; загрузчика field-библиотек нет).

**Изменения (два варианта — выбрать владельцем, план под оба):**

- **Вариант A (рекомендую — короче и закрывает бриф):** импорт измеренных
  Nova-блобов (junk-only, S=0 — публичные, не секреты) как `CatalogVersion=2`:
  - перенести блобы из zapret-gui/Nova-источников в сидах с сохранением
    провенанса (комментарий-источник + хэш);
  - каждому quic-семейству — пин-тест: маркер 44d0 в ожидаемой позиции, длина
    Initial ≥ 1200, структура валидна нашим валидатором (chain-DSL);
  - `CatalogVersion` поднять до 2; сиды v1 оставить как fallback только при
    явном флаге конфигурации (по умолчанию — off), либо удалить.
- **Вариант B:** загрузчик внешних профилей: `LoadProfileLibrary(dir string)
  ([]Profile, error)` — файлы JSON в формате каталога, валидация существующим
  `Profile.Validate` + `Build` (он готов), пин-инварианты каталога
  (TestCatalogInvariants) поверх объединённого набора. Сиды остаются fallback.

В обоих вариантах: инвариант-тест «каждый Target=cf-warp/awg-server профиль
семейства quic содержит 44d0-маркер и Initial ≥ 1200 Б».

**Тесты приёмки:** `TestCatalogV2QuicMarkers` (44d0 + длины), полный суит
инвариантов, e2e fake-edge с routing-discipline не деградирует.

**Риски:** блобы из внешнего источника требуют верификации провенанса (лицензия
zapret-gui — проверить; данные «измерены», не «сгенерированы» — сверить хэши с
первоисточником). Если Nova-данные недоступны ревьюверу исполнителя — вариант B
безусловно, но тогда честно понизить заявление «junk-first лестница
поле-готова» в отчёте.

---

#### PATCH-06. Kernel-route teardown-пакет: корректный Restore + подстрочный матчинг + fail-closed show + гонка Close/Assert

**Приоритет:** P1 (база для PATCH-07). **Оценка:** M.
**Файлы:** `transport/nested/kernelroute.go`, `kernelroute_ops.go`,
`kernelroute_test.go`.
**Закрывает:** E1 (Restore-утечка пина), E5 (show-error), E6 (fallback без
рестора), E7 (подстрочный dev-матчинг), E8 (Close/Assert гонка).

**Изменения:**

1. **Restore (E1)** — переписать тело цикла (kernelroute_ops.go:97–107):
   ```go
   for _, r := range owned {
           // 1) наш пин удаляем ВСЕГДА (идемпотентно)
           _, _ = c.cfg.Runner(ctx, r.family, "route", "del",
                   r.dst.String()+"/"+prefixLenOf(r.family), "dev", c.cfg.Device)
           // 2) verbatim-restore — ТОЛЬКО если prev был маршрутом С ТЕМ ЖЕ префиксом
           //    (чужой /32|/128, который наш replace вытеснил). Покрывающий prev
           //    (default и т.п.) остался в таблице — ресторить нечего.
           if prev := strings.Fields(strings.TrimSpace(r.prev)); len(prev) > 0 &&
                   !devTokenIs(prev, c.cfg.Device) && prev[0] == r.dst.String() {
                   full := append([]string{r.family, "route", "replace"},
                           stripFamilyTokens(prev, r.family)...)
                   _, _ = c.cfg.Runner(ctx, full...)
           }
   }
   ```
   Токен-хелпер `devTokenIs(tok []string, dev string) bool` — строгий матчинг
   (следующий после «dev» токен равен имени). Дока комментария «tears down ALL
   owned pins» становится истинной.
2. **pinFamily show-fail (E5)** (kernelroute.go:144):
   ```go
   prevRaw, serr := c.cfg.Runner(ctx, fam, "route", "show", dst.String())
   if serr != nil {
           return fmt.Errorf("pin %s: route show failed (cannot snapshot prev): %w", dst, serr)
   }
   ```
   Fail-closed: нет снапшота — нет пина (иначе teardown-рестор невозможен).
3. **fallback-рестор (E6)** (kernelroute.go:159–165): в ветке повторного провала
   replace — verbatim-restore prev по образцу verify-fail ветки (173–177): del уже
   сделан; если prev существовал и не наш — `route replace <prev>`.
4. **Токенный dev-матчинг (E7)**: заменить три `strings.Contains(x, "dev "+Device)`
   (kernelroute.go:147,174,191; kernelroute_ops.go:99) на `devTokenIs(...)`
   поверх `strings.Fields`. (Bearer-строки «dev wg0» в тестовых ожиданиях
   обновить.)
5. **Close/Assert гонка (E8)**:
   - `Close()`: после `closeOnce(stopCh)` — `c.loopWg.Wait()` (гарантированно
     конечно: Assert ограничен 5-секундным таймаутом тика);
   - `Assert`: в начале итерации цикла по owned — `if c.closed.Load() { return ErrCarrierClosed }`
     (гейт перед repairPin);
   - `StopAssertionLoop()` оставить closeOnce-only (без Wait — его роль играет
     Close; задокументировать).

**Тесты приёмки (ядро пакета — новые):**

- `TestKernelRestoreWithCoveringPrevDeletesPin`: `showPre["9.9.9.9"] = "default via 10.1.1.1 dev wan0"`
  → после Restore пина НЕТ (это сегодня красный тест — репродукция E1); default
  не тронут (в fake: ключ «-4|default» не изменился).
- `TestKernelRestoreWithExactForeignPrefixRestoresVerbatim`: showPre = «9.9.9.9 via 10.1.1.1 dev wan0»
  → после Restore: пин удалён И foreign /32 восстановлен replace-командой.
- `TestKernelRestoreMultiLinePrevIsSafe`: showPre из двух строк → пин удалён,
  мусорная replace-команда не паникует.
- `TestKernelSetupFailsClosedWhenShowFails` (E5): Runner возвращает ошибку на
  show → Setup-отказ, replace НЕ вызывался.
- `TestKernelFallbackRetriesRestorePrev` (E6): failReplace[dst]=true →
  del-ветка → рестор prev вызван, foreign не потерян.
- `TestKernelDeviceTokenNoPrefixCollision` (E7): девайс «wg0», маршрут через
  «wg01» → НЕ считается нашим; verify с «dev wg01» — провал.
- `TestKernelCloseWaitsAssertionLoop` (E8): wipe пина → Close() сразу после →
  poll fake-таблицы 2 с: пин НЕ появляется (Assert-in-flight не пере-пинил);
  `Close` возвращается < 6 с.
- Все существующие kernelroute-тесты зелёные (обновить пару литералов под
  токенный матчинг).

**Риски:** поведение Restore для exact-prefix prev меняется с «replace, возможно
без del» на «del + replace» — на реальном iproute2 эквивалентно (del затем replace
того же префикса), на fakeRoutes — проверить, что del не роняет чужую запись
(fake del удаляет по ключу dst — совпадает с нашим пином; после del replace
ставит foreign обратно). В fakeRoutes при del чужого префикса (не нашего пина)
ничего не удалить — ок.

---

#### PATCH-07. Kernel-W+M: один носитель на рантайм + фактическое имя устройства + watch-утечка

**Приоритет:** P1 (зависит от PATCH-06). **Оценка:** M.
**Файлы:** `transport/nested/wgmasque.go` (+ `wgmasque_test.go`, новая фикстура
fake-outer), точечно `transport/wg/tun.go` (если понадобится Name()-гейт).
**Закрывает:** E2 (утечка носителя на поколение + потеря провенанса), E4
(InterfaceName не пробрасывается → пин в неправильный девайс), E9 (watch-утечка).

**Изменения:**

1. **Единый KernelRouteCarrier на рантайм (E2)**: переносится из buildCarrier в
   поле рантайма, создаётся лениво (первый onParentUp в kernel-режиме) ИЛИ в
   Start (после валидации):
   ```go
   // onParentUp:
   r.mu.Lock(); krc := r.kernel; r.mu.Unlock()
   if krc == nil {
           krc, err = r.buildKernelCarrier()   // New + Setup + RunAssertionLoop(ictx)
           if err != nil { r.setInvalidated(...); return }
           r.mu.Lock(); r.kernel = krc; r.mu.Unlock()
   }
   // assert-цикл продолжает чинить пины через воссоздания устройства —
   // это и есть заявленное закрытие zapret-gui-гэпа; НЕТ нового носителя
   // на поколение; НЕТ перезаписи r.kernel без teardown.
   ```
   `buildCarrier` для kernel-ветки вырождается в возврат существующего
   `r.kernel` (Setup идемпотентен: «уже наш и owned» — no-op, prev-провенанс
   сохраняется). Netstack-носители остаются свежими по поколениям (новый стек —
   новая обёртка) — текущее поведение сохранить.
   `RunAssertionLoop` привязать к `cancelCtx` рантайма (вместо
   `context.Background()`), чтобы смерть рантайма гасила цикл даже без Close.
2. **Фактическое имя устройства (E4)** — двойная защита:
   - `Start` (139–144): `Tunnel: twg.TunnelConfig{ ..., InterfaceName: r.cfg.KernelDevice }`
     (подсказка ядру; конфликт имени → ошибка создания TUN → структурный отказ
     вместо молчаливого чужого имени);
   - `buildKernelCarrier`: после установления outer — взять фактическое имя:
     ```go
     tun := outer.Tunnel()
     devName := r.cfg.KernelDevice
     if tun != nil && tun.Device != nil {
             if n := tun.Device.Name(); n != "" { devName = n }
     }
     // KernelRouteCarrierConfig{ Device: devName, ... }
     ```
     Носитель создаётся ПОСЛЕ OnEstablished (уже так и есть: onParentUp), поэтому
     Tunnel() живой; при несовпадении с KernelDevice — warning-событие
     (наблюдаемость), пин — по фактическому имени.
   - `WgMasqueConfig.Validate` (67–72): KernelDevice непустой уже требуется —
     оставить; задокументировать новую семантику («пин следует фактическому
     имени устройства; KernelDevice — подсказка создания»).
3. **watch-утечка (E9)** (224–227):
   ```go
   func (r *WgMasqueRuntime) watch(parent context.Context) {
           defer close(r.done)
           ctx := r.ctxOrBackground() // cancelCtx: r.cancel() будит watch при Stop
           select {
           case <-parent.Done():
           case <-ctx.Done():
           }
   }
   ```
   (cancelCtx устанавливается в Start до запуска watch — порядок уже корректен.)
4. Заодно: `Stop()` — при не-started-рантайме r.kernel nil — ветка уже safe;
   после E2-фикса Stop делает StopAssertionLoop + Restore + Close единственного
   носителя — совместимо с существующим кодом (197–204).

**Тесты приёмки:**

- Новая фикстура `fakeOuterSession` (по образцу fakeedge_test.go / минимальный
  интерфейс сессии, который использует WgMasqueRuntime: Start/Stop/Tunnel/
  коллбеки — если Session конкретный тип, вынести seams через маленький интерфейс
  в тесте НЕ получится; тогда — интеграционный тест через настоящий
  netstack-режим: fake edge из fakeedge_test.go + WgMasqueRuntime с
  OuterKernelTUN=false покрывает onParentUp/onParentLost цикл; kernel-ветку —
  через injected fake Runner + ручной вызов внутренностей… НЕТ: правильный путь —
  рефакторинг buildCarrier/onParentUp под тестируемость: вынести функцию
  `newOuterSession(cfg)` в поле-фабрику `r.newSessionFn` (как `newTunnelFn` в
  Session — house style), тест подменяет фабрику фейком с управляемыми
  коллбеками. Это допустимое расширение ради тестируемости, паттерн слоя).
- `TestWgMasqueKernelCarrierSurvivesOuterGenerations`: 3 поколения outer
  (фейк-фабрика дергает OnEstablished/OnLost) → создан РОВНО ОДИН
  KernelRouteCarrier (счётчик конструкций Runner'ом/событиями assert-цикла),
  goroutine-дельта = 0, `ip route get`-вызовов не растёт между поколениями
  (кроме тиков).
- `TestWgMasqueKernelPinsActualDeviceName`: фейк-туннель с Device.Name()="tun42"
  ≠ KernelDevice="wgout" → пин через «dev tun42» (проверка по calls fake-Runner).
- `TestWgMasqueInterfaceNameHintPassed`: конфиг OuterKernelTUN=true → в
  TunnelConfig, переданный фабрике, InterfaceName==KernelDevice.
- `TestWgMasqueStopUnblocksWatch`: Start → Stop → done закрывается ≤1 с при
  живом parent (сейчас — висит; станет красным→зелёным).
- `TestWgMasqueForeignRouteProvenanceAcrossGenerations`: showPre задан → два
  поколения → Stop → foreign-маршрут восстановлен verbatim (сквозной приёмочный
  для E1+E2 вместе).

**Риски:** рефакторинг фабрики сессии — касание Start; держать дифф минимальным
(поле + вызов). Кленч-кейс: ядро не смогло выделить KernelDevice (занято) —
создание TUN упадёт с ошибкой поколения → штатный рестарт-цикл (совместимо с
PATCH-03). assert-цикл на cancelCtx: при смерти рантайма цикл гаснет даже без
Close — поведение строже прежнего, безопасно.

---

#### PATCH-08. Ретрай мёртвого child при живом parent (оба рантайма)

**Приоритет:** P1. **Оценка:** M. **Файлы:** `transport/nested/matrix.go`
(MasqueAwgRuntime.run), `transport/wg/nested_runtime.go` (WG-WG аналог,
WG MINOR 13), тесты обоих.
**Закрывает:** E3 + WG MINOR 13 (nested_runtime.go:199–246).

**Изменения:**

1. `matrix.go run()` (308–338) — реструктуризация: `held` отражает ТОЛЬКО
   состояние parent; состояние child — отдельная переменная; ретрай с бэкоффом:
   ```go
   held := false
   var nextRetry time.Time
   backoff := time.Second
   for { /* select ctx/tick */
           nowHeld := r.cfg.Plane.Snapshot().RouteHeld
           switch {
           case !nowHeld:
                   if held { r.stopChild(); r.link = "child-invalidated"; r.emit(parentLost) }
                   held = false
           case !held:                    // parent поднялся
                   held = true
                   nextRetry = time.Time{} // сброс бэкоффа на новом parent
                   backoff = time.Second
                   fallthrough
           default:
                   if r.link != "up" && !time.Now().Before(nextRetry) {
                           gen := r.parentGen + 1
                           if err := r.startChild(gen); err != nil {
                                   r.setLink("child-invalidated", gen, err.Error())
                                   nextRetry = time.Now().Add(backoff)
                                   backoff = min(backoff*2, 30*time.Second)
                           } else {
                                   r.setLink("up", gen, "")
                                   backoff = time.Second
                           }
                   }
           }
   }
   ```
   (Go запрещает fallthrough из case с телом в switch — переписать на
   if/else-лестницу; псевдокод выше — для понимания семантики: parent-флап
   сбрасывает бэкофф; child ретраится сам с экспонентой до 30 с; PollInterval
   20 мс остаётся тиком, nextRetry гейтит попытки.)
2. `transport/wg/nested_runtime.go` (199–246): тот же таймер-паттерн для
   WG-WG рантайма: при `link=child-invalidated` и живом parent — ретрай с
   бэкоффом (переиспользовать хелпер, если ляжет чисто; иначе продублировать
   15 строк — пакеты разные, дублирование допустимо).

**Тесты приёмки:**

- `TestMasqueAwgRuntimeRetriesChildAfterFailedStart`: плоскость RouteHeld=true,
  инжектированный провал startChild (например, кривой InnerProfile → NewSession
  откажет) первые 2 попытки, затем успех → link=up в пределах ~3 с (бэкофф 1с→2с);
  без фикса — link навсегда child-invalidated (красный до, зелёный после).
- `TestMasqueAwgRuntimeBackoffCapsAt30s`: 5 подряд провалов → интервалы
  попыток [1,2,4,8,16…]с не выше 30 с; parent-флап сбрасывает.
- WG-WG: `TestNestedRuntimeRetriesChildWhileParentAlive` (по образцу
  nested_runtime_test.go, провал через кривой inner-config).
- Горутины: NumGoroutine-дельта после Stop == 0 (паттерн уже есть в
  nested_runtime_test.go:411–444).

**Риски:** ретрай-цикл добавляет события — прогнать через CountingEvents, чтобы
не взорвать RouteLostTotal (провал startChild классифицируется
ClassCarrierRouteLost в setLink — оставить как есть: счётчик честно растёт).
PATCH-03-бэкофф в WG-Session — независим; здесь свой, локальный.

---

### II.4 Волна P2 — миноры

#### PATCH-09. NetstackRoundTripper: ретрансляция DNS-проб

**Закрывает:** WG MINOR 6 (trustgate.go:243–318 — netstack-гейт без ретрансляции:
одна потерянная проба ⇒ teardown+рестарт; rawTUN-путь ретранслирует каждые 700 мс;
при 1–3 % UDP-loss ~2–6 % провалов establishment; в seek-режиме — ложные strike).
**Файлы:** `transport/wg/trustgate.go`, `trustgate_test.go`. **Оценка:** S.

**Изменения:** цикл «читать до таймаута; таймаут → повторная запись в пределах
окна гейта» по образцу RawTUNRoundTripper (156–206): вынести общий каркас
ретрансляции (параметры: интервал 700 мс, бюджет = окно гейта минус QR/TXID-гэп),
NetstackRoundTripper использует его поверх gonet-сокета. Счётчик
`gate_retransmits_total` в событии провала (диагностика lossy-путей).

**Приёмка:** `TestNetstackGateRetransmitsOnLoss` — фейк-резолвер теряет первый
ответ → гейт проходит со второй попытки (сейчас — провал); rawTUN-тесты не
деградируют; инвариант «последовательный QR/TXID-матчинг» не ослаблен (5-кортеж
проверяется на КАЖДОМ ответе).

---

#### PATCH-10. E2EProbe в прод-wiring (ironclad-lite)

**Закрывает:** WG MINOR 14 / вопрос A5 (trustgate.go:53–63,119–128 — двойная
trace-проба warp=on|plus не подключена ни в одном прод-пути; гейт = 2 DNS RT;
против on-path активного инжектора с подбором 16-бит TXID защиты нет).
**Файлы:** точка wiring — супервизорный путь уровня интеграции (E7/E8), сам
слот trustgate.go уже готов. **Оценка:** M (wiring + координация).

**Изменения:** в прод-wiring (уровень, который собирает SessionConfig для
прод-сессий) подключать `Gate.E2EProbe` в netstack-режиме: HTTP 204
`/cdn-cgi/trace` через gvisor-стек туннеля, два замера (warp=on, plus),
сравнение по образцу слота. Для seek-режима — off (бюджет 900 мс не вместит);
для establishment-гейта — on. Ошибка E2EProbe → структурный отказ
establishment (fail-closed, не warning).

**Приёмка:** интеграционный тест с fake-edge, отдающим подделанный DNS-ответ с
верным TXID, но HTTP-след ≠ warp=on → establishment отклонён (сейчас — принят);
юнит на сам слот существует; флаг конфигурации `Gate.E2EProbeEnabled`
(по умолчанию on в прод-wiring, off в тестах seek).

**Риски:** +1 RTT к establishment; замерить в интеграционном стенде и убедиться,
что handshake-бюджет 10 с не страдает (запас сейчас большой).

---

#### PATCH-11. Дамп effective-config при провале IpcSet

**Закрывает:** WG MINOR 15 / B9 (session.go:278–284 — ошибка IpcSet возвращается
без рендера конфига и номера поколения; sing-box-паттерн из дизайна §1 не
реализован; диагностируемость полевых конфиг-отказов ниже обещанной).
**Файлы:** `transport/wg/session.go`, тест. **Оценка:** S.

**Изменения:** в ветке провала IpcSet — событие
`wg_ipc_set_failed {gen, rendered_config, err}`: рендер
`Config.IPCString()` с маскированием секретов (см. PATCH-14 — скраб-хелпер
переиспользовать: private_key/preshared_key → sha256-префикс), человекочитаемая
обёртка ошибки с полем gen. Логгер-мост DiscardLogf сохраняется — дамп уходит в
событие/структурный лог, не в stdout.

**Приёмка:** `TestSessionEmitsEffectiveConfigOnIpcSetFailure`: мок-устройство,
отвергающий IpcSet-определённый ключ → событие содержит рендер БЕЗ приватных
ключей (инвариант-тестом по регулярке `private_key=[0-9A-Za-z+/]{40,}`), с gen.

---

#### PATCH-12. Seek: пер-кандидатный дедлайн

**Закрывает:** WG MINOR 7 (seek.go:30 — DefaultSeekTotalDeadline=90 с на ВЕСЬ
Seek, тогда как KPI §1.3/дизайн §5 — «80–120 с НА ENDPOINT»; при 3+ кандидатах
пер-кандидатный бюджет ниже плана). **Файлы:** `transport/wg/seek.go`,
`seek_test.go`. **Оценка:** S.

**Изменения:** `SeekConfig.PerEndpointDeadline` (default 90 с; валидатор
ограничивает 80–120 с) + общий дедлайн как потолок `n × perEndpoint` (или
явный `TotalDeadlineOverride` для тестов). Проверить каскад: остановка текущего
кандидата по его бюджету НЕ отменяет оставшихся (сейчас общий дедлайн обрезает
лестницу серединой).

**Приёмка:** `TestSeekPerEndpointBudget`: 3 кандидата, второй висит → бюджет
второго истёк, третий начат и завершился; суммарное время ≈ Σ бюджетов, а не
«первый же дедлайн всё убил». Уточнить формулировку KPI у владельца (semantics
«общий» — если намерение; тогда — только документация, без кода).

---

#### PATCH-13. Уникальность тегов региональных пулов

**Закрывает:** WG MINOR 8 (endpoints.go:140–165, 323–345 — два пула с
Tag "unassigned": PoolCandidates возвращает только первый, второй недостижим
через opt-in API). **Файлы:** `transport/wg/endpoints.go`, `endpoints_test.go`.
**Оценка:** S.

**Изменения:** теги → `unassigned-aether-188` / `unassigned-nova-hosts`
(читаемые, с сутью подсети); инвариант-тест в TestCatalogInvariants-семействе:
`все Tag в каталоге уникальны` (мапа-детект дубликатов при Build). Проверить,
что нигде вне пакета тег "unassigned" не упоминается (grep по репо; старый тег
оставить как alias только если есть внешние потребители — по коду их нет).

**Приёмка:** `TestCatalogTagsUnique` + `TestPoolCandidatesReachesNovaHosts`
(оп-in по новому тегу возвращает 8.x /32-хосты).

---

#### PATCH-14. IPCSnapshot: скраб секретов

**Закрывает:** WG MINOR 9 / B10 (session.go:503–511 — метод отдаёт полный
IpcGet-дамп, содержащий private_key: upstream uapi.go:104; экспортированный API
готов уронить «ключи никогда в дампах» первым диагностическим вызовом).
**Файлы:** `transport/wg/session.go`, тест. **Оценка:** S.

**Изменения:** в IPCSnapshot — замена значений `private_key` и `preshared_key`
на `sha256(<ключ>)[:12]` (префикс-хэш для корреляции без раскрытия); хелпер
`scrubIPC(string) string` экспортировать для PATCH-11. Регексп по строкам
`^private_key=…`/`^preshared_key=…` (IpcGet-формат — построчный).

**Приёмка:** `TestIPCSnapshotNeverContainsSecrets`: реальный IpcGet-дамп с
ключами → на выходе нет base64-ключей (проверка подстрокой полного значения
ключа фикстуры), хэш-префиксы стабильны (одинаковый ключ → одинаковый скраб).

---

#### PATCH-15. Класс wg-dial-policy для EPERM

**Закрывает:** WG MINOR 10 / B1 (session.go:285–287 + socket_linux.go:19–56 —
отказ applySocketControl (EPERM без CAP_NET_ADMIN) маппится в
ClassParamRejected("device-up"): «нет привилегий» неотличим от «битый конфиг»).
**Файлы:** `transport/wg/failures.go`, `session.go`, `socket_linux.go`, тест.
**Оценка:** S.

**Изменения:** `ClassDialPolicy = "wg-dial-policy"` (Failures-таблица:
структурная ошибка, remediation «поднять CAP_NET_ADMIN / проверить маркеры»);
в applySocketControl оборачивать EPERM/EACCES в `errDialPolicy{op, errno}`
(sentinel-тип), session.go маппит `errors.As(errDialPolicy)` → ClassDialPolicy.
Чек-лист B1-аналог из MASQUE-трека (FailureDialPolicy) — сверить нейминг,
чтобы классы были симметричны между транспортами.

**Приёмка:** `TestSessionClassifiesEPermAsDialPolicy`: мок bind, Control-колбэк
возвращает EPERM → класс wg-dial-policy, а не param-rejected; юнит на маппинг
errno→класс.

---

#### PATCH-16. goleak для пакета wg (+nested)

**Закрывает:** WG MINOR 11 / B8 (goleak v1.3.0 в go.mod, но VerifyTestMain
не используется; сейчас только ручная NumGoroutine-дельта в
nested_runtime_test.go:411–444). **Файлы:** `transport/wg/main_test.go`
(новый), `transport/nested/main_test.go` (новый). **Оценка:** S.

**Изменения:** `func TestMain(m *testing.M) { goleak.VerifyTestMain(m, goleak.IgnoreAnyFunction("github.com/amnezia-vpn/amneziawg-go/v3/device.(*Device).RoutineSendHandshakeRetries…")) }`
— игноры собрать по фактическому прогону (upstream device/timers.go
fastrandn-гонки известны из race-фильтра); политику_race-фильтра не менять.

**Приёмка:** `go test ./transport/wg/ -count=2 -race` зелёный с VerifyTestMain;
при падении — список утечек разложить по патчам (известные — IgnoreAnyFunction
с комментарием-обоснованием, неизвестные — отдельные findings, НЕ молчать).

---

#### PATCH-17. engine_generation в профилях

**Закрывает:** WG MINOR 12 (profiles.go — поле engine_generation из брифа
(Часть III, WG4) не реализовано; гейтинг по поколению демона отсутствует).
**Файлы:** `transport/wg/profiles.go`, `profiles_test.go`. **Оценка:** S.

**Изменения:** `Profile.EngineGeneration int` (0 = любое; 1+ = минимум
поколения демона) + проверка в `Build()`/каталоге: профиль с EngineGeneration >
текущего — пропускается лестницей (не отбрасывается навсегда). Если владелец
сочтёт требование снятым (риск при CatalogVersion=1 низкий) — записать решение
в профиль-доку; план исходит из реализации.

**Приёмка:** `TestProfileEngineGenerationGatesLadder`: профиль gen=2 при
демоне gen=1 — не выбирается; после «обновления» демона — выбирается.

---

#### PATCH-18. M+W: OuterMTU-проброс + инвариант + sport-коллизия

**Закрывает:** E13 (matrix.go:246–249 — OuterMTU не пробрасывается носителю:
дефолт 1280 всегда; при plane-MTU < 1228 все inner-датаграммы отклоняются
локально → «up»-чёрная дыра) + E11 (masque_carrier.go:141–151 — коллизия sport
молча перезаписывает flow; Close старого flow удаляет НОВЫЙ; комментарий ложен).
**Файлы:** `transport/nested/matrix.go`, `masque_carrier.go`, тесты. **Оценка:** S.

**Изменения:**

1. `MasqueAwgConfig` + NewMasqueAwgRuntime: `OuterMTU` в MasqueCarrierConfig
   из `Pair.Outer.MTU` (если задан) иначе дефолт; `PairConfig.Validate`:
   инвариант `InnerMTU+UDPDatagramOverhead ≤ OuterMTU-эффективного` — на уровне
   деклараций: если оба заданы — проверять; иначе документировать, что effective
   берётся у плоскости.
2. `DialUDPThrough` (masque_carrier.go:141–151): до 3 попыток выбора sport при
   занятом ключе; занятость после 3 попыток → ошибка `nested: sport collision`;
   комментарий 222–224 переписать честно.

**Приёмка:** `TestMasqueCarrierSportCollisionDoesNotStealFlow`: форс-коллизия
(инжект существующего ключа через два DialUDPThrough к одному peer) → второй
диал либо другой sport, либо структурная ошибка; Close первого flow НЕ удаляет
регистрацию второго. `TestMasqueRuntimePropagatesOuterMTU`: Pair.Outer.MTU=1240
→ writeDatagram с payload 1220 отклонён (1220+28=1248 > 1240).

---

#### PATCH-19. Контракт Start/Stop обоих рантаймов + pump-after-close

**Закрывает:** E15 (matrix.go:279–288 — Stop-без-Start дедлок на `<-r.done`;
Start-после-Stop → зомби: второй Stop no-op) + E21 (masque_carrier.go:92–100 —
StartPumping после Close вечная подписка). **Файлы:**
`transport/nested/matrix.go`, `wgmasque.go`, `masque_carrier.go`, тесты.
**Оценка:** S.

**Изменения:**

1. Оба рантайма: `started atomic.Bool` + `stopped atomic.Bool`:
   - `Stop()` при `!started` → закрыть done немедленно (без ожидания run) и
     выйти;
   - `Start()` при `stopped` → структурная ошибка `nested: runtime stopped`
     (сейчас — молчаливый зомби);
   - `MasqueAwgRuntime.Stop` ждать done только при started.
2. `StartPumping`: первый оператор pumpOnce-тела — `if c.closed.Load() { return }`.

**Приёмка:** `TestRuntimeStopBeforeStartReturnsImmediately` (обе структуры:
Stop-без-Start завершается < 1 с); `TestRuntimeStartAfterStopRejected`;
`TestPumpNotStartedAfterCarrierClose` (после Close StartPumping не подписывается:
subs-счётчик плоскости не растёт).

---

#### PATCH-20. Метрики N4: оживить PairActive и gate-серии

**Закрывает:** E12 (metrics.go:14–28,45–56; metrics_pipeline.go:43–50 —
PairActive никто не пишет; ObserveGate никто не вызывает; gate-серии
экспортируются ненаблюденными как 0.000; ClassInnerVersionMismatch без
продьюсера). **Файлы:** `transport/nested/{matrix.go,wgmasque.go,metrics.go,
metrics_pipeline.go}`, тесты. **Оценка:** M.

**Изменения:**

1. Оба рантайма держат `*Metrics` (конструктор: опциональное поле Config.Metrics;
  nil → внутренний, никому не экспортированный — чтобы не менять сигнатуры);
   `CountingEvents(m, cfg.OnEvent)` оборачивает пользовательский OnEvent.
2. PairActive: `Store(1)` при переходе link→"up", `Store(0)` при
   child-invalidated/Stop — в setLink/startChild/stopChild (одна точка:
   helper `r.setLinkUp()/r.setLinkDown()`).
3. ObserveGate:
   - inner (M+W): в startChild — обернуть `sess.Start()`? НЕТ — gate-время
     приходит из событий сессии: измерять по `InnerOnEvent` между
     `wg_starting`→`wg_established` (таймстемпы событий уже есть) — в
     innerEvent-обёртке: `case "wg_established": m.ObserveGate("inner", ev.At.Sub(startedAt))`;
   - outer (W+M): аналогично по outerEvent между первым событием поколения и
     OnEstablished (штамп запомнить в onParentUp-предшественнике; колбэк
     OnEstablished не несёт времени — использовать time.Now() в колбэке и
     штамп старта поколения).
4. Sentinel: `OuterGateMS/InnerGateMS atomic.Int64` → −1 = «не наблюдалось»;
   Snapshot пропускает −1. Init: конструктор Metrics делает Store(−1).
5. ClassInnerVersionMismatch: продьюсер — innerEvent-обёртка в MasqueAwgRuntime:
   события сессии класса version-mismatch (WG-слой уже классифицирует
   WG-классом) транслируются в Event{Class: ClassInnerVersionMismatch} (маппинг
   классов сессии → классы nested в одном месте).

**Приёмка:** `TestRuntimeMetricsPairActiveLifecycle`: parent up→down→up →
Snapshot: pair_active 1→0→1, route_lost_total растёт на флапе;
`TestGateSeriesAbsentUntilObserved`: свежий Metrics → в Snapshot НЕТ
layer_gate-серий; после ObserveGate("outer", 2s) — есть, 2.0;
`TestInnerGateObservedFromSessionEvents`: фейк-сессия с событиями
(starting→established за 1.5 с мок-времени) → InnerGateMS ≈ 1500.
e2e M+W прогнать с включённым Metrics-собором — серии ненулевые.

---

#### PATCH-21. FamilyPolicy: реализовать AttemptV6 или убрать

**Закрывает:** E14 (carrier.go:89–94,80 — AttemptV6 мёртв; ErrFamilyUnsupported
недостижим; дизайн §1.1 «v6 warn-only» фактически не реализован).
**Файлы:** `transport/nested/carrier.go`, `kernelroute.go`, тест. **Оценка:** S.

**Изменения** — два варианта, выбрать владельцем:

- **A (реализация):** `KernelRouteCarrierConfig` получает необязательный
  `V6Endpoint netip.AddrPort` (v6-форма inner-edge, если известна); Setup при
  `Policy.AttemptV6 && V6Endpoint.IsValid()` пинит и её (warn-only ветка уже
  готова: 119–121); WgMasqueConfig — проброс. ErrFamilyUnsupported начинает
  возвращаться DialUDPThrough при запросе v6-адреса в v4-only пине.
- **B (честное удаление):** убрать AttemptV6 и ErrFamilyUnsupported, доку
  FamilyPolicy переписать («только v4-критичность; v6 — будущая работа»),
  дизайн-дельту записать в self-report.

**Приёмка (A):** `TestKernelSetupAttemptsV6WhenOptedIn` — v6-пин при AttemptV6
(событие warning при провале, не rollback); **(B):** grep AttemptV6/ErrFamilyUnsupported
→ 0 вхождений вне истории.

---

#### PATCH-22. VerifyMeta TTL региональных тегов

**Закрывает:** рекомендация A7 из WG-отчёта (реверификацию region-тегов привязать
к дате в VerifyMeta; «flip только по полевым loc=» уже есть, TTL при повторном
поле — нет). **Файлы:** `transport/wg/endpoints.go` (VerifyMeta), тест.
**Оценка:** S.

**Изменения:** VerifyMeta + `VerifiedAt time.Time`; sourced-кандидат с
region-тегом старше N дней (config, default 180) понижается до unverified-пула
(в дефолтный sourcing не попадает; PoolCandidates/opt-in продолжает работать).
Логика в CatalogCandidates: фильтр по свежести.

**Приёмка:** `TestRegionTagTTLDowngradesStalePools`: пул с VerifiedAt −200д →
не в CatalogCandidates; свежий → в.

---

### II.5 Волна P3 — нит-пакеты

#### PATCH-23. E-WG нит-пакет (7 нит, один PR — везде механика)

| NIT | файл:строки | действие |
|-----|-------------|----------|
| WG NIT 1 | bind.go:75 | удалить мёртвое поле `closers []ioCloser` |
| WG NIT 2 | seek.go:424 | удалить `var _ = fmt.Sprintf` |
| WG NIT 3 | session.go:316,324 | переименовать `preOK` → `preErr` |
| WG NIT 4 | validate.go:218–225 | parseUint32 → `strconv.ParseUint(strings.TrimSpace(s), 10, 32)` (хвостовой мусор «12abc» — ошибка) |
| WG NIT 5 | confbridge.go:207–214 | пустые AllowedIPs → явная ошибка валидации (не молчаливый 0.0.0.0/0+::/0) |
| WG NIT 6 | identity.go:43–46 | Key: `MarshalJSON/UnmarshalJSON` в hex-строку (round-trip тест остаётся зелёным; файл становится читаемым) |
| WG NIT 7 | seek.go:296,355 | «all-candidates-cooling»/«seek-exhausted» → отдельный класс `ClassDiscoveryExhausted` (метрики перестают смешиваться со stall-rx) |

**Приёмка:** полный суит; для NIT 4 — `TestParseUint32RejectsTrailingGarbage`;
NIT 5 — `TestEmptyAllowedIPsRejected`; NIT 6 — `TestKeyJSONRoundTripHex` +
обратная совместимость чтения старого массива (Unmarshal принимает ОБА формата:
массив-чисел (легаси) и hex — иначе чужие сторы ломаются).

#### PATCH-24. E-NM нит-пакет (E16–E23 минус закрытых в других патчах)

| NIT | файл:строки | действие |
|-----|-------------|----------|
| E16 | kernelroute.go:123–125 | удалить `restCtx := ctx`; передать ctx прямо |
| E17 | kernelroute.go:129; netstack.go:57 | док-комментарий контракта: InjectUDPDatagram — fire-and-forget без ctx (5-секундный внутренний бюджет); расширение сигнатуры — будущее API v2 |
| E18 | matrix.go:127–146 | ResolveCarrier: `case CarrierDatagram` → ошибка «resolved-only mode cannot be declared» (синхрон с Validate 113–117) |
| E19 | supervisor.go:421–431 | fanOutTaps: копия на подписчика (как M-30 сессии) ЛИБО док-контракт «read-only shared slice» в SubscribePackets — выбрать копию (дёшево, безопасно) |
| E20 | udpdgram.go:100–104 | ulen сверять с tot; док: инбаунд-чексуммы не верифицируются — доверие QUIC-AEAD внешней плоскости |
| E22 | netstack.go:82 | убрать мёртвую ns==nil проверку |
| E23 | forwarder.go:236–239 | `if !ap.Addr().Is4() { return nil /* drop: single-session v4 semantics */ }` |

**Приёмка:** суит обоих пакетов; для E19 — тест: два подписчика, один мутирует
буфер → второй видит исходные данные.

#### PATCH-25. Док-контракты (истина в комментариях)

**Закрывает:** Documentation-долг, найденный построчным чтением: (а)
carrier.go:17–18 — InjectUDPDatagram описан как путь «handshake and transport
traffic», но ответ через него не возвращается (random sport; реальный
bidirectional путь — DialUDPThrough) — переписать контракт; (б) асимметрия
гейтинг-постур носителей (kernel: жёсткий proofOK; masque: мягкий
wake-up-буфер плоскости; netstack: живой стек) — одна таблица в doc.go;
(в) док «Restore/teardown ownership» после PATCH-06/07 — обновить формулировки.
**Оценка:** S. **Приёмка:** ревью доков; код не меняется.

---

### II.6 Порядок исполнения и граф зависимостей

```
PATCH-01 (P0) ──┐
PATCH-02 (P0) ──┼─ независимы, стартуют немедленно, параллельно
                │
PATCH-06 (P1) ──► PATCH-07 (P1)      # reuse-носитель опирается на честный Restore
PATCH-03 (P1) ──► PATCH-04 (P1)      # бэкофф-механика переиспользуется
PATCH-01 ─────────► PATCH-04         # семантика watchdog едина
PATCH-05 (P1)    — независим
PATCH-08 (P1)    — независим (позже PATCH-03 желательно, для консистентности бэкоффа)
                │
PATCH-09..17 (P2) — независимы между собой и от P1 (PATCH-11 после PATCH-14: скраб-хелпер)
PATCH-18..22 (P2) — PATCH-19/20 после PATCH-08 (события lifecycle стабильны)
                │
PATCH-23..25 (P3) — в любое время (23/24 — по касанию файлов из P1/P2, удобно тем же PR)
```

Суммарная оценка волн: P0 ≈ 1.5–2 дня; P1 ≈ 6–8 дней; P2 ≈ 6–8 дней;
P3 ≈ 1–2 дня. Для поля достаточно P0+P1 (именно они закрывают BLOCKER, все
MAJOR и наиболее опасные MINOR-комбинации из I.14).

### II.7 Definition of Done (для агента-исполнителя)

1. Каждый патч — отдельная ветка/PR: `fix/wg-watchdog-trigger2`, …; commit-message
   ссылается на ID находки (например, `fix(E1): kernelroute restore deletes owned pin`).
2. Гейты каждого PR: gofmt/vet/build/test/race из §II.0 + новые тесты приёмки
   из тела патча. Красный-до/зелёный-после тест обязателен для дефектных патчей
   (E1, E3, E10, E15, WG BLOCKER 1 — тест, падающий на старом коде).
3. Для PATCH-06/07/08: интеграционные прогоны с NumGoroutine-дельтой до/после
   (утечки — главный риск волны).
4. Отчёт по каждому патчу в docs/reports/warp/ (по образцу
   NESTED_MATRIX_IMPLEMENTATION): что изменено, сам-верификация командами,
   отклонения от этого плана (если были) с обоснованием.
5. По завершении волны — обновить WG_IMPLEMENTATION_REPORT/NESTED_MATRIX:
   закрытые хвосты, CatalogVersion, список оставшихся полевых рисков
   (MAJOR 5-обмер каденса CF, A10-патч констант, интеграционный e2e W+M kernel).

### II.8 Чего НЕ делать (красные линии патчей)

1. **Не патчить vendored amneziawg-go** (константы очередей — A10: кандидат
   полевого этапа с замером RSS до/после; сейчас ломает «Modifications: none»
   в NOTICE и лицензионную гигиену слоя).
2. **Не рендерить J1–J3/Itime** в IPCString (zapret-gui-урок закрыт тестом —
   не ослаблять; PATCH-11 добавляет только маскированный дамп эффективного
   конфига).
3. **Не логировать ключи** ни в PATCH-11 (дамп), ни в PATCH-14 (скраб):
   регулярка-инвариант в тестах обоих.
4. **Не менять Reserved-дисциплину** (B2, красная линия 3): PATCH-ки E-NM её не
   касаются; при касании файлов bind/identity — тесты TestJunk*/инварианты
   обязательны к прогону.
5. **Не «чинить» инбаунд-чексуммы в SplitUDPDatagram** верификацией — целостность
   гарантирует QUIC-AEAD внешней плоскости; только документация (E20).
6. **Не смягчать fail-closed** носителей в погоне за «удобством» (мягкий
   wake-up MASQUE — осознанная семантика плоскости, не повод делать мягким
   kernel-носитель).
7. **Не добавлять новых зависимостей** ни одному патчу (goleak уже в go.mod;
   блобы PATCH-05 — данные, не код).
8. **Не объединять** P0/P1-патчи в один мега-PR: BLOCKER/MAJOR-фиксы должны
   ревьюиться и откатываться независимо.
