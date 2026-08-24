# REVIEW BRIEF — Nested Matrix (WARP-in-WARP) + HTTP/3 Transport (E-NM + E-H3)

**Кому:** ревьювер (сильная модель). **От:** владелец проекта b4x + агент-исполнитель.
**Дата компиляции:** 2026-08-24. **Фаза 3 из 3** программы ревью WARP-слоя
(Фаза 1 — MASQUE `WARP_V2_REVIEW_BRIEF.md`; Фаза 2 — WireGuard/AWG `WARP_WG_REVIEW_BRIEF.md`;
их разделы про общие компоненты identity/supervisor/trust-gate/trace — обязательный контекст).
**Материалы ревью:** (1) этот документ, (2) `.ag/research/warp-nested-matrix-design.md` —
архитектура nested, (3) `.ag/research/eh3-design.md` — архитектура H3,
(4) `.ag/research/wg-dataplane-research.md` + `wg-dataplane-research.md`… точнее
`.ag/research/wg-dataplane-research.md` и разделы H3 в `eh3-design.md` Приложении,
(5) код `src/transport/wg/` (nested) и `src/transport/warp/` (H3-режимы),
(6) по желанию — первоисточники: zapret-gui `awg_warp_in_warp.py`/`warp_in_warp.py`,
Aether `lib.rs/wireguard.rs/quic.rs`, warp-socks `masque/mod.rs`, usque `api/masque.go`,
sing-box `transport/wireguard`, connect-ip-go.

> **ВАЖНО — объём сдачи:** бриф описывает состояние ПОСЛЕ выполнения этапов N1–N5
> (nested-матрица) и EH1–EH5 (H3-транспорт). Карты Части III — контракт сдачи:
> отсутствующий компонент = находка `plan-deviation` (SEV=MAJOR). Вне объёма (НЕ находки):
> живые Cloudflare-прогоны, полевой TUN/PBR слой, NDMS ASC, performance-замеры на целевом
> железе, Chrome-fingerprint форк quic-go (осознанно отложен, см. §9 дизайна H3).

---

# Часть I. Погружение: роли, ценность, KPI

## 1.1. Что добавляют эти два модуля к программе

**Nested-матрица (E-NM)** замыкает все комбинации вложения WARP-туннелей:
M+W (MASQUE-outer, AWG-inner — эскалационный путь НЕ РФ, работает даже при полностью
зарезанном UDP: весь трафик пары выглядит как один TLS), W+W (gool-классика),
W+M (нишевый: AWG пробил UDP-цензуру, внутри H2-скорость). Базируется на Carrier-абстракции:
outer-режим (kernel-route пин /32 или userspace-netstack) определяет носителя, inner-движок
потребляет его через единый интерфейс.

**H3-транспорт (E-H3)** закрывает мейнстрим-режим экосистемы (usque/Aether/warp-socks/
warpscout/zapret-gui-performance — все H3-first): QUIC DATAGRAM вместо капсульного H2,
устранение head-of-line blocking TCP, connection migration (в пределах API quic-go).

## 1.2. Уникальные утверждения для проверки как главная ценность

Nested: (а) первая Carrier-абстракция, покрывающая ВСЕ пары одной логикой жизненного цикла;
(б) авто-re-assert маршрута-пина каждый тик — фикс задокументированного бага zapret-gui
(пин терялся при пересоздании outer навсегда); (в) прямая инъекция датаграмм вместо
loopback-шима Aether (минус хоп и состояние); (г) edge-collision гейт до подъёма;
(д) вертикальная интеграция: endpoint внутреннего слоя известен из собственной регистрации
(у zapret-gui для masque-inner — ручной параметр, т.к. чужой бинарник — чёрный ящик).

H3: (а) полный каталог ловушек протокола с обработками (Часть III §EH2, таблица §4 дизайна);
(б) trust gate без послаблений (QUIC не даёт структурного «200-доверия»);
(в) лестница H3↔H2 с структурной классификацией причин (udp-blocked / handshake-fail /
silent-after-handshake) и запретом осцилляций; (г) mark'и доезжают до QUIC через Dialer-
абстракцию, не трогая библиотеку (решение §18 аддендума, подтверждено практикой sing-box);
(д) cf-warp-colo телеметрия и на H3-ответе.

## 1.3. KPI

1. Latency: handshake-бюджет кандидата 5–8 с; trust gate каждого слоя ≤10 с; re-assert
   носителя в пределах тика супервизора; цена эскалации пары (TTFB vs одиночный) измерена.
2. Stability: восстановление пина после пересоздания outer — автоматом; teardown child-first
   с восстановлением прежнего состояния маршрутов; ноль диалов inner мимо outer в период
   инвалидации; caps/cooldowns переиспользуются.
3. Speed: MTU inner ≤1200 при любом outer; netstack TCP-буферы ≥256 KiB; drop-on-full
   политика датаграммных очередей; zero-copy где доступно.
4. Honest observability: per-layer attribution обязательна (никаких заявлений о скорости
   вложенности без разложения по слоям); каждый исход — структурный класс + событие.

---

# Часть II. Как формировалась архитектура: источники решений

Метод прежний: шесть исследований агентов по референсам (факты с file:line в
`.ag/research/wg-dataplane-research.md` §2/B.3 и двух отдельных отчётах по H3 — usque+Aether,
warp-socks/warpscout/Nova/mihomo; компиляция в конце `eh3-design.md`). Ключевые решения:

| Решение | Почему | Первоисточник |
|---|---|---|
| Carrier-абстракция вместо трёх дизайнов пар | Режим дата-плоскости outer'а (kernel-TUN/userspace) определяет носителя; транспорт inner'а ортогонален | синтез zapret-gui (kernel-путь) + sing-box stackDevice (юзерспейс) |
| KernelRouteCarrier: пин /32//128 через dev outer в MAIN | Проверено полем zapret-gui; таблицы движков 100–999 не конфликтуют с main | awg_warp_in_warp.py:209-337 |
| **Владение пином со снимком прежнего состояния** (`_pin_route_owned`/`_restore_route`) | Разборка восстанавливает прежний маршрут дословно (даже чужого интерфейса), а не удаляет вслепую | warp_in_warp.py:201-239 |
| **Re-assert пина каждым тиком супервизора** | Их примитив идемпотентен по построению, но зациклен не был → их задокументированный баг потери пина | наш фикс их пробела; примитив — их |
| NetstackCarrier через gvisor | Единая точка решения зависимости на Backend-B + userspace-WG + этот carrier | sing-box stackDevice; wireproxy-awg |
| Прямая инъекция UDP вместо loopback-шима | Минус хоп/состояние/класс ошибок «сиротский порт» | улучшение против Aether forwarder lib.rs:1493-1537 |
| Разные edge-IP слоёв ЖЁСТКО + edge-collision класс | gool правило; у zapret-gui проверки нет | Aether lib.rs:1546-1551 |
| MTU inner ≤1200, ka разведены (5/25 vs 20) | Двойная энкапсуляция; несинфазность реконнектов | gool; zapret-gui |
| Trust gate КАЖДОГО слоя полным набором данных | «Интерфейсы подняты» ≠ работает; handshake обманывает | z2k+Aether+warp-socks линейка |
| H3 primary на quic-go/http3; минимальный рукописный H3 — запасной путь A→B | Остаток H3-диалекта (QPACK/фреймы/control-stream) НЕ мал — владеть самим рискованно; ловушка Extended-CONNECT CF задокументирована с политикой закрытия | дизайн §2.1; warp-socks доказал минимальный путь против прод-CF |
| CID=20, settings {0x276:1}, retry-once PROTOCOL_VIOLATION | Иначе edge рвёт соединение; эмпирика | usque masque.go:181-183,146-159 |
| `:authority`=IP:port (JoinHostPort, v6-скобки); host-заголовок запрещён | Домен → 403; host рядом → H3_MESSAGE_ERROR 270 | warp-socks mod.rs:11-19,258-261 |
| open_bi под дедлайном 10 с; полный reconnect вместо ретрая на висящем conn; худшие бюджеты 38/53 с | Край подвешивает открытие потока при исчерпании квоты | warp-socks mod.rs:44-65 |
| Два таймера зависаний (dial + первый запрос) | Заблокированный край завершает handshake и МОЛЧИТ — не обрывается QUIC-таймаутами | warpscout masque.go:459-467 |
| Параллельный диал кандидатов first-wins | Последовательный перебор = «кандидаты × бюджет» | warp-socks mod.rs:459-485 |
| Unknown capsule/GREASE inbound — skip, не kill | connect-ip-go падает жёстко; Aether игнорирует | masque.rs:196-199 vs conn.go:250-252 |
| Mark'и через Dialer-abstraction | Подтверждено sing-box: помеченный Dialer отдаёт conn в QUIC; внутрь библиотеки socket-options не протаскиваются | sing-box common/dialer/default.go:262+ |
| cf-warp-colo парсинг (lowercase; Huffman-векторы известны) | Бесплатная телеметрия узла выхода | warp-socks qpack.rs:159-207,330-345 |
| NFQ cover-шаблон bootstrap'а: ipset 15×CF-v4 + 2606:4700::/32, 7 портов, fake-bin×6, autottl=3 | Проверено Nova в поле; наши примитивы уже есть | Nova strat/warp.json + nova.pyw:2731-2778 |

Сознательно НЕ берём: kmod awg-proxy (GPL-2.0; урок FASTNAT/PPE-обхода учтён концептуально);
ChromeParrot-форк quic-go (отдельное решение владельца, вне этапа); 0-RTT/DialEarly (pinning+
replay риск; прецеденты DoQ/TUIC зафиксированы на будущее); BBR (quic-go не даёт — ограничение
зафиксировано); миграцию соединений как фичу (quic-go API не даёт активной миграции).

---

# Часть III. Карта сдачи (контракт; отсутствие = plan-deviation)

## Этапы N1–N5 — пакет src/transport/wg (nested-подсистема) [+ конфиг-схема]

| Компонент | Обязанности |
|---|---|
| carrier.go | Интерфейс NestedCarrier{InjectUDPDatagram, DialTCPThrough, ProofSnapshot}; выбор реализации по режиму outer'а |
| carrier_kernel.go | KernelRouteCarrier: резолв inner-endpoint ДО подъёмов; пин /32//128 через dev outer с ВЛАДЕНИЕМ (снимок прежнего состояния → restore дословно при teardown, даже если маршрут чужого интерфейса); add→replace fallback; v6-fail=warn/v4-fail=rollback; `_routes_cover`-эквивалент перед продолжением |
| reassert.go | Интеграция в тик супервизора: Assert() каждый тик; потеря пина ⇒ событие nested/carrier-route-lost + автоматический repin (фикс бага zapret-gui) |
| carrier_netstack.go | NetstackCarrier поверх gVisor-стека outer'а (решение по gvisor — после FIELD1 пробы netns; до решения слот BLOCKED_CARRIER, fail-closed) |
| nested_matrix.go | Сборка пар: валидация kind-пары, identity_slot != primary, разные edge-IP до подъёма маршрутов (edge-collision класс), порядок setup §4 (резолв → outer+gate → carrier → inner+gate), teardown child-first с восстановлением прежних маршрутов |
| parent_link интеграция | Reconnect outer ⇒ child INVALIDATED (ноль диалов), REVALIDATED против нового SessionGen; события трассировки |
| конфиг-схема | nested.{outer,inner,carrier,failure_mode} с валидацией kind-пар и существования профилей |

Тесты: carrier unit (fake route-table), пары × матрица отказов (kill outer/inner/WAN),
edge-collision, pin-restore, per-layer latency атрибуция.

## Этапы EH1–EH5 — H3-режим в пакете src/transport/warp

| Компонент | Обязанности |
|---|---|
| go.mod | +quic-go (pinned; единственная новая зависимость этапа) |
| udpdial.go | DialPolicy-адаптер для UDP: тот же Control-цепочка (SO_MARK/SO_BINDTODEVICE), буферы SO_RCVBUF/SO_SNDBUF 8 МБ ignore-error, dual-bind по семейству peer'а |
| fakeedge_h3_test.go | Фейковый H3-MASQUE сервер (quic-go server side): серт/pin, ALPN h3, extended-CONNECT (конфигурируемое отсутствие рекламы!), эхо датаграмм, матрица поведения (silent/hang/teardown/statuses) |
| session_h3.go | Диал (CID=20, settings {0x276:1}, InitialPacketSize авто/1242-fallback, окна 10M/1–2M, streams 100, payload ≤1350, idle 60–120 s явно, ka 10–15 с) → CONNECT (:authority IP:port через JoinHostPort, cf-connect-proto, pq-enabled=false, UA пустой) → 200 → **trust gate** (2 DNS RT/600 мс/10 с) → established; датаграммы qsid(auto)+ctx(0)+payload; skip unknown frames (≤8 подряд, HEADERS ≤64 КиБ); ICMP TooBig MTU 1280 полный рецепт; open_bi/stream-open под дедлайном 10 с; **два таймера зависаний**: dial-budget + отдельный budget первого запроса (silent-handshake ловушка warpscout); ретрай ×1 только PROTOCOL_VIOLATION-класс |
| ladder_h3h2.go | Лестница H3→H2: классификация udp-blocked / handshake-fail / silent-after-handshake; переход только событием с причиной; возврат на H3 через cooldown-цикл; ноль осцилляций |
| discovery_h3.go | Активация QUIC-ветки каталога (.1/.2, v6-пары); UDP-reachability проба как часть верификации кандидата |
| cover_nfq.go | Координация с nfq-hook (E7): fake-QUIC профиль (ipset WARP-диапазонов + 2606:4700::/32, порты 7 шт., fake-bin, repeats ×6, autottl=3) на время установления — параметры Nova warp.json |
| telemetry | cf-warp-colo парсинг (lowercase; готовые Huffman-векторы warp-socks) → trace payload |

Тесты: fakeedge-матрица (статусы/silent/hang/teardown/framing), ladder-переходы, stall,
framing round-trip, TooBig-конструирование checksums, authority-форматтер (v4/v6-скобки),
seek-интеграция, colo-парсер на реальных QPACK-векторах.

Верификация при сдаче:

```text
docker run --rm --dns 8.8.8.8 --mount type=bind,source=D:\b4x,target=/src \
  --mount type=bind,source=C:\Users\AlexZander\go\pkg\mod,target=/go/pkg/mod \
  -w /src/src golang:1.25.3-alpine \
  go vet ./transport/... && go test ./transport/... -count=1 && go test ./transport/wg/ -race && go test ./transport/warp/ -race
```

### Известные ограничения (НЕ считать находками)

1. Живой Cloudflare не прогонялся (consent rule); BLOCKED_TARGET_VALIDATION остаётся.
2. Полевой TUN/PBR/NDMS слой вне объёма; движок экспортирует io-адаптеры.
3. H3: активная connection migration недоступна (API quic-go); NAT-rebinding обрабатывает
   библиотека незаметно; BBR congestion недоступен (quic-go NewReno-only).
4. Chrome-fingerprint ClientHello требует форка quic-go — осознанно отложено (§9 H3-дизайна).
5. Backend-B nested зависит от решения по gvisor (триггер — FIELD1 netns-проба); до решения
   слот BLOCKED_CARRIER fail-closed.
6. Performance-замеры на целевом железе отсутствуют; ориентиры — числа референсов
   (usque README 833/772 Mbps desktop-class; Keenetic-class ожидаемо ниже).
7. Linux mark-пути — smoke-план (CAP_NET_ADMIN для автотеста).

---

# Часть IV. Задание ревьюверу

## Часть A. Оценка архитектуры (verdict agree / agree-with-changes / disagree + обоснование)

A1. **Carrier-абстракция**: полна ли тройка методов (UDP-inject / TCP-dial / proof) для всех шести пар? Не потребуется ли третий метод (например, потоковый relay для TCP-inner поверх юзерспейс-outer)?
A2. **KernelRoute vs Netstack**: корректен ли критерий выбора по режиму outer'? Что делать на гибридных конфигурациях (kernel-TUN outer + требование юзерспейс-isolation inner)?
A3. **Re-assert пина**: бюджет тика достаточен? Гонки с внешними пересозданиями интерфейса (NDMS/сетевой менеджер)? Нужен ли джиттер, чтобы не воевать с чем-то ещё за таблицу маршрутизации?
A4. **Edge-collision**: достаточно ли сравнения IP после установки (post-connect), или нужен pre-connect прогноз (резолв hostname-inner до подъёма)? Как вести карту соответствий пул↔colo?
A5. **Identity-слоты**: достаточно ли двух (primary/secondary) или матрица пар требует третьего? Миграция сторов обратно совместима?
A6. **Лестница H3↔H2**: критерии переключения устойчивы к флапу сети (осцилляции)? Правильна ли точка возврата на H3 (cooldown-цикл)?
A7. **Trust gate на H3**: сохранение параметров (2 RT/600 мс/10 с) адекватно QUIC-особенностям (0-RTT выключен; handshake медленнее на HRR)? Нужен ли ironclad-lite в дефолте?
A8. **ICMP TooBig**: полный рецепт (включая IPv6 pseudo-header и swap адресов) соответствует RFC и практике connect-ip-go? Кто отвечает за PMTU-кэш?
A9. **НЕ РФ дерево (§7.5)**: порядок AWG-регион → masque+awg → fail-closed согласован с политикой E6? Замер revocation latency заложен корректно?
A10. **Ресурсы**: tier-числа для Keenetic (Low/Medium) применимы к gVisor-нетстеку и QUIC-очередям одновременно?

## Часть B. Чеклист кода

### Nested (src/transport/wg/nested*, carrier*)
B-N1. carrier_kernel: семантика add→replace→verify (`route get`) точно как спецификация; снимок previous сохраняется ДО модификации; restore дословно (shlex-эквивалент) включая чужие интерфейсы; v6-fail=warn/v4-fail=rollback асимметрия.
B-N2. reassert: вызывается ли Assert на каждом тике; гонка с teardown (child-first); событие carrier-route-lost эмится ровно один раз на эпизод.
B-N3. edge-collision: проверка ДО подъёма маршрутов; источник IP обоих слоёв (не доверять конфигу — сверять факт подключения).
B-N4. identity-слоты: inner берёт secondary; primary не переиспользуется; store-записи не пересекаются.
B-N5. parent-link: reconnect outer ⇒ child INVALIDATED мгновенно (ноль диалов), revalidation строго против нового SessionGen; тесты покрывают гонку «outer поднялся раньше, чем child заметил».
B-N6. cleanup: каждая owned-сущность (пины, netns, veth, NAT, listener, маркеры) имеет terminal-record; teardown child-first; частичный провал setup откатывает всё сделанное (ownership flags).
B-N7. MTU/keepalive: значения из матрицы применяются фактически (не только в конфиге); clamp MSS inner-MASQUE при двойной энкапсуляции.

### H3 (src/transport/warp/session_h3*, ladder*, discovery_h3*, cover*)
B-H1. Датаграммный формат: qsid добавляется библиотекой (не дублировать!), ctx=0 вручную; inbound толерантность к вариантам (bare vs ctx-prefixed); лимит 64 КиБ на HEADERS, max 8 skipped подряд.
B-H2. :authority форматтер: IPv4/IPv6-скобки/порт; отсутствие host-заголовка; пустой User-Agent.
B-H3. Trust gate: параметры 2/600ms/10s; поведение при конкурентном потребителе пакетов; teardown по таймауту гарантирован; ironclad-lite опция отключена по умолчанию, но присутствует интерфейсом.
B-H4. Два таймера зависаний: dial-budget и первый-запрос-budget раздельны; ни один не наследует lifetime-context сессии (ловушка AfterFunc-vs-ctx из warpscout).
B-H5. Лестница H3↔H2: переходы только событиями; осцилляции исключены cooldown-циклом; udp-blocked классифицируется ДО попыток H2 (быстрый fail).
B-H6. ICMP TooBig: конструирование IPv4/IPv6 вариантов с checksums; MTU-значения 1280/1232; адресация swap.
B-H7. colo-парсер: lowercase-сравнение; Huffman-векторы; отсутствие заголовка — не ошибка.
B-H8. Ошибки: таксономия полная (udp-blocked/handshake-fail/silent-after-handshake/quota-hang/pin-mismatch); retriable-набор соответствует исследованию; WrapError-нормализация к net.ErrClosed.
B-H9. Ресурсы: drop-on-full очереди; буферные pool'ы; горутин-утечки при Close (прогнать leak-тест); tier-константы применены.

### Общие
B-O1. Конкурентность: одновременные Submit/Close/Status по всем инстансам; дедлоки emit-vs-done.
B-O2. Приватность: ключи/client_id/endpoints — только хэши в трейсах.
B-O3. Тесты: покрытие всех сценариев Части III; отсутствие ложных PASS на silent-drop; интероп-матрица.

Формат отчёта:

```text
[SEV] area/file:line — проблема → предлагаемый fix
SEV ∈ {BLOCKER, MAJOR, MINOR, NIT}; area ∈ {arch|code|test|ops|plan-deviation}
```

Итоговые таблицы: (а) findings по severity; (б) вердикты A1–A10; (в) список «проверено,
проблем нет»; (г) top-5 приоритетных действий; (д) plan-deviation по картам Части III
(ОБЕ карты: N-этапы и EH-этапы).

---

# Часть V. Красные линии

1. Ни одна nested-пара не активирует маршрут без ОБОИХ пройденных trust gates.
2. Никаких silent fallback между транспортами/носителями — только события с причинами.
3. amneziawg-go и quic-go — единственные новые зависимости, обе pinned, лицензии MIT
   зафиксированы в NOTICE; никакого GPL/kmod/sing-box-GPLv3 кода.
4. Reserved-байты только для cf_warp-пиров; vanilla-safe профили против CF-края.
5. Никакой мутации established-потока; cutoff строго по data-plane подтверждению.
6. Foreign-ресурсы никогда не удаляются; owned — с терминальными записями.
7. Родительские запреты действуют (роутер, коммиты, live-CF в тестах, чужие пакеты).

---

# Часть VI. Шпаргалка констант

```text
Nested:      edge-IP слоёв разные ЖЁСТКО; inner MTU <=1200; ka outer/inner разведены;
             setup: resolve-inner -> outer+gate -> carrier assert -> inner+gate;
             teardown child-first; пин с восстановлением прежнего состояния;
             re-assert каждый тик; v6-fail=warn, v4-fail=rollback
Carrier:     KernelRoute (пин /32,//128 через dev outer, MAIN) | Netstack (gvisor)
             выбор по режиму outer; BLOCKED_CARRIER до решения
H3:          ALPN h3; authority=IP:port (JoinHostPort); host-заголовок запрещён;
             settings {0x276:1}; CID/SCID 20; initial packet 1350 (fallback 1242);
             ka 10-15 c; idle 60-120 c; окна 10M/1-2M; streams 100
Gate:        2 DNS RT / 600 ms / окно 10 c на КАЖДЫЙ слой + e2e warp=on
Stall(WG):   нет RX >10 c ИЛИ tx>=4096 при delta rx<=1024 за 120 c
Seek:        >=3 попытки; durability burst 10x200ms tail>=3; cooldown 300 c
Caps H3:     qsid(lib)+ctx(0)+payload; unknown-skip; DATA-only после 200
Отказы H3:   udp-blocked -> H2 немедленно; silent-after-handshake -> H2+пометка;
             PROTOCOL_VIOLATION -> retry x1; access-denied -> fail-closed
NFQ-cover:   ipset 15x CF-v4 + 2606:4700::/32; порты {443,500,1701,4500,4443,8443,8095};
             fake-quic bin x repeats 6; autottl=3
```

*Конец брифа. Спасибо за глубину.*
