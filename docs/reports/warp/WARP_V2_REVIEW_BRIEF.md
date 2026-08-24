# REVIEW BRIEF — WARP MASQUE Tunnel v2 (архитектура + код)

**Кому:** ревьювер (сильная модель). **От:** владелец проекта b4x + агент-исполнитель.
**Дата компиляции:** 2026-08-23 (карта сдачи — по факту завершения этапов). **Фаза 1 из 3**
(Фаза 2 — WireGuard/AWG: `WARP_WG_REVIEW_BRIEF.md`; Фаза 3 — nested-матрица + H3:
`WARP_NESTED_H3_REVIEW_BRIEF.md`. Общие компоненты identity/supervisor/trace ревьюются здесь,
в следующих фазах — только дельта и интеграционный срез). Все номера строк/фактов соответствуют
состоянию репо на дату компиляции.
**Материалы ревью:** (1) этот документ, (2) `.ag/research/warp-dataplane-design.md` — архитектура v2,
(3) код `src/transport/warp/` (+ контракты `src/warp/`), (4) сравнительные анализы
`WARP_VS_AETHER_WARPSOCKS.md` (детальное против #2/#3 рейтинга референсов) и
`WARP_VS_15_REFERENCES.md` (черновик пользовательского README со сравнениями vs usque/z2k/
usque-keenetic/Nova), (5) по желанию — первоисточники ниже.

> **ВАЖНО — что считается объёмом сдачи:** бриф описывает состояние ПОСЛЕ выполнения всех этапов
> E0–E6 плана дизайна. Файловая карта в Части III — это контракт сдачи: **отсутствующий или
> переименованный без объяснения файл/компонент сам по себе является находкой** (SEV=MAJOR,
> категория `plan-deviation`). Полевые вещи (TUN/NDM/PBR, живой роутер) и этапы E7–E8 в объём
> НЕ входят и перечислены в «Известных ограничениях» — их не считать находками.

---

# Часть I. Погружение: продукт, цели, KPI

## 1.1. Что это за проект

**b4** — Go-демон обхода DPI для роутеров Keenetic (arm64, Entware, ~64 МБ RAM у целевого железа).
Текущий стек: NFQUEUE-based маскирование TCP/QUIC (fake SNI, ClientHello split/combo, PPE-окно),
классификатор трафика, observability. Живой полигон — YouTube на двух устройствах владельца.
Исходники: `src/`, точка входа `src/main.go`. Контрактный слой WARP уже существовал (`src/warp`,
77 тестов): типы, hard-gate продюсеры §72/73/73A/73B, trace pipeline v2. **Data plane до недавнего
времени отсутствовал** — это зафиксировано собственным аудитом репо: `B4X_FIX_BACKLOG.md`,
тикет **B4X-FIX-0004**: «No functional MASQUE/CONNECT-IP data-plane exists».

## 1.2. Зачем туннель (мотивация из поля)

Роутерная анти-ECH лестница исчерпана (доказательства: `PROJECT_DIRECTIVES.md`, карта
`YOUTUBE_DATAPLANE.md` §7): steer/refused/ipfrag закрыты навсегда как вредные. Параллельно
зафиксированы **штормы ротации эджа Google** (23.08: 105 уникальных QUIC-endpoint'ов/час, 4 POP-кода,
умерший fra16s31; UX-жалобы зеркальны на обоих клиентах). Вывод владельца: даже идеальное
маскирование пакетов не защищает от перехоумингов — нужен **альтернативный L3-path**, т.е. туннель.

## 1.3. Фичи, которые мы хотим, и зачем

| # | Фича | Зачем |
|---|---|---|
| F1 | **Base WARP tunnel** (MASQUE CONNECT-IP поверх HTTP/2 TCP 443, scoped per-client/per-set) | Обход ECH-стены и IP-блокировок для выбранных скоупов; fail-open по умолчанию |
| F2 | **WARP+WARP (nested)** | Вторая изолированная сессия поверх первой; кандидат на смену egress без внешних сервисов |
| F3 | **Режим «НЕ РФ»** (experimental) | Обход геоблокировок по IP: маршрут активен ТОЛЬКО при свежем multi-provider подтверждении egress ≠ RU; иначе scoped fail-closed |
| F4 | **Полностью автоматическая регистрация** | Enrollment/renewal/reprovision без единого ручного шага; monitored, bounded; владелец один раз даёт consent на Cloudflare ToS |
| F5 | **Интеграция с существующим слоем обфускации** | Control-flow туннеля исключается из generic desync (иначе самоуничтожение); enrollment наоборот прикрывается нашими bypass-стратегиями; camouflage C0–C6 поверх готовых примитивов nfq |

## 1.4. KPI (по ним оценивать и архитектуру, и предложения)

1. **Низкая латентность**: бюджет установления (TCP+TLS+CONNECT-headers) ≤ 20 s worst case;
   data-plane validation ≤ 10 s при каденции зондов 700 ms; endpoint verification per-probe timeout 2 s;
   минимизация TTFB первого пользовательского соединения после cold-start.
2. **Стабильность**: нет ресторм-штормов (backoff 1→30 s, reset после 60 s стабильной работы);
   все повторения ограничены кулдаунами со штампами «до действия»; fail-open маршрута после streak≥3;
   терминальная ошибка inbound = немедленное закрытие сессии (никаких полуживых состояний).
3. **Скорость туннеля**: inner MTU 1280 (аддендум §16), zero-copy uplink (буфер MTU+1 с
   зарезервированным байтом под context-ID — трюк usque), корректный ICMP TooBig(1280) вместо
   молчаливой потери, отсутствие лишних копий в капсульном парсере.
4. **Честность наблюдаемости**: ни одно «работает» не декларируется без сквозного доказательства
   (probe round-trips, e2e `warp=on`), структурные коды отказов вместо строк.

---

# Часть II. Как формировалась архитектура v2 (процесс и источники идей)

## 2.1. Процесс

Шаг 1 — **исследование**: 15 reference-репозиториев из `D:\b4x\warp\` (все — read-only референсы,
все с собственным git). Пять параллельных глубоких раскопок по профилям: data plane, регистрация,
endpoint-discovery/латентность, валидация/здоровье, роутерный lifecycle+обфускация. Компиляция фактов:
**`.ag/research/warp-dataplane-research.md`** (каждый факт с file:line; ниже даём выжимку со ссылками).
Протокол дополнительно сверен с **запинненным** upstream usque @ `6aa03fc97d12848dce34eedbd187fb1077b5d1ea`
(MIT; pin из аддендума §1.2).

Шаг 2 — **синтез дизайна** (v1), шаг 3 — ревизия v2 по трём требованиям владельца:
(1) аддендум v1.2 остаётся нормативной базой; (2) нативная посадка в `B4_FORK_ARCHITECTURE_v2.5.md`
с синергией обфускации; (3) проработка режима НЕ РФ включая проверку идеи «подменные DNS».
Дизайн утверждён владельцем. Итог: **`.ag/research/warp-dataplane-design.md` v2**.

## 2.2. Первоисточники ключевых фактов о протоколе (для проверки кода)

Wire-протокол Cloudflare MASQUE H2 (наш primary транспорт):

| Факт | Первоисточник |
|---|---|
| Клиентский серт: self-signed ECDSA P-256, 24 ч, serial 0; регенерируется на запуск | usque `internal/utils.go:106-117 GenerateCert`, `api/masque.go:35-89 PrepareTlsConfig` |
| Аутентикация сервера = **pinning публичного ключа leaf** (ECDSA-equality), `InsecureSkipVerify:true` обязателен, т.к. SNI≠имя серта | usque `api/masque.go:57-86`; аналогично warp-socks `tls.rs` (SPKI-SHA256 pins), Aether `consts.rs:52-65` (два запечённых пина: CF self-signed root + GTS WE1) |
| ALPN h2; заголовки CONNECT: `cf-connect-proto: cf-connect-ip`, `pq-enabled: false`, пустой `User-Agent` | usque `api/masque.go:121-124`; Aether `masque_h2.rs:163-174` |
| CONNECT на URI-template `https://cloudflareaccess.com`; `req.Host` = authority с дефолт-портом 443; body = io.Pipe, `ContentLength=-1` | usque `internal/consts.go:10 ConnectURI`, `api/masque.go:126-131`, `client_h2.go DialH2` (connect-ip-go fork) |
| Капсулы DATAGRAM обе стороны: `varint(type=0) varint(len) <ip-packet>`; **context-ID на проводе ОТСУТСТВУЕТ** (non-RFC особенность Cloudflare); чужие типы капсул inbound пропускаются | connect-ip-go `client_h2.go`: `h2DatagramCapsuleType uint64 = 0`, `SendDatagram`/`ReceiveDatagram`/`parseCapsule` |
| x/net/http2 поддерживает normal CONNECT (`isNormalConnect`): пишет только `:method`+`:authority` | golang.org/x/net@v0.46.0 `http2/internal/httpcommon/request.go:88-98`, `http2/transport.go:1400-1403` |
| Endpoint H2 по умолчанию `162.159.198.2`, порт 443; endpoint приходит числом из регистрации (DNS в пути подключения отсутствует) | usque `config/endpoints.go:11 DefaultEndpointH2V4`, `cmd/register.go`/`cmd/enroll.go` (парсинг peers[0]) |
| API регистрации: `https://api.cloudflareclient.com/v0a4471/reg`; headers `User-Agent: WARP for Android`, `CF-Client-Version: a-6.35-4471` (**суффикс версии пути обязан совпадать с build-числом заголовка**) | usque `internal/consts.go:4-5,19-24`; warp-reg-gw `internal/registration/registration.go:40-43` |
| Two-step enrollment: POST `/reg` с throwaway curve25519 → PATCH `/reg/{id}` c `key_type=secp256r1`, `tunnel_type=masque`, Bearer-токеном; токен выдаётся ТОЛЬКО в ответе POST | usque `api/cloudflare.go:37-187`; warp-reg-gw `registration.go:225-358` |
| TOS timestamp формат `2006-01-02T15:04:05.000-07:00`; serial hex8; model PC; locale en_US | usque `internal/utils.go TimeAsCfString/GenerateRandomAndroidSerial`, `api/cloudflare.go:58-69` |
| QUIC-varint RFC 9000 §16; границы классов длин 63/16383/1073741823 | RFC 9000 §16 (литературный пример 15293→`7b bd`) |

Измеренная карта gateways (три независимых инструмента сходятся):

| Факт | Первоисточник |
|---|---|
| QUIC-MASQUE отвечает только `162.159.198.1/.2` (+v6 `2606:4700:103::1/::2`, `104::1/::2`); прочие адреса /24 отвечают QUIC, но режут TLS | warpscout `masque.go:50-87` |
| TCP-MASQUE (h2): вся `162.159.198.0/24` + `162.159.199.0/24`; v6 целиком `103::/48`+`104::/48` | warpscout `masque.go:74-87` |
| Порты MASQUE: `{443,500,1701,4500,4443,8443,8095}` | warpscout `masque.go:91` = Nova `strat/warp.json` = MSN-GUARD `core/aether/src/prober.rs:45` |
| WG-диапазоны (188.114.96–99, 162.159.192/195…) для MASQUE бесполезны: TLS alert 40, другой публичный ключ | z2k `z2k-warp.sh:128-143`, warpscout `pools.go` |

## 2.3. Первоисточники операциональных практик (латентность/стабильность/безопасность)

| Практика | Значение | Первоисточник |
|---|---|---|
| **Data-plane trust gate**: после 200 ничего не «работает», пока N=2 сквозных probe round-trip'ов не пришли за окно; probe = синтетический DNS A→8.8.8.8, каденция 700 ms; общий стартовый дедлайн 30 s; иначе разрыв с причиной «control ok, traffic dropped» | Aether `quic.rs:63-76,240-285,370-387`, `masque.rs:280-326`, `lib.rs:937-964`; Docs/GUIDE.en.md |
| **Liveness is proven, not assumed**: e2e HTTPS `https://1.1.1.1/cdn-cgi/trace` через интерфейс + требование `warp=on`; двойная проба (первая будит спящий туннель, вторая судит; опциональная третья cap 20 s — CF штрафует wake-up 10–20 s); кэш-вердикт TTL 180 s с третьим состоянием unknown | z2k `z2k-warp.sh:89-104,304-317,428-472` |
| Backoff супервизора 1→30 s, reset при жизни ≥60 s; лок вокруг check-and-spawn; kill всей группы потомков | z2k `S51z2k-warp:353-399,503-508` (= аддендум §19 reconnect defaults) |
| App-level keepalive каждые 120 s (в h2 флаг `-k` no-op!); ICMP через туннель дропается 100% | z2k `S51z2k-warp:54-66`, `z2k-warp.sh:429-471` |
| H2 PING keepalive 15 s / timeout 20 s → stalled → разрыв; h3 ack-eliciting 20 s | Aether `masque_h2.rs:68-84`, `quic.rs:237-272` |
| Watchdog «нет входящих data >10 s» = туннель мёртв (идея last_valid_rx, переносима на MASQUE) | Aether `wireguard.rs:163,278-304` |
| Zero-copy uplink: sync.Pool буферов ёмкости **MTU+1**, первый байт зарезервирован под context-ID 0 | usque `api/tunnel.go:158-160,233` (`datagramContextIDHeadroom`) |
| Oversized → синтетический **ICMP TooBig с MTU 1280** (IPv4 type3/code4; IPv6 type2, payload до 1232); клиент декрементирует TTL как router-hop | connect-ip-go `icmp.go`, `conn.go` (minMTU=1280), вызовы usque `tunnel.go:331-350` |
| Ошибки: CloseError/TUN-read/TUN-write = kill session; транзиентные write/read (H3) = log+continue; **в H2 любая ошибка чтения фатальна** | usque `api/tunnel.go:305-376`, commit 25c7f0a |
| Pump shutdown grace 2 s; сериализация readMu между циклами | usque `api/tunnel.go:152-156,388-400` |
| **Потеря пакета-будильника** при AlwaysReconnect=false (usque читает TUN и выбрасывает) — известный баг, мы фиксируем буферизацией | usque `api/tunnel.go:240-254` |
| Scan: per-probe timeout 2 s; **минимум 3 попытки на endpoint** (MASQUE флапает: одна попытка давала 1–3 из 14 рабочих, три — 11–13); **durability burst 10 эхо ×200 ms, torn-down = tail-run ≥3 подряд промахов** (при burst 3 → 13/70 ложных «рабочих»); ранжирование loss > in-tunnel RTT > host ICMP; throughput вне ранжирования; вложенный скан jt=1 (рейтлимит CF) | warpscout `flags.go:177,221,354-360`, `discovery.go:52,103-161`, `tunnel.go:196-217,306-364,407-417`, `README.md:321-372` |
| Стратегии скана turbo/balanced/thorough/stealth/ironclad с конкретными бюджетами (conc 16–20, per-probe 6–15 s, budget 45–300 s, quiet-window 15–30 s); seeds-first + sample-per-CIDR с интерливом; rtt = время до 2-го data-probe echo | Aether `prober.rs:162-214,440-519,322-326` |
| Last-good cache + быстрый re-verify 5 s перед ресканом; cooldown 300 s после 2 провалов | Aether `lastconn.rs`, `lib.rs:705-754,812-824,1052-1059` |
| QUIC-тюнинг (на будущее H3): SCID len 20 (обязателен — иначе PROTOCOL_VIOLATION), keep_alive 10 s / idle 60 s (warp-socks) или 120 s (Aether), окна conn 10 MB / stream 1–2 MB, 100 streams, payload 1350 | usque `masque.go:181-183`; warp-socks `tls.rs:95-102`, `mod.rs:3-4`; Aether `tls.rs:170-181` |
| TLS kx-группы P-256/P-384 (X25519 вызывает HelloRetryRequest у CF edge) | warp-socks `tls.rs:4,73-79` |
| `:authority` обязан быть IP:port (домен → 403; host-заголовок рядом с IP-authority → H3_MESSAGE_ERROR 270); постоянный H3 control stream; open_bi может ПОДВЕСТИ при исчерпании квоты → timeout 10 s; разделённые link/reconnecting локи | warp-socks `mod.rs:11-19,69-74,116-165,44-65` |
| **`cf-warp-colo` заголовок в ответе CONNECT** = бесплатная телеметрия edge-ноды | warp-socks `mod.rs:276-312` |
| DoH строго внутри туннеля (162.159.36.1/46.1:443, SNI cloudflare-dns.com), TTL-cache clamp 5–300 s; UDP в MASQUE не поддерживается → явный reject, никакого тихого direct-egress | warp-socks `doh.rs:24-30`, `socks5.rs:8-9` |
| Health = SOCKS-пробой `https://cloudflare.com/cdn-cgi/trace` с требованием `warp=on\|plus`; MASQUE-first/WG-fallback; порог N=3 провалов; exit-on-unhealthy вместо вечного recovery | warp-socks `health/probe.rs:40-81`, `supervisor.rs:78-120` |
| Регистрация строго последовательная; caps ≤10 устройств; частичный успех сохраняется; reconcile до target_accounts; планировщик ≥15 мин | warp-reg-gw `registration.go:634-654`, `main.go:141-144,186-198`, `gateway/service.go:208-238` |
| **Refuse vs throttle**: только 401/404/410 = мёртвая идентичность → автоперевыпуск; 403/429/5xx = rate-limit/сеть → НИКОГДА не перерегистрируемся; API retry 900 ms×2^n cap 15 s jitter ±⅓, Retry-After cap 30 s; cert renewal за 7 дней до конца, keep-old-on-failure; атомарная запись identity tmp+fsync+rename+0600, битый файл → карантин *.corrupt | Aether `account.rs:242-273,831-903`, `config.rs:103-205` |
| Camouflaged API fallback: raw TLS на случайные CF edge `141.101.113.0/24` БЕЗ DNS + split-CH fingerprint профили | Aether `apifront.rs:12-118,137-353` |
| Enrollment через bypass: `cloudflareclient.com` в hostlist стратегий (иначе enroll падает в TLS-таймаут); транспорт-спека direct/interface-proxy с whitelist одного хоста, fail-closed привязка сокета | z2k `extra-domains.txt:24-27`, `z2k-warp.sh:1061-1172`; zapret-gui `usque_manager.py:232-349`, `iface_socks.py` |
| **Control-flow исключается из generic desync** (exclusion-ipset/nozapret паттерн, re-add каждый тик); proxy-env демона чистится, enrollment получает явный транспорт | z2k `z2k-warp.sh:785-808`, `S51z2k-warp:438-443`; контрпример — zapret-gui, где исключения НЕТ (дыра) |
| Fail-open: route держится только под доказанной живостью; streak≥3 → route снят; exit-код контракт toggle (0 verified / 1 hard-fail / 2 applied-but-dead flag stays ON) | z2k `z2k-warp.sh:1220-1257,876-884` |
| Кулдаун-инварианты: штамп ДО действия; незаписываемый штамп = «не делать»; штамп из будущего = сброс; штампы вне /tmp; kick 300 s, reg/install 600 s, variant TTL 600 s | z2k `z2k-warp.sh:200-226` |
| Endpoint-вариант = копия конфига, оригинал неприкосновенен; ротация только при причине «probe failed AND сессия НЕ установлена»; если сессия встала, а данных нет — однократная охраняемая перерегистрация (backup+rollback) | z2k `z2k-warp.sh:234-290,968-1006,1102-1134` |
| Адрес интерфейса строго из session.conf ipv4 (полевой кейс «session.conf 172.16.0.2, интерфейс 172.16.240.1 → туннель up, несёт nothing»); MTU первым движением до NDM + re-assert каждый тик (usque читает буфером ровно MTU и молча режет) | z2k `S51z2k-warp:117-167,479-488`, `z2k-warp.sh:810-817` |
| Gool (WARP-in-WARP): разные edge-IP слоёв ОБЯЗАТЕЛЬНЫ; outer MTU 1280/ka 5 s, inner MTU 1200/ka 20 s; community использует именно для смены страны выхода | Aether `lib.rs:46-47,1546-1561`; oblivion warning «смените через Gool» |
| Bootstrap WARP защитой QUIC-fake десинка на диапазоны WARP (паттерн для будущего H3) | Nova `nova.pyw:2731-2776`, `strat/warp.json` |
| Фазовая классификация отказа resolve→connect→handshake→upgrade→carry; RST-порог по доле RTT | Nova `docs/adr/0003-tunnel-phases.md` |
| Resource tiers Low/Med/High: scan conc 4/10/∞, chan 128/512/1024, sock buf 256KB/2MB/7MB | Aether `sysprofile.rs:125-169` |
| Страна выхода: colo определяется anycast-ближайшим edge; регистрацией страну НЕ выбрать; чужой IP /24 проходит TLS+pin, но CONNECT-IP отбивает 0x131; подменные DNS (geohide/comss/xbox.dns) работают на уровне DNS-ответов для конкретных доменов и в пути подключения к WARP не участвуют | warp-reg-gw `main.go:380-394,README.md:139-150`; warpscout `flags.go:682-700`; анализ в дизайне §14 |

## 2.4. Ключевые решения v2 и почему приняты

| Решение | Почему | Откуда |
|---|---|---|
| Primary транспорт **H2/TCP-443**, H3 — capability later | Целевые сети РФ часто режут UDP/QUIC; H2 покрывает worst case; дефолт аддендума `protocol: masque-h2` | аддендум §3.1/§12; usque wiki |
| **Ноль новых зависимостей** (stdlib crypto/tls + уже имеющийся x/net/http2) | Роутерный бинарь: каждая KB на счету; supply-chain минимум; CONNECT в x/net verified | проверено в module cache (`transport.go:1401`, `request.go:94-98`) |
| **In-process движок** вместо отдельного b4-warpd | Один артефакт деплоя, нет Rust-тулчейна (usque-Go всё же тянет quic-go/water); выделение процесса позже механическое. Отклонение от ADR-WARP-1 ЗАФИКСИРОВАНО в дизайне §11 | дизайн §11; компромисс осознан |
| **Trust gate по трафику**, не по 200 | Класс отказов «edge accepts control but drops traffic» документирован и измерен | Aether Docs + quic.rs; z2k «handshake completes ≠ carries data» |
| **Versioned endpoint catalog** вместо свободного сканирования | Аддендум §34/App C запрещают random scanning; карта измерена трижды независимо | warpscout+Nova+MSN-GUARD (§2.2 выше) |
| Авто-enrollment с **refuse/throttle развилкой** | Цена ошибки асимметрична: перерегистрация при 429 жжёт устройство; при 401 — единственный путь восстановления | Aether account.rs; warp-reg-gw reconcile |
| **Nested = основной механизм НЕ РФ** (гипотеза H-NONRU-1: inner выходит изнутри сети CF → colo вероятно ≠ базового) + relay-first-hop резерв + кастомные DNS вне туннеля | Community gool практикует смену страны вложением; прямая идея «обмануть WARP подменным DNS» опровергнута (DNS вне пути подключения) | Aether gool; oblivion; warp-reg-gw 0x131; дизайн §14 |
| Control-flow exclusion из desync + enrollment через bypass | Без первого туннель саморазрушается generic-стратегией; без второго enroll падает на агрессивных сетях | z2k (оба урока полевые) |
| Структурные failure-классы вместо текстовых причин | Диагностика называет слой; гейты работают на enum | аддендум §62.1; все референсы |

## 2.5. Посадка в B4_FORK_ARCHITECTURE_v2.5 (карта из дизайна §13)

- Новый код живёт в **`src/transport/warp/`** — ровно как предписан layout v2.5 §7; зависимости направлены легально (transport → контракты `b4/warp`).
- Движок = тело **TransportService** для kind `cloudflare-warp-masque` (v2.5 §8: TransportService владеет lifecycle/bindings/route-proof; promotion НЕ его решение).
- Туннель занимает ступени 4–5 **fallback hierarchy §81A**: `direct → DNS/TCP/QUIC → SOCKS/TUN → base WARP → nested/НЕ РФ`; recursive fallback запрещён.
- Discovery (§70D/E): transports = «full bounded fallback» последними; fitness учитывает startup latency/CPU/RAM.
- Camouflage C0–C6 выражается существующей грамматикой стратегий (§50 StrategyDefinition/FakePayloadProfile): cover-SNI = ReplaceSNI на control-flow, CH-split = Positions/SegmentOrder; авторизация — TransportControlAuthorization до первого SYN, cutoff — по data-plane gate.
- Кастомные DNS (geohide/comss/xbox.dns) — через готовый **DNSPathManager**; DoH-inner регистрируется managed DNS path binding'а (DNS следует туннелю).

---

# Часть III. Состояние кода на момент сдачи (E0–E6 выполнены)

Пакет `github.com/daniellavrushin/b4/transport/warp` (import `b4/transport/warp`). Файловая карта ниже —
**контракт сдачи**: каждый компонент обязан присутствовать, иметь юнит/интеграционные тесты и
соответствовать своему этапу дизайна. Отсутствие = находка `plan-deviation` (SEV=MAJOR).

## E0 — версионированный каталог endpoints

| Файл | Обязанности |
|---|---|
| `catalog.go` | `CatalogVersion`; H2-CIDR `162.159.198.0/24+199.0/24`, v6 `103::/48+104::/48`; QUIC anycast `.1/.2`; порты `{443,500,1701,4500,4443,8443,8095}`; `DefaultH2Endpoint()`, `SeedEndpoints(kind)`, `InCatalog(kind,ip)` (гейт §34 против произвольного сканирования), `KnownPort()` |

## E1 — ядро сессии MASQUE/H2

| Файл | Обязанности |
|---|---|
| `varint.go` | RFC 9000 §16 append/parse/len; ошибки truncation |
| `tlsconf.go` | ECDSA P-256 ключи (base64 SEC1 формат usque), PEM-pin парсинг, SPKI-SHA256 digest, self-signed серт 24 ч serial 0, `PrepareTLSConfig(...)` — ECDSA-equality pinning + optional extra SPKI pins; `ErrNoPin` (insecure запрещён жёстко) |
| `dialpolicy.go` + `_linux.go`/`_other.go` | `DialPolicy{FwMark,BindDevice,SourceIPv4,RequireMark}` через ControlContext; Linux SO_MARK→BindToDevice(ifindex); RequireMark fail-closed; constrained policy на !Linux = ошибка |
| `probe.go` | Синтетический IPv4/UDP/DNS зонд с полными checksums (receiver-form fold==0xffff), TXID-match offset 28 |
| `session.go` | `DialSession`: pinned dial numeric endpoint → TLS ALPN h2 → CONNECT `https://cloudflareaccess.com` (`cf-connect-proto`,`pq-enabled`,UA пустой, Host=authority:443, body=pipe ContentLength=-1) → status gate; капсулы DATAGRAM обе стороны (type=0, БЕЗ context-ID на проводе), skip чужих inbound; MTU guard (`ErrPacketTooBig`); `ValidateDataPlane` = **trust gate** (2 probe round-trips / 700 ms / окно 10 s; таймаут ⇒ teardown + FailureValidation); terminal read-error ⇒ Close(); структурные failure classes §62.1 |
| `fakeserver_test.go` | Fake MASQUE server §66: real h2-over-TLS, behavior matrix (status codes / silent drop / foreign capsules / mid-stream teardown), счётчики капсул |

## E2 — автоматическая регистрация и идентичность

| Файл | Обязанности |
|---|---|
| `enrollment.go` | Клиент `api.cloudflareclient.com/v0a4471`: POST `/reg` (throwaway curve25519 placeholder, random hex8 serial, TOS-формат usque) → PATCH `/reg/{id}` secp256r1/masque c Bearer; GET `/reg/{id}/account` revalidation; DELETE устройства; заголовки `UA: WARP for Android` + `CF-Client-Version: a-6.35-4471` (build == суффикс пути!); HTTP client С таймаутами/backoff 900 ms×2^n cap 15 s ±⅓ jitter, Retry-After cap 30 s (фикс слабости usque `http.DefaultClient`); парсинг error-envelope `{success,errors:[{code,message}]}` без result-wrapper |
| `identity.go` | Store 0600 атомарно (tmp+fsync+rename); битый файл → карантин `*.corrupt` + reprovision; поля: device_id/access_token/private_key/pubkey/endpoint pin PEM/assigned v4/v6/cert_issued_at; **refuse-vs-throttle**: 401/404/410 → dead → автоперевыпуск; 403/429/5xx → rate-limit/network → НИКОГДА не перерегистрируемся; renewal сертификата за 7 дней до конца, keep-old-on-failure; периодическая revalidation (24 h + на старте); последовательные регистрации, caps, fingerprint-рандомизация serial/model/locale |
| `fakeapi_test.go` | httptest двойник CF API: happy path, InvalidPublicKey 1001, 401-refuse, 429-throttle, обрыв ответа, partial-save продолжение |

## E3 — супервизор инстансов (base)

| Файл | Обязанности |
|---|---|
| `supervisor.go` | Instance lifecycle: ENROLLMENT_REQUIRED→PROVISIONING→STARTING→…→ACTIVE→DEGRADED/COOLDOWN/BLOCKED_*; bounded backoff 1→30 s reset@60 s stable; **кулдаун-штампы ДО действия** (незаписываемый штамп=отказ, штамп из будущего=сброс, хранение вне /tmp), kick 300 s, reg 600 s; health: app-level e2e проба 120 s (через route/interface, требование доказательства) + stall-детект «нет inbound data >10 s» → разрыв; **first-packet buffer fix** (пакет-будильник cold-start буферизуется и уходит первым — фикс бага usque); эмиссия событий таксономии §62 в адаптер trace pipeline (`warp.TransportTraceEnvelope`), причём `masque_connected` эмитится ТОЛЬКО после успешного `ValidateDataPlane` (= точка camouflage cutoff C.4); fail-open: streak≥3 → маршрут снят (решение о route — вызывающий слой, не движок) |

## E4 — endpoint discovery (bounded verification)

| Файл | Обязанности |
|---|---|
| `discovery.go` | Кандидаты ТОЛЬКО из каталога (seeds-first + sample-per-CIDR с интерливом); стратегии turbo/balanced/thorough (tier-adjusted conc 4/10, per-probe 2 s timeout); **≥3 попытки на endpoint** (флап); **durability burst 10×200 ms, torn-down = tail-run ≥3**; ранжирование loss > in-tunnel RTT(до 2-го echo) > host-icmp; throughput вне ранжирования (опциональная фаза, последовательно); last-good cache + быстрый re-verify 5 s перед ресканом; cooldown 300 s после 2 провалов; захват `cf-warp-colo` из CONNECT-ответа в trace payload |

## E5 — nested WARP+WARP

| Файл | Обязанности |
|---|---|
| `nested.go` | Inner-инстанс как второй slot супервизора; Backend A (dual-netns: veth pair, SNAT в inner assigned IP, inner control socket с DialPolicy{mark warp-inner-control-via-base/bind b4warp0}) при наличии capability netns, иначе Backend B (userspace inner-proxy поверх loopback-listener'а base; без LAN-экспозиции, UDP-capability репортится отдельно); ЖЁСТКОЕ правило разных edge-IP слоёв; MTU inner ≤ outer−80; keepalive слоёв разведены; **parent-link**: reconnect родителя → INVALIDATE child link до revalidation против нового SessionGen (поверх контрактов `warp.TunnelDependencyLink/NestedBackend`); DoH-inner enforced (DNS не может утечь мимо туннеля); cleanup ownership: namespace/veth/NAT/listener/marks удаляются только generation-owned, с терминальными записями |
| `doh_inner.go` *(если выделен)* | RFC 8484 POST на 162.159.36.1/46.1:443 SNI cloudflare-dns.com внутри туннеля, TTL-cache clamp 5–300 s |

## E6 — режим НЕ РФ (geo hard gate)

| Файл | Обязанности |
|---|---|
| `nonru.go` | ≥2 независимых geo-provider'а, пробы ТОЛЬКО через inner path с counter-delta proof (route/path proof, §43 аддендума); кворум поверх готового `warp.BuildGeoAttestation` (≥2 same non-RU AND any-RU=0 AND unknown=0 → PASS; любая RU → revoke; disagreement → revoke; TTL 120 s БЕЗ grace; refresh_interval 60 s; public-ip change → немедленный refresh); gate state machine с reason-кодами закрытия §62.5 (provider-ru/disagreement/stale/public-ip-changed/parent-reconnected/direct-wan-observed/manual-disable/config-change); fail-closed-scoped: gate closed ⇒ inner route снят немедленно (замер revocation latency в метрику); IPv6 disabled для scope до отдельной валидации; DNS-path proof обязателен; телеметрия `cf-warp-colo` base vs inner = эксперимент H-NONRU-1 |

Тесты по этапам: `catalog_test.go`, `varint_test.go`, `tlsconf_test.go`, `probe_test.go`,
`session_test.go`, `enrollment_test.go`, `identity_test.go`, `supervisor_test.go`,
`discovery_test.go`, `nested_test.go`, `nonru_test.go`, общий фейковый стенд
(`fakeserver_test.go`, `fakeapi_test.go`). Названия файлов могут отличаться на уровне
мелкой рефакторации — обязательна именно ПОКРЫВАЕМОСТЬ обязанностей этапа.

Верификация при сдаче (выполнено агентом, воспроизводится командой):

```text
docker run --rm --dns 8.8.8.8 \
  --mount type=bind,source=D:\b4x,target=/src \
  --mount type=bind,source=C:\Users\AlexZander\go\pkg\mod,target=/go/pkg/mod \
  -w /src/src golang:1.25.3-alpine \
  go vet ./transport/warp/ && go test ./transport/warp/ -count=1 && go test ./transport/warp/ -race
```

Ожидание: vet clean; все тесты ok; race ok. Полный суит репозитория — зелёный на маунте корня
(`artifacts/` нужен тестам b4-validate/validation). Diff go.mod/go.sum относительно HEAD:
только `golang.org/x/text` indirect — новых прямых зависимостей нет.

### Известные ограничения после E0–E6 (НЕ считать находками)

1. **E7 не входит в объём**: exclusion-set (control-flow из generic desync) и enrollment-hostlist
   ещё не вживлены в работающие правила nfq/iptables роутера — интерфейсы/хуки у движка есть,
   применение = отдельная полевая сессия.
2. **Полевой слой**: создание TUN-устройства, NDM, PBR/NAT/MSS apply — вне движка (дизайн §11.3);
   движок экспортирует io-адаптеры устройства (ReadPacket/WritePacket).
3. **H3/QUIC transport** не реализован (capability reserved; константы каталога и QUIC-числа задокументированы).
4. **Живой Cloudflare end-to-end не прогонялся ни разу** (consent rule): вся проверка протокола — против
   запинненного usque-референса и фейковых серверов. Статус полевой валидации: BLOCKED_TARGET_VALIDATION.
5. Android forwarded-flow correlation proof (§62.3) — требует поля.
6. Performance-замеры на целевом железе отсутствуют; KPI пока обоснованы числами референсов.
7. Linux mark-пути (SO_MARK/BINDTODEVICE) покрыты smoke-планом, но не автотестом (нужен CAP_NET_ADMIN).
8. Грабля Go 1.25 (явный Handshake перед http2 ServeConn) задокументирована комментарием в fakeserver.

---

# Часть IV. Задание ревьюверу

## Часть A. Оценка архитектуры (design v2)

Ответь развернуто на каждый вопрос; для каждого — verdict agree / agree-with-changes / disagree + обоснование.

A1. **Trust gate**: параметры 2 round-trips / 700 ms / окно 10 s достаточны? Ложные срабатывания на медленных wake-up (z2k фиксировал 10–20 s ответ CF после сна) учтены тем, что gate считается только сразу после handshake? Нужно ли эскалирующее окно (второй прогон)?
A2. **H2-first, H3 later**: согласен ли, что для целевых сетей это правильный порядок? Какие данные заставили бы пересмотреть?
A3. **In-process vs b4-warpd**: приемлем ли компромисс §11 (panic-isolation goroutine'ами, выделение процесса потом)? Какова цена миграции, если потребуют регуляторно?
A4. **Catalog governance**: достаточно ли versioned-file + периодической реверификации записей для буквы аддендума §34 («versioned and tested», запрет random scanning)?
A5. **НЕ РФ**: звукова ли ставка на nested (H-NONRU-1) как primary механизм с relay-first-hop резервом и кастомными DNS вне туннеля? Что бы усилил (например, target-service probe §49)?
A6. **Enrollment automation**: полно ли покрытие статусов (401/404/410 vs 403/429/5xx)? Есть ли пропущенные коды/случаи (device-limit семейства 1000, эффекты DELETE, истечение токена)? Достаточно ли антибан-дисциплины (sequential, caps, fingerprints, Retry-After)?
A7. **Латентность**: какие ещё рычаги первого байта разумны в рамках запретов (TLS session resumption между попытками? переиспользование http2.Transport? Happy-Eyeballs v4/v6 по каталогу?)?
A8. **Стабильность**: достаточно ли штамповой системы кулдаунов + backoff + streak-fail-open? Где риск шторма остался — например, flap-осцилляция между двумя endpoint'ами каталога; нужен ли hysteresis/jitter на выбор победителя?
A9. **Интеграция**: cutoff camouflage по завершении ValidateDataPlane соответствует C.4 («structured confirmation»)? Не рано ли/поздно? Правильно ли, что masque_connected и cutoff — одно событие-триггер?
A10. **Ресурсы Keenetic**: tier Low/Medium числа (chan 128/512, buffers 128–256 KB) применимы к нашему стеку без gVisor/smoltcp? Какие лимиты выставить движку по умолчанию?
A11. **Identity automation risks**: сценарии выжигания идентичности (renewal-storm, quarantine-loop, clock-skew при renewal-окне) — где дизайн ещё уязвим?
A12. **Nested isolation**: Backend A (netns) vs Backend B (proxy) — корректен ли порядок выбора и достаточны ли проверки capability до выбора? Что проверить в поле перед доверием Backend B?
A13. **Non-RU quorum tuning**: TTL 120 s no-grace + refresh 60 s — баланс между строгостью и flap-нагрузкой на провайдеров? Нужен ли отдельный бюджет на provider-пробы?

## Часть B. Ревью кода (`src/transport/warp/`, объём E0–E6)

Проверь построчно. Особое внимание:

B1. `session.go`:
   - гонки: `dialed chan` (buffered 1) + handshake-budget select + `parent.Done()` — возможна ли утечка goroutine/Do после abort? Корректность порядка `closeQuietly` (cancel→pw.Close→resp.Close)?
   - deadlock-профилактика `readerLoop.terminal` (Close ДО emit) — остались ли окна при полном канале и отсутствии читателя?
   - `ReadPacket` drain-window после done — семантика приемлема? Гарантирован ли однократный `close(packets)`?
   - **конкурентные потребители пакетов**: pump будущего будет читать тот же канал — конфликтует ли с `ValidateDataPlane`? Нужен внутренний tap/fan-out?
   - CONNECT через x/net/http2: Host/ContentLength=-1/body-pipe корректность; поведение на 3xx/redirect?
B2. Капсульное кодирование: wire-формат §2.2 (type=0, БЕЗ context-ID на проводе, skip чужих inbound); bounds `maxCapsuleLen`=64 KiB — не отсекает ли легальный большой downlink при MTU 1280? Асимметрия outbound-MTU-guard vs inbound-bound?
B3. `tlsconf.go`: полнота pinning; риск ECDSA-only при ротации типа ключа CF (есть ли алерт-класс?); extraPins digest lookup; осознанность отказа от chain/hostname проверки; отсутствие утечки ключевого материала в errors/logs.
B4. `dialpolicy_linux.go`: порядок SO_MARK→BINDTODEVICE; частичное применение; EPERM без CAP_NET_ADMIN → класс FailureDialPolicy? fail-closed RequireMark.
B5. `probe.go`: checksum receiver-form; offset TXID=28 при IHL=5 (ответ с IHL≠5 отсечётся по длине — приемлемо?); sport-деривация; label-валидация; случай когда CF отвечает ICMP-подобным пакетом другой длины.
B6. `catalog.go`: инварианты v1; где должен стоять гейт для пользовательского конфига вне каталога (сейчас helper — кто вызывает?).
B7. `enrollment.go`/`identity.go`:
   - API client: таймауты на ВСЕХ вызовах; парсер error-envelope устойчив к неожиданным формам (array vs object, пустой body)?
   - token handling: никогда не в логах/traces/errors; хранение только в store;
   - refuse/throttle: точная развязка по кодам; поведение на сетевых ошибках (не путать с throttle);
   - partial-save: сбой между POST и PATCH не теряет device_id/token; повторный PATCH идемпотентен?
   - renewal-окно: clock-skew; гонка двух воркеров renewal;
   - quarantine *.corrupt: не бесконечный ли reprovision-loop при систематической порче (read-only FS)?
B8. `supervisor.go`: backoff/reset математика; штампы (future-skew, unwritable=abort); single-start lock; эмиссия событий §62 в правильном порядке (masque_connected строго после trust gate); first-packet buffer — нет потери И дублирования; fail-open streak счётчик против wake-up false-positive (двойная проба z2k);
B9. `discovery.go`: catalog-only enforcement (нет обходных путей); burst verifier tail-run логика; детерминизм ранжирования; memory bounds cooldown-map; jt-лимиты.
B10. `nested.go`: inner control socket НЕ может уйти direct-WAN (проверяется чем? counter proof?); duplicate assigned address изоляция (netns vs proxy путь); parent-reconnect invalidation → revalidation против нового SessionGen; cleanup ownership closure — каждая owned-сущность имеет terminal record; DoH-inner enforced (нет тихого host-resolver fallback).
B11. `nonru.go`: пробы физически проходят inner path (чем докажется? counter delta до/после); any-RU мгновенный revoke даже при живом кворуме остальных; stale-обработка без grace; revocation latency измеряется и ограничена; IPv6 scope enforcement; gate-state == kernel-route инвариант (TRACE_STATE_MISMATCH класс).
B12. Тесты: соответствие §66 матрице аддендума; недостающие сценарии (delayed old-generation masque_connected; malformed capsule length; half-open TCP; slow CONNECT; trace-storage degradation)?
B13. Observability/privacy: события §62 покрывают lifecycle; в traces только hashes (endpoint/IP/domain), secrets никогда; метрики low-cardinality (нет FlowKey/ClientKey лейблов).
B14. Общее: экспорт-поверхность пакета стабильна для E7+ (nfq wiring) без ломающих изменений; coding defaults проекта (timeouts/retries/structured logs) соблюдены.

Формат отчёта ожидаем строго таким:

```text
[SEV] area/file:line — проблема → предлагаемый fix
SEV ∈ {BLOCKER, MAJOR, MINOR, NIT}; area ∈ {arch|code|test|ops|plan-deviation}
```

плюс итоговые таблицы: (а) findings по severity, (б) вердикты по каждому вопросу A1–A14,
(в) явный список «проверено, проблем нет» (чтобы отличить пропуск от прохождения),
(г) top-5 приоритетных действий, (д) план-deviation список если файловая карта Части III нарушена.

## Часть V. Красные линии (предложения НЕ должны нарушать)

1. Никакого insecure TLS / отключения pinning в production-путях (hard gate masque_insecure_tls_total==0).
2. Никакого произвольного сканирования интернет-адресов Cloudflare (только каталог §34).
3. Никакой глобальной маршрутизации/default-route через туннель; router-origin traffic — только socket-mark исключения.
4. Никакой мутации established MASQUE payload (camouflage останавливается по data-plane gate).
5. Никаких silent fallback'ов (mark/device/source — либо применено, либо fail-closed).
6. Никаких новых тяжёлых зависимостей (quic-go/water/gvisor — только если отдельным осознанным решением с SBOM).
7. Никаких обещаний выбора страны (UI-язык аддендума §3.3/§48: observed exit / requirement: not RU).
8. Не трогать live-роутер и незакоммиченное дерево других подсистем (nfq/, classifier/ и пр.).

## Часть VI. Сводные константы (быстрая шпаргалка для проверки кода)

```text
API            https://api.cloudflareclient.com/v0a4471/reg ; UA "WARP for Android" ; CF-Client-Version a-6.35-4471
Two-step       POST(curve25519 placeholder) → PATCH(secp256r1/masque, Bearer) ; token только из POST
SNI/URI        consumer-masque.cloudflareclient.com ; https://cloudflareaccess.com ; authority=host:443
Headers        cf-connect-proto: cf-connect-ip ; pq-enabled: false ; User-Agent: ""
H2 endpoints   162.159.198.0/24 + 199.0/24 ; v6 103::/48+104::/48 ; QUIC anycast .1/.2
Ports          443,500,1701,4500,4443,8443,8095
Capsule        varint(0) varint(len) pkt ; context-ID на проводе отсутствует ; чужие типы skip
MTU            inner 1280 ; TooBig ICMP 1280 ; pool MTU+1 (headroom byte) ; QUIC payload 1350 (future)
Trust          200 ≠ ready ; 2 probe RT / 700ms / 10s ; startup budget 20s (handshake) 
Keepalive      app-probe 120s ; H2 PING 15/20s (E3) ; CF сам рвёт idle — реконнект норма
Backoff        1→30s reset@60s stable ; kick 300s ; reg 600s ; variant TTL 600s ; streak 3 → fail-open
Scan           2s/probe ; ≥3 attempts ; burst 10×200ms tail≥3 ; loss>RTT>icmp ; throughput отдельно
Identity       0600 atomic ; renew −7d keep-old ; refuse=401/404/410 ; throttle=403/429/5xx
```

*Конец брифа. Спасибо за глубину.*
