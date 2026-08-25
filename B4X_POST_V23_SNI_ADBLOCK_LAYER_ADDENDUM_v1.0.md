# B4X Post-v2.3 SNI AdBlock Layer Addendum

**Версия:** `1.0`
**Дата:** `2026-08-25`
**Статус:** проект companion addendum для owner review (решение владельца 24–25.08: путь «В» гибрид выбран вместо DNS-sinkhole)
**База:** `B4_FORK_ARCHITECTURE_v2.4.md`, `B4_FORK_PATCH_PLAN.md` v2.3, действующие post-v2.3 addenda; ортогонален `B4X_POST_V23_ADAPTIVE_DNS_DETECTOR_PATH_CONTROLLER_AND_MANAGED_DNSCRYPT_BACKEND_ADDENDUM_v1.0.md` (ADNS)
**Основная платформа:** Keenetic/Entware (MIPS/ARM), NFQUEUE/TUN режимы
**Целевая capability:** `sni-adblock`
**Стадии:** `BLK-1 … BLK-8`

---

# 0. Owner summary

## 0.1. Что получает пользователь

Блокирование рекламных/трекерных доменов **на уровне роутера по SNI**, независимо от того,
как клиент резолвит DNS (системный резолвер, собственный DoH браузера, Secure DNS) — то,
что DNS-sinkhole подходы (Pi-hole/AdGuard Home/dnscrypt filtering) принципиально не умеют.

```text
LAN-клиент открывает TLS/QUIC соединение
        ↓
NFQ-конвейер B4X извлекает SNI (уже существует: sni-пакет)
        ↓
adblock.Decide(host): exact/suffix матч против загруженных списков
        ↓ match
verdict DROP (ClientHello не уходит наружу; сервер не отвечает; клиент мгновенно фейлится)
        ↓ no match
обычная обработка без изменений
```

## 0.2. Почему SNI-слой, а не DNS-sinkhole или dnscrypt-filtering

| Подход | Обходит клиентский DoH | Цена | Покрытие |
|---|---|---|---|
| Pi-hole/AGH (DNS sinkhole) | ❌ | отдельный сервис, RAM под списки, конфликт с системным DNS | все протоколы, но ломается Secure-DNS |
| dnscrypt-proxy filtering | частично | управляемый backend (ADNS-7/8) | DNS-level only |
| **SNI-layer (этот аддендум)** | ✅ | lookup один раз на флоу в уже существующей точке парса | только TLS/QUIC установления |

ADNS-аддендум §12 прямо выводит `filtering/blocklists/cloaking` dnscrypt-proxy из v1.0 —
ад-блок не вешается на managed backend. Этот слой DNS вообще не касается: **нулевое
пересечение полномочий с ADNS**, единственная точка стыковки — общая конфиг-модель.

## 0.3. Честные ограничения (не цели)

- **ECH**: при включённом на клиенте ECH настоящий SNI скрыт (наружу public-name) — флоу
  НЕ блокируется; считается в счётчике покрытия (`ech_skipped`). Детект ECH уже есть.
- **Не-TLS реклама** (чистый HTTP/1.x, UDP-SDK) не покрывается.
- **Транспортная реклама YouTube** (server-side ads) — вне любых сетевых блокировщиков.
- Никакой инспекции payload/MITM: решение принимается ТОЛЬКО по открытомy SNI ClientHello.

## 0.4. Ускорение повторных блокировок (BLK-8, IP-learn)

Повторные соединения к уже заблокированному рекламному серверу гаснут **в ядре**: первый
блок домена по SNI учитывает его dst-IP в выделенном nft/ipset-сете с drop-правилом,
стоящим ДО правила NFQUEUE-перехвата. Aging-TTL ограничивает жизнь записи, CDN-guards
защищают от ложных блоков shared-IP. Важно: сам аппаратный PPE **не может** ускорять
решение — инспекция SNI требует userspace-прохождения ClientHello, аппаратный офлоад
флоу исключает инспекцию; PPE-координация нужна лишь для сброса offload-окон при
изменениях конфигурации слоя. Детали — §BLK-8.

---

# Часть I. Нормативная архитектура

## 1. Место в конвейере

Единая точка решения — ПОСЛЕ авторитетной нормализации SNI, ДО любых desync/steer действий:

```text
TCP flow:
  ClientHello packet → classifier reassembly
    → resolveAuthoritativeTLSObservation()   [существует]
    → adblock.Decide(obs.Host)               [НОВОЕ]
        match → vc.drop() (+counter+log)     конец флоу
        ECH-only → counter ech_skipped, продолжить
        no match → обычная обработка

UDP/QUIC flow:
  Initial packet → quic.LooksLikeQUIC
    → sni.ParseQUICClientHelloSNI()          [существует]
    → adblock.Decide(host)                   [НОВОЕ, та же семантика]
```

Инвариант hot path: решение принимает ОДИН раз на флоу (на ClientHello/Initial),
никаких пер-пакетных lookup'ов; стоимость = O(len(host)) suffix-lookup.

## 2. Границы объектов

```text
AdBlockConfig ≠ BlocklistFile ≠ SuffixSet ≠ MatchDecision ≠ MetricsSnapshot
≠ LearnedIPEntry ≠ NftSetRule ≠ KernelDropVerdict
```

Списки (файлы) и активный матчер разделены: обновление файла → атомарная перестройка
матчера → swap под RLock. Частичный/битый список НИКОГДА не становится активным.

## 3. Запрещённые shortcuts

```text
ошибка загрузки списка → блокировать весь трафик          (запрещено; слой = disabled + counter)
пустой список → enabled-слой без матчей                    (запрещено; enabled требует ≥1 источника)
regex на MIPS в default-политике                           (только exact+suffix; regex — opt-in)
матч на каждом пакете флоу                                 (запрещено; только ClientHello/Initial)
блокировка без ECH-учёта в статистике                      (запрещено; ech_skipped обязателен)
URL-подписка без атомарной замены и лимита размера         (запрещено)
учить private/reserved/CDN-коллидирующий IP                (запрещено; BLK-8 guards)
применять табличные изменения на пакетном пути             (запрещено; enqueue-only worker)
ошибка материализации таблиц ⇒ block-all                   (запрещено; fail-open, SNI-слой живёт)
```

## 4. Отношение к существующим подсистемам (ownership)

| Subsystem | Владеет | Не владеет |
|---|---|---|
| `src/sni` | парсинг SNI/metadata/ECH | политикой блокирования |
| nfq Worker | вердиктами, порядком хуков | содержимым списков |
| adblock (новый) | конфиг, загрузчики, матчер, счётчики | вердиктами чужих слоёв, DNS |
| config | секцию `adblock` | runtime-матчером |
| Monitoring/Metrics | экспорт счётчиков | решениями |

Запрещённые зависимости: `nfq hot path → файловый IO`; `adblock → resolver catalog/DNS`;
`adblock → TransactionalRuntime` (слой пассивный, транзакций не требует).

# Часть II. Конфигурационная модель

## 5. Секция конфигурации (b4.json)

```json
"adblock": {
  "enabled": false,
  "action": "drop",
  "lists": ["/opt/etc/b4/adblock/oisd-small.domains"],
  "allowlist": ["/opt/etc/b4/adblock/allow.domains"],
  "refresh_hours": 24,
  "log_matches": true
}
```

- `enabled=true` без валидных источников ⇒ слой остаётся disabled, эмитится
  `adblock_list_missing_total`.
- `allowlist` имеет приоритет над blocklist (первый матч wins: allow → пропустить).
- `action`: `drop` (v1.0); `rst` зарезервирован (BLK-6, опционально).

## 6. Формат списков

Совместим с распространёнными: строки-домены, `#комментарии`, hosts-строки
(`0.0.0.0 domain`), `@@`-исключения игнорируются с предупреждением. Загрузчик строит
exact-map + suffix-set; дубликаты схлопываются; лимит записей на список конфигурируем
(дефолт 300k, защита RAM на MIPS).

Обновление по URL (BLK-5, опционально): download → size-limit → parse-validate →
atomic rename; сеть через существующий mark/bypass путь; никогда не блокирует hot path.

# Часть III. Data model и observability

## 7. Решение

```go
type Decision uint8
const (DecisionPass Decision = iota; DecisionBlock)

func Decide(host string) (Decision, string /*listName*/, bool /*ech*/)
```

Чистая функция над RLock-снапшотом матчеров; тестируется таблицей без сети.

## 8. Метрики

```text
b4_adblock_decisions_total{result=pass|block}
b4_adblock_blocked_total{list}
b4_adblock_ech_skipped_total
b4_adblock_list_state{list,state}      # loaded|missing|invalid|disabled
b4_adblock_reload_total{list,result}
b4_adblock_allowlisted_total
b4_adblock_fetch_ok_total
b4_adblock_fetch_fail_total
b4_adblock_ip_learn_total
b4_adblock_ip_learn_cdn_skip_total
b4_adblock_ip_learn_private_skip_total
b4_adblock_ip_learn_dropped_total      # переполнение очереди обучения
b4_adblock_ip_active                   # gauge активных выученных записей
b4_adblock_table_apply_fail_total
```

Лог совпадений: существующий `LogConnection` c protocol="blocked"; qname/SNI в логах
без ключевого материала (правило privacy действует).

## 9. Trace-события

```text
ADBLOCK_LIST_LOADED / ADBLOCK_LIST_INVALID / ADBLOCK_FLOW_BLOCKED / ADBLOCK_ECH_SKIPPED
```

В существующий trace-канал, префикс `adblock_`.

# Часть IV. Implementation stages

## BLK-1 — Config + loader
`src/config/adblock.go` (типы+дефолты+валидация), поле в Config; `src/adblock/loader.go`
(parse domains/hosts, exact+suffix построение, atomic swap, лимиты). Верификация: unit
таблица форматов, битый файл → disabled+counter, reload идемпотентен.

## BLK-2 — Decide + TCP hook
`src/adblock/decide.go`; хук после `resolveAuthoritativeTLSObservation` в TCP-ветке nfq;
ECH-only флоу — skip+counter. Верификация: синтетический ClientHello → drop verdict;
negative-host → pass; ECH-only → pass+ech_skipped.

## BLK-3 — QUIC hook
Хук после `ParseQUICClientHelloSNI` в UDP-ветке. Верификация: синтетический QUIC Initial
→ drop; TCP-fallback поведение клиента не регрессирует.

## BLK-4 — Allowlist + метрики + лог
Приоритет allowlist; экспорт счётчиков; LogConnection-интеграция. Верификация: allow
побеждает block; метрики отражают решения.

## BLK-5 — Remote lists (опционально)
URL-подписки, refresh_hours, atomic replace, size-limit. Верификация: обрыв загрузки
сохраняет предыдущий активный матчер.

## BLK-6 — RST action (РЕАЛИЗОВАНО 26.08, bd b4x-3s3; локально до команды владельца)

Быстрый фейл клиента вместо тихого drop: при `action:"rst"` сработавший TCP-хук BLK-2
ДОПОЛНИТЕЛЬНО к дропу ClientHello отправляет LAN-клиенту forged TCP RST, подделанный от
имени реального сервера (`src/nfq/rst_client.go`, переиспользование готовых примитивов
ip-block пути).

### Семантика

| Свойство | Значение |
|---|---|
| Транспорт | **только TCP**; QUIC (UDP) не имеет reset-примитива — всегда тихий timeout-drop |
| 5-tuple | зеркалируется: src/dst и порты меняются местами относительно перехваченного пакета |
| SEQ | = текущий ACK клиента из его же ClientHello (`seq=clientACK`) — значение, которое сервер вправе использовать; установленный стек принимает такой RST мгновенно |
| ACK/флаги | ACK=0, flags ровно RST(0x04), data-offset 5 |
| Чексуммы | IPv4+TCP через существующие `sock.FixIPv4Checksum/FixTCPChecksum(/V6)` |
| Отправка | тот же client-sender путь, что и ip-block RST; hot path получает только вызов билдера+Send на уже заблокированном флоу |
| Лог метадата | `"adblock"` при drop, `"adblock-rst"` при rst; QUIC всегда `"adblock-quic"` |

Неверный SEQ клиент молча игнорирует ⇒ байт-тесты обязательны и существуют
(`rst_client_test.go`: зеркальность tuple, seq==clientACK, flags, чексуммы через
пересчёт на копии).

### Конфигурация / API

```json
"adblock": { "enabled": true, "action": "rst" }
```

`PUT /api/adblock/config {"action":"rst"}` теперь 200 и персистится; валидация строго
`drop|rst`. Дефолт — `drop` (поведение по умолчанию слоя не изменилось).

### Ограничения

- Bare-SYN ретрай клиента (ACK=0) даёт seq=0 — такой RST стек может проигнорировать;
  последующие ретраи уже с ACK и гасятся нормально.
- IPv6 поддержан симметрично (v6-билдер + v6-sender); TUN-режим не затронут (слой живёт
  в NFQ-конвейере).
- ECH-only флоу не блокируются вовсе (BLK-2 семантика), RST на них не действует.

## BLK-7 — Выполнено вместе с BLK-5: дефолтные подписки

| Источник | URL | Формат | Провенанс |
|---|---|---|---|
| AdGuard DNS filter | `https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt` | ABP network rules | компиляция AdGuard Base+Social+Tracking+Mobile+EasyList/EasyPrivacy; ежедневная пересборка; содержит региональные ad-сети |
| AdGuard Russian filter | `https://filters.adtidy.org/extension/chromium/filters/1.txt` | ABP | RU-специфичные рекламные/трекерные домены |
| StevenBlack unified hosts | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` | hosts | классический независимый baseline |

Все три верифицированы живым fetch на момент включения (25.08). Форматы покрыты
парсером после добавления ABP-tolerance (`||domain^`, `.domain^`, `$modifiers`
отбрасываются консервативно; regex/wildcard правила пропускаются).
Порядок загрузки не влияет на результат: merge в единый exact/suffix матчер;
allowlist всегда сильнее.

## BLK-8 — IP-learn → nft sets с aging (bd b4x-8jz; РЕАЛИЗОВАНО 26.08, локально, ждёт слова владельца на коммит)

Kernel-level ускорение повторных блокировок. Первый блок домена по SNI учитывает его
dst-IP в выделенный сет `b4_adblock_learn`(+6) с drop-правилом, установленным **до** правила
NFQUEUE-перехвата; последующие соединения к этому IP (ретраи клиента, новые процессы)
дропаются в ядре без userspace.

### Карта файлов (факт 26.08)

| Файл | Содержимое |
|---|---|
| `src/config/adblock.go` | `ip_learn` / `ip_learn_ttl_sec` / `ip_learn_max_entries` + дефолты + имена сетов |
| `src/adblock/iplearn.go` | стор, worker, guards, aging, cap-вытеснение, персист (atomic 0600), метрики |
| `src/nfq/adblock_learn.go` | hot-path хенд-офф: CDN-guard + bounded-enqueue (метод Worker) |
| `src/tables/adblock_learn.go` | материализация: сеты+цепочка+jump+drop (iptables/ipset и nft), аплаер |
| `src/main.go` | биндинг аплаера (`cfgPtr.Load`) и refresh-func после создания пула |

### Механика (факт)

```text
SNI block (domain, dstIP)  [BLK-2/3]
        ↓ CDN-guard на месте хука (matcher.MatchIPWithSource → skip+counter)
        ↓ EnqueueLearn: ОДИН аллок ip.String() в bounded chan(256); full ⇒ dropped_total++
worker-goroutine:
  parse → private/reserved-guard → dedup / TTL-extend / cap-evict(oldest-expiry)
        → LearnApplier.AddIPs (батч: ipset restore / nft add element {… timeout})
aging sweeper (60s): expire → RemoveIPs; EnsureRules + reassert живых (z2k#6);
                     persist-if-dirty
таблицы пересобраны извне (TablesRefreshFunc и т.п.) ⇒ tail AddRules переустанавливает
правила и дёргает мгновенный reassert (окно без kernel-дропов ~мс)
```

Порядок правил гарантирован конструкцией: drop живёт в **отдельной цепочке**
(`B4_ADBLOCK` / `b4_adblock_chain`), в capture-цепочку встаёт один jump **головой**
(iptables `-I B4` применяется последним в манифесте ⇒ верх; nft `insert rule` = prepend).
Юнит-гейт: manifest-index тест (jump после всех NFQUEUE-правил) + replay-тест nft-плана
(insert ⇒ позиция 0). Дропы скоупятся по настроенным service-dport'ам (tcp+udp) — паритет
с тем, что SNI-слой вообще мог увидеть.

### Guards (консервативные, обязательные) — все реализованы

| Guard | Правило | Где |
|---|---|---|
| CDN-коллизии | не учить IP, уже матчащийся сервисным сетам (`matcher.MatchIPWithSource`) | nfq-хук |
| Диапазоны | unspecified/loopback/private/link-local/multicast/broadcast (v4+v6) | worker |
| Allowlist | структурно (Decide отдаёт allow→pass) + purge при позднем allowlist'е | Decide + purge |
| Кап | `ip_learn_max_entries`, вытеснение по старейшему ExpiresAt | worker |
| Hot path | только bounded-enqueue; таблицы/валидация вне пакетного пути | дизайн |

### Конфигурация

```json
"adblock": {
  "ip_learn": false,
  "ip_learn_ttl_sec": 21600,
  "ip_learn_max_entries": 4096
}
```

Выключение ip_learn полностью снимает слой: stop worker → flush сета → TearDown правил
(jump/цепочка/сеты) → удаление персист-файла. Персист — `<cache_dir>/iplearn.json`
(atomic tmp+fsync+rename, 0600), восстановление при старте фильтрует протухшие записи;
корректность НИКОГДА не зависит от файла (z2k#6).

### Метрики

Экспорт — `adblock.Stats` → GET `/api/adblock` (`stats.*`): `ip_learn_total`,
`ip_learn_cdn_skip_total`, `ip_learn_private_skip_total`, `ip_learn_dropped_total`,
`ip_active_gauge`, `table_apply_fail_total`. Prometheus-неймспейс `b4_adblock_*` из §8 —
следующий шаг (не в этом периметре).

### Координация PPE-offload

Переход disabled→enabled ip_learn вызывает существующий механизм полного обновления таблиц
(тот же closure, что `SetTablesRefreshFunc`) — на живых l5ppe-системах это точка сброса
offload-окон. Биндинг выполняется ПОСЛЕ создания пула: включённый при загрузке ip_learn не
может перестроить таблицы до готовности NFQUEUE-листенеров (boot-порядок гарантирует tail
AddRules). Инспекция SNI требует userspace-прохождения ClientHello — аппаратный офлоад
флоу исключает инспекцию; глобальный `offload_policy=exclude` запрещён (FORBIDDEN).

### Верификация (гейты 26.08, docker golang:1.25.3-alpine, скелет repo-root)

gofmt чисто (файлы слоя); go build ./... OK; go vet {adblock,tables,nfq,config} чисто;
go test ./... -count=1 = 60 ok / 0 FAIL слоя (единственный FAIL — чужой флап
transport/wg TestRaceEndpointsStaggerOrder, A/B: проходит при повторе); CGO race
{adblock,nfq,tables} ok. Тесты слоя: TTL-aging, повтор-продление, кап-вытеснение,
reserved-диапазоны ×11, переполнение очереди, unlearn по удалению списка и по allowlist,
lifecycle disable (flush+persist-remove), персист round-trip 0600, CDN-guard хука,
порядок правил (iptables manifest + nft plan replay).

# Часть V. Red lines

1. Слой НЕ трогает DNS-трафик и не зависит от ADNS-компонентов (§12 ADNS соблюдён).
2. Fail-open к disabled при любой ошибке списков; никогда не блокировать по умолчанию.
3. Только client-side SNI из ClientHello/QUIC-Initial; никакой payload-инспекции.
4. Hot path: одно решение на флоу; O(len(host)); без аллокаций на пакеты без SNI.
5. Списки: локальные файлы владельца ИЛИ подписки; при `enabled=true` с пустым
   `lists` активируются встроенные дефолтные подписки (решение владельца 25.08,
   см. §BLK-7) — всегда видимые в effective-config, переопределяемые явным списком.
   Никаких скрытых «рекомендованных» списков вне конфигурации.
6. Базовые ограничения этапа: коммиты по явной просьбе, роутер не трогаем,
   live-тесты только с consent.
7. IP-learn никогда не применяется к private/reserved/link-local диапазонам, к IP,
   коллидирующим с сервисными сетами, и к allowlist-доменам; кап записей обязателен.
8. Ошибка материализации таблиц переводит только IP-learn в disabled (fail-open);
   SNI-слой продолжает работать через NFQ-точку.
9. Изменения слоя (enable/списки/ip_learn) требуют сброса существующих offload-окон
   флоу для гарантии инспекции новых установлений.
6. Все ограничения базового этапа действуют: коммиты по явной просьбе, роутер не трогаем,
   live-тесты только с consent.

# Часть VI. Связь с ADNS-аддендумом

| Аспект | ADNS | этот слой |
|---|---|---|
| Цель | здоровье/анти-цензура DNS-пути | контентная фильтрация TLS/QUIC |
| DNS-трафик | да (основной объект) | нет (не касается) |
| Клиентский DoH | источник проблемы для sinkhole'ов | прозрачен (SNI виден всегда) |
| Managed backend | опциональный провайдер | не используется |
| Конфиг | `dns.mode` | `adblock.enabled` |

Совместная эксплуатация легальна без дополнительных контрактов: разные пакеты, разные
объекты конфигурации, разные точки конвейера.
