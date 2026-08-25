# B4X Post-v2.3 SNI AdBlock Layer Addendum

**Версия:** `1.0`
**Дата:** `2026-08-25`
**Статус:** проект companion addendum для owner review (решение владельца 24–25.08: путь «В» гибрид выбран вместо DNS-sinkhole)
**База:** `B4_FORK_ARCHITECTURE_v2.4.md`, `B4_FORK_PATCH_PLAN.md` v2.3, действующие post-v2.3 addenda; ортогонален `B4X_POST_V23_ADAPTIVE_DNS_DETECTOR_PATH_CONTROLLER_AND_MANAGED_DNSCRYPT_BACKEND_ADDENDUM_v1.0.md` (ADNS)
**Основная платформа:** Keenetic/Entware (MIPS/ARM), NFQUEUE/TUN режимы
**Целевая capability:** `sni-adblock`
**Стадии:** `BLK-1 … BLK-6`

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

## BLK-6 — RST action (опционально, отдельным owner decision)
Быстрый фейл клиента вместо таймаута. Только после полевой проверки BLK-1..4.

# Часть V. Red lines

1. Слой НЕ трогает DNS-трафик и не зависит от ADNS-компонентов (§12 ADNS соблюдён).
2. Fail-open к disabled при любой ошибке списков; никогда не блокировать по умолчанию.
3. Только client-side SNI из ClientHello/QUIC-Initial; никакой payload-инспекции.
4. Hot path: одно решение на флоу; O(len(host)); без аллокаций на пакеты без SNI.
5. Списки — только локальные файлы владельца или подписки с явным enable; никаких
   встроенных «рекомендованных» списков в бинаре.
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
