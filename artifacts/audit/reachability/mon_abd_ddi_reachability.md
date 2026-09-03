# Reachability: MON v1.0 / ABD v1.2 / DDI+TGB (monitor, detector, discovery+telegram bridge)

Аудит 31.07.2026 (фаза независимой верификации; факты перепроверены главным агентом 31.07 вечер).
Критерий: цепочка production root → импорт → runtime owner → implementation → observable side effect → cleanup.

## Итог

- **MON: PARTIAL** — legacy-путь (watchdog/applyBatchResults) REACHABLE и АКТИВЕН; strangler-замена (/api/monitor/v1, legacy_watchdog_*, shadow-режим) — FAIL.
- **ABD: PARTIAL** — detector suite API reachable; BlockingProfile — расхождение схемы.
- **DDI/TGB: FAIL (severity HIGH)** — Telegram bridge работает по legacy-пути (молчаливый drop, FB-04); новые типы (FirstDataMachine/PendingHandshakeManager/BridgeOutcome/RoutePlan) — только тесты; detector prior игнорируется (FB-05).

## MON v1.0 — PARTIAL

### REACHABLE и АКТИВЕН (legacy-путь, подтверждено цепочкой)

| Звено | Файл (проверено) |
|-------|------------------|
| watchdog.New | `src/main.go:392` |
| wd.Start() | `src/main.go:422` |
| run()/tick() | `src/watchdog/watchdog_tick.go:10` (run), `:32` (tick), `:109-117` (условие `System.Checker.Watchdog.Enabled && len(Domains)>0`) |
| applyBatchResults | `src/watchdog/watchdog_heal.go:111` |
| applyGroup (мутация cfg.Sets) | `src/watchdog/applier.go:44` |
| Сохранение | saveFunc: SaveToFile + pool.UpdateConfig + SyncConfig |

### FAIL (severity HIGH) — strangler-замена MON не подключена

| Механизм | Статус |
|----------|--------|
| shadow-режим монитора рядом с watchdog | ABSENT в production (src/monitor — пакет достижим только транзитивно через типы; конструкторы не исполняются) |
| /api/monitor/v1 | ABSENT (в RegisterEndpoints нет; проверено common.go:163-194) |
| ключи `legacy_watchdog_*` | ABSENT (grep = 0) |
| cutover по флагу | ABSENT |

## ABD v1.2 — PARTIAL

| Механизм | Статус |
|----------|--------|
| Detector suite (API) | REACHABLE: POST /api/discovery/start → StartSuite → Queue.IsDiscovery (см. Stage 21); watchdog_heal.go:29 (StartSuite Automatic) |
| BlockingProfile | PARTIAL/FAIL: схема расходится — SchemaVersion 1 в коде vs 2 в норме (ABD); делегирование компиляции raw evidence→BlockingProfile не зафиксировано (FB-14 п.1) |
| Guided strategy search / адаптивная матрица | FAIL — см. Stage 23 (RunAdaptiveMatrix только тесты) |

## DDI/TGB — FAIL (severity HIGH)

| Механизм | Файл (проверено) | Статус |
|----------|------------------|--------|
| TGB Handle (Telegram bridge) | `src/mtproto/transparent.go:97-104` (zero-byte → `return true, nil`), `:157` (dial fail → `return true, nil`) — fixed 5s deadline, legacy bool | FAIL — молчаливый destructive drop без fail-open; НЕ соответствует норме DDI/TGB («never silently claimed», парковка в PendingHandshakeManager) — задача FB-04 |
| FirstDataMachine / PendingHandshakeManager / BridgeOutcome / RoutePlan | новые типы (src/mtproto/) | FAIL — вызовы только тестами; в production-пути legacy-логика |
| detector prior в hint-планировании | `src/discovery/hint_planner.go:56` — `_ = prior` (подтверждено повторно) | FAIL — DDI-6/DDI-7/ABD-11 не исполняются — задача FB-05 |
| ABD-11 release gate | `src/diagnostics/` | PARTIAL — gate существует, но опирается на неактивную матрицу (Stage 23) |

## Ложные readiness

- `docs/reports/mon-*.md`, `abd-*.md`, `ddi-*.md`, `tgb-*.md`, `ddi-tgb-companion-release-register.md` — отчёты фаз спринтов; утверждения об интеграции в них не содержат «wired в production»-заявлений, не требующих пересмотра. Конкретных ложных readiness НЕ выявлено.

## Связь с fix backlog

- MON: **FB-07** (strangler-замена watchdog), частично FB-02.
- ABD: **FB-05** (prior), FB-14 п.1 (ownership BlockingProfile).
- DDI/TGB: **FB-04** (молчаливый drop), **FB-05** (prior).
- Новых задач не требуется (всё покрыто существующими FB-04/05/07/14).
