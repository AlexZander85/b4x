# B4X Audit Verdict

**Репозиторий:** AlexZander85/b4x, ветка `agent/classifier-v2.3-capture-envelope`
**База:** B4 1.73.0, commit `7160ee8f066bbbed1c713b4d0114db4e8acbc882`; рабочее дерево = HEAD `49a73e177601f33f067fbdc8ed91317fe51eef10` + 33 untracked
**Дата аудита:** 31.07.2026
**Объём:** 14 нормативных документов (PATCH_PLAN, ARCHITECTURE v2.4, 11 addenda, b4-1.73-flow-path.md), 472+ атомарных требований, 783 Go-файла, Linux-верификация в Docker (golang:1.25-alpine / golang:1.25-bookworm), прогоны `go build` / `go vet` / `go test` / `go test -race` выполнены

---

## ВЕРДИКТ: **B4X_NOT_COMPLIANT**

Репозиторий **НЕ соответствует** нормативной документации ветки `agent/classifier-v2.3-capture-envelope`. Аудит завершён полностью; `coverage_complete=true` для всех 14 документов; блокирующие несоответствия подтверждены исполненными командами и чтением исходного кода.

## Ключевые блокирующие несоответствия

### B4X-AUDIT-001 (BLOCKER) — Продуктовый слой документов не исполняется в бинарe
Пакеты `warp`, `serviceprofile`, `fieldtest`, `silentpath` (суммарно ~77 файлов, реализующих WARP v1.2, SP v1.6, FT v1.5, SPF v1.0) имеют **0 импортеров/вызовов** во всём `src` (grep по `warp.`/`serviceprofile.`/`fieldtest.`/`silentpath.` = 0 совпадений; `go list -deps ./` от main их не включает; в `http/handler` и `main.go` — 0 упоминаний; API-эндпоинтов нет). Требования этих 4 документов: WARP 0/44 IMPLEMENTED, SP 9/22, FT 8/14, SPF 26/74 — и ни одно из них не исполняется в production.

### B4X-AUDIT-002 (BLOCKER) — Hard gates не активны
Из 160 счётчиков-гейтов, требуемых документами (WARP §72/73/73A/73B — 58, SPF — 22, FT §26 — 82), в production активен 1: `unrelated_control_action_total` (CSI-18, `crossservice/validation.go:265,392`). `warp_trace_secret_leak_total`, P0 dropped counters, SPF hard gates — отсутствуют вовсе. `WARP_CAUSAL_TRACE_READY` — только константа (`fieldtest/cleanup.go:36`), `BLOCKED_TARGET_VALIDATION` — только константы (`validation/verdict.go:9`, `fieldtest/promotion.go:7`). IV meta-suite (`validation/meta.go`, `fieldtest/hard_gates.go`) реализован, но никем не вызывается.

### B4X-AUDIT-003 (BLOCKER) — Тесты capture/ppe не компилируются
`capture/ppe/product_bundle_test.go:100-101`: `config.Config` (значение) передаётся туда, где требуется `*config.Config`. `go test ./...` (linux/amd64): FAIL `capture/ppe [build failed]` — единственный FAIL из 42 пакетов (подтверждено и в `-race` прогоне). Пакет PPE активен в бинаре, но его 52 теста не исполняются.

### B4X-AUDIT-004 (BLOCKER) — MON v1.0 не реализован
Strangler-замена Watchdog (shadow/cutover, 6 фаз) не начата: `watchdog/applier.go:18` — legacy `applyBatchResults` активен, direct apply работает; `/api/monitor/v1` отсутствует; MON-1..12: 0/32 IMPLEMENTED. Safety-инвариант документов держится только на отсутствии монитора.

### B4X-AUDIT-005 (BLOCKER) — #277 и #278 (Telegram bridge / DDI) живы
`mtproto/transparent.go:97-104`: 5s deadline → zero-byte → `return true, nil` (молчаливый destructive drop, handled=true, без fail-open); `:157` dial fail → тоже `true, nil`. Норма DDI/TGB требует парковку в PendingHandshakeManager и observable классификацию. `discovery/hint_planner.go:56`: `_ = prior` — detector prior игнорируется (#278).

### B4X-AUDIT-006 (MAJOR) — CI не защищает регрессии
`.github/workflows/release.yml:90-92`: `go test ./...` без `-race` и без `go vet`. Сломанные тесты capture/ppe ломают release-CI, но не vet-проверки (их нет). goleak — в 3 файлах. Fuzz есть (25), но не в CI.

### B4X-AUDIT-007 (MAJOR) — Расхождения кода с нормами в живых подсистемах
- CSI-15: GSOPassToken без Authorization/EffectivePolicy/CandidateDisposition (`nfq/gso_token.go:25-36`) — расхождение CSI §18 vs RST/GSO H4.
- Stage 16: мёртвые константы `tcpHoldAbortFIN/RST` — нет явного abort hold на FIN/RST (пакет висит до таймаута 750 мс).
- Stage 27: `m.mu` удерживается всю canary-транзакцию (до `MaxCanaryDuration=1h`) — блокирует Prepare/Rollback/AbortPending/Close.
- Stage 4: `CaptureEnvelopeEnabled` декоративный — на обработку пакетов не влияет.
- PPE self-test не стартует автоматически при `mode: startup-and-change` (`reconciler.go:122`).
- WARP-пакет: geo TTL 300s vs 120s (`geo.go:52`); `InnerRevokedBeforeParent` не проверяется (`isolation.go:16`).

### B4X-AUDIT-008 (MAJOR) — Меж-документные противоречия
13 подтверждённых + 1 снятое как ложное (DDI-4 ownership; ADR-WARP 1..7 — «changelog 1..6» снято: changelog-секции в WARP v1.2 нет; GSOPassToken два определения; WARP_CAUSAL_TRACE_READY в 2 документах неидентичен; acceptance criteria 86 vs 77; §23.1 registry устарел; цепочки ссылаются на SP v1.5/ARCH v2.3; порог 16 KiB; gso_mode=classify gate не формализован; zero-byte close: idle_preconnect_expired vs never silently claimed и др.) — см. findings_draft.md секция C.

### B4X-AUDIT-009 (MINOR) — Сборка и окружение
- Свежий клон не собирается: `ui/dist` и `defaults.json` gitignored; Makefile `build` не вызывает `build-ui`; требуется `go run tools/gendefaults.go` (Linux) + `pnpm build`.
- PATCH_PLAN и WARP v1.2 закодированы в cp866 (не UTF-8).
- packageManager пинит pnpm@10.29.2, установлен 9.15.9; Node 22.11 < требуемого vite 22.12.

## Что реализовано хорошо (сохранённая ценность)
- Core Fix (уровень A): 15/16 stages IMPLEMENTED+wired — capture envelope, clean SYN инвариант (`nfq/tcp_gate.go`), TCP FSM, HostHintStore, DNS→first-flow, QUIC handoff, DomainOnly v2, observe-only reassembly с бюджетами, ActionTokenStore, fail-open executor, redaction.
- Живые подсистемы: PPE 38/49, RST/GSO 27/34, CSI 25/32 — включая ADR-CSI-1 (candidate≠authorization, `classifier/authorization.go`), запрет mark 0x08000000 (`packetmark/marks.go`).
- Тестовый корпус: 268 файлов / 1077 функций / 25 fuzz / 28 benchmark; 41/42 пакетов зелёные, включая `-race`.
- Runtimecontrol: last-good/cooldown/rollback реализованы (кроме блокировки мьютекса).

## Ограничения аудита
- `B4_FORK_ARCHITECTURE_v2.4.md` (40 записей) и `B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md` (39 записей) индексированы, но детальный постатейный аудит не проводился; их ключевые требования покрыты через аудиты hard gates, test quality, PATCH_PLAN stages (в т.ч. §42-45 hold, §132-136 WARP, IV meta-suite, критерии 1-86). Требования ARCH/IV в каталоге отмечены как BLOCKED (требуют постатейной сверки) либо покрыты косвенно — см. B4X_BLOCKED_VALIDATIONS.json.
- Windows-хост: полная сборка/тесты выполнялись только для linux/amd64 (целевая платформа роутера); `log` пакет не компилируется на Windows (syslog/Dup2).
- Не git-репозиторий: PR-декомпозиция (PATCH_PLAN §1487-1543) не проверяема; расхождения с base commit подтверждены через normalized blob-сравнение.

**Итоговая рекомендация:** к релизу ветка не готова. Приоритетный fix backlog: (1) интеграция или явная деактивация warp/serviceprofile/fieldtest/silentpath с обновлением документов; (2) активация hard-gate счётчиков и meta-suite; (3) починка тестов capture/ppe; (4) CI с -race + vet; (5) #277/#278; (6) разблокировка мьютекса runtimecontrol и abort hold FIN/RST. Полный перечень — B4X_FIX_BACKLOG.md.

**Артефакты:** req_index_part1..3.md, wiring_analysis.md, patch_plan_audit.md, patch_plan_quality.md, hard_gates_audit.md, test_quality_audit.md, warp_audit.md, mon_abd_ddi_audit.md, csi_ppe_rstgso_audit.md, sp_ft_spf_audit.md, findings_draft.md, logs/go-build.log, logs/go-vet.log, logs/go-test.log.
