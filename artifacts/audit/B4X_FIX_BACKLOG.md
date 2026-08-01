# B4X Fix Backlog

Дата: 31.07.2026. Порядок — по приоритету. Зависимости: P0 задачи независимы; P1 после P0.

## P0 (блокируют релиз)

| ID | Задача | Finding | Файлы | Сложность |
|---|---|---|---|---|
| FB-01 | Починить компиляцию тестов capture/ppe: `cfg := config.NewConfig()` → `cfg := &config.NewConfig()` (или `config.NewDefault()` по сигнатуре), `service.ApplyConfig(ctx, &cfg)` | B4X-AUDIT-003 | src/capture/ppe/product_bundle_test.go:100-101 | S |
| FB-02 | Принять решение по 4 мёртвым пакетам: (а) интегрировать (IPC/event bus, hooks в nfq/http/config, hard-gate счётчики) или (б) явно деактивировать и переиздать документы с пометкой «не в этой ветке» | B4X-AUDIT-001 | src/warp, src/serviceprofile, src/fieldtest, src/silentpath + 4 документа | XL |
| FB-03 | Реализовать hard-gate счётчики и вердикты: WARP (58 счётчиков §72/73/73A/73B: warp_trace_secret_leak_total, P0 dropped...), SPF (22), FT §26 (82); подключить meta-suite (validation/meta.go, fieldtest/hard_gates.go) к CI/валидации; вердикты WARP_CAUSAL_TRACE_READY, BLOCKED_TARGET_VALIDATION — в реальные проверки | B4X-AUDIT-002 | src/warp/*, src/silentpath/*, src/fieldtest/*, src/validation/*, src/observability/* | XL |
| FB-04 | #277: mtproto/transparent.go — zero-byte timeout и dial-fail не должны давать `handled=true`/silent drop; парковка в PendingHandshakeManager, observable классификация, fail-open | B4X-AUDIT-005 | src/mtproto/transparent.go:97-104,157 | M |
| FB-05 | #278: detector prior в discovery/hint_planner.go:56 (`_ = prior`) — использовать или явно задокументировать деактивацию | B4X-AUDIT-005 | src/discovery/hint_planner.go | M |

## P1

| ID | Задача | Finding | Файлы | Сложность |
|---|---|---|---|---|
| FB-06 | CI: добавить `go vet ./...` и `go test -race ./...` в release.yml; goleak-проверки для конкурентных пакетов | B4X-AUDIT-006 | .github/workflows/release.yml | S |
| FB-07 | MON v1.0: реализовать shadow/cutover strangler (6 фаз), /api/monitor/v1, legacy_watchdog_* ключи, удалить applyBatchResults | B4X-AUDIT-004 | src/monitor, src/watchdog, src/http/handler | XL |
| FB-08 | Разблокировать мьютекс runtimecontrol Apply: не держать m.mu на весь canary (до 1h); staged-подход или отдельный canary-lock | B4X-AUDIT-007 | src/runtimecontrol/rollout_manager_apply.go:33-34 | M |
| FB-09 | Abort hold на FIN/RST: реализовать tcpHoldAbortFIN/RST пути в nfq/handler.go | B4X-AUDIT-007 | src/nfq/tcp_hold_config.go:17-18, handler.go | M |
| FB-10 | CSI-15: GSOPassToken — добавить Authorization/EffectivePolicy/CandidateDisposition (согласовать RST/GSO H4 vs CSI §18) | B4X-AUDIT-007 | src/nfq/gso_token.go:25-36 | M |
| FB-11 | CaptureEnvelope: подключить флаг к фактической обработке (first-N/SYN-ACK/FIN/RST/QUIC контур) или удалить | B4X-AUDIT-007 | src/config/types.go:106, src/capture, src/tables/iptables.go:361-362 | M |
| FB-12 | PPE self-test: авто-старт при mode=startup-and-change (не только через HTTP) | B4X-AUDIT-007 | src/capture/ppe/reconciler.go:122 | M |
| FB-13 | fieldtest/session.go:59 — исправить коллизию json-тегов (RouteGen, SessionGen → свои теги) | A2 | src/fieldtest/session.go | S |
| FB-14 | Устранить 14 меж-документных противоречий (переиздать документы): DDI-4 ownership, ADR-WARP 1..7, GSOPassToken, WARP_CAUSAL_TRACE_READY, acceptance 86 vs 77, registry §23.1, цепочки v1.5/v2.3, 16 KiB, zero-byte close | B4X-AUDIT-008 | документы | M |

## P2

| ID | Задача | Finding | Файлы | Сложность |
|---|---|---|---|---|
| FB-15 | Сборка: Makefile build → зависимость от build-ui+gen-defaults (или коммит ui/dist) | B4X-AUDIT-009 | Makefile, src/http/ui | S |
| FB-16 | Перекодировать PATCH_PLAN и WARP v1.2 в UTF-8 | B4X-AUDIT-009 | 2 документа | S |
| FB-17 | WARP-пакет (при интеграции): geo TTL 120s, InnerRevokedBeforeParent, ExpiresAt | B4X-AUDIT-007 | src/warp/geo.go:52, isolation.go:16, selection.go:15 | S |
| FB-18 | Постатейная сверка ARCH v2.4 (40) и IV v1.5 (39) с кодом | BLOCKED | — | L |
