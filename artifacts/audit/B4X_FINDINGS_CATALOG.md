# B4X Findings Catalog

**Репозиторий:** AlexZander85/b4x, ветка `agent/classifier-v2.3-capture-envelope`. **Дата:** 31.07.2026.
Полный черновик с evidence: `findings_draft.md` (секции A–N). Подробные аудиты: `wiring_analysis.md`, `patch_plan_audit.md`, `patch_plan_quality.md`, `hard_gates_audit.md`, `test_quality_audit.md`, `warp_audit.md`, `mon_abd_ddi_audit.md`, `csi_ppe_rstgso_audit.md`, `sp_ft_spf_audit.md`.

## BLOCKER

| ID | Название | Evidence | Связанные требования |
|---|---|---|---|
| B4X-AUDIT-001 | Продуктовый слой не исполняется: warp/serviceprofile/fieldtest/silentpath — 0 импортеров во всём src | grep `warp.`/`serviceprofile.`/`fieldtest.`/`silentpath.` = 0; `go list -deps ./` не включает; handler/main 0 упоминаний | WARP 44, SP 22, FT 14, SPF 74 |
| B4X-AUDIT-002 | Hard gates не активны: 1 из 160 счётчиков в production (`unrelated_control_action_total`, crossservice/validation.go:265,392) | hard_gates_audit.md; WARP_CAUSAL_TRACE_READY — константа fieldtest/cleanup.go:36; BLOCKED_TARGET_VALIDATION — validation/verdict.go:9 | WARP §72/73/73A/73B (58), SPF (22), FT §26 (82), IV-11 |
| B4X-AUDIT-003 | Тесты capture/ppe не компилируются: product_bundle_test.go:100-101 (config.Config vs *config.Config) | `go test ./...` (linux/amd64): FAIL ppe [build failed]; лог logs/go-test.log; также в -race прогоне | PPE-24/26, IV criteria |
| B4X-AUDIT-004 | MON v1.0 не реализован: strangler не начат, watchdog/applier.go:18 applyBatchResults активен; MON 0/32 IMP | mon_abd_ddi_audit.md | MON-1..12, §57-63, §80-86 |
| B4X-AUDIT-005 | #277 и #278 живы: mtproto/transparent.go:97-104,157 — zero-byte/dial-fail → `return true, nil` (silent drop); discovery/hint_planner.go:56 `_ = prior` | прочитано лично | DDI-1..10, TGB-1..10 |

## MAJOR

| ID | Название | Evidence |
|---|---|---|
| B4X-AUDIT-006 | CI не защищает: release.yml:90-92 `go test ./...` без -race и vet; goleak в 3 файлах | test_quality_audit.md |
| B4X-AUDIT-007 | Расхождения в живых подсистемах: CSI-15 GSOPassToken без Authorization/EffectivePolicy/Disposition (nfq/gso_token.go:25-36); tcpHoldAbortFIN/RST мёртвые (tcp_hold_config.go:17-18); m.mu на всю canary-транзакцию до 1h (rollout_manager_apply.go:33-34, rollout_types.go:21); CaptureEnvelopeEnabled декоративный (config/types.go:106); PPE self-test только через HTTP (capture_offload_product.go:183, reconciler.go:122); WARP geo TTL 300s vs 120s (geo.go:52), InnerRevokedBeforeParent не проверяется (isolation.go:16) | patch_plan_quality.md, csi_ppe_rstgso_audit.md, warp_audit.md — все claims перепроверены |
| B4X-AUDIT-008 | 14 меж-документных противоречий (DDI-4 ownership; ADR-WARP 1..7 (vs 1..6 — снято: changelog-секции в WARP v1.2 нет); GSOPassToken два определения; WARP_CAUSAL_TRACE_READY неидентичен в WARP vs IV; acceptance 86 vs 77; registry §23.1 устарел; цепочки → SP v1.5/ARCH v2.3; 16 KiB; gso_mode=classify; scoped-hints vs strict; zero-byte close формулировка) | findings_draft.md секция C |
| B4X-AUDIT-009 | Сборка/окружение: ui/dist+defaults.json gitignored, make build не вызывает build-ui; PATCH_PLAN и WARP v1.2 в cp866; pnpm 9.15.9 vs pinned 10.29.2; Node 22.11 < 22.12 (vite) | verified: кодировки (866-декодирование), go build до генерации UI → embed error |

## Статистика покрытия (482 требования; итог — NOT COMPLIANT)
| Документ | Всего | IMP | PART | ABS/FAIL |
|---|---|---|---|---|
| WARP v1.2 | 44 | 0 | 32 | 12 |
| ABD v1.2 | 26 | 2 | 20 | 4 |
| MON v1.0 | 32 | 0 | 13 | 19 |
| DDI/TGB | 30 | 0 | 14 | 16 |
| PPE | 49 | 38 | 3 | 8* (*REPORT-EXISTS) |
| RST/GSO | 34 | 27 | 2 | 5* |
| CSI | 32 | 25 | 0 | 7* (1 FAIL: CSI-15) |
| SPF v1.0 | 74 | 26 | 25 | 23 |
| SP v1.6 | 22 | 9 | 9 | 4 |
| FT v1.5 | 14 | 8 | 6 | 0 |
| PATCH_PLAN | 36 | 26 | 7 | 0 |
| ARCH v2.4 | 40 | — | — | BLOCKED (индексирован) |
| IV v1.5 | 39 | — | — | BLOCKED (индексирован) |
