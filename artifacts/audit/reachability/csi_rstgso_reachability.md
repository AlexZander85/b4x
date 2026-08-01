# Reachability: CSI + RST/GSO (CROSS_SERVICE_ISOLATION, RST_GSO_HARDENING addenda)

Аудит 31.07.2026 (фаза независимой верификации; факты перепроверены главным агентом 31.07 вечер прямыми grep/чтением).
Критерий: цепочка production root → импорт → runtime owner → implementation → observable side effect → cleanup.

## Итог

- **CSI: REACHABLE** (все ключевые механизмы в production-пути; 1 поправка к прежнему аудиту — см. ниже).
- **RST: PARTIAL** — пассивная диагностика и suppression REACHABLE; активный контролируемый RST — ABSENT.
- **GSO: FAIL (severity HIGH)** — нормализующий пайплайн (primary+normalizer топология) в production НЕ достижим; токен-механизм частично достижим.

## CSI — REACHABLE (подтверждено)

| Механизм | Файл (проверено) | Цепочка |
|----------|------------------|---------|
| ADR-CSI-1: CaptureCandidate ≠ ActionAuthorization | `src/classifier/authorization.go:37, :50, :72`; `classification_decision.go`, `route_binding.go` | nfq/handler.go:44-72 handlePacket → dispatch → classification → authorization |
| promote-гейт | `crossservice.Default().RequirePromotion` (src/runtimecontrol/runtime_control.go:91-93) | /api/v2/runtime-control/promote → гейт (активен) |
| Счётчик isolation | `src/crossservice/validation.go:265, :392` (unrelated_control_action_total) | единственный из 160 hard-gate счётчиков, инкрементируемый в production |

### ПОПРАВКА к прежнему аудиту (запрет mark 0x08000000) — подтверждён, замечание субагента снято

- Прежний аудит (`csi_ppe_rstgso_audit.md:46,125-126`): «mark 0x08000000 зарезервирован (fixed), в src нет других использований».
- Повторная проверка: `src/packetmark/marks.go:5` — `const ProcessedBit uint32 = 1 << 27`; **`1 << 27 == 0x08000000`** (2^27 = 134217728 = 0x08000000). Бит зарезервирован под ProcessedBit/ProcessedMask (:5-6), единственные другие использования этого значения — `ProcessedMarkMask: 1 << 27` в `src/config/classifier_v23.go:332` (тот же бит, дефолт конфига). Canary-биты — 26/25/24 (:9-12).
- Вывод: прежний аудит ПРАВ; промежуточное замечание («0x08000000 не найден») — ошибка интерпретации (в коде запись `1 << 27`, а не hex-литерал). Действий не требуется; упоминание в разделе 7 B4X_AUDIT_FIX_TASKS.md корректно.

## RST/GSO hardening — разбивка

### REACHABLE (пассивная RST-подсистема)

| Механизм | Файл (проверено) | Цепочка |
|----------|------------------|---------|
| PassiveRST observe (incoming/outgoing) | `src/nfq/handler.go:230` (observePassiveRSTIncoming), `:245` (observePassiveRSTOutgoing); `src/nfq/passive_rst_observe.go` (observe :31/:51) | прямой вызов из handlePacket-пути (production) |
| PassiveRST store | `src/nfq/connstate.go:382-401` (NewPassiveRSTStore :401, env :108-115) | создаётся в newRuntimeState (production pool) |
| Suppression/injection (conservative) | `src/nfq/passive_rst_enforce.go` (:95-130 → vc.drop, handler.go:232-235); rollback RecordHealth :81 | активируется конфигом mode=conservative (default observe, config/classifier_v23.go:35-39, :336) |
| Health-rollback при promote | `src/runtimecontrol/live_runtime.go:280` (RecordPassiveRSTHealth) | runtime-control promote-путь |
| Статус/API | `src/nfq/hardening_status.go:10-12, :41-44`; GET /api/v2/classifier/hardening (handler/classifier_hardening.go, регистрация classifier_v23.go:63) | REST |

### FAIL (severity HIGH) — активная часть и GSO-пайплайн

| Механизм | Файл (проверено) | Статус |
|----------|------------------|--------|
| PlanControlledRST / CompareRSTPaths / AnalyzeRSTPath | `src/diagnostics/rst_path.go` (:432, :478) | FAIL — вызовы только rst_path_test.go; SYN-трассировка (fieldtest/rst.go) недостижима (пакет не импортируется) |
| GSO normalizer пайплайн (primary+secondary+normalizer топология) | `src/nfq/gso_normalizer.go:12` (configureGSONormalizer), `src/nfq/topology.go:28-57` (NewGSOQueueTopology, NewGSOPrimaryPool :43, NewGSONormalizerPool :51), `src/nfq/pool.go:138` | **FAIL** — NewGSOQueueTopology вызывается ТОЛЬКО из topology_test.go:17,49; PlanGSOTopology/PlanGSOTopologyTransition — только тесты; интерфейс GSOTopologyBackend реализован только test-фикстурой (gso_topology_transaction_test.go:25-51). Production-пул создаётся через `nfq.NewPool` (discovery/runtime_backend.go:47) БЕЗ GSO-топологии. Точка записи метрик gso_fastpath.go:211 (MetricNFQueueGSONormalized) недостижима |
| GSOTopologyTransaction (транзакции поколений) | `src/runtimecontrol/gso_topology_transaction.go:15, :109` | FAIL — исполнители только тесты; в production API runtime-control транзакции топологии не зарегистрированы |
| GSOPassToken поля (CSI-15) | `src/nfq/gso_token.go:25-36` | PARTIAL — токен-механизм в production (Claim через ActionTokenStore, connstate.go:381), но отсутствуют поля Authorization/EffectivePolicy/CandidateDisposition (задача FB-10) |

## Ложные readiness

- `docs/validation/rst-gso-h10.md` — корректный NO-GO (заявляет невыполнение части критериев; не утверждает production-готовность).
- `docs/reports/rst-gso/H10_VALIDATION_REPORT.md` — не содержит ложных «wired»-утверждений (проверка поля).
- `docs/reports/ppe/PPE_STAGE_*` — см. patch_plan_19_36.md, секция PPE (ложных readiness нет).

## Связь с fix backlog

- GSO-пайплайн: **новые задачи FB-26/FB-27** (см. итоговый отчёт) — подключить топологию/транзакции к runtime-control или задекларировать неактивным.
- GSOPassToken: **FB-10**. Пассивный RST: работает, правок не требует.
