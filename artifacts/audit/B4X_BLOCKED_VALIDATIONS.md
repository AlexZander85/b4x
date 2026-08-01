# B4X Blocked Validations

Дата: 31.07.2026. Что не удалось валидировать и почему.

| ID | Валидация | Причина блокировки | Статус | Связанный finding |
|---|---|---|---|---|
| BV-01 | Постатейная сверка ARCH v2.4 (40 требований) | Индексировано в req_index_part3.md; детальный аудит не проводился (покрыто косвенно: §42-45 hold → patch_plan_quality, §132-136 WARP → warp_audit) | BLOCKED → P2 (FB-18) | — |
| BV-02 | Постатейная сверка IV v1.5 (39 записей, критерии 1–86) | То же; критерии требуют исполняемых hard gates (B4X-AUDIT-002) | BLOCKED → P2 (FB-18) | B4X-AUDIT-002 |
| BV-03 | PR-декомпозиция PATCH_PLAN §1487-1543 | `D:\b4x` не git-репозиторий; PR-история не доступна (только clone для blob-сравнения) | BLOCKED | — |
| BV-04 | Сборка/тесты на Windows | log/syslog, unix.Dup2 — Unix-only; целевая платформа Linux | NOT_APPLICABLE (проверено для linux/amd64) | — |
| BV-05 | `go test -race` для capture/ppe | Тесты не компилируются (B4X-AUDIT-003) — race-прогон для пакета невозможен до FB-01 | BLOCKED | B4X-AUDIT-003 |
| BV-06 | E2E на роутере (Stage 36: 14 Android-сценариев) | Нет железа; fieldtest не подключён (B4X-AUDIT-001) | BLOCKED | B4X-AUDIT-001 |
| BV-07 | Проверка правильности 4 требований RST/GSO (NOT-VERIFIED) | Не удалось сопоставить с кодом за отведённый объём (см. csi_ppe_rstgso_audit.md) | BLOCKED → уточнить | — |
| BV-08 | Исполнение кода `src/fieldtest`, `src/silentpath` интеграционно | Пакеты не подключены; интеграционных тестов нет | BLOCKED | B4X-AUDIT-001 |
| BV-09 | Проверка live-поведения PPE на реальном NFQUEUE | Требует root/сетевых capability; в Docker проверялась только компиляция и unit-тесты (кроме сломанных) | BLOCKED | B4X-AUDIT-003 |
