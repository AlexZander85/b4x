# Reachability: SP v1.6 / FT v1.5 / SPF v1.0 (serviceprofile, fieldtest, silentpath)

Аудит 31.07.2026 (фаза независимой верификации; ключевые факты перепроверены главным агентом 31.07 вечер).
Критерий: цепочка production root → импорт → runtime owner → implementation → observable side effect → cleanup.
НЕ засчитываются: unit-вызовы, конструктор-тесты, Valid(), test-only адаптеры, документация.

## Итог: все три пакета — 0 импортеров из production, все механизмы FAIL (severity HIGH)

## Ключевой факт (подтверждён повторно)

- grep по всему `src/`: `b4/serviceprofile`, `b4/fieldtest`, `b4/silentpath`, `b4/validation` — **только внутренние импорты** внутри самих пакетов; 0 внешних импортеров.
- `go list -deps` от main (linux/amd64, сессия 2) не включает ни один из пакетов.
- Отдельно: `src/validation` (meta-suite, verdicts) — см. FB-03: `validation/meta.go` и `fieldtest/hard_gates.go` никем не вызываются.

## SERVICE PROFILE v1.6 (src/serviceprofile, 17 файлов) — все FAIL

| Механизм | Файл (проверено) | Статус |
|----------|------------------|--------|
| Компилятор профилей | `src/serviceprofile/compiler.go:37` (и весь пакет) | FAIL — только unit-тесты |
| Ownership | `src/serviceprofile/ownership.go:35` | FAIL — только unit-тесты |
| warp_profile / `path_proof_supported` | в пакете ОТСУТСТВУЕТ (проверено grep) | ABSENT — поле не существует (требуется FB-02 шаг 2) |
| `warp_recommendation` YAML (§28A.5 WARPProjection) | 0 вызовов во всём src (проверено повторно) | FAIL |
| Transaction (применение профилей) | `src/serviceprofile/transaction*.go` | FAIL — только unit-тесты |

## FIELD TEST v1.5 (src/fieldtest, 26 файлов) — все FAIL

| Механизм | Файл (проверено) | Статус |
|----------|------------------|--------|
| Controller | `src/fieldtest/controller*.go` | FAIL — не вызывается ни откуда (только тесты) |
| HardGatesPass | `src/fieldtest/hard_gates.go:5` | FAIL — 0 вызовов (подтверждено FB-03:5) |
| Мутант-фикстуры FT-AC (9) / FT-AD (7) / FT-AE (12) | не существуют в репо | ABSENT |
| Сессии/трассы | `src/fieldtest/session.go:59` — коллизия JSON-тегов (vet error, FB-13) | FAIL — пакет недостижим; плюс дефект сериализации |
| 14 requiredScenarioIDs | `src/crossservice/validation.go:144` — константы есть, но исполняются только через операторский POST /api/v2/classifier/isolation/validate (не автоматизированный сюит) | FAIL (см. Stage 36) |

## SILENT PATH v1.0 + SPF (src/silentpath, 10 файлов) — все FAIL

| Механизм | Статус |
|----------|--------|
| BaselineModel (SPF-19) | ABSENT — не существует в репо |
| RetryCorrelator (SPF-20) | ABSENT |
| DifferentialProbeController (SPF-21) | ABSENT |
| Quarantine (SPF-40) / thresholds (SPF-41) | ABSENT |
| Счётчики silentpath | 0 инкрементов в production (весь пакет не импортируется) |

## Ложные readiness

- `docs/reports/service-profile-v1.6.md`, `docs/reports/field-test-automation-v1.5.md`, `docs/reports/spf-*.md` — отчёты описывают реализацию/валидацию пакетов и честно не утверждают production-интеграцию (интеграция — отдельные фазы спринтов в самих документах). Ложных «wired»-утверждений нет.

## Связь с fix backlog

- Полное покрытие: **FB-02** (интеграция serviceprofile/fieldtest/silentpath по addenda), **FB-03** (hard gates + meta-suite вызовы), **FB-13** (JSON-теги fieldtest), **FB-14 п.5** (цепочка WARP→RST/GSO→PPE→SPF).
