# Reachability: WARP v1.2 (B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md)

Аудит 31.07.2026 (фаза независимой верификации, повторная проверка ключевых фактов главным агентом 31.07 вечер).
Критерий: цепочка production root → импорт → runtime owner → implementation → observable side effect → cleanup.
НЕ засчитываются: unit-вызовы, конструктор-тесты, Valid(), test-only адаптеры, документация.

## Итог: 0 REACHABLE, 9 FAIL (severity HIGH)

## Ключевой факт (подтверждён повторно)

- Пакет `src/warp` (24 файла) **не импортируется ни одним production-файлом**: grep `b4/warp` по всему `src/` даёт 0 совпадений за пределами самого пакета; `go list -deps` от main (проверено в сессии 2: `go list -deps ./...` из контейнера linux/amd64) не включает warp.
- Конфиг-ключей warp (секции `warp.*` в схеме конфига) нет — пакет не участвует ни в одном контуре валидации конфига.
- Единственная связь с бинарём — транзитивная через типы в `src/classifier`/`src/nfq` (типы, не вызовы): конструкторы/функции warp в runtime не исполняются.

## Механизмы (все FAIL, severity HIGH)

| # | Механизм | Файл (проверено) | Производственный вызов |
|---|----------|------------------|------------------------|
| W-1 | Enrollment | `src/warp/enrollment.go` | Только `enrollment_test.go`; в production нет точки входа (нет API, нет импорта) |
| W-2 | Secrets | `src/warp/secrets.go` | `SecretStore` — in-memory `map[string][]byte` (:10, :14), без файла/шифрования/consent; вызовы только тесты |
| W-3 | Geo-аттестация | `src/warp/geo.go` (:32, :62) | Только `geo_test.go`; TTL 300s vs норма 120s (см. FB-17) |
| W-4 | Causal trace | `src/warp/trace.go` (TransportTraceEnvelope :19, TracePipeline :39-74, ValidateTraceCompatibility :74) | Только `trace_test.go`; файл `warp_trace.go` в репо НЕ существует (неточность ранней сводки); вердикт-классы — `src/warp/camouflage_auth.go:22-27` (Bypass/Camouflage/Established), также test-only |
| W-5 | Route/selection | `src/warp/routing.go`, `src/warp/selection.go` (CandidateResult.ExpiresAt не заполняется — FB-17) | Только тесты |
| W-6 | Isolation | `src/warp/isolation.go` (InnerRevokedBeforeParent не проверяется — FB-17) | Только тесты |
| W-7 | MASQUE/transport | `src/warp/manifest.go`, `tun.go`, `adapter.go` | Только тесты; в production tun-путь использует `src/tun` (main → tproxy/tun), не warp |
| W-8 | Cамозащита/cover | `src/warp/cover_sni.go`, `cutoff.go`, `nested.go`, `rst.go`, `health.go` | Только тесты |
| W-9 | Вердикты Ready()/готовность | В пакете warp **нет** функций `Ready()` (повторная проверка grep = 0) | — |

## Ложные readiness

- **Ложных отчётов нет**: `docs/reports/warp/WARP_1_REFERENCE_AUDIT.md`, `WARP_11_PRODUCT_INTEGRATION.md`, `WARP_IMPLEMENTATION_REPORT.md`, `WARP_VALIDATION_REPORT.md`, `WARP_CAMOUFLAGE_VALIDATION_REPORT.md` — честные: не утверждают интеграцию в production-бинар; вердикты валидации относятся к unit-уровню пакета.

## Связь с fix backlog

- Полностью покрывается **FB-02** (интеграция warp в production: enrollment + geo-аттестация + causal trace + счётчики), **FB-03** (hard-gate счётчики WARP), **FB-17** (3 нормативных правки внутри пакета — только после FB-02).
- Новых задач не требуется; подтверждено: без FB-02 требования WARP v1.2 в production не исполняются (0/44 IMP подтверждено прежним аудитом `warp_audit.md`).
