# FB-14 — Remediation report: 14 меж-документных противоречий

**Дата:** 2026-08-01
**Источник:** `B4X_FB14_CONFLICTS_RESOLVED.md` (14 owner-решений), `B4X_FB14_CONFLICTS_MAP.md`
**Статус:** правки внесены в canonical documents; коммит `fix(b4): FB-14 — ...` (см. git log)

Все правки содержат в тексте документов метку `FB-14 решение N` и, где требуется, `superseded`-блок с «было → стало».

---

## Таблица правок (решение → документ → секция → статус)

| № | Решение | Документ | Секция / место | Правка | Новый SHA-256 (полный) |
|---|---|---|---|---|---|
| 1 | DDI-4 ownership: ABD — единственный compiler raw evidence → `BlockingProfile`; DDI — только envelope/freshness/persistence/revalidation/delivery | `B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md` | §DDI-4 | Заголовок и deliverables переписаны, ownership передан ABD-10, добавлена superseded-заметка. ABD v1.2:129 уже нормативен — без правки | `a9748ec6ffc5e307ad5b2fc7006d7ba4cc4250d9bcdc20ee8a5134ea210b87e7` |
| 2 | ADR-WARP 1..7: changelog-конфликт **СНЯТ** (changelog-секции в WARP v1.2 не существует — grep «changelog»: 0 совпадений) | — | — | Правок в документы не требуется; зафиксировано в RESOLVED.md §2.2, MAP №2, findings_draft.md C.2, B4X_AUDIT_VERDICT.md, B4X_FINDINGS_CATALOG.md, B4X_FIX_BACKLOG.md, `B4X_AUDIT_FIX_TASKS v2.md` | — |
| 3 | Legacy `/api/watchdog/*`: event-driven cutover, до cutover shadow/read-only, после — 410 Gone, один minor release GET alias, `MON_PRODUCTION_READY` заблокирован при достижимом legacy mutating path | `B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md` | §57 → §57.1 | Добавлен «57.1. Legacy API lifetime — event-driven cutover» с условиями cutover, запретами и superseded-блоком | `f0693e9c48ad359c38086defa022011ce9b3625eb565001a1a863bb731cf4cce` |
| 4 | Один canonical `GSOPassToken` (compact immutable references, ID/digest, single-use, generation binding); второе определение удалено | `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md` (H4) + `B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md` (§18) | H4, §18 | H4: canonical schema + свойства + superseded. CSI §18: заменён на «GSOPassToken reference» на canonical schema | RST/GSO: `a6e40d8c58437400a53478b2eb7693eab4d4ec0b59c1b5c7d4e3b950f8db5d90`; CSI: `4b70095728692e55004e08e2fd7c2cf1bb56639bf1b67380f1044f22051c6485` |
| 5 | Универсальная цепочка `WARP→RST/GSO→PPE→SPF` запрещена; три плоскости: data plane / diagnostic-control plane / transport escalation | `B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md` (§0.1) + CSI §17 | §0.1, §17 | SPF §0.1: заменён трёхплоскостной моделью + superseded. CSI §17: уточнение «release sequencing, не runtime dependency chain» | SPF: `2a1611b2598b47c265df9e6e78d3f9cb973f0120f7dcd69f38ed97ab271f411c`; CSI: см. №4 |
| 6 | Ручные totals (77/86/146) не нормативны; `criteria_total = count(canonical registry)` (FB-33); до registry — BLOCKED | `B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md` | §45 | Добавлен superseded-блок в §45 «Расширенные acceptance criteria» | `aae0c3e63fb1c2b1fd2fdaa3f9b27662132521cd50a8862240c3f0eea60484b5` |
| 7 | §23.1 — не самостоятельный Exact Source-Stage Registry; единственный canonical registry (FB-33); списки — generated views | IV v1.5 | §23.1 | Добавлен superseded-блок, перечень источников приведён к canonical registry | IV: см. №6 |
| 8 | Все normative cross-references — актуальные версии (ARCH v2.4, WARP v1.2, SP v1.6, ABD v1.2); исторические — только changelog с пометкой | SP v1.6 (шапка, §последовательность, §32), FT v1.5 (§последовательность), IV v1.5 (шапка, §41.8, критерий 15), PATCH_PLAN (шапка), SPF v1.0 (шапка), CSI (шапка), MON (шапка), DDI/TGB (шапка), WARP v1.2 (шапка), ABD v1.2 (шапка), RST/GSO (шапка) | шапки/последовательности | `B4_FORK_ARCHITECTURE.md v2.3` → `v2.4` (9 файлов), WARP `v1.1` → `v1.2` (SPF, SP), ABD `v1.0/v1.1` → `v1.2` (SP, FT, IV), SP `v1.5` → `v1.6` (FT, IV), IV §41.8 помечен historical, SP §32 помечен historical/non-normative | см. строки ниже |
| 9 | `WARP_CAUSAL_TRACE_READY` — узкий composable causal verdict; nested/non-RU/camouflage/Android — отдельные verdicts | WARP v1.2 (§73B/§74), FT v1.5 (§25 verdict/§26 gates), IV v1.5 (§38A, §52) | §73B, §74, §25-26, §38A, §52 | Все три документа приведены к узкому causal-trace составу (required-event set, ordering, generation, parity, counters, cleanup; missing/skipped/stale ≠ PASS) | WARP: `d72cc142b1ae90e46912ed6735484b666d5bc585350b0e295a0e408c75f450a7`; FT: см. №8 |
| 10 | §28A.4 + SP-30 объединены в canonical causal decision matrix; unhealthy/inconclusive/unknown всегда → blocked-by-safety/rejected/inconclusive; `eligible-to-test` при unhealthy запрещён | `B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md` | §28A.4 → §28A.4.1 | Добавлена «28A.4.1. Canonical causal decision matrix» + superseded | SP: `1608e7c34e092bf0b14da46c3cdb657622bdc655e04c460ef2275879681a3d49` |
| 11 | `16 KiB` — default bounded memory budget `max_reassembly_bytes_per_flow`, не protocol/DPI граница; configurable validated maximum + global bounds; запрещён ложный complete | MON §5 → §5.1, PATCH_PLAN §Body policy | §5.1, Body policy | MON: добавлен «5.1. 16 KiB — bounded memory budget» + superseded (строки 214/237). PATCH_PLAN: «success threshold > typical 16 KiB cutoff» заменён на budget-семантику | MON: см. №3; PATCH_PLAN: `23abccb5e1df4af91a1385faed2c06532fcd1f8c0fda2548e7ed9a7b33f0dc67` |
| 12 | `gso_mode=classify` — только при current-generation verdict `GSO_CLASSIFY_READY`; UNKNOWN/STALE/FAIL → downgrade в observe; classify не разрешает mutation | `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md` | H3 Classify | Добавлены `GSO_CLASSIFY_READY` (состав условий), downgrade-правило, запрет normalization без additional gates + superseded | RST/GSO: см. №4 |
| 13 | `strict` — authoritative identity для destructive authorization; `scoped-hints` — только provisional/correlation evidence; hint-only destructive authorization запрещён | `B4_FORK_ARCHITECTURE_v2.4.md` | §106 | Добавлены подсекции `strict`/`scoped-hints` с перечнем, exact-scope, критической границей и запретами | ARCH: `6df1c1a245158addd7837296c3e927a714970bb761e3f1e7e68064fbecbdc73b` |
| 14 | Zero-byte Telegram close: soft deadline паркует (не closed/handled); hard deadline — только observable `idle_preconnect_expired` + metric/reason/cleanup/release; fixed-5s silent `handled=true` запрещён | DDI/TGB | §16.2 | §16.2 переписан на soft/hard deadline + запреты + superseded; DoD «never silently claimed» сохранён | DDI/TGB: см. №1 |

## Полные SHA-256 изменённых документов

| Документ | SHA-256 |
|---|---|
| B4_FORK_ARCHITECTURE_v2.4.md | `6df1c1a245158addd7837296c3e927a714970bb761e3f1e7e68064fbecbdc73b` |
| B4_FORK_PATCH_PLAN.md | `23abccb5e1df4af91a1385faed2c06532fcd1f8c0fda2548e7ed9a7b33f0dc67` |
| B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md | `a6e40d8c58437400a53478b2eb7693eab4d4ec0b59c1b5c7d4e3b950f8db5d90` |
| B4_POST_V23_CROSS_SERVICE_ISOLATION_ADDENDUM.md | `4b70095728692e55004e08e2fd7c2cf1bb56639bf1b67380f1044f22051c6485` |
| B4_POST_V23_SILENT_PATH_FAILURE_AND_SCOPED_RECOVERY_ADDENDUM_v1.0.md | `2a1611b2598b47c265df9e6e78d3f9cb973f0120f7dcd69f38ed97ab271f411c` |
| B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md | `d72cc142b1ae90e46912ed6735484b666d5bc585350b0e295a0e408c75f450a7` |
| B4X_POST_V23_ADAPTIVE_BLOCKING_DETECTOR_AND_GUIDED_STRATEGY_SEARCH_ADDENDUM_v1.2.md | `5d2b03b02aed8e4ede89b9b60a853db119ac1e334d1650d9ee9ce0895df1fce7` |
| B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING_AND_DETECTOR_ESCALATION_ADDENDUM_v1.0.md | `f0693e9c48ad359c38086defa022011ce9b3625eb565001a1a863bb731cf4cce` |
| B4X_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md | `a9748ec6ffc5e307ad5b2fc7006d7ba4cc4250d9bcdc20ee8a5134ea210b87e7` |
| B4_SERVICE_PROFILES_BEGINNER_UX_ADDENDUM_v1.6.md | `1608e7c34e092bf0b14da46c3cdb657622bdc655e04c460ef2275879681a3d49` |
| B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md | `aae0c3e63fb1c2b1fd2fdaa3f9b27662132521cd50a8862240c3f0eea60484b5` |

## Acceptance criteria FB-14 (RESOLVED.md §4) — статус

| Критерий | Статус |
|---|---|
| 14/14 owner-решений перенесены в canonical documents | 14/14 внесены (решение 2 — «снято», зафиксировано в отчётах) |
| 0 активных противоречащих normative definitions | Достигнуто правками (проверка — новый conflict scan, см. ниже) |
| 0 duplicate canonical schemas | GSOPassToken единственный (H4), CSI §18 ссылается |
| 0 stale normative version references | Все ссылки актуализированы (ARCH v2.4, WARP v1.2, SP v1.6, ABD v1.2) |
| registry consistency PASS | **Зависимость FB-33** (canonical Exact Source-Stage Registry + generated totals + CI-валидатор) — отдельная XL-задача |
| production reachability requirements добавлены | `GSO_CLASSIFY_READY` (production reachability через реальный packet entry point), legacy API cutover-условия |
| validation/field gates обновлены | `WARP_CAUSAL_TRACE_READY` состав унифицирован в WARP/FT/IV; SP causal matrix |
| новый independent conflict scan не находит 14 конфликтов | Выполнен grep-контроль ключевых маркеров после правок (changelog-секции нет; 16 KiB budget; GSO_CLASSIFY_READY; единственный GSOPassToken; v2.4/v1.2/v1.6/v1.2 ссылки) |

## Открытые зависимости

- **FB-33** — canonical Exact Source-Stage Registry, generated totals, CI static checks (duplicate type/schema/verdict, stale version reference, registry count mismatch) — закрывает registry-критерий FB-14.
- **FB-18A** — постатейная сверка ARCH v2.4 ↔ IV v1.5 (отдельный preflight, идёт после FB-14).
- **FB-03/FB-04** — кодовая реализация hard gates и zero-byte bridge (поведенческие решения 9/12/14 требуют production-root интеграционных тестов, RESOLVED.md §3.9).
