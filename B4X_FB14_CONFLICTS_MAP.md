# B4X FB-14 — карта конфликтующих мест в документах

**Назначение:** рабочая карта для задачи FB-14 (`B4X_AUDIT_FIX_TASKS v2.md`). Решения принимает ВЛАДЕЛЕЦ — они зафиксированы в `B4X_FB14_CONFLICTS_RESOLVED.md` (раздел 2). Этот файл НЕ содержит новых решений; он указывает, где именно в canonical документах находятся конфликтующие/устаревшие формулировки, которые надо исправить или пометить `superseded` при переносе решений.

**Правила использования (обязательны):**
- не менять решения владельца; при расхождении формулировок здесь и в RESOLVED.md действует RESOLVED.md;
- координаты строк актуальны на 31.07.2026; после правок документов строки сдвигаются — искать по тексту/секции, не только по номерам;
- после каждой правки: «было → стало», новая версия/дата, SHA-256, migration note (требование v2.md 0.3 п.3);
- после всех 14 правок пересчитать FB-18A по новым хэшам (v2.md 0.1).

| № | Конфликтующие места (документ:строки/секции) | Суть конфликта | Решение (кратко; полный текст — RESOLVED.md раздел 2) |
|---:|---|---|---|
| 1 | `B4_POST_V23_DETECTOR_GUIDED_DISCOVERY_AND_TELEGRAM_BRIDGE_HARDENING_ADDENDUM_v1.0.md` (DDI/TGB) :1668-1676 vs `ABD v1.2` :129 | Кто компилирует raw evidence → BlockingProfile | ABD — единственный compiler; DDI — только envelope/freshness/persistence/revalidation/delivery. Удалить DDI-owned compiler semantics |
| 2 | ~~WARP addendum v1.2: changelog «ADR-WARP 1..6»~~ — СНЯТ (ложное срабатывание): changelog-секции в WARP v1.2 не существует (grep «changelog» — 0 совпадений); секции ADR-WARP-1…7 присутствуют (398/463/509/632/889/1199/1379) | — | Правок не требуется; нормативны ADR-WARP-1…7 |
| 3 | `B4X_POST_V23_CONTINUOUS_BLOCKING_MONITORING..._v1.0.md` §57 «Compatibility strategy» (1443+), MON-11 (2315-2444) | Срок жизни legacy `/api/watchdog/*` не задан | Event-driven cutover; до cutover — shadow/read-only; после — 410 Gone; мутирующие sources of truth не сосуществуют |
| 4 | `B4_POST_V23_RST_GSO_HARDENING_ADDENDUM.md` H4 (379-398) vs CSI addendum §18 (1153-1178) | Два определения GSOPassToken | Один compact canonical token с ID/digest (перечень полей — RESOLVED.md п.4); второе определение удалить |
| 5 | CSI-14 (1142) vs `SPF v1.0` §0.1 (71-93) vs SPF:1217 | Единая линейная цепочка WARP→RST/GSO→PPE→SPF | Универсальная цепочка запрещена; отдельные flow: data plane, diagnostic/control plane, transport escalation (диаграммы в RESOLVED.md п.5) |
| 6 | `B4_IMPLEMENTATION_VALIDATION_ADDENDUM_v1.5.md` §45 (заголовок «редакция 1.3», «77») vs фактический счёт критериев (86; до 146 с §56) | Ручные totals расходятся | Ни 77/86/146 не нормативны; totals — только из generated registry (FB-33); до registry — BLOCKED |
| 7 | IV v1.5 §23.1 (1100-1113) registry: перечисляет IV-1…12, FT-A…L, SP-1…15 | Не включает IV-13…17, FT-AC…AE, SP-20…23, SP-30…32, MON | Один canonical Exact Source-Stage Registry; §23.1 удалить/генерировать; delta-списки (§44/§49/§58) — только generated views |
| 8 | Stale версионные ссылки: IV:2406 («Service Profiles v1.5 compiler»), PATCH_PLAN:4 («ARCH редакции 2.3»), FIELD_TEST:25 и SP:15/3666 («SP v1.5», «ARCH v2.3») | Цепочки ссылаются на старые редакции | Все normative ссылки: ARCH v2.4, WARP v1.2, SP v1.6, ABD v1.2, DDI/TGB v1.0, SPF v1.0, FT/IV v1.5; исторические — только changelog с пометкой |
| 9 | `B4_FIELD_TEST_AUTOMATION_ADDENDUM_v1.5.md` WARP_CAUSAL_TRACE_READY (3146-3152) vs IV v1.5 (3905-3918) vs ARCH §136 | Неидентичный состав условий causal verdict | Узкий composable verdict (перечень — RESOLVED.md п.9); base/camouflage/nested/non-RU/Android/production — отдельные verdicts |
| 10 | SP v1.6 §28A.4 (3235-3255, «forbidden при unhealthy controls») vs SP-30 DoD (3604-3614, допускает рекомендацию при unhealthy) | Граница unhealthy controls | Обе нормы объединить в одну causal decision matrix; unhealthy/inconclusive/unknown всегда блокируют action/promotion |
| 11 | `B4_FORK_PATCH_PLAN.md` (927-930): «success threshold > typical 16 KiB cutoff» + «near-16k is classifier label, not hard-coded success logic» vs IV §22 (exact offset persisted) | 16 KiB — порог или бюджет? | 16 KiB — default bounded memory budget per-flow, не protocol threshold; configurable validated maximum + глобальные bounds |
| 12 | RST/GSO addendum: `gso_mode=classify` как «рекомендуемый production mode» | Разрешающий gate не формализован | Отдельный verdict `GSO_CLASSIFY_READY`; classify не разрешает normalization/mutation; UNKNOWN/FAIL → downgrade в observe |
| 13 | PATCH_PLAN Stage 12 (529-562): strict/scoped-hints/legacy/disabled; ARCH §106 (2549-2558) | Условия выбора режима не определены | Hints — provisional/correlation evidence; destructive authorization требует authoritative identity; hint-only authorization запрещён |
| 14 | DDI/TGB:962-969 (`idle_preconnect_expired` как допустимое завершение) vs DDI/TGB:1875 («never silently claimed») | Zero-byte close: drop или park? | Soft deadline паркует (не closed/handled); hard deadline — только observable cleanup (`idle_preconnect_expired` + metric/reason/cleanup); fixed-5s silent handled=true запрещён. Код: `src/mtproto/transparent.go:97-104` (см. FB-04) |

**Откуда взяты координаты:** исходный опросник `B4X_FB14_CONFLICTS.md` (не сохранён) и `B4X_AUDIT_FIX_TASKS.md` FB-14 (строки 119-132; также в Приложении A `B4X_AUDIT_FIX_TASKS v2.md`). Решения — `B4X_FB14_CONFLICTS_RESOLVED.md` (раздел 2, статус 31.07.2026).
