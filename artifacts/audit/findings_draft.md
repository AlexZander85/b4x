# Findings Draft (рабочий черновик) — аудит B4X, сессия 2

Статусы: V=verified (компилятор/выполненная команда), R=review (чтение кода), D=doc (меж-документное расхождение).
Все пути — D:\b4x. Логи build/vet/test: artifacts\audit\logs\.

## A. Верифицированные build/test findings (V)

### A1. capture/ppe — тесты не компилируются [V]
`src\capture\ppe\product_bundle_test.go:100-101`: `cfg := config.NewConfig()` (значение) передаётся в `NewProductService(func() *config.Config {...})` и `service.ApplyConfig(ctx, cfg)` — требуется `*config.Config`.
Доказательство: `go test ./...` (linux/amd64, golang:1.25-alpine): `FAIL github.com/daniellavrushin/b4/capture/ppe [build failed]`; то же в `-race` прогоне (bookworm). Лог: artifacts\audit\logs\go-test.log.
Влияние: единственный FAIL из 42 пакетов; пакет PPE активен в бинаре (см. B1), его тесты не работают.

### A2. fieldtest — коллизия JSON-тегов [V]
`src\fieldtest\session.go:59`: `ConfigGen, RouteGen, SessionGen uint64` — все три поля `json:"config_gen,omitempty"`. `go vet`: "struct field RouteGen/SessionGen repeats json tag config_gen".
Влияние: при сериализации событий трассы (Schema=1) значения RouteGen/SessionGen конфликтуют за один ключ — потеря данных generation-aware causal trace (норма FIELD_TEST v1.5: трасса должна нести ConfigGen/RouteGen/SessionGen).

### A3. Сборка из свежего клона невозможна без генерации UI [V]
`src\http\server.go:24`: `//go:embed ui/dist/*`. `src\http\ui\dist\` и `src\http\ui\src\models\defaults.json` gitignored (`src\http\ui\.gitignore`). Makefile: `build` зависит только от `swagger`, НЕ от `build-ui`/`gen-defaults` → `make build` падает на свежем клоне.
Воспроизведено: `go build ./...` до генерации → `pattern ui/dist/*: no matching files found`. Рабочая последовательность: `go run tools/gendefaults.go` (Linux) → `pnpm build` → `go build ./...` = OK.
Прочее: packageManager пинит pnpm@10.29.2, фактически pnpm 9.15.9; vite требует Node ≥22.12 (установлен 22.11 — warning, build проходит).

## B. Wiring findings (R+V)

### B1. capture/ppe подключён и стартует [R]
`src\http\server.go:43-182`: `ensureProcessPPE` → `service.Start`; observation bus → nfq pool; visibility-gate влияет на tcp_hold/tcp_reassembly/passive_rst. (wiring_analysis.md)

### B2. Мёртвый продуктовый слой: warp, serviceprofile, fieldtest, silentpath [V]
0 импортов/вызовов во всём src (grep `warp.`/`serviceprofile.`/`fieldtest.`/`silentpath.` = 0; `go list -deps ./` от main не включает; в http/handler и main.go — 0 упоминаний; API-эндпоинтов нет).
Состав пакетов: warp (24 файла: enrollment, geo, nested, trace, routing, cover_sni, rst, cutoff, secrets, isolation...), serviceprofile (17: compiler, ownership, transaction, import_export, warp_profile, recommendation...), fieldtest (26: controller, hard_gates, trace_causal, path_correlation, warp_gate, nonru...), silentpath (10: differential, progress, suppressors, rollback, leases...).
Влияние: требования WARP v1.2 / SP v1.6 / FT v1.5 / SPF v1.0 в production-бинаре не исполняются. Даже при прохождении unit-тестов пакетов — интеграция отсутствует.

### B3. monitor ≠ MON v1.0 [R]
Пакет monitor — библиотека типов для detector (MonitorScopeKey, Authority); shadow/cutover strangler-замена Watchdog НЕ реализована в runtime. Runtime-монитор — tables.Monitor (iptables rules). Shadow-пробы — только discovery/adaptive.go (другая сущность). MON-1..12 в production не исполняются.

### B4. capture/ppe стартует при WebServer.Port==0 [R]
`src\http\server.go:43` — `ensureProcessPPE` вызывается до проверки порта на :44 → PPE запускается даже при отключённом веб-сервере (возможно намеренно, но порядок неочевиден).

### B5. Второстепенное [R]
- `metrics/` — пустой пакет (коллектор живёт в handler).
- `geodat`, `quic` — 0 тестов при активном использовании.
- 115 API-эндпоинтов (108 REST + 3 auth + 4 WS).

## C. Меж-документные расхождения (D) — кандидаты в findings
1. DDI-4 ownership: ABD v1.2:129 требует делегирование компиляции raw evidence→BlockingProfile в ABD-10; DDI/TGB:1668–1676 описывает её как свой deliverable. Документ не обновлён.
2. ~~ADR-WARP пронумерованы 1..7, changelog v1.2 говорит 1..6 (ADR-WARP-7 geo attestation не отражён)~~ — ОШИБКА ЗАПИСИ: changelog-секции в WARP v1.2 не существует; конфликт снят (см. CONFLICTS_MAP №2).
3. MON §57: legacy /api/watchdog/* — срок существования адаптера не задан (MON-11 single source of truth без deadline).
4. GSOPassToken определён дважды: RST/GSO H4 (379–398) vs CSI §18 (1153–1178) — в CSI добавлены Authorization/EffectivePolicy/Disposition; субординация неявная.
5. Порядок цепочек: CSI-14 (1142) — RST/GSO после CSI-1..10 без упоминания WARP/PPE; SPF §0.1 (71–93) — WARP→RST/GSO→PPE→SPF; SPF требует PPE-proof (1217) — позиция PPE в цепочке разорвана.
6. IV v1.5: acceptance criteria фактически 86 (группы 1–42/43–67/68–86), заголовок §45 "редакция 1.3" и упоминания "77" вводят в заблуждение.
7. IV §23.1 registry устарел: не включает IV-13..17, FT-AC..AE, SP-20..23/30..32.
8. Цепочки ссылаются на SP v1.5 и ARCH v2.3 — в репо v1.6/v2.4.
9. WARP_CAUSAL_TRACE_READY определён в WARP v1.2 и IV v1.5 с неидентичным составом условий.
10. §28A.4 (forbidden при unhealthy controls) vs SP-30 DoD — расхождение трактовки.
11. Порог 16 KiB в PATCH_PLAN — label, без явного согласования с IV §22.
12. gso_mode=classify «рекомендуемый production mode» — разрешающий gate не формализован.
13. scoped-hints vs strict: «если нет доказанной причины для strict» — условия не определены.
14. zero-byte close: закрытие как idle_preconnect_expired vs «never silently claimed» (DDI/TGB:962–969 vs 1875) — уязвимое место false-pass.

## D. Замечания из извлечения требований
- 482 атомарных требования извлечены: part1=135 (WARP 44, ABD 27, MON 33, DDI/TGB 31), part2=189 (PPE 49, RST/GSO 34, CSI 32, SPF 74), part3=158 (FT 14, SP 22, IV 39, PATCH_PLAN 43, ARCH 40).
- Файлы: artifacts\audit\req_index_part1..3.md, wiring_analysis.md.

## E. Аудит B4_FORK_PATCH_PLAN.md (приоритетный документ)
ВНИМАНИЕ: PATCH_PLAN закодирован в **cp866** (866), не UTF-8 — верифицировано: UTF-8-декодирование даёт мусор, 866 — корректный текст. При чтении использовать `[System.Text.Encoding]::GetEncoding(866)`.

### E1. Маппинг 36 stages (patch_plan_audit.md)
- IMPLEMENTED+wired: 26 (1–16, 18, 20–27, 30, 32, 34, 35). PARTIAL: 7 (17, 19, 28, 29, 31, 33, 36). ABSENT: 0.
- Топ-проблемы: Stage 17 (planner/markers — библиотека, production-инъекции на legacy nfq/extsplit.go, desync.go, combo.go); Stage 19 (action/executor.go вызывается только из тестов — «centralized packet builder» в проде нет); Stage 36 (fieldtest не импортируется, 14 сценариев не автоматизированы); Stage 33 (routing.FallbackManager не подключён к nfq/tun); Stage 28/29/31 (Level C — библиотека с fuzz/bench, не в NFQ-пути).
- Stage 1: docs\audit\b4-1.73-flow-path.md существует, тоже cp866.

### E2. Качество реализации ключевых stages уровня A (patch_plan_quality.md) — ВСЕ 3 серьёзных расхождения ПОДТВЕРЖДЕНЫ повторной проверкой
- **E2a. Stage 16 — мёртвые FIN/RST abort константы**: `nfq\tcp_hold_config.go:17-18` (tcpHoldAbortFIN/RST) объявлены, нигде не используются (grep = 2 совпадения, только объявления). На FIN/RST held-пакет не релизится явно — висит до таймаута 750 мс (fail-open сохранён).
- **E2b. Stage 27 — глобальный лок на всю canary-транзакцию**: `runtimecontrol\rollout_manager_apply.go:33-34` — `m.mu.Lock()`+defer на весь Apply, включая `runtime.Canary` (строка 66); MaxCanaryDuration=1h (rollout_types.go:21,165-166) → Prepare/Rollback/AbortPending/Close заблокированы до часа.
- **E2c. Stage 4 — CaptureEnvelope декоративный**: `CaptureEnvelopeEnabled` (config\types.go:106) используется только в diagnostics.go:300 (статус), classifier_v23.go:241 (diff UI) и тесте; на фактическую обработку пакетов не влияет; контур iptables строится из старого cfg.Queue.Mark (tables\iptables.go:361-362).
- PASS подтверждены: Stage 7 (nfq\tcp_gate.go clean SYN → NF_ACCEPT), Stage 14 (обсервер-реассемблинг с бюджетами), Stage 18 (ActionTokenStore), Stage 19 fail-open, Stage 20 redaction, Stage 27 частично.

## F. Hard gates (hard_gates_audit.md)
- Активен в production 1 из 160 счётчиков-гейтов: `unrelated_control_action_total` (CSI-18, crossservice\validation.go:265,392). Плюс 1 механизм без счётчика: PPE visibility safety gate.
- Недостающие: все 56 WARP-гейтов (warp_trace_secret_leak_total, P0 dropped — счётчиков нет вообще), все 22 SPF-гейта (grep silentpath: hard/gate/single_signal/auto_fallback = 0), IV meta-suite (validation\meta.go + fieldtest\hard_gates.go реализованы, никем не вызываются).
- WARP_CAUSAL_TRACE_READY — только константа (fieldtest\cleanup.go:36); BLOCKED_TARGET_VALIDATION — константы (validation\verdict.go:9, fieldtest\promotion.go:7).
- Расхождение документов: WARP v1.2 §73B (26 gates) vs IV v1.5 §38A.9 (56) vs FT v1.5; имена в RequiredHardGates совпадают с FT §26 только 7 из 17.

## G. Качество тестов (test_quality_audit.md)
- Сильные стороны: 268 тест-файлов/1077 функций, 25 fuzz (13 пакетов), 28 benchmark; лидеры nfq (113), http/handler (69), tables (60).
- Слабости: CI без -race и go vet (проверить .github/workflows — агент утверждает), goleak в 3 файлах, capture/ppe красный (52 теста не исполняются), 4 отключённых пакета без интеграционных тестов, MON shadow/cutover 0 тестов, FT causal trace 1 тест против 9 мутантов.

## H. Кодировки и CI (верифицировано)
- cp866: только B4_FORK_PATCH_PLAN.md и B4_POST_V23_BUILTIN_WARP_MASQUE_TRANSPORT_ADDENDUM_v1.2.md. Остальные 12 документов — UTF-8.
- CI: .github/workflows = docs.yml, release.yml. Тесты: release.yml:90-92 `go test ./...` БЕЗ -race и БЕЗ go vet. capture/ppe build failure → release-CI падает.

## I. Аудит WARP v1.2 → src\warp (warp_audit.md)
- 44 требования: IMPLEMENTED 0, PARTIAL 32 (только модели/валидация), ABSENT 12 (ADR-WARP-2 IPC, ADR-WARP-3 hooks/RouteManager, §15 NDM, §62 таксономия событий, §72/73/73A/73B — все hard-gate счётчики (58), §74 вердикты, WARP-C10, WARP-12, Appendix B).
- Пакет — библиотека моделей без side-effect: нет syscall/HTTP/persistence/счётчиков/эмиссии событий. Тесты 19/19 PASS (Docker), но только модели; trace_test.go НЕ покрывает causal trace/leak counter/P0.
- Нормативные расхождения в коде: geo TTL 300s vs 120s (geo.go:52); InnerRevokedBeforeParent не проверяется (isolation.go:16); CandidateResult.ExpiresAt не заполняется (selection.go:15).
- Готовность к интеграции: НЕТ.

## J. Аудит MON/ABD/DDI-TGB → код (mon_abd_ddi_audit.md)
- 88 требований: IMPLEMENTED 2, PARTIAL 47, ABSENT 39. MON ≈ 0%, DDI/TGB ≈ 0%, ABD ≈ 7%.
- ПОДТВЕРЖДЕНО ПОВТОРНО: #277 жив — mtproto\transparent.go:97 (5s deadline) → :102-104 (head==0 → `return true, nil` — молчаливый drop, handled=true, без fail-open) и :157 (dial fail → `return true, nil`). Норма DDI/TGB требует парковку в PendingHandshakeManager и observable классификацию, не handled=true.
- MON-strangler не начат: watchdog\applier.go:18 applyBatchResults активен, direct apply работает; /api/monitor/v1 нет, legacy_watchdog_* ключей нет.
- BlockingProfile/schema не соответствуют ABD §19/§24.2: нет SchemaVersion/Components/DNS/Infrastructure/Exclusions/Controls/SearchPrior; envelope SchemaVersion=1 вместо 2.
- DDI-7/ABD-11: discovery\hint_planner.go:56 `_ = prior` — detector prior игнорируется; API не расширен (DDI-6) — #278 жив.
- Уточнение: detector/monitor/observability/metrics ДОСТИЖИМЫ из main транзитивно (detector: http\handler\detector.go, discovery\profile_store.go, hint_planner.go; monitor: detector\abd_*.go, discovery\network_context.go; observability/metrics: широко nfq/action/handler) — но MON-механизмы (эскалация/shadow/cutover) не реализованы, детектор работает только частично (legacy-пути).

## K. PATCH_PLAN quality — детальные evidence (все подтверждены)
- E2a: tcpHoldAbortFIN/RST — только объявления (grep: 2 совпадения, tcp_hold_config.go:17-18).
- E2b: m.mu.Lock() rollout_manager_apply.go:33-34 на весь Apply (Canary до 1h, rollout_types.go:21,165-166).
- E2c: CaptureEnvelopeEnabled — config\types.go:106; использования: diagnostics.go:300, classifier_v23.go:241, classifier_test.go:25. На логику пакетов не влияет.

## L. Аудит CSI/PPE/RST-GSO (живые подсистемы) — csi_ppe_rstgso_audit.md
- PPE (49): 38 IMPLEMENTED, 3 PARTIAL, 8 REPORT-EXISTS (PPE_STAGE_1..8). RST/GSO (34): 27 IMP, 2 PART, 1 REPORT, 4 NOT-VERIFIED. CSI (32): 25 IMP, 1 FAIL (CSI-15), 2 REPORT, 4 NOT-VERIFIED.
- Инварианты: ADR-CSI-1 (candidate≠authorization) PASS — classifier\authorization.go:11,23; запрет mark 0x08000000 PASS (packetmark\marks.go); GSOPassToken: PASS по RST/GSO H4, FAIL по CSI §18 (gso_token.go:25-36 — нет Authorization/EffectivePolicy/CandidateDisposition); PPE self-test: PARTIAL — только через HTTP (capture_offload_product.go:183), авто-старт при mode startup-and-change не подключён (reconciler.go:122).

## M. Аудит SP/FT/SPF (мёртвые пакеты) — sp_ft_spf_audit.md
- serviceprofile (22): 9 IMP/9 PART/4 ABS — частично. fieldtest (14): 8 IMP/6 PART/0 ABS — частично. silentpath (74): 26 IMP/25 PART/23 ABS — частично. Все — модели-verdict-ядра без обвязки.
- Топ-пробелы: (1) детекционная цепочка silentpath ABSENT: BaselineModel (SPF-19), RetryCorrelator (SPF-20), DifferentialProbeController (SPF-21), quarantine (SPF-40), thresholds (SPF-41) — confidence ladder без источника корреляции; (2) warp_recommendation — 8/9 полей, нет path_proof_supported, YAML не реализован; (3) fieldtest Controller не вызывает HardGatesPass (hard_gates.go:5), мутант-фикстуры FT-AC (9)/FT-AD (7)/FT-AE (12) не существуют; transaction.Apply/Rollback — флаговые заглушки; cooldown отсутствует (SP-22, FT-U); SPF-57 гейты — 17/21 и не в silentpath; TODO/FIXME/panic — 0.

## N. Итоговая трассируемость 482 требований (все документы)
| Документ | Всего | IMP | PART | ABS/FAIL | Комментарий |
|---|---|---|---|---|---|
| WARP v1.2 | 44 | 0 | 32 | 12 | пакет мёртвый, gates ABSENT |
| ABD v1.2 | 26 | 2 | 20 | 4 | детектор частично в проде, схемы не соответствуют |
| MON v1.0 | 32 | 0 | 13 | 19 | strangler не начат |
| DDI/TGB | 30 | 0 | 14 | 16 | #277 жив, #278 жив |
| PPE | 49 | 38 | 3 | 8* | живой; *REPORT-EXISTS; тесты сломаны |
| RST/GSO | 34 | 27 | 2 | 5* | живой; *1 REPORT + 4 NOT-VERIFIED |
| CSI | 32 | 25 | 0 | 7* | живой; *1 FAIL (CSI-15) + 2 REPORT + 4 NOT-VERIFIED |
| SPF v1.0 | 74 | 26 | 25 | 23 | пакет мёртвый |
| SP v1.6 | 22 | 9 | 9 | 4 | пакет мёртвый |
| FT v1.5 | 14 | 8 | 6 | 0 | пакет мёртвый, verdict декларативен |
| PATCH_PLAN | 36 | 26 | 7 | 0 | stages 17/19/28/29/31/33/36 PARTIAL |
| ARCH v2.4 | 40 | — | — | — | детальный аудит не проводился; key: §42-45 hold PARTIAL (см. K), §132-136 WARP мёртв |
| IV v1.5 | 39 | — | — | — | критерии 1-86: неисполнимы из-за мёртвых gates (см. F, G) |
| ИТОГО | 472+ | ~161 | ~131 | ~98+ | |

Вывод: НЕ COMPLIANT. Живые подсистемы (nfq/PPE/RST-GSO/CSI/classifier/discovery/handler) реализованы в основном качественно (26/36 stages, 90/115 живых требований), но весь «продуктовый слой» документов (WARP/SP/FT/SPF/MON/DDI-TGB) не исполняется в бинаре, hard gates не активны, тесты capture/ppe сломаны, CI без race/vet.
