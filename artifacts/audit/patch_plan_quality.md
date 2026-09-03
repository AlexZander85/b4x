# Аудит качества реализации: 9 stages уровня A (Core Fix) из B4_FORK_PATCH_PLAN.md

Дата: 2026-07-31. Read-only аудит; код не изменялся.
Метод: чтение B4_FORK_PATCH_PLAN.md (cp866) + статический анализ src/ (Go).
Обозначения: PASS / PARTIAL / FAIL / NOT_FOUND. Все номера строк — по состоянию на дату аудита.

---

## Stage 4 — Capture Envelope и processed provenance mark

(a) Документ требует:
- envelope: first-N outgoing/incoming, SYN-ACK/FIN/RST queue rules, QUIC Initial, IPv4/IPv6, processed mark bypass, queue-bypass, production/candidate separation;
- mark contract: все raw-sent/injected/replayed пакеты получают один reserved mark, правила исключают его до NFQUEUE;
- readiness через procfs (queue number + owner PID/portid), fixed sleep — только backoff;
- offload self-check: test flow seen, reply visibility, queue counters, `flow_offload_bypass_suspected`;
- тесты: rules snapshots, marked bypass, owner mismatch, cleanup idempotency, IPv4/IPv6, mocked procfs.

(b) Что в коде:
- `src/capture/envelope.go`: `CaptureEnvelope` (стр. 55-70), `Decide()` с приоритетом processed → family → protocol → DNS → SYN-ACK/FIN/RST → QUIC Initial → first-N (стр. 196-229), `QueueRole` production/candidate (стр. 32-35), `QueueBypass` обязателен (Validate стр. 164-166), bound `MaxCapturePacketLimit=4096` (стр. 48);
- mark contract: `src/packetmark/marks.go:5-6` (`ProcessedBit=1<<27`, `ProcessedMask`), re-export в `src/capture/marks.go`; sender инжектит mark в `src/nfq/verdict.go:64` (`reinjectMark = ProcessedMarkFor(cfg.Queue.Mark)`), `tun/tun.go:102`;
- readiness: `src/capture/readiness.go` — парсер `/proc/net/netfilter/nfnetlink_queue` (стр. 71-124), owner portid mismatch (стр. 167-173); используется в `src/nfq/topology.go:122`, `src/runtimecontrol/live_runtime.go:138-140` (с `RequireOwner: true`, PID процесса), `src/discovery/runtime_backend.go:72`, `src/http/handler/diagnostics.go:302`;
- offload: `src/capture/offload_check.go:36-78` — `FlowOffloadBypassSuspected` (стр. 70), консервативная логика «недостаточно наблюдений ≠ bypass»;
- тесты: envelope_test.go, marks_test.go, readiness_test.go (включая idempotency), offload_check_test.go.

(c) Оценка: PASS

(d) Замечания:
1. Envelope используется только в диагностике/readiness (`http/handler/diagnostics.go:293-312`, `runtimecontrol/live_runtime.go`); флаг `CaptureEnvelopeEnabled` (config/types.go:106) нигде не переключает реальную генерацию правил — ядро-контур first-N в iptables остался на старом bypass `cfg.Queue.Mark` (`tables/iptables.go:361-362`). «Правило» и «envelope» — две не связанные сущности.
2. Отдельного файла `nfq/pool.go`-readiness в nfq нет — `QueueReadinessSpec` собирается без `ExpectedOwnerPortID` в `topology.go:122` (owner проверяется только в runtimecontrol/discovery контуре).

---

## Stage 7 — Clean SYN pass

(a) Документ требует:
- инвариант: SYN + no payload + no explicit SYN technique → NF_ACCEPT;
- clean SYN guard ДО generic TLS injection;
- TCPFlowPhase/FSM, transition function, FIN/RST cleanup, ServerProgress state;
- тесты: clean SYN с fake-SNI, SynFake allowed, TCPMD5, SYN retransmission, SYN-ACK, TFO, FIN/RST.

(b) Что в коде:
- инвариант: `src/classifier/tcp.go:22-27` `IsCleanSYN(flags, payloadLen, explicitSYNTechnique)`; `src/nfq/tcp_gate.go:11-13` `shouldPassCleanSYN`; вызов в hot path `src/nfq/handler.go:421-424` — `return vc.accept()` (NF_ACCEPT) до generic TLS/action-диспетчеризации;
- explicit technique: `src/nfq/handler.go:129-135` `needsTCPSynInjection` = `set.TCP.SynFake || (active strategy && Faking.TCPMD5)`; ветка SynFake-инжекции отдельно `handler.go:480-495`;
- FSM: `src/classifier/tcp.go:29-293` — `TCPFlowPhase` (new→syn-seen→established→clienthello→action→server-progress→closed), `transition()`, `TCPFlowStore` (FIN/RST → TCPClosed немедленно, стр. 136-144, 337-340), ServerProgress закрывает mutation window (стр. 285-287);
- тесты: `src/nfq/tcp_gate_test.go` (включая «synfake»-набор, стр. 21), `src/classifier/tcp_test.go:18-35`.

(c) Оценка: PASS

(d) Замечания:
1. Guard стоит после DNS-хинт/matched-логики, но до raw-send/injection — инвариант соблюдён; однако при `set == nil` (нет матча) clean SYN всё равно ACCEPT — корректно, но срабатывает только для TCP-портов (`cfg.IsTCPPort(dport)`).
2. `TCPFlowStore` определён и покрыт тестами, но явной интеграции FSM-переходов в основной dispatch (handler.go) не обнаружено — production-путь использует точечные признаки (actionTokens.CloseServerProgress на FIN/RST, handler.go:417-419); риск дублирования семантики FSM в двух местах.

---

## Stage 12 — DomainOnly v2

(a) Документ требует:
- 4 режима: strict / scoped-hints / legacy / disabled, решение по policy, не ad-hoc цепочкам условий;
- булев конфиг мигрирует в эквивалентный legacy-режим;
- trace: all evidence, selected source/confidence, mode/result, set/strategy.

(b) Что в коде:
- режимы: `src/config/types.go:78-89` (`DomainPolicyStrict/ScopedHints/Legacy/Disabled` + alias `DomainOnlyLegacy`); валидация режимов `src/config/validation.go:383-386`; дефолт `DomainOnlyLegacy` (`src/config/types.go:130`, migration `src/config/migration.go:43-44` — пустое значение → legacy);
- policy: `src/classifier/policy.go:47-103` — `normalizeDomainOnlyMode`, `domainPolicyFromMode` (стр. 208-215), фильтрация evidence по домену + результат `DomainOnlyResult` (стр. 69-83); `src/classifier/types.go:36-48, 158-194`;
- интеграция: `src/nfq/classifier_decision.go:15-54` (`classifierDomainOnlyMode`, `classifierSetIsDomainOnly`), trace `traceNFQDecision` (стр. 192-193: `domain_only=%s/%s set=%s strategy=%s`), структурированные поля `domain_only`/`domain_result` (стр. 264-265); scoped hints `src/nfq/dns_hints.go:94-118`;
- UI: `src/http/handler/classifier_v23.go:37,109` (`DomainOnlyModes` = 4 режима), hot-apply `classifier_v23_test.go:119-126`;
- тесты: `src/classifier/policy_test.go:214-246` (все 4 режима), `src/nfq/classifier_decision_test.go:13+`, `config/domain_policy_test.go`, `authoritative_sni_test.go`.

(c) Оценка: PASS

(d) Замечания:
1. Миграция «булевого конфига → legacy» подтверждена только для пустого/отсутствующего значения (migration.go:43-44); явного маппинга старого `domain_only: true/false` (булево) не найдено — старый булев ключ, скорее всего, отбросится схемой типов, и дефолт legacy применится сам по себе (результат совпадает, но механизм не задокументирован).
2. Decision order в policy.go соблюдён, но приоритет set-level (`set.Targets.DomainOnly`, classifier_decision.go:312) vs global mode местами пересекается с config/domain_policy.go:60-76 — связка «global mode × set flag» выражена не в одном месте.

---

## Stage 14 — Observe-only TCP reassembly

(a) Документ требует:
- RangeSet: base sequence, exact record length, out-of-order, retransmission, identical/conflicting overlap, multiple records/trailing data, timeout/FIN/RST/generation abort, memory budgets;
- observe-only: не задерживать original packets и не менять action;
- metrics complete/abort reason/bytes/time/segments.

(b) Что в коде:
- `src/classifier/tcp_ranges.go` — полный RangeSet: `Insert` с identical/conflicting overlap detection (стр. 91-152), `EstimateNewBytes` (стр. 64-89), бюджеты `maxBytes/maxRanges` (стр. 40-48, 102-103, 146-148), `Contiguous` (стр. 156-184), ошибки `ErrRangeBudget/ErrRangeConflict/ErrRangeOverflow` (стр. 8-12);
- `src/classifier/tcp_reassembly.go` — store (стр. 116-153), конфиг с 6 лимитами (стр. 47-67: MaxFlows=1024, MaxBytesPerFlow=32KB, MaxBytesTotal=4MB, MaxSegments=64, MaxClientHello=32KB, Timeout=5s), abort-причины budget/conflicting-overlap/malformed/sequence-before-base/manual (стр. 40-45), `ObserveEvent`/`Close` (FIN/RST/generation, стр. 356-380), GC (стр. 382-394); явный observe-only контракт (стр. 116-118);
- production-путь: `src/nfq/tcp_reassembly_observe.go:15-49` — активен только при `TCPReassemblyMode == ReassemblyObserve`, возвращает результат, не меняя action/verdict; store инстанцируется в `src/nfq/pool.go:27`, release hold при complete/aborted `handler.go:394-396`;
- metrics: `src/observability/observability.go:29-31` (started/completed/aborted);
- тесты: `tcp_ranges_test.go` (включая fuzz, стр. 46+), `tcp_reassembly_test.go`, `nfq/tcp_reassembly_test.go`, `nfq/tcp_reassembly_visibility_test.go`.

(c) Оценка: PASS

(d) Замечания:
1. Дефолт `TCPReassemblyMode = ReassemblyOff` (config/types.go:133) — observe-режим полностью опционален, что соответствует «observe-only», но означает: диагностическая ценность недоступна без явного включения.
2. `RangeSet` не синхронизирован сам по себе (tcp_ranges.go:31-32) — синхронизация только на уровне flow-хранилища; при ошибке в интеграции возможен data race, но в текущих вызовах (под mutex store) безопасно.

---

## Stage 16 — Auto hold/replay (off/observe/auto/always-debug), fail-open abort paths

(a) Документ требует:
- режимы off / observe / auto / always-debug;
- auto policy: hold только при incomplete ClientHello + ниже порога + бюджеты + не ServerProgress/closed + policy позволяет;
- ВСЕ abort paths (timeout, malformed/conflicting overlap, FIN/RST, shutdown, pressure, generation change) release unchanged;
- Keenetic guard: дефолтные timeout/budgets валидированы.

(b) Что в коде:
- режимы: `src/config/types.go:92-95` (`HoldReplayOff/Observe/Auto/Debug`), валидация `src/config/validation.go:393-396`; `src/nfq/tcp_hold_worker.go:13-37` (`holdReplayMode`, `holdReplayActive`, `holdReplayObserve`);
- auto-условия: `maybeHoldTCPPacket` (tcp_hold_worker.go:73-105) — partial CH + `NeedBytes>0` + `payload[0]==0x16` + нет clear SNI/scoped hint + visibility gate + режим; Hold-бюджеты через store;
- abort paths: timeout (GC, `tcp_hold_store.go:109-125`), pressure (стр. 27-38, 44), generation change (стр. 24-26, 92), visibility incomplete (стр. 16-19, 74-79 + SubscribeBlocked `tcp_hold_config.go:104-106`), shutdown (стр. 99-107), server-progress (`releaseTCPHoldOnServerProgress`, worker.go:58-67, вызывается handler.go:242), evidence-confirmed (worker.go:87);
- fail-open: release = `SetVerdict(NfAccept)` (store.go:193-204), store хранит оригинальные NFQUEUE packet ID (комментарий tcp_hold_config.go:71-73);
- бюджеты дефолтные: `src/config/classifier_v23.go:335` (256 flows / 8 pkt / 64KB / 750ms) с range-валидацией `classifier_v23_validation_flow.go:26-30`;
- тесты: `tcp_hold_test.go`, `tcp_hold_visibility_test.go`, `tcp_hold_worker` покрыт через nfq-тесты.

(c) Оценка: PARTIAL

(d) Замечания:
1. Константы `tcpHoldAbortFIN`/`tcpHoldAbortRST` объявлены (tcp_hold_config.go:17-18), но нигде не используются: нет явной ветки FIN/RST release — held-пакет при RST останется до таймаута (750 мс) или server-progress. Fail-open сохранён (release = ACCEPT), но план требует явный FIN/RST abort, которого в коде нет.
2. Режимы `auto` и `always-debug` неразличимы в логике (`holdReplayActive` возвращает true для обоих, tcp_hold_worker.go:30-33) — «always-debug» не даёт «всегда держать» поведение; debug-отличие только в логе (worker.go:101).

---

## Stage 18 — First-flight-only + retransmission idempotency (ActionTokenStore)

(a) Документ требует:
- один action на логический ClientHello; retransmission suppressed; partial overlap suppressed; new flow allowed; ServerProgress закрывает mutation window; rollback инвалидирует candidate tokens; budget перед send;
- тесты: exact/reordered retransmit, timeout/retry, duplicate NFQUEUE delivery, config hot apply, processed mark bypass, amplification cap.

(b) Что в коде:
- `src/action/token_types.go:71-99` — `ActionTokenStore` (MaxFlows=4096, Timeout=5min, bounded, race-safe);
- `src/action/token_claim.go` — `Claim`: invalid → suppressed (стр. 12), processed provenance mark → suppressed (стр. 16), generation invalidated → suppressed (стр. 37), server progress → suppressed (стр. 49), retransmission → `Reused+Suppressed` (стр. 52-54), первый логический ClientHello → claim (стр. 70-75);
- overlap: suppress по `StreamStart/StreamEnd` в рамках `ClientHelloID` (token_test.go:20-23);
- lifecycle: `src/action/token_lifecycle.go` — `CloseServerProgress` (стр. 9), `InvalidateGeneration` (стр. 27), GC;
- интеграция: `src/action/strategy.go:100-149` и `src/action/tlsrecordsplit.go:109-151` — `FirstFlightOnly` прекондиция + Token claim + `ErrRetransmission`; `handler.go:417-419` — `CloseServerProgress` на FIN/RST; budget перед планированием `src/action/budgets.go:11-45` (amplification cap 4x);
- метрика `MetricTCPActionTokenReuse` (observability.go:35);
- тесты: `token_test.go` (включая fuzz стр. 84+, benchmark), `tlsrecordsplit_test.go:54-62`, `strategy_test.go:145-160`, `token_visibility_test.go`.

(c) Оценка: PASS

(d) Замечания:
1. «Rollback инвалидирует candidate tokens» — `InvalidateGeneration` есть, но вызова из runtimecontrol.Rollback в коде не найдено: связь rollback ↔ token invalidation не подтверждена на уровне вызовов (возможно, скрыта внутри `liveRuntime.Rollback`, но прямой ссылки нет).
2. Duplicate NFQUEUE delivery покрыт тестами через повторный Claim с тем же ClientHelloID; а вот поведение при смене `ClientHelloID` при ретрае (новый token для того же flow) разрешено как «new logical ClientHello» — соответствует плану.

---

## Stage 19 — Executor fail-safe

(a) Документ требует:
- централизованный packet builder; checksum/length validation; raw send error handling; mark verification; action budget enforcement; partial send handling; cleanup on cancellation; fail-open при невалидном плане;
- тесты: re-entry, send failure, invalid MTU, IPv4/IPv6, TCP options, max writes/bytes/delay.

(b) Что в коде:
- builder: `src/action/packet_builder.go` — `Build` (стр. 18-67: IPv4/IPv6, MTU, пересчёт IP/TCP checksum), `ValidatePacket` (стр. 69-94: длина + IPv4 csum==0 + TCP csum==0);
- executor: `src/action/executor.go` — `ExecuteContext` (стр. 66-151): `!plan.Valid` → FailOpen (стр. 71-75), `RequirePlanMark` (стр. 76-80), mark mismatch → FailOpen (стр. 81-85), бюджет MaxWrites/MaxBytes → FailOpen (стр. 86-90), delay budget (стр. 93-97, 108-113), sender nil → FailOpen (стр. 102-106), build-ошибка → FailOpen + PartialSend (стр. 120-130), `ValidatePacket` fail → FailOpen (стр. 131-136), send error → FailOpen + PartialSend (стр. 137-142), cancellation через ctx (стр. 153-173);
- fail-open семантика: Executor не имеет NFQUEUE-verdict — при любой ошибке пакет не дропается, только результат FailOpen/PartialSend;
- бюджеты: `src/action/budgets.go:11-45`;
- тесты: `src/action/executor_test.go`.

(c) Оценка: PASS

(d) Замечания:
1. PartialSend корректно помечен и останавливает дальнейшие writes, но «частичная отправка» (несколько пакетов уже в ядре) не компенсируется — для первого ClientHello это допустимо (idempotency на уровне token, Stage 18), но в метриках нет отдельного counter для partial-send.
2. `RequirePlanMark` выключить нельзя из конфига (всегда true в `DefaultExecutorConfig`), что безопасно, но делает конфигурационный параметр мёртвым.

---

## Stage 20 — Metrics, trace, issue bundle v2 (redacted, no raw ClientHello)

(a) Документ требует:
- все metrics: classifier/evidence/confidence, capture/queue/offload, FSM/reassembly, action/token/amplification, ECH fallback, Discovery outcomes;
- trace: structured JSON + human-readable;
- issue bundle: versions/commit/config hash, redacted client/flow IDs, DNS/QUIC/TLS evidence, FSM/action timeline, queue/offload status, ProbeOutcome, no raw ClientHello unless explicit.

(b) Что в коде:
- метрики: `src/observability/observability.go:18-78` — полный набор (classifier/evidence/confidence, capture/queue/offload, reassembly, action/token/amplification, ECH, discovery, failure/candidate, fallback, passive-RST); registry bounded (стр. 127-179);
- trace: `TraceRecorder` (стр. 226-271) с принудительной redaction ID и полей (стр. 246-248, 459-488 `sensitiveFieldKey`), JSON + `Text()` (стр. 421-425);
- bundle: `IssueBundle` (стр. 319-329) — `Versions`/`ConfigHash` (BundleMeta стр. 309-317), `QueueSummary` (стр. 291-298), `ProbeOutcomeSummary` (стр. 300-307), `EvidenceSummary` (стр. 282-289), `RawCapture: false` жёстко (стр. 328, 401); redaction `RedactIdentifier`/`RedactDomain` (стр. 408-419), RecordEvidence redacts SetID/DomainID (стр. 352-353);
- no raw ClientHello: в логах nfq/метриках ClientHello-контент не пишется (grep по src/log пуст; метрики содержат только размеры/sni_hash); `src/lab/clienthello_capture.go` — опциональная лаборатория, сама redact-ит (стр. 536, 541);
- тесты: `observability_test.go` — leak-check (стр. 65), `RawCapture` запрет (стр. 68-69), schema (стр. 85-92).

(c) Оценка: PASS

(d) Замечания:
1. «FSM/action timeline» в bundle представлен только Trace-событиями без отдельной типизированной секции — функционально покрыто, но не выделено в схеме.
2. `sensitiveFieldKey` — allowlist/denylist гибрид: поля вроде `clienthello_size`/`domain_result` помечены как нечувствительные явно; новый ключ по умолчанию НЕ redact-ится (если не содержит суффикса), т.е. риск утечки новых полей через trace лежит на разработчике.

---

## Stage 27 — Transactional apply, last-good, canary, cooldown, rollback

(a) Документ требует:
- транзакция: validate → build immutable generation → allocate runtime → queue readiness → canary probes → atomic promote → drain previous;
- last-good: только хэши schema/config/strategy/set + validation summary, не live flows/hints;
- canary: client group, set, new-flow %, duration, min samples, explicit stop;
- cooldown: scoped by set/client/protocol/candidate generation;
- rollback: atomic generation restore, state/token cleanup, candidate worker shutdown, reason/metrics/history.

(b) Что в коде:
- транзакция: `src/runtimecontrol/rollout_manager_apply.go:16-131` — validate (38-42) → build (49-56) → readiness (57-65) → canary (66-75) → last-good Prepare (77-80) → Promote (90-95) → `active.Store` (97) → Commit с откатом active при ошибке (98-108) → drain previous (111-122); стадии в `TransactionError` (rollout_types.go:38-51); staged-вариант `rollout_manager_pending.go` (Prepare/CanaryPending/PromotePending/AbortPending, стр. 12-211);
- readiness через реальный procfs owner-PID: `live_runtime.go:138-140`; канарейка со steering rules и stop-условиями: `live_runtime.go:152-242` (MaxFailures/MaxFailureRate/QueueDrops, finishCanary с MinSamples стр. 244-289);
- last-good: `LastGoodRecord` (rollout_types.go:234-244) — только хэши/ids/validation/canary; явный запрет live flows (стр. 261-262); `FileLastGoodStore` — atomic write + pending sidecar, crash-safe (rollout_store.go:78-172);
- cooldown: `CooldownKey{SetID, ClientGroup, Protocol, CandidateGeneration}` (rollout_store.go:174-199), Check/RecordFailure/RecordSuccess;
- rollback: `rollout_manager_apply.go:140-191` — Resume previous → активная смена → Commit → `current.runtime.Rollback(reason)` → Close → восстановление lastGood; cleanup кандидата при любой ошибке (стр. 205-209); метрики promote/rollback (стр. 129, 189), история (стр. 211-218);
- тесты: `rollout_staged_test.go` (commit-failure restore стр. 70-120, rollback commit failure), `rollout_apply_test.go`, `gso_topology_transaction_test.go`, `live_runtime_test.go`.

(c) Оценка: PASS

(d) Замечания:
1. Критичный риск конкурентности: одношаговый `Apply` держит `m.mu` на протяжении всей транзакции, включая canary (rollout_manager_apply.go:33-34 + canary до `MaxCanaryDuration = 1h`, rollout_types.go:21) — на всё это время блокируются Prepare/Rollback/AbortPending/Close. Staged-путь (pending) этого избегает, но одношаговый API остаётся блокирующим.
2. «State/token cleanup» при rollback делегирован интерфейсу `Runtime.Rollback` (rollout_types.go:109, live_runtime.go:334 — тело Rollback минимально: остановка pool); явного вызова `ActionTokenStore.InvalidateGeneration`/release held flows в runtimecontrol не видно — clean-up держится на реализации pool/worker'ов и не проверен на уровне кода.

---

## Сводка

| Stage | Оценка | Ключевой evidence |
|-------|--------|-------------------|
| 4. Capture Envelope + processed mark | PASS | capture/envelope.go:196-229; readiness.go:126-180; offload_check.go:70 |
| 7. Clean SYN pass | PASS | nfq/tcp_gate.go:11-13; handler.go:421-424; classifier/tcp.go:22-27 |
| 12. DomainOnly v2 | PASS | classifier/policy.go:208-215; config/types.go:83-89,130; http/handler/classifier_v23.go:109 |
| 14. Observe-only reassembly | PASS | classifier/tcp_ranges.go:91-152; tcp_reassembly.go:47-67; nfq/tcp_reassembly_observe.go:15 |
| 16. Auto hold/replay | PARTIAL | tcp_hold_worker.go:13-37; tcp_hold_config.go:17-18 (мёртвые FIN/RST) |
| 18. ActionTokenStore | PASS | action/token_claim.go:9-75; token_lifecycle.go:9,27 |
| 19. Executor fail-safe | PASS | action/executor.go:66-151; packet_builder.go:69-94 |
| 20. Metrics/trace/bundle v2 | PASS | observability.go:319-329,408-419; no raw ClientHello (log/ пуст) |
| 27. Transactional apply | PASS | rollout_manager_apply.go:16-131,140-191; rollout_store.go:78-199 |

---

## Три самых серьёзных расхождения документа и кода

1. **Stage 16: явные FIN/RST abort-пути hold отсутствуют.** План требует «timeout; malformed/conflicting overlap; FIN/RST; shutdown; pressure; generation change — все abort paths release unchanged». Константы `tcpHoldAbortFIN`/`tcpHoldAbortRST` объявлены (src/nfq/tcp_hold_config.go:17-18), но не используются нигде: в handler.go на FIN/RST (стр. 410-420) релизятся passiveRST/gsoPassTokens/actionTokens, но НЕ tcpHold. Held-пакет при RST висит до таймаута 750 мс (или server-progress). Fail-open (release = NfAccept) сохранён, но явного пути нет.

2. **Stage 27: глобальная блокировка `m.mu` на время canary-транзакции (до 1 часа).** `Apply` берёт `m.mu.Lock()` (src/runtimecontrol/rollout_manager_apply.go:33-34) и держит его через `runtime.Canary` (стр. 66), чей `Duration ≤ MaxCanaryDuration = 1h` (rollout_types.go:21, live_runtime.go:212). Всё это время заблокированы Prepare/Rollback/AbortPending/Close — транзакционная модель не сериализует, а парализует control-plane. Staged-путь (rollout_manager_pending.go) этой проблемы избегает.

3. **Stage 4: CaptureEnvelope не подключён к генерации правил.** Envelope полностью реализован и протестирован, но используется только в диагностике (`http/handler/diagnostics.go:293-312`) и readiness (runtimecontrol/discovery/topology); флаг `CaptureEnvelopeEnabled` (config/types.go:106) не влияет ни на какие правила. Ядро-контур first-N/SYN-ACK/FIN/RST/QUIC в реальных iptables-правилах не строится из `CaptureEnvelope.Decide` — bypass остался на старом `cfg.Queue.Mark` (tables/iptables.go:361-362). «Правило» и «envelope» не связаны, что делает весь первый-N контур неработающим в production-пути (только диагностика).

Сопутствующие риски (менее критичны): rollback↔token invalidation не связаны явным вызовом (Stage 18/27); режимы auto и always-debug неразличимы (Stage 16); миграция булевого domain_only → legacy не реализована явно, только «пусто → legacy» (Stage 12).
