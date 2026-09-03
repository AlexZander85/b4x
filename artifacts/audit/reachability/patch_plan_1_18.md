# Reachability audit: B4_FORK_PATCH_PLAN.md этапы 1–18

Дата: 2026-07-31. Read-only, без запуска кода (production-код Linux-only; build tags только у capture/ppe/signal_bridge_unix.go). Легенда: **REACHABLE** — root→wiring→runtime owner→implementation→side effect→cleanup подтверждены; **PARTIAL** — часть DoD не достижима из production; **FAIL** — механизм существует, но production-вызовов нет; **NA** — deliverable не runtime-механизм.

## Общие production-roots
- `src/main.go:79` main() → :86 runB4(): :111 cfg.EnsureRuntimeGeneration(), :185/:320 tables.AddRules, :221 cfg.Validate(), :248 nfq.NewPool(&cfg), :369 b4http.StartServer(&cfgPtr, pool).
- Пакетный путь: src/nfq/handler.go:44 handlePacket → :72 dispatch (TCP handleTCPPacket, UDP :935 observeQUICHandoff); processed-mark bypass :58, offload decode :54.
- Wiring воркеров: src/nfq/pool.go:19 NewWorkerWithQueue (dnsHints/tcpReassembly/tcpHold/clientHelloClaims/gsoPassTokens/actionTokens), спец-пулы :69/:75/:82; connstate.go:400 actionTokens.
- Конфиг-гейты: src/config/types.go:102-113 (флаги; дефолты :130-134: DomainOnlyLegacy, ReassemblyOff, HoldReplayOff; bool-флаги false); config/validation.go:363-396 (enums; active reassembly запрещён).

## Этап 1. Baseline implementation audit — NA (документ)
- DoD = документ: docs/audit/b4-1.73-flow-path.md существует (:309 флаги, :381 hold/reassembly disabled by default, :389 readiness NO-GO). Runtime-механизмов нет.

## Этап 2. Regression fixtures — NA (test-only по дизайну)
- src/fixtures/corpus.go + android_corpus.json (embed). Импортируется только из *_test.go (17 файлов). План не требует fixtures в production-графе.

## Этап 3. Config/version scaffolding — REACHABLE
- Wiring: main.go:111 EnsureRuntimeGeneration, :221 Validate; реализация config/config.go:328-333 (immutable UUID generation), classifier_v23.go (SchemaVersion v2.3), validation.go:363-396, migration.go:43-44.
- Потребление: nfq/dns_hints.go:154 dnsHintConfigGeneration; флаги читаются в dns_hints.go (ScopedDNSHintsEnabled), quic_handoff.go (QUICToTCPHandoffEnabled), tcp_reassembly_observe.go:14 (TCPReassemblyMode), tcp_hold_worker.go:13 (TCPHoldReplayMode/AutoHoldReplayEnabled), gso_fastpath.go:43/54 (GSOMode), classifier_decision.go:31 (classifierDecisionEnabled).
- Cleanup: pool.go:325/:379 InvalidateGeneration при смене поколения.

## Этап 4. Capture Envelope + processed mark — PARTIAL
- **REACHABLE**: mark-контракт — capture/marks.go, senders nfq.go:66 (ProcessedMarkFor), bypass handler.go:58; firewall-исключение tables/iptables.go:365,622-631, nftables.go:197,246-259; SYN-ACK/RST/FIN правила iptables.go:411-455,521-536; queue-bypass во всех NFQUEUE (iptables.go:223-225); readiness — capture/readiness.go:126 CheckQueueReadiness, вызов discovery/runtime_backend.go:72; offload self-check — handler.go:54 DecodeOffloadMetadata; production/candidate разделение — capture/envelope.go:28-34, gso_topology.go:16-22, пулы pool.go:69/75/82, topology.go:114.
- **НЕ достижимо**: CaptureEnvelope.Decide (envelope.go:196, first-N/AlwaysQueue-поля) вызывается только из http/handler/diagnostics.go:293 (API snapshot) и тестов — пакетный путь её не использует (семантика материализована в правилах tables + Queue config). Severity: LOW.

## Этап 5. ClassificationPhase/Evidence/Confidence — REACHABLE
- classifier/types.go (ClassificationPhase, Evidence, ClassificationDecision, ConfidenceThresholds), evidence.go:9/28/35 (EffectiveConfidence/IsFresh/ValidForContext), policy.go (Decide, CanClassify/CanMutate/CanDestructivelyMutate/CanUseHostMarkers/CanProxyFallback).
- Runtime owner: nfq/classifier_decision.go:108 decideNFQEvidenceScoped (Decide :111/:163); callers handler.go:310/:386, gso_fastpath.go:113, gso_token.go:292. Side effect: decision→matched/strategy; trace classifier_decision.go:217.

## Этап 6. Client identity — REACHABLE
- classifier/identity.go (ClientKey, IdentityQuality, MACLookupState, :134 IdentityStore.Resolve). Потребители: nfq/dns_hints.go:126 dnsClientKey, handler.go:295/:363, matchScopedDNSHintWithMetadata (dns_hints.go:68). Late ARP, bounded cache, no cross-VLAN merge.

## Этап 7. Clean SYN pass + TCP FSM — PARTIAL
- **REACHABLE**: инвариант nfq/tcp_gate.go:11 shouldPassCleanSYN → handler.go:421 (FIN/RST cleanup :410-420).
- **FAIL (подкритерий FSM)**: classifier/tcp.go:303/:311 TCPFlowStore/NewTCPFlowStore конструируются ТОЛЬКО в tcp_test.go:98/:124 — в production ни одного вызова; TCPFlowPhase/Transition в runtime отсутствуют. ServerProgress реализован лишь как actionTokens.CloseServerProgress (handler.go:418). Severity: MEDIUM — «явная FSM-машина» — библиотека; поведение держится на legacy-коде (desync.go, extsplit.go, combo.go, firstbyte.go, disorder.go).

## Этап 8. Bounded HostHintStore — REACHABLE
- classifier/hints.go (HintKey, HostHintStore: Observe/Lookup/LookupForGeneration/InvalidateGeneration/DeleteClient/GC/Stats). Wiring: pool.go:26. Owner: nfq/dns_hints.go:17 observeDNSResponse → dns.go:216 (system DNS), :279 (DoH); Lookup :62/:80 → handler.go:331. Cleanup: GC, DeleteClient, pool.go:325/:379. Гейт: ScopedDNSHintsEnabled (default false).

## Этап 9. Structured DNS parser — REACHABLE
- dns/structured.go (A/AAAA/CNAME/HTTPS/SVCB/ECHConfig, RCODE/TTL, bounds/pointer-loop), dns/query.go, doh.go. Потребитель: nfq/dns_hints.go:55 (ParseStructuredResponse), dns.go:39/:81. Negative → без positive hint.

## Этап 10. DNS → first-flow — REACHABLE
- DoH: dns.go:279 observeDNSResponse (до :305 sendDNSResponseToClient). System DNS: :216. Set resolution: handler.go:331 matchScopedDNSHint. NXDOMAIN/SERVFAIL → диагностика, не hint.

## Этап 11. QUIC → TCP handoff — REACHABLE
- handler.go:935 observeQUICHandoff (UDP path); quic_handoff.go:13/:20 (TTL 90s); парсеры quic/parse.go|sniff.go|initial.go|locate.go. Гейт: QUICToTCPHandoffEnabled (default false). Source-scoped.

## Этап 12. NFQ decision + DomainOnly v2 — REACHABLE
- nfq/classifier_decision.go: classifierDomainOnlyMode :15, classifierDecisionEnabled :31, classifierSetIsDomainOnly :41, decideNFQEvidenceScoped :108; callers handler.go:310/:324/:386, gso_fastpath.go:113, gso_token.go:292. Моды strict/scoped-hints/legacy/disabled — config/domain_policy.go:60 EffectiveDomainPolicy; legacy-дефолт types.go:130, migration.go:43; boolean DomainOnly → legacy (validation.go:139, domain_policy.go:95).

## Этап 13. Structured TLS metadata — REACHABLE
- sni/metadata.go (complete/incomplete, SNI, ALPN, ECHPresent, size), classifier/types.go TLSMetadata. Потребители: nfq/tls.go, authoritative_sni.go:27/:31 → handler.go:265; merge tcp_reassembly_metadata.go:12 (гейты: observe + ppe visibility). Backward wrapper: classifier_decision.go:100-101.

## Этап 14. Observe-only TCP reassembly — REACHABLE (config-gated, fail-open)
- classifier/tcp_ranges.go, tcp_reassembly.go (TCPReassemblyStore, LogicalClientHelloID, бюджеты). Wiring: pool.go:19. Owner: handler.go:259-261 observeTCPReassembly + submitClientHelloSegment (гейты: sequenceOK, !Truncated, TCPReassemblyMode==observe, tcp_reassembly_observe.go:14 ppe.DefaultVisibilityGate). Abort: handler.go:291-303 (conflict → tcpHold.Release + SignalReassemblyAbort + fail-open), :394-396. Observe-only не меняет action (validation.go:391).

## Этап 15. ECH-aware evidence policy — REACHABLE
- classifier/policy.go Decide (ECH corroboration; no final unknown on ECH — fail-open), ECHPresent из sni/metadata; решение handler.go:310/:386, gso_token.go:292. Scoped lookup handler.go:331. Contradiction → fail-open handler.go:291-303.

## Этап 16. Auto hold/replay — REACHABLE (config-gated, default off, fail-open)
- nfq/tcp_hold_worker.go (holdReplayMode:13, maybeHoldTCPPacket → handler.go:427), tcp_hold_store.go:12 Hold (+Release/ReleaseAll, visibility-abort), tcp_hold_config.go:24/:32. Wiring: pool.go:19; GC pool.go:183-185 (30s); ReleaseAll на shutdown nfq.go:463. Моды off/observe/auto/always-debug (validation.go:393-396). Условия hold: incomplete ClientHello, бюджеты (MaxFlows 256, MaxPacketsPerFlow 8, MaxBytesTotal 64KB, TimeoutMS 750), ReleaseOnPressure, не ServerProgress (handler.go:242). Abort-пути: timeout (GC), pressure, FIN/RST (handler.go:410-420), conflict (:291-293), generation, shutdown.

## Этап 17. Stream-offset planner — FAIL (severity HIGH)
- action/stream_map.go, markers.go, planner.go:69 Plan, packet_builder.go — существуют и протестированы (planner_test.go).
- **Production-вызовов Plan нет** (grep по src: только тесты и библиотечные вызовы из unwired hostfakesplit/fakemix/tlsrecordsplit). Production продолжает legacy-инъекции: handler.go:434+ (duplicate), extsplit.go, desync.go, combo.go, firstbyte.go, disorder.go, syn.go sendFakeSyn, inc.go HandleIncoming.
- DoD «перевести существующие fake/split/combo actions на planner» не выполнен. Расхождение с patch_plan_audit.md (PARTIAL): по критерию runtime owner — FAIL.

## Этап 18. First-flight + retransmission idempotency — REACHABLE
- clientHelloDecisionClaimStore: authoritative_sni.go:98 (newClientHelloDecisionClaimStore, Claim:108, GC:136), wiring pool.go:19, вызов handler.go:373-377 (Claim перед side effects; duplicate → suppressed). ClientHelloID: handler.go:282, ConfigGen guard :278-280.
- actionTokens: action/token_*.go, wiring connstate.go:400, pool.go:31; Claim gso_token.go:302, CloseServerProgress handler.go:418, InvalidateGeneration pool.go:325/:379, Clear topology.go:170.

## Ложные readiness
1. artifacts/audit/patch_plan_audit.md:17 (Этап 7) — «IMPLEMENTED (wired)» для TCP FSM: в проде нет конструктора TCPFlowStore (только tcp_test.go:98/:124); фактически PARTIAL.
2. artifacts/audit/patch_plan_audit.md:27 (Этап 17) — «PARTIAL (библиотека)»; по строгим критериям — FAIL (ноль production-вызовов, legacy-пути активны).
3. artifacts/audit/patch_plan_audit.md статусы «wired» для этапов 4–16 основаны на импортах, не на runtime-вызовах; большинство механизмов активны только при флагах default-off — «IMPLEMENTED» не означает production-активность.
4. docs/reports/cross-service/CSI_IMPLEMENTATION_REPORT.md:13 (CSI-3) — «Complete bounded reassembly feeds the authoritative matcher» — верно только при TCPReassemblyMode=observe (default off) + visibility; без оговорки вводит в заблуждение.
5. Корректные (НЕ ложные): b4-1.73-flow-path.md:389 (NO-GO), rst-gso-h10.md:7, PPE_STAGE_7_VALIDATION_REPORT.md (PASS_WITH_LIMITATIONS с дисклеймером).

## Сводка
| Статус | Этапы |
|---|---|
| REACHABLE (13) | 3, 5, 6, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18 |
| PARTIAL (2) | 4 (envelope.Decide не в пакетном пути), 7 (FSM-хранилище не wired) |
| FAIL (1) | 17 (planner — библиотека без production-владельца, HIGH) |
| NA (2) | 1 (документ), 2 (fixtures test-only по дизайну) |
