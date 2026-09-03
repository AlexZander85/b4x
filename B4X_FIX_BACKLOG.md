# B4X_FIX_BACKLOG.md

Repository: AlexZander85/b4x · Branch: agent/classifier-v2.3-capture-envelope · Commit: `49a73e177601f33f067fbdc8ed91317fe51eef10`


Total backlog items: **10**


## Приоритетная сводка

| # | ID | Priority | Subsystem | Findings | Complexity |
|---|---|---|---|---|---|
| 1 | `B4X-FIX-0001` | P1 | Transparent Telegram Bridge | B4X-AUDIT-0006 | S |
| 2 | `B4X-FIX-0002` | P1 | Continuous Monitoring / Legacy Watchdog | B4X-AUDIT-0009 | M |
| 3 | `B4X-FIX-0003` | P1 | Adaptive Blocking Detector + Detector-Guided Discovery | B4X-AUDIT-0008, B4X-AUDIT-0007 | L |
| 4 | `B4X-FIX-0004` | P1 | WARP/MASQUE Transport | B4X-AUDIT-0003 | XL |
| 5 | `B4X-FIX-0005` | P1 | Implementation Validation Framework | B4X-AUDIT-0004 | L |
| 6 | `B4X-FIX-0006` | P2 | Field Test Automation Controller | B4X-AUDIT-0010 | L |
| 7 | `B4X-FIX-0007` | P2 | Silent Path Failure & Scoped Recovery | B4X-AUDIT-0005 | M |
| 8 | `B4X-FIX-0011` | P3 | Service Profile Framework | B4X-AUDIT-0011 | L |
| 9 | `B4X-FIX-0002B` | P4 | Transactional Runtime | B4X-AUDIT-0001 | S |
| 10 | `B4X-FIX-0004B` | P4 | Cross-Service Isolation — legacy learned-IP | B4X-AUDIT-0002 | S |

---

## Полные записи


### B4X-FIX-0001 — Transparent Telegram Bridge (P1)
- **Finding IDs**: B4X-AUDIT-0006
- **Likely affected files**: mtproto/transparent.go, mtproto/pending_manager.go, mtproto/handshake_state.go, mtproto/prefix_handoff.go
- **Problem summary**: Zero-byte / dial-failure timeout in Handle() still returns true,nil (destructive drop), verbatim unchanged from upstream issue #277's reported defect. New supporting code exists but is never called.
- **Required implementation outcome**: Handle() routes through PendingHandshakeManager.Acquire() at accept; head==0 and DialObfuscatedDCWithPool-failure branches return a fail-open handoff (false, &prefixConn{...}) instead of true,nil.
- **Tests to add/repair**: Regression test reproducing issue #277's exact timing pattern (first byte at 4.9s vs 5.1s per FT-AA); unit test for the DialObfuscatedDCWithPool failure branch.
- **Field validation required**: FT-AA field suite (Field Test Automation) once its own controller is wired (see B4X-FIX-0002/0009).
- **Acceptance criteria**: ISSUE_277_RESOLVED can be claimed with reproducible evidence, not just unit-isolated new code.
- **Dependencies**: none blocking
- **Risk**: Low risk, well-scoped, self-contained fix
- **Estimated complexity**: S

### B4X-FIX-0002 — Continuous Monitoring / Legacy Watchdog (P1)
- **Finding IDs**: B4X-AUDIT-0009
- **Likely affected files**: watchdog/applier.go, watchdog/watchdog_heal.go, config/config.go, config/types.go, monitor/*.go, docs/reports/mon-12-field-validation.md
- **Problem summary**: Legacy watchdog.applyBatchResults() remains fully live (SkipDNS/ValidationTries:1 shortcuts, watchdog-* set creation), violating the project's own top-level ADR-014 prohibition. Required legacy_watchdog_direct_apply config field does not exist. New monitor/ core never starts. Existing report makes an unverified/false claim about this gate's status.
- **Required implementation outcome**: (a) Start monitor.DiagnosticScheduler in main.go; (b) add the legacy_watchdog_direct_apply config field defaulting false with startup warning if true; (c) gate or remove applyBatchResults()'s forbidden shortcuts; (d) correct docs/reports/mon-12-field-validation.md's specific claim.
- **Tests to add/repair**: Unit test asserting no direct apply is reachable once new monitor core is active (per doc's own §77 requirement, currently absent); test for the new config field's default/warning behavior.
- **Field validation required**: MON-12 field validation stage, FT-MON-A suite (needs to be added to Field Test Automation doc per its own §96 cross-reference, currently missing).
- **Acceptance criteria**: monitor_legacy_watchdog_direct_apply_total==0 can be measured and is actually zero; report claims match verified code behavior.
- **Dependencies**: none blocking
- **Risk**: Highest-priority non-safety-critical-yet finding: real users on pre-existing Watchdog.Enabled=true installations affected
- **Estimated complexity**: M

### B4X-FIX-0003 — Adaptive Blocking Detector + Detector-Guided Discovery (P1)
- **Finding IDs**: B4X-AUDIT-0008, B4X-AUDIT-0007
- **Likely affected files**: detector/abd_*.go, monitor/abd_adapter.go, discovery/hint_planner.go, discovery/adaptive.go, discovery/guided_api.go
- **Problem summary**: CompileBlockingProfile, ABDEscalationAdapter.Begin, and CompileHintPlan are all unreachable/inert (the latter discards its detector-typed parameter internally even if called). The MON->ABD->DDI pipeline described as the document's central chain does not function end-to-end.
- **Required implementation outcome**: (a) Wire monitor's trigger-decision logic to call ABDEscalationAdapter.Begin; (b) wire Begin() to execute the real abd_*.go probe/evidence/profile pipeline; (c) fix CompileHintPlan to use its prior parameter and ensure something calls it with a real ABD-produced DiscoverySearchPrior; (d) wire discovery/hint_planner.go or adaptive.go to consult the resulting GuidedSearchPlan.
- **Tests to add/repair**: End-to-end integration test: monitoring signal -> ABD run -> EvidenceGraph -> BlockingProfile -> DiscoverySearchPrior -> observable change in Discovery's actual candidate ordering.
- **Field validation required**: Real router/Android field validation per ABD-12/DDI-10 stages.
- **Acceptance criteria**: A traceable, reproducible example of detector evidence measurably changing Discovery's search order in production.
- **Dependencies**: B4X-FIX-0002 (shares MON-side trigger wiring)
- **Risk**: Missing enhancement, not a regression; moderate complexity given the pipeline spans 3 packages
- **Estimated complexity**: L

### B4X-FIX-0004 — WARP/MASQUE Transport (P1)
- **Finding IDs**: B4X-AUDIT-0003
- **Likely affected files**: warp/*.go, go.mod, config/types.go
- **Problem summary**: No functional MASQUE/CONNECT-IP data-plane exists. warp/ package is isolated policy/type scaffolding only, never imported, missing all dependencies, config schema, API, and doesn't match the document's own recommended repository layout (cmd/b4-warpd, third_party/usque, src/transport/warp/).
- **Required implementation outcome**: Either (a) implement the actual transport (vendor/wrap usque per Appendix A, wire config/API/route-binding integration) as a substantial new project, or (b) if this is intentionally an early-stage/deferred feature, correct all status reporting (docs/reports/warp/*.md, and dependent SP-16..32/FT-M..AD/IV-6/8/12/17 stage-completion claims) to accurately reflect 'policy scaffolding only, no transport'.
- **Tests to add/repair**: Integration test exercising a real (or namespace-isolated real-protocol) WARP session once implemented.
- **Field validation required**: Full WARP-12 target Android/Keenetic matrix (currently BLOCKED regardless of code state — needs hardware).
- **Acceptance criteria**: go.mod has a real MASQUE/QUIC dependency or documented subprocess management; config schema exists; at least one production package calls into warp/; WARP_CAUSAL_TRACE_READY achievable with real evidence.
- **Dependencies**: none blocking
- **Risk**: Largest-scope item in this backlog — effectively a from-scratch feature implementation, not a wiring fix
- **Estimated complexity**: XL

### B4X-FIX-0005 — Implementation Validation Framework (P1)
- **Finding IDs**: B4X-AUDIT-0004
- **Likely affected files**: validation/*.go, main.go
- **Problem summary**: The project's own mechanism for preventing false-PASS claims (src/validation/, Aggregate(), FullRun{}, DetectFalsePass()) is never invoked by anything. No tools/validation-controller or b4-validate CLI exists.
- **Required implementation outcome**: Build the missing orchestration/CLI layer (cmd/b4-validate or a 'b4 validate' subcommand) that actually constructs StageResult/FullRun from real test/probe execution and calls Aggregate().
- **Tests to add/repair**: End-to-end test: a known-broken stage (e.g. WARP, using B4X-FIX-0004's current state) correctly produces a FAIL/BLOCKED verdict through this pipeline, not a silent omission.
- **Field validation required**: N/A (this IS the field-validation-adjacent tooling itself).
- **Acceptance criteria**: A runnable validation command exists, is documented, and reproducibly regenerates at least one docs/reports/*.md file from a clean checkout.
- **Dependencies**: none blocking
- **Risk**: Foundational tooling gap affecting trust in every other document's self-reported status
- **Estimated complexity**: L

### B4X-FIX-0006 — Field Test Automation Controller (P2)
- **Finding IDs**: B4X-AUDIT-0010
- **Likely affected files**: fieldtest/*.go, tools/
- **Problem summary**: Local Field-Test Controller (fieldtest/ package, 25 files) and the recommended tools/field-test-controller do not exist as runnable tooling. fieldtest/hard_gates.go duplicates CSI's real, working gate vocabulary without being connected to it.
- **Required implementation outcome**: Build the missing local controller CLI/orchestration; reconcile fieldtest.HardGatesPass() with the real crossservice-backed gate rather than maintaining a disconnected duplicate.
- **Tests to add/repair**: N/A (this is largely the same missing piece as B4X-FIX-0005's field-validation counterpart).
- **Field validation required**: N/A.
- **Acceptance criteria**: A runnable field-test controller exists and can drive at least one real scenario (e.g. FT-AA for B4X-FIX-0001) against target hardware or a faithful local simulation.
- **Dependencies**: B4X-FIX-0005 (shares infrastructure pattern)
- **Risk**: Also should add the FT-MON-A..J suites required by Continuous Monitoring's own §96 cross-reference, currently entirely absent from the v1.5 document
- **Estimated complexity**: L

### B4X-FIX-0007 — Silent Path Failure & Scoped Recovery (P2)
- **Finding IDs**: B4X-AUDIT-0005
- **Likely affected files**: silentpath/*.go, api/, config/, validation/
- **Problem summary**: src/silentpath/ (progress observation, differential proof, scoped recovery leases) is never imported by anything. Default observe-mode design limits practical urgency.
- **Required implementation outcome**: Wire packet-path hooks (nfq/handler.go or equivalent) to feed real ProgressObservation events; add api/config/validation surfaces per the document's own Appendix B.
- **Tests to add/repair**: Integration test showing packet-path events reaching silentpath.ProgressObserver.
- **Field validation required**: SPF-10 target validation (BLOCKED on hardware regardless).
- **Acceptance criteria**: At least one production package imports silentpath/ and feeds it real observations.
- **Dependencies**: none blocking
- **Risk**: Lower urgency: no traffic impact while unwired since default mode is observe-only anyway
- **Estimated complexity**: M

### B4X-FIX-0011 — Service Profile Framework (P3)
- **Finding IDs**: B4X-AUDIT-0011
- **Likely affected files**: serviceprofile/*.go, config/types.go, http/handler/
- **Problem summary**: src/serviceprofile/ (compiler, catalog, recommendation engine including WARP/Telegram/GSO-RST projections) has zero wiring of any kind — no imports, no API, no config schema.
- **Required implementation outcome**: Wire the compiler into config load/apply path; add HTTP API surface; connect WARPProjection/TelegramProjection to their respective (currently also broken) foundations once those are fixed.
- **Tests to add/repair**: Compiler round-trip test (profile -> compiled config -> applied); API contract test.
- **Field validation required**: Real Android UX validation per SP-32.
- **Acceptance criteria**: At least one production package imports serviceprofile/; a profile can be compiled and applied end-to-end.
- **Dependencies**: B4X-FIX-0003 (ABD, feeds recommendation evidence), B4X-FIX-0004 (WARP, feeds WARP projection)
- **Risk**: Depends on 2 other currently-broken foundations for its WARP-specific recommendation feature to be meaningful
- **Estimated complexity**: L

### B4X-FIX-0002B — Transactional Runtime (P4)
- **Finding IDs**: B4X-AUDIT-0001
- **Likely affected files**: runtimecontrol/live_runtime.go, runtimecontrol/rollout_manager_apply.go
- **Problem summary**: liveRuntime.Drain() is an unconditional no-op. Currently safe (single shared Pool, real cleanup happens synchronously in Promote() via InvalidateGeneration) but a maintainability/regression risk if a future Runtime implementation introduces genuinely separate per-generation resources.
- **Required implementation outcome**: Either document that generation invalidation IS the drain step (performed in Promote), or implement Drain() for real before any future Runtime variant needs it.
- **Tests to add/repair**: Test asserting state tied to a retired generation cannot be acted on after retirement, tied to the actual mechanism.
- **Field validation required**: N/A.
- **Acceptance criteria**: Drain()'s behavior (or documented equivalent) has explicit test coverage tied to the real mechanism, not just the interface method name.
- **Dependencies**: none blocking
- **Risk**: Low risk today, protects against future regression
- **Estimated complexity**: S

### B4X-FIX-0004B — Cross-Service Isolation — legacy learned-IP (P4)
- **Finding IDs**: B4X-AUDIT-0002
- **Likely affected files**: sni/match.go
- **Problem summary**: Legacy learned-IP cache remains destination-IP-keyed; safety currently relies on a single guard clause (Targets.DomainOnly check) rather than structural (type-level) scoping.
- **Required implementation outcome**: Add a permanent regression test for the guard clause; consider rescoping the cache itself to (ClientKey, DestinationIP) for defense in depth, matching the 'reject ambiguity' pattern used elsewhere in this codebase.
- **Tests to add/repair**: Regression test: 'a learned IP mapped to a DomainOnly set can never be returned as matched.'
- **Field validation required**: N/A.
- **Acceptance criteria**: Test exists; ideally guard is enforced at write-time as well as read-time.
- **Dependencies**: none blocking
- **Risk**: Safe today, low urgency
- **Estimated complexity**: S
