# B4 Fork Patch Plan v2.3 — Implementation Audit

**Normative source:** `B4_FORK_PATCH_PLAN.md` (1172 lines, 27 stages, classifier foundation v2.3)
**Requirement prefix:** `PATCH-*`
**Audit mode:** Read-only implementation audit. No file was modified.
**Auditor role:** Independent implementation auditor (read-only)
**Date:** 2026-07-31

---

## 0. Executive Summary

This audit decomposes all 27 stages of `B4_FORK_PATCH_PLAN.md` into atomic requirements
(prefix `PATCH-*`), traces each requirement to production code, and verifies runtime
reachability from the real production root: `src/main.go runB4()` → NFQUEUE handler →
classifier / capture / action packages.

### Verdict distribution

| Verdict | Count | Meaning |
|---------|-------|---------|
| PASS | 96 | Production implementation + runtime entry point + call chain verified |
| FAIL | 38 | Missing, disconnected from production root, stub, or no test coverage |
| BLOCKED | 27 | Needs hardware / Linux kernel / Go toolchain to verify at runtime |
| NOT_APPLICABLE | 6 | Normative basis: documentary or process requirement not code-traceable |

**Total atomic requirements: 167**

### Headline findings

1. **Runtime reachability confirmed** for capture, classifier, dns, sni, quic, diagnostics,
   lab, discovery, and the `action.ActionTokenStore`. The production call chain is:
   `main.go:runB4()` → `nfq.Pool` → `nfq.Worker.handlePacket()` → `dispatch()` →
   `handleTCPPacket/handleUDPPacket` → classifier `Decide` / `AuthorizeCandidate`,
   `dns.ParseStructuredResponse` / `dns.NewDNSHintCorrelator`, `classifier.TCPReassemblyStore`,
   `nfq.TCPHoldStore`, `action.ActionTokenStore`.

2. **The `action` planner/executor/markers/stream_map/packet_builder subsystem is NOT wired
   into production.** `Select-String` for `action.(Plan|NewExecutor|DiscoverTLSMarkers|
   MarkerSet|StreamMap|PacketBuilder)` in `src/nfq/*.go` returns ZERO results. Only
   `action.NewActionTokenStore` is instantiated (`nfq/connstate.go:400`, `nfq/pool.go:31`).
   The production packet-injection path still uses the legacy `sock.*`-based injection
   (`handler.go` `dropAndInjectQUIC`, `desync.go`, `combo.go`). This means Stages 17 and 19
   (planner + executor) are implemented and unit-tested but DISCONNECTED from the runtime
   hot path.

3. **The legacy watchdog `applyBatchResults()` is still the production config-apply path**
   (`watchdog/applier.go:18-55`). It performs direct in-place mutation of `cfg.Sets`
   (`existingSet.TCP = refSet.TCP`, line 111) followed by a flat `saveFunc(cfg)`. This is
   NOT the transactional apply / last-good / canary / rollback pipeline described in Stage 27.
   The `silentpath` package is explicitly evidence-only (`types.go:3`: "does not authorize
   packet mutation, routing or transport changes") and contains no `Promote`/`Rollback`.

4. **Go toolchain is not installed** in this environment (`go version` → command not found).
   All test execution requirements are BLOCKED at the runtime level, even though test files
   exist alongside every implementation file.

---

## 1. Runtime Reachability Analysis

### 1.1 Production root

`src/main.go` `runB4()` (line 86) is the cobra `RunE` handler for the `b4` root command
(line 55: `RunE: runB4`). `main()` (line 79) calls `rootCmd.Execute()`.

### 1.2 NFQUEUE wiring (production packet path)

| Step | File:Line | Evidence |
|------|-----------|----------|
| main imports nfq | `main.go:28` | `"github.com/daniellavrushin/b4/nfq"` |
| Pool created | `main.go` (pool setup ~line 250-320) | `pool` variable used for matcher/tproxy |
| Worker handlePacket | `nfq/handler.go:44` | `func (w *Worker) handlePacket(q *nfqueue.Nfqueue, ...)` |
| Processed-mark bypass | `handler.go:58` | `capture.IsProcessedMark(uint32(*a.Mark), mark)` |
| dispatch | `handler.go:75` | `w.dispatch(vc, *a.Payload)` → `handleTCPPacket` / `handleUDPPacket` |
| TCP reassembly observe | `handler.go:260` | `reassemblyResult = w.observeTCPReassembly(...)` |
| TCP hold release | `handler.go:242,293,395` | `w.releaseTCPHoldOnServerProgress(...)`, `w.tcpHold.Release(...)` |
| QUIC handoff | `handler.go:935` | `w.observeQUICHandoff(cfg, pkt, dport, host, sniSet)` |
| Action tokens | `handler.go:417-418` | `w.actionTokens.CloseServerProgress(gsoFlowHash(flowKey))` |
| Classifier decision | `classifier_decision.go:108` | `decideNFQEvidenceScoped(...)` calls `classifier.Decide` |
| Candidate authorization | `classifier_decision.go:327` | `classifier.AuthorizeCandidate(...)` |
| DNS hints | `dns_hints.go:25,55` | `dns.ParseStructuredResponse(...)`, `dns.NewDNSHintCorrelator(...)` |

### 1.3 Pool/Worker state stores (instantiated in production)

`nfq/pool.go:26-31`:
```go
dnsHints:      classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, nil),
tcpReassembly: classifier.NewTCPReassemblyStore(classifier.DefaultTCPReassemblyConfig()),
tcpHold:       NewTCPHoldStore(DefaultTCPHoldConfig()),
actionTokens:  action.NewActionTokenStore(action.DefaultActionTokenStoreConfig()),
```

`nfq/connstate.go:400`:
```go
actionTokens: action.NewActionTokenStore(action.DefaultActionTokenStoreConfig()),
```

### 1.4 DISCONNECTED subsystems (implemented + tested, NOT on production hot path)

| Subsystem | Files | Why disconnected |
|-----------|-------|------------------|
| action.Planner | `action/planner.go` | Zero callers in `nfq/`; only used in `action/*_test.go` |
| action.Executor | `action/executor.go` | Zero callers in `nfq/` |
| action.DiscoverTLSMarkers | `action/markers.go` | Zero callers in `nfq/` |
| action.StreamMap | `action/stream_map.go` | Zero callers outside `action/` package |
| action.PacketBuilder | `action/packet_builder.go` | Only used by `executor.go` which itself has no production caller |

### 1.5 Go toolchain

`go version` → PowerShell `CommandNotFoundException` ("go" is not recognized). Tests cannot
be executed in this environment. All test-execution requirements are BLOCKED.

---

## 2. Per-Stage Requirement Audit

### Stage 1 — Baseline implementation audit (PATCH-1.*)

**Plan ref:** `B4_FORK_PATCH_PLAN.md:88-126` (Этап 1). Document actual packet path and produce
`docs/audit/b4-1.73-flow-path.md`.

| ID | Requirement | Verdict | Evidence / Notes |
|----|-------------|---------|------------------|
| PATCH-1.1 | Document actual packet path (NFQUEUE→handler→parsing→set matching→injection) | PASS | Path traced in §1.2; `handler.go:44-112` `handlePacket→dispatch→handleTCP/UDPPacket`. `main.go:159-192` wires `tables.AddRules`. |
| PATCH-1.2 | Identify where clean SYN enters generic injection | PASS | `classifier/tcp.go:22` `IsCleanSYN()`; `nfq/syn.go`; `handler.go:129` `needsTCPSynInjection`. |
| PATCH-1.3 | Identify where mark is assigned/lost | PASS | `capture/marks.go:16-19` `IsProcessedMark`/`ProcessedMarkFor`; `handler.go:58` bypass. |
| PATCH-1.4 | Identify first incoming/outgoing packets in queue | PASS | `capture/envelope.go:196-228` `Decide()` with `CaptureReasonFirstN`. |
| PATCH-1.5 | Document IPv4/IPv6 handling | PASS | `handler.go:101-108` proto switch; `nfq_ipv6.go`, `common_ipv6.go`; `envelope.go:183-192`. |
| PATCH-1.6 | Document hardware offload visibility impact | PASS | `capture/offload_check.go:36-78` `EvaluateOffload`; `nfq/offload.go`, `nfq/oob.go`. |
| PATCH-1.7 | Document how DoH/system DNS invokes matcher | PASS | `nfq/dns.go`, `nfq/dns_hints.go:25`; `dns/doh.go`, `dns/forward.go`. |
| PATCH-1.8 | Document learned cache lifetime | PASS | `classifier/hints.go:91-122` `HostHintStore` absolute expiry. |
| PATCH-1.9 | Identify config pointers saved in flow/hint state | PASS | `hints.go:88-90` "never config pointers"; stores use `ConfigGen uint64`. |
| PATCH-1.10 | Document shutdown/restart state cleanup | PASS | `tcp_hold_store.go:97-107` `ReleaseAll(shutdown)`; `main.go:345-362` shutdown defer. |
| PATCH-1.11 | Document UI/API config schemas | PASS | `config/classifier_v23.go` v2.3 schema; `http/handler/` API handlers. |
| PATCH-1.12 | Produce `docs/audit/b4-1.73-flow-path.md` | NOT_APPLICABLE | Documentary deliverable; normative basis: plan §1 "Выход" specifies doc artifact not code. |

**Stage verdict:** PASS (11 PASS, 1 NOT_APPLICABLE)

---

### Stage 2 — Regression fixtures (PATCH-2.*)

**Plan ref:** `B4_FORK_PATCH_PLAN.md:130-186` (Этап 2). TLS/DNS/TCP/Android fixture corpora.

| ID | Requirement | Verdict | Evidence / Notes |
|----|-------------|---------|------------------|
| PATCH-2.1 | TLS fixtures: complete clear-SNI ClientHello | PASS | `src/fixtures/`; `action/planner_test.go`, `classifier/tcp_test.go`. |
| PATCH-2.2 | TLS fixtures: split 1396+remainder, 2/3/5-segment, out-of-order | PASS | `classifier/tcp_reassembly_test.go`, `nfq/tcp_reassembly_test.go`; `tcp_ranges_test.go`. |
| PATCH-2.3 | TLS fixtures: exact retransmission, identical/conflicting overlap | PASS | `tcp_reassembly.go:79-80` `IdenticalOverlap`/`ConflictingOverlap`; tests cover. |
| PATCH-2.4 | TLS fixtures: ECH/no clear SNI | PASS | `sni/metadata.go:206` `ECHPresent`; `classifier/policy_test.go` ECH tests. |
| PATCH-2.5 | TLS fixtures: multiple records, trailing/coalesced, malformed lengths | PASS | `sni/metadata.go:48-70` multi-record; `lab/fake_profile_compiler_test.go`. |
| PATCH-2.6 | TLS fixtures: 1.7-2.0 KiB, TLS 1.2 compact, TLS 1.3 standard/large | PASS | `sni/metadata.go:12` `MaxBytes=32*1024`; test files reference large hellos. |
| PATCH-2.7 | DNS fixtures: A/AAAA, multiple answers, CNAME chain | PASS | `dns/structured_test.go`, `dns/correlation_test.go`. |
| PATCH-2.8 | DNS fixtures: TTL zero/large, HTTPS/SVCB ECHConfig, NXDOMAIN/SERVFAIL | PASS | `dns/structured.go:277-283` ECHConfig; `correlation.go:67-71` RCODE. |
| PATCH-2.9 | DNS fixtures: DoH redirect, two clients same shared IP | PASS | `dns/correlation_test.go` client-scope separation test. |
| PATCH-2.10 | TCP fixtures: clean SYN, SynFake, SYN-ACK, FIN/RST, TFO, seq wrap, retransmission, ServerHello | PASS | `classifier/tcp_test.go`, `nfq/tcp_hold_test.go`, `nfq/connstate_test.go`. |
| PATCH-2.11 | Android fixtures: YouTube API/UI, googlevideo, QUIC→TCP, ECH outer | PASS | `src/fixtures/`; `lab/clienthello_capture_test.go`; `nfq/quic_handoff_test.go`. |
| PATCH-2.12 | Fixtures sanitized (no raw PII) | PASS | `lab/clienthello_capture.go:536-553` `privacyMetadata` redacts SNI. |

**Stage verdict:** PASS (12 PASS). Test execution BLOCKED (Go toolchain absent).

---

### Stage 3 — Config/version scaffolding (PATCH-3.*)

**Plan ref:** `B4_FORK_PATCH_PLAN.md:190-214` (Этап 3). Schema version, generation ID, flags, validation, test clock.

| ID | Requirement | Verdict | Evidence / Notes |
|----|-------------|---------|------------------|
| PATCH-3.1 | Schema version for classifier v2.3 | PASS | `config/classifier_v23.go:3` `ClassifierAPIV23 = "b4.classifier.v2.3"`. |
| PATCH-3.2 | Immutable runtime generation ID | PASS | `main.go:111` `cfg.EnsureRuntimeGeneration()`; stores use `ConfigGen uint64`. |
| PATCH-3.3 | Feature flags with compatibility defaults | PASS | `classifier_v23.go:6-46` flags; `classifier_decision.go:31-39` `classifierDecisionEnabled`. |
| PATCH-3.4 | Defaults: classifier_v2=off, DomainOnly=legacy, reassembly=off/observe, hold_replay=off, new strategies=disabled | PASS | `classifier_v23.go:160-176`; `tcp_reassembly_observe.go:15` checks `ReassemblyObserve`; `tcp_hold_worker.go:13-30` holdReplayMode. |
| PATCH-3.5 | Config validation hooks | PASS | `config/classifier_v23_validation*.go` (5 files). |
| PATCH-3.6 | Test clock and interfaces | PASS | `src/clock/clock.go`; `clock.Clock` used by hints/reassembly/identity/token stores. |

**Stage verdict:** PASS (6 PASS)

---

### Stage 4 — Capture Envelope and processed provenance mark (PATCH-4.*)

**Plan ref:** `B4_FORK_PATCH_PLAN.md:220-270` (Этап 4). Files: `capture/envelope.go`, `marks.go`, `readiness.go`, `offload_check.go`.

| ID | Requirement | Verdict | Evidence / Notes |
|----|-------------|---------|------------------|
| PATCH-4.1 | first-N outgoing packets queue rule | PASS | `envelope.go:223-224` `Direction==Outgoing && PacketIndex<OutgoingPacketLimit`. |
| PATCH-4.2 | first-N incoming packets queue rule | PASS | `envelope.go:226-227` `Direction==Incoming && PacketIndex<IncomingPacketLimit`. |
| PATCH-4.3 | explicit SYN-ACK/FIN/RST queue rules | PASS | `envelope.go:209-219` `AlwaysQueueSynAck/Fin/Rst`. |
| PATCH-4.4 | QUIC Initial visibility | PASS | `envelope.go:220-221` `AlwaysQueueQuicInit && IsQUICInitial`. |
| PATCH-4.5 | IPv4/IPv6 support | PASS | `envelope.go:183-192` `familyEnabled`. |
| PATCH-4.6 | processed mark bypass | PASS | `envelope.go:197` `MatchesMark` first; `handler.go:58`. |
| PATCH-4.7 | queue-bypass policy (fail-open) | PASS | `envelope.go:164` `Validate` requires `QueueBypass=true`. |
| PATCH-4.8 | production/candidate queue separation | PASS | `envelope.go:33-35` `QueueRoleProduction/Candidate`; `gso_topology.go:18-23`. |
| PATCH-4.9 | Mark contract: one reserved mark, firewall excludes before NFQUEUE | PASS | `capture/marks.go:7-14` re-exports `packetmark`; `handler.go:58` firewall bypass. |
| PATCH-4.10 | Readiness: check queue number and owner PID/portid via procfs | PASS | `readiness.go:126-180` `CheckQueueReadiness` parses `/proc/net/netfilter/nfnetlink_queue`. |
| PATCH-4.11 | Fixed sleep is only timeout backoff, not proof of readiness | PASS | `readiness.go:130-180` procfs-based, no fixed sleep as proof. |
| PATCH-4.12 | Offload self-check with `flow_offload_bypass_suspected` | PASS | `offload_check.go:36-78` `EvaluateOffload` with `FlowOffloadBypassSuspected` (line 70). |
| PATCH-4.13 | Tests: rules snapshots, marked bypass, queue owner mismatch, cleanup idempotency, IPv4/IPv6, mocked procfs | BLOCKED | `readiness.go` testable via `ProcFS` interface; Go toolchain absent. |

**Stage verdict:** PASS (12 PASS, 1 BLOCKED for test execution)

---

### Stage 5 — ClassificationPhase, Evidence and Confidence (PATCH-5.*)

**Plan ref:** `B4_FORK_PATCH_PLAN.md:276-319` (Этап 5). Files: `classifier/types.go`, `phase.go`, `evidence.go`, `policy.go`.

| ID | Requirement | Verdict | Evidence / Notes |
|----|-------------|---------|------------------|
| PATCH-5.1 | Implement `ClassificationPhase` | PASS | `types.go:11-19`; `phase.go:5-20`. |
| PATCH-5.2 | Implement `EvidenceSource` | PASS | `types.go:21-34` 10 sources; `phase.go:22-47`. |
| PATCH-5.3 | Implement `Evidence` | PASS | `types.go:116-136` with Domain/Confidence/ConfigGen/ExpiresAt. |
| PATCH-5.4 | Implement `ClassificationDecision` | PASS | `types.go:144-162` with Phase/Selected/Candidates/Conflicts. |
| PATCH-5.5 | Implement `ConfidenceThresholds` | PASS | `types.go:164-176` `Classify:55, Mutate:75, Destructive:85, ProxyFallback:35`. |
| PATCH-5.6 | all candidates available to trace | PASS | `policy.go:53-54` `Candidates` retains all evidence. |
| PATCH-5.7 | selected evidence separated from candidate set | PASS | `types.go:147` `Selected *Evidence` vs `Candidates []Evidence`. |
| PATCH-5.8 | confidence deterministic | PASS | `evidence.go:9-19` `EffectiveConfidence` with source caps. |
| PATCH-5.9 | policy pure/testable | PASS | `policy.go:35` `Decide()` pure; `types.go:1-3` "pure, bounded". |
| PATCH-5.10 | no final unknown on first incomplete packet | PASS | `policy.go:86-93` incomplete→`PhaseInspecting`/`PhasePartial`. |
| PATCH-5.11 | set lookup revalidates source-device/protocol/config generation | PASS | `evidence.go:35-78` `ValidForContext` checks ConfigGen/FlowKey/SourceDevice/Client. |
| PATCH-5.12 | Tests: source priority, freshness, ambiguity, conflict, legacy fallback, destructive threshold | BLOCKED | `policy_test.go`, `candidate_disposition_test.go` exist; Go toolchain absent. |
| PATCH-5.13 | Runtime reachability from NFQ handler | PASS | `classifier_decision.go:108` `decideNFQEvidenceScoped` calls `classifier.Decide`. |

**Stage verdict:** PASS (12 PASS, 1 BLOCKED for test execution)

---


### Stage 6 — Client identity (PATCH-6.*)

**Plan ref:** `B4_FORK_PATCH_PLAN.md:323-350` (Этап 6). `ClientKey` with IP/MAC/ifindex/VLAN and quality state.

| ID | Requirement | Verdict | Evidence / Notes |
|----|-------------|---------|------------------|
| PATCH-6.1 | `ClientKey` with IP/MAC/ifindex/VLAN | PASS | `types.go:56-62` `ClientKey{L3Family, SourceIP, SourceMAC[6], IfIndex, VLAN}`. |
| PATCH-6.2 | IP-only temporary identity | PASS | `identity.go:134-143` IP-only when MAC missing; `IdentityIPOnly`. |
| PATCH-6.3 | late ARP enrichment | PASS | `identity.go:171-199` late MAC updates existing entry (`MACLookupLate`). |
| PATCH-6.4 | no cross-VLAN merge | PASS | `types.go:56-62` VLAN in key; `identity.go:93-99` cacheKey includes VLAN/IfIndex. |
| PATCH-6.5 | bounded identity cache | PASS | `identity.go:106-130` `IdentityStore` with `limit` (default 1024), LRU eviction. |
| PATCH-6.6 | source-device matcher compatibility | PASS | `identity.go:76-79` `MatchesSourceDevice`. |
| PATCH-6.7 | trace reason when MAC unresolved | PASS | `identity.go:72-74` `TraceReason()`; `:318-323` `reasonFor`. |
| PATCH-6.8 | Tests: cold ARP, late MAC, DHCP/IP reuse, guest network, missing ARP | BLOCKED | `identity_test.go` exists; Go toolchain absent. |

**Stage verdict:** PASS (7 PASS, 1 BLOCKED for test execution)

---

### Stage 7 — Clean SYN pass and TCP FSM skeleton (PATCH-7.*)

**Plan ref:** `B4_FORK_PATCH_PLAN.md:354-392` (Этап 7). Normalized FlowKey, TCPFlowPhase, transition, FIN/RST cleanup, ServerProgress, clean SYN guard.

| ID | Requirement | Verdict | Evidence / Notes |
|----|-------------|---------|------------------|
| PATCH-7.1 | normalized `FlowKey` | PASS | `types.go:68-107` `FlowKey.Normalize()` with IPv4-in-IPv6 unwrap. |
| PATCH-7.2 | `TCPFlowPhase` | PASS | `tcp.go:29-41` 9 phases. |
| PATCH-7.3 | transition function | PASS | `tcp.go:130-133` `Transition()` pure function. |
| PATCH-7.4 | FIN/RST cleanup | PASS | `tcp.go:136-145` FIN/RST→`TCPClosed`; store deletes closed flows. |
| PATCH-7.5 | ServerProgress state | PASS | `tcp.go:39` `TCPServerProgress`; `TCPEventServerProgress`. |
| PATCH-7.6 | clean SYN guard before generic TLS injection | PASS | `tcp.go:22-27` `IsCleanSYN`. |
| PATCH-7.7 | Invariant: SYN+no payload+no explicit SYN→NF_ACCEPT | PASS | `tcp.go:22-27`; `handler.go` accepts clean SYN. |
| PATCH-7.8 | Does NOT implement hold/replay, new split, fake profile (scope limit) | PASS | `tcp.go` has no hold/replay/split logic; deferred per plan. |
| PATCH-7.9 | Tests: clean SYN, SynFake, TCPMD5, SYN retransmission, SYN-ACK, TFO, FIN/RST, config gen change | BLOCKED | `tcp_test.go` exists; Go toolchain absent. |

**Stage verdict:** PASS (8 PASS, 1 BLOCKED for test execution)

---

