# WARP-12 — implementation report

Implemented transport contracts cover bundled engine provenance, protected enrollment, supervisor trace identity, TUN ownership, recursive-route protection, scoped authorization, layered health, camouflage identity/cutoff, candidate selection, nested dependencies, geo quorum, instance isolation, RST observation, product diagnostics, and release gates.

Combined automated validation passes:

```text
go test ./warp ./detector ./discovery ./monitor ./mtproto
```

---

## 2026-08-23 — Data plane engine E0+E1 (bd b4x-ukp; design `.ag/research/warp-dataplane-design.md` v2, owner-approved)

New package `src/transport/warp` (`transportwarp`) — the first real MASQUE/CONNECT-IP data-plane code of this repository (closes the implementation half of B4X-FIX-0004). Zero new external dependencies (stdlib crypto/tls + already-present golang.org/x/net/http2).

Delivered:

| File | Content |
|---|---|
| `catalog.go` | Versioned endpoint catalog (CatalogVersion=1): measured MASQUE gateway map (H2: 162.159.198.0/24 + 199.0/24, v6 103::/48+104::/48; QUIC anycast .1/.2; ports {443,500,1701,4500,4443,8443,8095}). `InCatalog` guard implements addendum §34 "no arbitrary scanning". |
| `varint.go` | RFC 9000 §16 variable-length integers (append/parse/len). |
| `tlsconf.go` | ECDSA P-256 client key lifecycle (usque-compatible base64 SEC1 format), PEM pin parsing, SPKI-SHA256 digest, self-signed 24h client cert, pinned-peer TLS config (insecure forbidden — hard gate masque_insecure_tls stays enforceable), optional extra backend pins (Aether-style rotation tolerance). |
| `dialpolicy.go` + `_linux/_other` | SO_MARK / SO_BINDTODEVICE / source-pin control socket policy (addendum §17–18); constrained policies fail closed on unsupported platforms. |
| `probe.go` | Synthetic IPv4/UDP DNS data-plane probe with full checksums and txid reply matching (Aether validation pattern). |
| `session.go` | H2 CONNECT-IP session: pinned dial to numeric endpoint, CONNECT https://cloudflareaccess.com + cf-connect-proto/pq-enabled headers, capsule DATAGRAM framing both directions, foreign-capsule skip, MTU enforcement, structured failure classes (§62.1 subset), **data-plane trust gate**: 200 is NOT trusted until ValidateDataPlane observes 2 probe round trips in 10 s (refines addendum §29 L2 per design §12); terminal read errors close the session. |
| `fakeserver_test.go` | §66 fake MASQUE server: real h2-over-TLS CONNECT endpoint with behavior matrix (status codes, silent drop, foreign capsules, mid-stream teardown). |

Verification (executed in golang:1.25.3 container):

```text
go vet ./transport/warp/            → clean
go test ./transport/warp/ -count=1  → ok (26 tests)
go test -race                       → ok
go test ./...                       → all green on repo layout (b4-validate/validation need artifacts/ from repo root)
```

§66 scenarios covered offline: TCP refused → tcp-connect-failed; TLS pin mismatch → tls-pin-mismatch; CONNECT 403/429/500 → connect-ip-rejected with status; success echo round trip incl. MTU-size packet; silent-drop after handshake → data-plane-validation-timeout + session teardown; foreign capsule skipping; concurrent writers keep capsule framing; context cancellation honored; oversized packet rejected (ErrPacketTooBig for ICMP TooBig generation at pump level later).

## 2026-08-23 (later) — E2 enrollment + identity reconcile (bd b4x-ukp, design §5)

New files in `src/transport/warp` — the fully automatic identity layer (design §5; zero new deps: placeholder curve25519 via stdlib crypto/ecdh):

| File | Content |
|---|---|
| `identity.go` | `Identity` JSON schema (format-versioned), field validation re-deriving every security-relevant value (key parses ECDSA P-256, pin PEM parses, PinDigest recomputed+matched, v4 parses). Atomic store: tmp+chmod 0600+fsync+rename; corrupt file quarantined to `*.corrupt` (evidence kept, reprovision allowed). |
| `enrollment.go` | Registration API client: POST /v0a4471/reg (curve25519 placeholder + random serial-hex8/model/locale fingerprint + TOS layout `2006-01-02T15:04:05.000-07:00`) → PATCH secp256r1/masque (Bearer from POST-only token) → GET config (peers[0].public_key pin, interface addresses, client_id). Headers UA "WARP for Android" + CF-Client-Version a-6.35-4471 (path-suffix pairing invariant enforced by fake server). Outcome taxonomy: Refused(401/404/410) vs Throttled(403/429/5xx) vs Network vs InvalidKey(API code 1001) vs RequestError. Retry ONLY on transport errors inside one step: 900ms×2^n jitter ±⅓ cap 15s; 429 Retry-After parsed with hard cap 30s. Transport injected (`HTTP` field) — explicit enrollment path per design ladder. |
| `reconcile.go` | Decision point KEEP / RENEW / REPROVISION / STAY-BLOCKED: absent|corrupt→provision; account revalidation 200→keep (+renewal when ExpiresAt within 7d window, keep-old-on-failure, replaced device DELETEd best-effort); 401/404/410→dead→re-provision (no pointless DELETE of refused device); 403/429/5xx/net→NEVER re-register, cooldown stamped. Stamp discipline (z2k #8): intent stamp written BEFORE any attempt, unwritable stamp = no action, future-dated stamp (clock skew) reset. Registrations strictly sequential (mutex); flat floor DefaultMinEnrollInterval=600s between attempts. Blocked-cooldown/throttle are STRUCTURED outcomes (Action+FailureClass+ThrottleUntil), not errors — supervisor contract for E3. |

Fake API server (`fakeapi_test.go`): httptest implementing the protocol contract and RECORDING violations (version-pairing header check, UA, bearer-per-device, 32-byte placeholder key, hex8 serial, TOS layout, PKIX patch payload, top-level response objects).

E2 scenario matrix (design verification column) — all offline:
- happy path provision → second Ensure KeptValid with zero extra registrations; committed file mode 0600;
- API 1001 InvalidPublicKey on PATCH → transaction aborted, nothing committed, exactly one PATCH (no retry storm);
- 401 on revalidation → automatic reprovision with NEW device id, dead device NOT deleted;
- 429 (+Retry-After 120) → live identity kept, zero registrations across repeated Ensures, cooldown floor 600s respected (cap can only extend a short configured floor);
- 429 during enrollment → cooldown extended to capped Retry-After; immediate retry makes ZERO network calls (structured blocked-cooldown outcome);
- corrupt store file → quarantined `.corrupt`, reprovisioned over;
- renewal window: due identity renewed via full transaction + old device slot freed; failing API during renewal keeps old generation on disk byte-for-byte;
- transport error mid-enroll → single backoff sleep inside ±⅓ band, then recovery;
- stamp-from-the-future reset; unwritable intent stamp blocks all action (fail closed);
- pure tables: ClassifyHTTPStatus, parseRetryAfter, NeedsRenewal boundaries.

Verification (executed in golang:1.25.3-alpine container):

```text
gofmt -l <5 new files>               → clean
go vet ./transport/warp              → clean
go test ./transport/warp -count=1    → ok (39 tests: 26 E0+E1 + 13 new)
go test -race (CGO_ENABLED=1 + gcc)  → ok
go test ./...                        → ALL GREEN in replicated repo layout
                                       (/repo/{src,artifacts,specs} + root *.json/*.md;
                                        b4-validate needs artifacts/+specs/, fb18b needs root crosswalk json)
```

Known gaps to next stages (design E3–E8): supervisor instance loop wiring EnsureResult into backoff/events §62, endpoint discovery scans, nested warp+warp runtime, non-RU geo gate, nfq exclusion-set integration, TUN/PBR field layer. Target-router validation remains BLOCKED_TARGET_VALIDATION.

Process notes (honest record):
- three LOCAL commits appeared at 20:20–20:24 +05 (branch agent/classifier-v2.3-capture-envelope, ahead 3, NOT pushed) covering previous-session leftovers AND this session's E2 work; the agent performed no git write operations — environment auto-commit suspected; owner informed.
- full-suite recipe fixed for virtiofs slowness: replicate repo layout under /repo (NOT /tmp — findValidationDir walk-up collision documented in run_profiles_test).

## 2026-08-23 (evening) — E3 supervisor (bd b4x-ukp, design §1 L2 / §19 / §3)

New `supervisor.go` (+`supervisor_test.go`): the in-process instance lifecycle loop (ADR-WARP-1 deferral per design §11.1). One goroutine owns identity -> connect -> validate -> health -> reconnect.

Delivered:

| Concern | Implementation |
|---|---|
| Instance loop | Single start lock (`startOnce`), ctx-driven Stop, states idle/identity/connecting/connected/backoff/stopped, `Snapshot()` status incl. RouteHeld/BackoffUntil/PendingPacket/DroppedWakeups. |
| Backoff | Bounded exponential 1s->2s->...->30s cap; reset when the previous session lived >= ResetAfterStable=60s (addendum §19 reset_after_stable; z2k #14). Note: addendum §19 yaml also lists minimum_delay=5s; the owner-approved design text "1→30s" was implemented — deviation recorded here. |
| Identity integration | Ensure() at start and every RevalidationInterval=24h only — reconnect storms reuse stored identity and cannot hammer the registration API (verified by test: post==1 across the storm). Blocked outcomes (throttle/cooldown) are STRUCTURED even when err!=nil and take priority over the generic error path; while blocked the supervisor performs ZERO MASQUE dials and paces its next identity attempt until ThrottleUntil (test asserts the capped Retry-After ~30s wait). |
| Health watchdog | Periodic data-plane probe (synthetic DNS via tunnel, any inbound counts); ProbeTimeout miss = one failure; streak >= 3 -> FAIL-OPEN: route released IMMEDIATELY, session torn down, reconnection continues in background (z2k #7 black-hole rule). Recovery re-holds the route only after a fresh validated connect. |
| First-packet fix | Design §2 usque-bug fix: packets written while disconnected are buffered (single slot, latest wins; overwrites counted as dropped wake-ups) and flushed right after the next VALIDATED connect. WritePacket degrades to buffering when the live session dies mid-write. |
| Kick | Restart(force bool) closes the live session; kicks cooldown-paced 300s (z2k), force bypasses for operators. |
| Events §62.1 | warp_session_generation_started / warp_masque_connected / warp_masque_rejected / warp_masque_disconnected / warp_reconnect_scheduled / warp_keepalive_failed / warp_identity_blocked / warp_route_released_failopen via an INJECTABLE SINK — engine stays dependency-free; adapting to src/warp TransportTraceEnvelope pipeline is the E7 wiring. Diagnostic ring (last 64) + RecentEvents(). |

Test matrix (7 new scenarios, all offline against fake API + fake MASQUE):
- happy path: provision -> validated connect -> route held; first event is generation_started, connected follows it; exactly one registration POST;
- storm guard: dead endpoint -> recorded backoff series exactly [1s,2s,4s,...], reconnect_scheduled emitted per failure, registration API untouched during the storm;
- wake-up first-packet: two writes during an outage window -> latest buffered, earlier counted dropped, flushed packet received by the peer after recovery;
- fail-open: mid-session silent-drop flip -> 3 keepalive_failed -> route released immediately + teardown -> after server heal the route is held again;
- identity blocked: zero MASQUE dials while throttled, wait equals capped Retry-After;
- restart kick cooldown semantics incl. force bypass;
- backoff series unit semantics incl. stable-run reset boundary (61s resets, 59s does not).

Fixture fixes required by these scenarios (test-only): fakeServer now re-reads behavior flags PER CAPSULE (mid-session silent-drop flips act on LIVE connections) and can be constructed with a caller-provided key so the MASQUE endpoint presents exactly the key the registration API pinned.

Verification (executed in golang:1.25.3-alpine):

```text
gofmt -l <new/touched files>         → clean
go vet ./transport/warp              → clean
go test ./transport/warp -count=1    → ok (46 tests: 39 + 7 new)
go test -race (CGO_ENABLED=1 + gcc)  → ok
go test ./...                        → ALL GREEN (/repo layout recipe)
```

Known gaps to next stages (design E4–E8): endpoint discovery scans (E4), nested warp+warp runtime with inner dial policy (E5), non-RU geo gate (E6), nfq exclusion-set/enrollment-hostlist/camouflage wiring + TracePipeline adapter for supervisor events (E7), TUN/PBR field layer + downlink 10s idle watchdog at pump level (field layer; engine-level liveness covered by the health probe). Target-router validation remains BLOCKED_TARGET_VALIDATION.

## 2026-08-23 (night) — E4 endpoint discovery (bd b4x-ukp, design §4 / research Part 3)

New `discovery.go` (+`discovery_test.go`, +`CatalogCandidates` in catalog.go): measured-quality ranking over versioned-catalog candidates with last-good cache and cooldowns.

Delivered:

| Concern | Implementation |
|---|---|
| Candidate map | `CatalogCandidates(kind, strategy)` — the §34 no-arbitrary-scan gate: turbo = default endpoint only; balanced = seeds (default×7 ports) + deterministic .1/.254 sample per measured /24 on :443; thorough = full product of both H2 /24s × port set (3584 candidates); QUIC kind = anycast seeds. Unit test asserts EVERY entry passes InCatalog+KnownPort for all strategies; thorough size == 2*256*7. |
| Verifier | Flap tolerance: up to MinAttempts=3 connect+validate rounds per candidate (every round counted, including the successful one). Durability burst after a validated connect: BurstCount=10 probes spaced BurstInterval=200ms (instant in tests via injectable Sleep); classification Healthy (loss ≤20%) / Lossy / TornDown (tail-run ≥3 unanswered after answers, or fully silent post-validation) / Dead (never validated). |
| Ranking | loss → in-tunnel RTT (time to the SECOND echo) among verified; host-ICMP deliberately omitted (z2k #13: ICMP through tunnel dropped 100%); throughput out of scope/outside ranking — both recorded in report as design-conformant omissions. |
| Strategies | turbo/balanced/thorough shapes (targets 2/12/4096, budgets 45/120/300s, early-exit for turbo); tier-adjusted concurrency Low=4/Medium=10/High=16; early-exit runs SEQUENTIALLY so abandoned verifications waste no dial budget. Per-probe ceiling 2s (design v2 number replacing Aether 6/10s — deviation recorded). |
| Last-good cache | JSON at LastGoodPath (atomic 0600 tmp+rename): fast re-verify within FastReverifyBudget=5s (single attempt + 5-probe mini-burst) → pass ⇒ ENTIRE scan skipped (Source="last-good"); fail ⇒ strike + fallback scan; cache refreshed to each new winner. |
| Cooldown | strike map in-memory: 2 consecutive dead/torn-down rounds exclude an endpoint for Cooldown=300s from candidate selection (verified by test: round-3 makes ZERO contact with the excluded edge). |
| Telemetry | ConnectResult.Colo captures the cf-warp-colo CONNECT response header (warp-socks pattern) — flows into scores and the last-good entry. |
| Concurrency hygiene | Worker pool joined before return; ONE burst-reader goroutine per verification with its OWN derived context — close() cancels ReadPacket deterministically (a naive stop-channel variant deadlocks against session teardown ordering; found and fixed during this stage). |

Test matrix (8 new scenarios, all offline):
- ranking by RTT then loss (delayed-echo fixture vs lossy every-Nth-drop fixture), colo captured;
- torn-down-only candidate → ErrNoCandidates, never ranked;
- flap tolerance: reject-next-2 still verifies with Attempts==3; reject-forever is Dead;
- last-good pass → zero scan contacts on other endpoints;
- last-good fail → full-scan fallback + cache refreshed to new winner;
- cooldown: excluded endpoint untouched in round 3 after two dead rounds;
- turbo early exit touches exactly one candidate (≤3 connects total);
- catalog gate invariants for all three strategies.

Fixture additions (test-only): fakeServer dropEvery/echoDelay/rejectNext fixtures re-read behavior flags per capsule; cf-warp-colo served on success.

Verification (executed in golang:1.25.3-alpine):

```text
gofmt -l <new/touched>               → clean
go vet ./transport/warp              → clean
go test ./transport/warp -count=1    → ok (54 tests: 46 + 8 new)
go test -race (CGO_ENABLED=1 + gcc)  → ok
go test ./...                        → ALL GREEN (/repo layout recipe)
```

Known gaps to next stages (design E5–E8): nested warp+warp runtime (Backend A/B, inner dial policy, DoH-inner), non-RU geo gate, nfq exclusion-set/enrollment-hostlist wiring + TracePipeline adapter, TUN/PBR field layer. Supervisor↔Discoverer integration (winner feeding SessionConfig.Endpoint) is intentionally deferred to the E7 wiring pass. Target-router validation remains BLOCKED_TARGET_VALIDATION.

## 2026-08-24 — E5 nested warp+warp (bd b4x-ukp, design §6 / research gool+warp-socks)

New `nested.go` (+`dns_tunnel.go`) and per-layer colo telemetry in the supervisor.

Delivered:

| Concern | Implementation |
|---|---|
| Config-plane hard rules (`NestedConfig.Validate`, structural errors) | DIFFERENT edge IPs per layer (gool lib.rs hard rule; same addr on another port rejected); inner MTU strictly < outer (DefaultNestedInnerMTU=1200 vs 1280); duplicate assigned addresses rejected (§9 address_conflict, z2k #4 "tunnel up but carries nothing"); two INDEPENDENT identities (distinct device IDs); Backend A requires a CONSTRAINED inner policy (BaseInterface for SO_BINDTODEVICE or InnerFwMark for SO_MARK) unless the documented tests-only `AllowUnconstrainedInner` escape is set — an unconstrained inner socket would leak direct. |
| Backend modes | `backend-a-netns` (policy fields carried for the field layer) and `backend-b-proxy` (userspace adapter over base — adapter itself is E7 wiring; engine validates config + lifecycle around it). |
| Parent-link lifecycle | `NestedRuntime` owns base+inner via supervisor FACTORIES (inner factory invoked once per parent generation — supervisors are single-shot by design). Controller loop: while base route not held → child INVALIDATED (stopped, zero dialing, Link=child-invalidated, ChildRevalidated=false); every new validated base session bumps `ParentSessionGen` and restarts the child REVALIDATED against it (mirrors src/warp TunnelDependencyLink.InvalidateParent/RevalidateParent semantics). Teardown order child-first guaranteed. |
| Telemetry (H-NONRU-1 prep) | `Status.LastColo` on supervisors (set at each validated connect); `NestedStatus.BaseColo/InnerColo` expose both layers — the field experiment "inner terminates outside RU?" reads exactly these two values. Keepalive separation documented as wiring-time constants (NestedOuterProbeInterval=20s / NestedInnerProbeInterval=30s, gool 5/20 pattern); cross-supervisor enforcement deliberately left to composition (E7). |
| DNS inside the tunnel | `TunnelResolver`: plain UDP/53 to Cloudflare's dedicated resolvers 162.159.36.1/.46.1 as IP packets through the session — reuses probe.go packet builders/checksums, txid+port+direction reply filtering, compressed-name-aware A-record parser, own-context reader (same deadlock-safe pattern as E4). DEVIATION recorded: references use DoH-over-HTTPS-in-tunnel which needs a userspace netstack we do not ship (zero-dep rule, design §11); UDP-DNS-in-tunnel delivers the identical anti-leak property; TLS-wrapped DoH lands with the E7 field layer. |

Test matrix (5 new scenarios, all offline):
- config violations table: same edge IP / address conflict / MTU gradient / unconstrained Backend-A / identical identity → exact structural errors; positive case, tests-only escape, Backend-B skip all accepted;
- parent reconnect invalidates child: kick base → child stopped + invalidated within the down-window → base recovers → gen==2, child revalidated, inner dials again;
- per-layer colo telemetry surfaces in NestedStatus;
- tunnel resolver resolves A records end-to-end against a crafted-response fixture;
- silent-drop edge → ErrDNSNoAnswer inside deadline (no blocking).

Verification notes (honest): the invalidation checkpoint was initially FLAKY — with instant virtual pacing the base down-window was shorter than one controller poll tick, so the transient went unobserved (diagnosed with a temporary status-sampling debug test, then removed). Fix: the base fixture now reconnects with a REAL 300ms pause, making the window deterministic; package suite verified green twice consecutively plus -count=2.

Fixture additions (test-only): fakeServer `setResponder(fn)` hook replacing echo per payload (DNS response crafting).

Verification (executed in golang:1.25.3-alpine):

```text
gofmt -l <new/touched>               → clean
go vet ./transport/warp              → clean
go test ./transport/warp -count=1    → ok (59 tests: 54 + 5 new)
go test -count=2                     → ok (stability)
go test -race (CGO_ENABLED=1 + gcc)  → ok
go test ./...                        → ALL GREEN (/repo layout recipe)
```

Known gaps to next stages (design E6–E8): non-RU geo gate over the nested path (providers through inner, quorum, revocation latency), nfq exclusion-set/enrollment-hostlist/camouflage wiring + TracePipeline adapter + Backend-B userspace adapter + DoH upgrade (E7), TUN/PBR field layer (E7/E8). Target-router validation remains BLOCKED_TARGET_VALIDATION.

## 2026-08-24 (later) — E6 non-RU geo gate (bd b4x-ukp, design §7/§14; addendum §42–47, §62.5, §62.6, §63, §69)

New `nonru.go` (+`nonru_gate.go`, +`nonru_test.go`) and additive packet plumbing in `session.go`. The strict НЕ РФ route gate: the route is active ONLY under a fresh multi-provider PASS_NON_RU attestation; any RU / disagreement / stale / public-ip change / parent reconnect / DNS-path loss / direct-WAN escape / manual disable / config change revokes IMMEDIATELY with a §62.5 close reason and an honestly measured revocation latency.

Delivered:

| Concern | Implementation |
|---|---|
| Contract mirroring | `GeoObservation`/`GeoAttestation` mirror `src/warp` geo.go field semantics (attestationFresh/Valid identical); documented deviations: PublicIP stored HASHED only (§71 hash_public_ips wins over name parity) and `Country` carried explicitly so §44 "same non-RU country" is checkable. The engine stays dependency-free; E7 wiring feeds contract-package hard-gate producers from this runtime truth. |
| Quorum (`EvaluateGeoQuorum`) | Mirrors src/warp BuildGeoAttestation filters (expired / zero-counter-delta / no-DNS-proof excluded; any RU dominates) + §44 provider-count semantics: >=2 providers reporting the SAME country (distinct-country count vs vote count bug found and fixed during E6 verification). Distinguishes Disagreement (conflicting countries / unknown mix / cross-provider IP mismatch → immediate revoke per §73 hard gate) from Insufficient (missing votes → hold, attestation simply stops renewing → attestation-stale at TTL). |
| Probe path proof (§43) | Structural half: `GeoProbeTransport` exposes NO direct egress — DNS goes through the inner resolver as tunnel IP packets (`TunnelGeoTransport.ResolveA`, dns_tunnel.go packet builders), HTTPS through an adapter slot that is `ErrHTTPSNotWired` until E7. Observable half: every probe is bracketed by inner counter snapshots (`Session.Counters()`, added tx/rx packet+byte atomics); a result without counter movement = `ErrNoCounterDelta` → direct-wan-observed fail-closed. |
| Providers | `WhoamiDNSProvider` (Akamai whoami / Google o-o.myaddr debug-name patterns; classification oracle INJECTED — engine ships no GeoIP DB) and `CFTraceProvider` (cdn-cgi/trace parse with warp=on|plus requirement; body via the not-yet-wired HTTPS adapter). Config floor enforced in NewNonRUGate: >=2 providers, distinct IDs, transport factory required — Cloudflare trace can never be the only provider. |
| Gate controller (`NonRUGate`) | Poll loop: manual-disable > config-generation-change > parent-gen mismatch (stale parent route token, §69-20) > attestation-stale > transport availability (inner-path-lost) > refresh rounds. Open transition ONLY on fresh PASS: attestation issued → OnRouteOpen hook → gate_opened → route_promoted (events strictly after per-provider events + path proof — "summary without providers is invalid"). Revoke = edge-triggered: revocation_started → synchronous OnRouteRevoke hook → state flip → revoked(+latency) → gate_closed; latency measured AROUND the hook (§63 warp_nonru_revocation_latency_seconds honest semantics), stored in Status.LastRevocationLatency. Fail-closed event only for geo-failure reasons; optional FallbackToBase emits fallback_to_base (§47 advanced policy, UI warning upstream). |
| Session additions (additive) | Packet counters + `SubscribePackets()` tap fan-out for secondary in-tunnel consumers. Delivery is DROP-INSTEAD-OF-BLOCK on both primary queue and taps (research Part 4 resource discipline) — this also removes a latent head-of-line wedge where a stalled consumer would freeze the capsule reader mid-stream. |
| H-NONRU-1 | Telemetry only: BaseColo/InnerColo passthrough accessors surface into NonRUStatus. Per owner instruction the colo base-vs-inner verdict is FIELD-only; zero unit-test claims about it. |
| IPv6 scope | v1 keeps IPv6 disabled for the selected scope (§46 default); no IPv6 probe machinery by design; ipv6-path-failed constant declared for future wiring. |

Scenario matrix executed offline (§69): 1 (inner never connects → closed, zero probe activity), 2 (all-RU → provider-ru + fail-closed + measured latency), 3 (two same-country non-RU → open/promote with full event order), 4 (mixed DE+RU → FAIL_RU dominates, no route hooks while closed), 5 (provider unavailable → insufficient hold → exactly one attestation-stale revoke at TTL, NOT fail-closed), 6 (public-ip change → public_ip_changed event + revoke + forced refresh reopen against new IP hash), 7 (expiry during active traffic — same stale path as 5 with live traffic flowing), 11 (outer drop → inner-path-lost), 19/20 (gen bump → parent-reconnected → reopen only against NEW generation), 21 (fabricated results without inner delta → provider_failed(no counter delta) + direct-wan-observed). Plus: quorum pure table (9 cases incl. higher-quorum and expired-skipping), config floor rejections, manual-disable probing freeze, end-to-end real WhoamiDNSProvider pair through a fake tunnel session (§43 proofs asserted per observation), session counter/tap/drop accounting.

Verification (executed in golang:1.25.3-alpine):

```text
go vet ./transport/warp              → clean
gofmt -l <4 touched files>           → clean (verified via cp-progression run)
go test ./transport/warp -count=1    → ok (73 tests: 59 + 14 new)
go test ./transport/warp -count=2    → ok
go test -race (CGO_ENABLED=1 + gcc)  → ok
go test ./... (/repo layout)         → 51 packages ok, 0 FAIL
```

Known gaps to next stages (design E7–E8): nfq exclusion-set/enrollment-hostlist/camouflage wiring, TracePipeline adapter for supervisor+gate events, Backend-B userspace adapter (also unlocks HTTPSExchange for CFTraceProvider and DoH upgrade), TUN/PBR field layer with OnRouteOpen/OnRouteRevoke hooks. Target-service probes (§69 scenarios 17/18) intentionally out of E6 scope. Target-router validation remains BLOCKED_TARGET_VALIDATION.

## 2026-08-24 (evening) — E7 nfq+wiring (bd b4x-ukp; design §8/§13, z2k #6/#16, addendum §38/§50/§61–63)

New `backendb.go`, `pump.go`, `nfqwiring.go`, `enrollment_hosts.go`, `doh.go` in the engine package + NEW integration package `src/transport/warpwire` + one additive knob in `session.go`. The engine stays dependency-free: every kernel/config touchpoint is an injected interface bound by the field layer.

| Concern | Implementation |
|---|---|
| Backend-B plumbing (`backendb.go` + `session.go` DialFunc) | `StreamDialer` is the contract a base-tunnel TCP carrier must satisfy; `BackendBDialFunc(sd)` converts it into the new optional `SessionConfig.DialFunc`, which replaces ONLY the raw-TCP carrier inside DialSession — pinned TLS handshake, CONNECT-IP framing and validation are untouched. Proven end-to-end offline: a session configured with a TEST-NET endpoint connects and validates because the StreamDialer serves it from a fixture listener — direct dialing would fail. The netstack carrier itself remains field-layer work (zero-dep rule); until then Backend-B composition fails at dial time, never silently falls back. `TunnelGeoTransport.WithHTTPSExchange(fn)` attaches the same carrier class to the §43 probe slot: CFTraceProvider now parses real trace bodies in tests incl. warp=off fail-closed. |
| TUN/PBR field-facing pump (`pump.go`) | Design §11.3 keeps device APPLY on the router; this is the io adapter the field layer mounts a tun into. Uplink enforces MTU and answers oversized packets with a fully-checksummed synthetic ICMP dest-unreachable/frag-needed advertising 1280 (usque silently TRUNCATES oversized reads — we do not); downlink forwards capsules to the device; downlink idle watchdog (Aether WG-watchdog number, recorded E3 gap) fires OnStall once after 10s without inbound and terminates with reason "stall". All stop reasons structured ("stop"/"session-lost"/"tun-closed"/"stall"), goroutines joined via derived context — no leaks (race-clean). |
| Control-flow guard / exclusion-set + camouflage hook (`nfqwiring.go`) | One component owning both §50 sides: while no VALIDATED session is live the control endpoint IPs stay OUT of the exclusion set (establishment traffic keeps receiving strategy coverage = Nova bootstrap posture) and each connected→disconnected transition re-emits `warp_camouflage_authorized`; when Connected() flips true (composition feeds post-validation state only — masque_connected semantics), endpoints enter the exclusion set and `warp_camouflage_cutoff` fires (structural C.4). Membership diff-applied through injected `SetApplier` (field binds ipset/nft), REASSERTED on cadence even without diffs (z2k #6: sets don't survive restarts), apply errors counted and retried next tick — exclusions are never silently dropped. `ControlAuthorization` mirrors src/warp.Valid semantics for the warpwire conversion. |
| Enrollment hostlist contract (`enrollment_hosts.go`) | Canonical control-plane domains (api.cloudflareclient.com per z2k #16, cloudflareaccess.com, three MASQUE SNIs, cloudflare-dns.com) + pure `Missing/MergeWarpControlDomains` helpers with dot-suffix coverage semantics. A catalog missing the enrollment host is now a loud structural check instead of the silent TLS-timeout outage z2k hit. |
| DoH upgrade (`doh.go`) | RFC 8484 message layer (query wireformat, response parsing with min-positive-TTL, QR/rcode checks) + TTL-clamped cache [5s..300s] (warp-socks numbers) behind the TunnelResolver-compatible ResolveA shape. Carrier injected (`DoHExchangeFunc`); unwired = ErrDoHNotWired fail-closed, negative answers never cached. Same carrier dependency as Backend-B — recorded honestly. |
| warpwire.TracePipeline adapter (`tracepipe.go`) | EventAdapter converts Supervisor/Guard/NonRU events into sealed TransportTraceEnvelope v2 with strictly monotonic per-session Sequence; priority policy P0 (state-critical transitions) / P1 (required promotion evidence) — engine sources carry no P2; payload keys redacted-safe only (colo/class/status/reason/verdict/durations/truncated detail). Sink adapters publish through Runtime.PublishTrace so ALL §61 guards (secret-leak, order violation, generation mismatch, dropped-required accounting) execute unchanged. `RequiredPromotionEvents` exported for VerifyTraceCompleteness (§69-30 promotion blocking proven by test). DEVIATION recorded: StateAfter stays empty until the field layer wires ApplyRoute lifecycle — populating "established" today would fabricate TRACE_STATE_MISMATCH violations out of correct engine behavior. |
| warpwire hard-gate feed (`hardgate.go`) | `FeedNonRUGateStatus` converts engine NonRUStatus → contract NonRURouteTrace (attestation/observations 1:1, hashed IPs, stringified generations) and runs ALL §73 producers, aggregating violations; conservative fields documented (DirectDNS=false by construction proof, IPv6Enabled=false per §46 scope). Tests prove healthy open status passes clean and corrupted truth (route active + revoked/stale attestation; provider-RU observation) surfaces exactly the right violation classes. |

Verification (executed in golang:1.25.3-alpine):

```text
go vet ./transport/warp ./transport/warpwire → clean
go test ./transport/warp ./transport/warpwire -count=1
                                            → ok (85 + 5 tests)
go test ... -count=2                        → ok
go test -race (CGO_ENABLED=1 + gcc)         → ok
go test ./... (/repo layout)                → 52 packages ok, 0 FAIL
```

Known gaps to E8/finalization: userspace TCP carrier for Backend-B/DoH/CFTrace (field-layer netstack or equivalent; plumbing + fail-closed slots ready), ApplyRoute lifecycle wiring to enable StateAfter assertions, target-service probes (§69 scenarios 17/18), exclusion/enrollment binding into the live strategy catalog at config compile time, actual router field session (BLOCKED_TARGET_VALIDATION).

## 2026-08-24 (night) — E8 finalization (bd b4x-ukp close-out)

### Owner decisions at close-out (recorded verbatim in state packet)

1. **TCP carrier NOT now.** Zero dependencies preserved. This is a deliberate DEFERRAL, not a cancellation: the carrier is a separate mini-stage AFTER field session #1.
2. **Backend-B slot carries the structural status `BLOCKED_CARRIER`, never FAILED.** Diagnostics must say "carrier absent", not "network broken" — different failure layers. Implemented: `ErrBlockedCarrier` sentinel; `ErrHTTPSNotWired`/`ErrDoHNotWired` wrap it (`errors.Is` classification); `NestedConfig.Validate` REQUIRES `InnerTemplate.DialFunc` for BackendBProxy and returns ErrBlockedCarrier otherwise — previously such a composition would have dialed the inner session DIRECT (unconstrained), which was a silent direct-leak hole closed here. Two loopback fixtures that had used Backend-B as a "no policy gate" shortcut moved to the documented tests-only escape (`AllowUnconstrainedInner`) so the hard rule stays exception-free.
3. **DoH v1 resolution:** DNS through the inner path ships as UDP/53 IP packets (`TunnelResolver`, 162.159.36.1/.46.1) — the anti-leak property is COMPLETE. DoH encryption is an upgrade gated on the carrier, documented as such in `dns_tunnel.go`/`doh.go` docstrings (replacing the earlier "deviation" framing).
4. **Trust gate stays on DNS round-trips** (works over raw IP, no TCP stack needed): engine-level trust = data-plane DNS probes + §43 counter deltas. The warp=on HTTPS probe through the tunnel activates only with the carrier; until then e2e verification is performed by the FIELD instrument (curl with route) — field level, not engine level.
5. **Backlog item created in bd** for the userspace TCP-carrier with the dependency-decision wording (gvisor netstack or equivalent) and trigger = netns/veth check on target firmware during field session #1.
6. **go.mod untouched.** Stage closed with this documented limitation.

### Final verification (executed, golang:1.25.3-alpine, /repo layout replica)

```text
gofmt -l <all 14 engine+warpwire files touched E6–E8> → empty
go build ./...                                        → ok
go vet ./transport/...                                → clean
go test ./transport/warp ./transport/warpwire -count=1 → ok (85 + 5 tests)
go test ... -count=2                                  → ok
CGO_ENABLED=1 go test -race ...                       → ok
go test ./... (/repo layout)                          → 52 packages ok, 0 FAIL
```

No TODO/FIXME/debug leftovers in new files (grep-checked). No new go.mod entries since E0.

### Refinements to addendum v1.2 (design §12, promised by design §15)

| # | Refinement | Implementation evidence |
|---|---|---|
| 1 | **§29 L2 strengthened: CONNECT-IP 200 ≠ masque_connected.** Aether's "edge accepts control but drops traffic" class is covered by an explicit data-plane trust gate: 2 synthetic-DNS round trips within a 10s window before any connected event; silent-drop after handshake tears the session down with failure class `data-plane-validation-timeout`. | `session.go ValidateDataPlane` (+ fake-server silent-drop scenario); supervisor emits `warp_masque_connected` strictly after validation (`supervisor.go` connect phase); C.4 camouflage cutoff consumes exactly this post-validation state (`nfqwiring.go` ControlFlowGuard). |
| 2 | **§34 "versioned and tested" enforced literally.** Endpoint candidates exist ONLY in a versioned in-repo catalog (measured CIDRs/ports); every discovery candidate passes the InCatalog+KnownPort gate (unit-tested for all strategies); arbitrary internet scanning is structurally impossible. | `catalog.go` (CatalogVersion=1, `InCatalog`, `CatalogCandidates` turbo/balanced/thorough), discovery unit tests incl. "every entry passes InCatalog+KnownPort". |
| 3 | **§20 keepalive second contour — PARTIAL, honestly recorded.** Implemented: app-level e2e probe through the tunnel (supervisor health watchdog, streak≥3 → FAIL-OPEN), per-layer keepalive separation constants (outer 20s / inner 30s), downlink idle watchdog 10s at pump level (E7). NOT implemented: protocol-level H2 PING 15s contour — x/net/http2 client exposes no ping primitive without hacks; the app-level probe covers the same stalled-detection goal over raw IP. Recorded as a conscious omission, revisit only if field evidence demands protocol-level keepalive. | `supervisor.go healthLoop`; `nested.go` constants; `pump.go` stall watchdog. |

Additional refinement recorded at E7/E8: **§61.2 StateAfter assertions deferred** until the field layer's ApplyRoute lifecycle exists in composition — populating states today would fabricate TRACE_STATE_MISMATCH violations out of correct engine behavior (`warpwire/tracepipe.go stateFor`).

### Correspondence map to B4_FORK_ARCHITECTURE_v2.5 (design §13, final status)

| v2.5 element | Engine counterpart | Status |
|---|---|---|
| `src/transport/warp` layout | package transportwarp, zero deps beyond x/net/http2 | DONE |
| TransportService owns WARP lifecycle, bindings, route/path proof | Supervisor/NestedRuntime/NonRUGate = lifecycle body; no promotion policy inside engine (TransactionalRuntime/canary owns decisions) | DONE (engine scope) |
| §81A fallback hierarchy: tunnel = 4th/5th step, no recursive fallback | Gate fail-closed-scoped; Backend-B requires carrier or refuses config; inner never falls back past base | DONE |
| §70D exact-scope candidates | Discovery only over versioned-catalog entries | DONE |
| §70E fitness inputs | Tier-adjusted concurrency, MTU+1 buffer discipline, loss→RTT ranking; throughput deliberately outside ranking | DONE (scoped) |
| §50 StrategyDefinition/FakePayloadProfile for control flow | ControlFlowGuard authorization/cutoff + exclusion-set plumbing; binding into the live strategy catalog compile = wiring stage | PLUMBING READY |
| Nova bootstrap protection | Establishment traffic stays strategy-covered (endpoints excluded only while validated); QUIC-fake profile option not built (H3 deferred) | POSTURE DONE |
| DNSPathManager managed path | TunnelResolver (v1 shipping) + DoH message layer ready; registration as managed DNS path binding = wiring | PLUMBING READY |
| ServiceProfile kind cloudflare-warp-masque, forbidden_countries:[RU] executed by gate | NonRUGate executes §42–47 verdicts/quorum/revocation; profile-compiler link = wiring | GATE DONE, LINK PENDING |

### Final honest verdict

```text
Engine (E0–E8): COMPLETE — offline-verifiable scope green (90 tests, race, full repo suite).
Field session on target router: BLOCKED_TARGET_VALIDATION (no router touched in this arc).
Carrier-dependent surfaces: BLOCKED_CARRIER (structural, classified, fail-closed).
```

Every deviation from addendum letter is recorded in this report (§11 deferrals, E4 probe-ceiling number, E5 DoH note superseded by owner decision above, E7 StateAfter, E8 carrier). No claims are made about router behavior without field data; H-NONRU-1 remains a FIELD experiment reading BaseColo vs InnerColo telemetry.








