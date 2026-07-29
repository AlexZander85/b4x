# Cross-Service Isolation Implementation Report

## Scope

This report covers the post-v2.3 companion stages CSI-1 through CSI-10. The implementation keeps shared IP/CIDR/port matches provisional until a service-scoped authorization is produced, and keeps failure/routing side effects within client/flow/domain/set/config-generation scope.

## Stage delivery

| Stage | Commit | Delivered contract |
|---|---|---|
| CSI-1 | `feat(config): add effective per-set domain policy and legacy scope guard` | Per-set `DomainPolicy`, deterministic effective policy, legacy compatibility, unsafe legacy validation and migration preview. |
| CSI-2 | `refactor(classifier): separate capture candidates from action authorization` | Typed `CaptureCandidate` and `ActionAuthorization`; exact flow, client, set and generation binding. |
| CSI-3 | `fix(nfq): authorize domain sets from complete reassembled SNI` | Complete bounded reassembly feeds the authoritative matcher; conflict and duplicate-final protection. |
| CSI-4 | `fix(classifier): revoke provisional service matches on contradictory hostname evidence` | Positive/negative hostname evidence, candidate revocation, ambiguity fail-open and lifecycle trace. |
| CSI-5 | `fix(classifier): demote legacy learned IP to scoped provisional evidence` | Immutable source-scoped observations, absolute expiry and no v2 action/route authorization from legacy learned IP. |
| CSI-6 | `fix(nfq): scope block escalation and RST state by client domain and generation` | `ScopedFailureKey`, scoped escalation and exact-`FlowKey` RST bookkeeping with bounded cleanup. |
| CSI-7 | `fix(quic): require domain authorization before service-scoped UDP actions` | QUIC inspection-only IP candidates, domain gate for reject/mutate/fallback and unknown/malformed fail-open. |
| CSI-8 | `fix(routing): bind domain-scoped routes to authorized client flows` | Bounded exact-flow route/proxy bindings with owner, provenance, generation, transaction and expiry. |
| CSI-9 | `feat(observability): expose domain authorization and cross-service isolation state` | Required metrics, privacy-safe trace/API/UI state and Failure Inbox isolation signals. |
| CSI-10 | `test(field): gate YouTube rollout on Gmail and Google cross-service isolation` | Fourteen-scenario validation report, hashed actual-domain evidence, hard promotion gate and pending-candidate rollback. |

## Compatibility and migration

- Existing configurations continue to parse.
- An absent per-set policy resolves through the global classifier mode.
- Managed/generated domain-only profiles use `scoped-hints`; generators reject `legacy`.
- Unsafe legacy domain scope remains available only through an explicit advanced override and is visible through validation/API warnings.
- Destination-global legacy learned-IP state remains compatibility/diagnostic data and is not authoritative in classifier v2.

## Resource and ownership notes

- Candidate, authorization, hint, failure, route and validation stores are bounded.
- Evidence expiry is absolute; lookup does not extend source validity.
- No long-lived runtime state stores mutable `*SetConfig` pointers.
- Route bindings are exact-flow scoped, owned and deterministically expired/removed.
- Validation reports retain domain hashes and provenance only; they do not retain packet payloads or raw hostnames.
- There is no goroutine-per-packet behavior in the corrective layer.

## Promotion behavior

A staged runtime generation cannot be promoted unless a fresh validation report exists for the exact generation and all hard gates pass. A failed gate aborts persistence, records cooldown/history, rolls back and closes the pending runtime, and removes it from pending state. The report remains available for diagnostics; no domains or IP ranges are widened automatically.

## Known limitations

- Real Keenetic/Android acceptance evidence must still be collected on the target device. Synthetic and unit tests do not replace field validation.
- The development environment used for this implementation has Go 1.23.2 while the project requires Go 1.25.3; the full repository suite therefore could not be executed here.
- Frontend package dependencies were not installed; the dependency-free classifier UI contract validator and JSON validation were run instead of a full Vite build.
