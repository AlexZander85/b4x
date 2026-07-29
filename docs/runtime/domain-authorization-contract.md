# Domain Authorization Runtime Contract

## Decision boundary

```text
shared IP/CIDR/port/geosite match
→ CaptureCandidate only
→ parsing/hold/inspection may start
→ no service-scoped mutation, reject, failure cache or route side effect
```

```text
clear packet SNI
or complete conflict-free reassembled SNI
or fresh source-scoped DNS/QUIC evidence allowed by scoped-hints
→ ActionAuthorization bound to exact FlowKey, ClientKey, SetID and ConfigGen
```

```text
contradictory hostname
→ provisional candidate contradicted/revoked
→ no previous set survives
```

```text
ambiguous, stale, malformed or incomplete visibility
→ fail-open
→ release unchanged / accept direct
→ structured trace, metric and optional Failure Inbox event
```

## Effective domain policy

Resolution order:

```text
explicit set.targets.domain_policy
→ global classifier.domain_only_mode when inherit/absent
→ legacy mapping only for genuine compatibility configuration
```

- `strict`: packet/reassembled clear SNI or explicit static hostname only.
- `scoped-hints`: strict evidence plus fresh source-scoped DNS/QUIC evidence.
- `legacy`: compatibility mode, visible as unsafe when broad candidates and destructive actions coexist.
- `disabled`: explicit IP/CIDR fallback semantics; not suitable for shared Google service sets without manual opt-in.

## Authorization invariants

An action plan for a domain-scoped set must reference an unexpired authorization with the same:

- normalized `FlowKey` and client identity;
- set ID;
- config generation;
- protocol and destination port scope;
- effective domain policy.

One logical first ClientHello produces at most one final decision and one action token. Packet-local and reassembled hostname evidence use the same matcher. A conflict suppresses mutation and fails open.

## State and side effects

- Learned observations are client/IP/protocol/domain/set/generation scoped with absolute expiry.
- Block and escalation keys include client, domain, set and generation.
- RST sent/suppressed state is exact-`FlowKey` scoped.
- QUIC `FilterQUIC=all` means all packets of an already authorized set/flow.
- Domain-scoped routes use exact-flow bindings with owner, provenance, generation, transaction ID and timeout.
- Rollback/shutdown removes only owned bindings and invalidates generation-bound authorization/state.

## Promotion contract

A runtime candidate is promotion-eligible only after a fresh cross-service report for its exact generation passes all negative-control hard gates. Missing, stale or failed evidence aborts and rolls back the pending candidate. Validation evidence stores hashes/provenance only and cannot widen target domains or IPs.
