# PPE Stage 5 Implementation Report

## Scope

Implemented static and passive observability for the Keenetic PPE per-flow exclusion layer. This stage deliberately does not claim functional packet visibility.

## Delivered

- Read-only `/api/v1/capture/offload/status` endpoint alongside the PPE capability endpoint.
- Runtime capability, deterministic desired generation, owned rule counters and passive direction evidence in one status report.
- `iptables -w -t mangle -L B4_PPE_PRE/B4_PPE_FWD -n -v -x --line-numbers` counter collection for IPv4 and IPv6 plans.
- Counter parser accepts only B4 provenance comments (`b4:ppe:v1:tcp` and `b4:ppe:v1:quic`).
- Bounded passive tracker with TTL eviction and no packet payload, IP, domain or raw five-tuple export.
- Production NFQUEUE workers emit only hashed flow identifiers, direction, protocol, TCP flags/sequence metadata, payload length and QUIC shape.
- Passive states: `unknown`, `outgoing_only`, `bidirectional_observed`, and `suspected_offload_blindness`.
- Static/passive diagnostic states distinguish unsupported capability, missing counters, outgoing-only evidence, bidirectional evidence and suspected blindness.
- HTTP server wires one shared passive tracker to all production workers and the read-only status service.

## Safety properties

- Passive observations cannot set functional confirmation.
- PPE-5 always publishes `functional_verdict=not_run` and `production_ready=false`.
- Rule presence or counter increments are not treated as proof of packet visibility.
- Bidirectional passive traffic is evidence only; controlled endpoint proof remains PPE-6.
- The tracker is bounded and expires flow hashes; it retains no payload bytes.
