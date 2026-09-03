# PPE Stage 5 Validation Report

## Verdict

`PASS_WITH_LIMITATIONS`

## Passed

- PPE package unit tests, race detector and `go vet` in the dependency-isolated module.
- Passive state transitions: unknown → outgoing-only → suspected blindness → bidirectional evidence.
- Passive snapshots never set functional confirmation.
- Bounded flow tracking and TTL eviction.
- Rule counter parsing ignores non-B4 rules and accepts only owned provenance comments.
- Counter collection uses xtables wait and only owned private chains.
- Diagnostics with rule hits and bidirectional passive evidence still return `functional_verdict=not_run` and `production_ready=false`.
- Unsupported capability cannot be promoted by passive evidence.
- NFQUEUE passive observer implementation type-checks against a dependency-isolated package contract.
- Go parser, `gofmt`, and `git diff --check` pass for all changed files.

## Limitations

- The full repository Go suite cannot start because Go 1.25.3 and uncached external modules cannot be downloaded in the current network-restricted environment.
- No real Keenetic rule counters or packet traffic were sampled.
- Passive evidence is intentionally non-authoritative and cannot produce `PASS`.
- Controlled split ClientHello, retransmission, incoming progress, QUIC and A/B proof remains PPE-6.
