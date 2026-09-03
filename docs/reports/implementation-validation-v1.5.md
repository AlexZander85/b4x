# B4 Implementation Validation v1.5

Source addendum SHA-256: `aae0c3e63fb1c2b1fd2fdaa3f9b27662132521cd50a8862240c3f0eea60484b5` (пересчитано 01.08.2026 после FB-14; до FB-14: `b5ee991995b4a56674204da6e0645245adcc7d01ad53b3baabe6e889af9961b7`)

Implemented IV-1…IV-17 in `src/validation`:

- canonical requirement/suite registry with deterministic hashing and orphan detection;
- terminal verdict aggregation, dependency blocking and false-pass mutation guards;
- validation API/CLI request contract with idempotency/auth fields and dry-run;
- Stage 1–36 L0…L8 matrix, DNS/UDP/QUIC/IP-family fixtures, transport/WARP lifecycle, PPE, CSI/GSO/RST/camouflage, service-profile and Field Test conformance;
- validation-infrastructure meta-suite for artifact integrity, reproducibility and known-broken fixtures;
- full WARP-aware run ordering with separate base/camouflage/non-RU/causal verdicts;
- Silent Path Failure false-positive/scoped-recovery validation;
- ABD-1…ABD-12, DDI-1…DDI-10 and TGB-1…TGB-10 conformance registries;
- IV-17 causal trace schema/order/runtime consistency, path counters, forwarded Android correlation, nested dependency, geo quorum, DNS/IPv6, camouflage cutoff and cleanup ownership gates.

Verified locally:

```text
go test ./validation/... ./fieldtest/... ./serviceprofile/... ./detector ./discovery ./monitor ./mtproto ./warp
```

The validator is fail-closed. Missing artifacts, orphan requirements, absent current-generation proof, stale tokens, incomplete cleanup, unproduced hard-gate counters or forced-zero metrics cannot produce `PASS`. Real Keenetic/Android evidence remains required for target-scoped release claims.
