# PPE Stage 7 Implementation Report

## Verdict

PASS_WITH_LIMITATIONS

## Implemented

- Added one generation-bound `VisibilityGate` with `complete`, `outgoing-only`, `unknown`, and `incomplete` states.
- Only observe-only processing and stateless safe mutation remain allowed while proof is unknown or incomplete.
- Controlled PPE self-test is the only path that can publish `complete`; `PASS_WITH_LIMITATIONS`, `FAIL`, `UNSUPPORTED`, and `INCONCLUSIVE` remain blocking.
- PPE lifecycle assertion failure degrades visibility immediately. Successful rule reapply invalidates the previous proof and requires a new controlled self-test.
- Active TCP hold/replay checks visibility before enqueueing. Degradation releases all held NFQUEUE packets unchanged and blocks repeated hold loops.
- Active TCP reassembly is skipped and any existing flow state is aborted when complete visibility is unavailable. Current-packet stateless parsing remains available.
- ACK/server-progress dependent ActionToken closure is disabled without complete visibility.
- Automatic Discovery is blocked without complete visibility; explicitly initiated manual diagnostics remain available.
- Runtime-control builders are wrapped at the transaction boundary. Candidate canary and promotion are rejected when the visibility gate is not complete, including direct Manager calls outside HTTP/UI.
- Initial and candidate runtime generations establish a fresh proof requirement when `capture.offload_policy=exclude`.

## Safety properties

- Degradation is fail-open for packet holding.
- No raw packet, hostname, address, or payload is stored in the visibility state.
- A reasserted PPE generation cannot inherit a stale functional proof.
- `PASS_WITH_LIMITATIONS` never enables automatic promotion.
- Platforms/configurations not using PPE exclusion retain existing behavior because the gate is not enforced.

## Limitation

No real Keenetic/MediaTek rule-removal-during-hold test was executed. Product construction of the PPE reconciler/self-test service and user-facing API/UI is completed in PPE-8; until then the reusable lifecycle wrapper is available but not globally instantiated by startup code.
