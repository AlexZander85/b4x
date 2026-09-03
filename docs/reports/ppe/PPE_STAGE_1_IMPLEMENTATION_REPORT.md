# PPE Stage 1 Implementation Report

## Scope

- Added `capture/ppe` capability DTOs and runtime detector.
- Detects Keenetic NDM from runtime primitives; router model is metadata only.
- Requires exact `PPE` target registration.
- Functionally probes `connskip` in an owned transient mangle chain and always cleans it up.
- Separates IPv4 and IPv6 states, binaries, tables, lock support, permissions, and reasons.
- Added read-only `GET /api/v1/capture/offload/capabilities`.
- No persistent PPE exclusion rules are installed in this stage.

## Safety

A platform is product-supported only when Keenetic NDM is confirmed and IPv4 has the exact target plus a successful functional probe. Static capability explicitly warns that it does not prove bidirectional visibility.

## Verdict

PASS_WITH_LIMITATIONS — implementation is complete, but real-router evidence is intentionally deferred by operator decision. This verdict does not enable automatic promotion.
