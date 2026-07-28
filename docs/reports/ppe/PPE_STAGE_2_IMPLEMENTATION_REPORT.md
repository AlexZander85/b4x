# PPE Stage 2 Implementation Report

## Scope

Implemented the deterministic Keenetic MediaTek PPE private-chain rule compiler and persisted configuration model.

## Delivered

- `capture.offload_policy`: `detect`, `exclude`, `disable-global`.
- TCP/QUIC enable flags, configured ports, connskip window, IPv4/IPv6 modes, source scope, reassert interval and self-test settings.
- Backward-compatible defaults and validation; persisted migration/version bump is reserved for PPE-8 productization.
- Validation and normalization of policy, family modes, ports, connskip window, scope and self-test settings.
- Effective PPE ports compiled as configured ports intersected with ports used by enabled B4 inspection sets.
- Explicit pre-payload managed-device ipset requirement for `managed-devices` scope.
- Separate IPv4 and IPv6 family plans with `auto`, `on`, and `off` semantics.
- Owned `B4_PPE_PRE` and `B4_PPE_FWD` chains, one canonical jump per forwarding hook, TCP/QUIC provenance comments, and no CONNMARK/processed-mark persistence.
- Canonical restore text and deterministic SHA-256 desired-state generation.

## Safety properties

- `detect` compiles no mutation rules.
- `disable-global` is represented but never compiled as an automatic fallback operation.
- `ipv6=on` fails when capability is unavailable; `auto` records a skipped family.
- Managed-device scope cannot silently widen to all forwarded traffic.
- Multiport rules are bounded to 15 ports per rule.
