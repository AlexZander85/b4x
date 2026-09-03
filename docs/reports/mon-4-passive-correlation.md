# MON-4 — Passive flow-health correlation

Status: IMPLEMENTED_NOT_TARGET_VALIDATED

Added scope-preserving flow correlation with separate forwarded and
router-origin flags, explicit target/control role, per-address outcomes and a
health summary. SYN-ACK-only observations do not imply success; endpoint
failures are retained when another address succeeds.
