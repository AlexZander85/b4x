# SPF-7 — Scoped recovery leases

Status: IMPLEMENTED_NOT_TARGET_VALIDATED

Leases are generation-bound, scope-exact, TTL/attempt bounded and require a
rollback target. They reject recursive same-binding fallback.
