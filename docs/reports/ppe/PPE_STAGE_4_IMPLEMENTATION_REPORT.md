# PPE Stage 4 Implementation Report

## Scope

Implemented NDM netfilter-regeneration resilience and bounded stale-state reconciliation for the active B4 PPE generation.

## Delivered

- `TransactionManager.Assert` verifies the exact active generation without mutating firewall state.
- `TransactionManager.Reapply` reconciles only the current active generation and verifies it before success.
- `Reconciler` supports startup, NDM event, periodic safety assert, and manual reasons.
- NDM events are debounced and coalesced through a bounded channel.
- Reapply storms are blocked by a minimum retry interval and a longer failure backoff.
- Every reapply is followed by another exact assertion; rule presence is never inferred from a successful command alone.
- Reconciler status exposes checks, missing detections, successful reapplications, failures, suppressions, coalesced events, last reason, generation, and timestamps.
- An atomic Entware/NDM hook installer manages `/opt/etc/ndm/netfilter.d/94-b4-ppe-reconcile.sh`.
- The hook reacts only to `table=mangle` and signals the locked B4 process through its existing pid file using `SIGUSR1`.
- The signal bridge converts `SIGUSR1` into a bounded NDM reconcile event.
- Hook installation is idempotent and refuses to replace or remove files without the B4 ownership marker.

## Lifecycle semantics

- Event-driven NDM notification is the primary recovery mechanism.
- The configured periodic interval is a safety assertion only.
- A healthy exact assertion performs no mutation.
- A missing generation is restored once, then protected by the storm guard.
- Failed reconciliation retains the active desired generation and records a degraded status for a later bounded retry.
- No stale rule is treated as evidence that the current generation is healthy.
