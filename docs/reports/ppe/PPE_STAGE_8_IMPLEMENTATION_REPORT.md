# PPE Stage 8 Implementation Report

## Scope

Productized the Keenetic per-flow PPE visibility layer through authenticated
API routes, startup/shutdown lifecycle integration, beginner-safe UI controls,
advanced controlled self-test controls, privacy-safe diagnostics, and
compatibility migration documentation.

## Delivered

- `ProductService` owns capability detection, deterministic desired state,
  transactional rules, NDM reconciliation, observation bus, self-test store,
  visibility gate state, audit history and idempotent mutations.
- Startup applies exclusion only when explicitly configured and capability is
  proven; all failures degrade to monitoring/fail-open behavior.
- Authenticated read/mutation API under `/api/v1/capture/offload/*`.
- Generation preconditions and idempotency keys for apply/rollback/self-test.
- Rollback-to-monitoring removes only B4-owned rules and does not change global
  hardware offload.
- Existing issue bundle receives a PPE section; a dedicated PPE bundle is also
  available with desired and actual B4-owned rule fragments, counters, timeline
  and safety decisions. Both exclude raw packet data and identifiers.
- NFQUEUE self-test evidence correlates the controlled probe by family, protocol
  and client source port rather than an invented flow ID.
- Bounded PPE metrics and redacted trace events cover capability, rules, reapply,
  self-test, direction visibility and degradation.
- Classifier overview includes a basic per-flow toggle and an Advanced
  controlled A/B test panel in English and Russian.
- v52→v53 migration preserves `detect` and never enables exclusion or global
  disable during migration.
