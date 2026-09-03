# WARP-11 — product integration

The transport contract exposes base WARP status, candidate selection/reset, trace completeness, generation mismatch, and actionable failure-layer explanations. Camouflage is a separate capability and must be opt-in; experimental non-RU is a distinct control with a strict fresh geo quorum and no country-selection guarantee.

Required companion registrations:

- Field Test: base WARP, camouflage, non-RU, causal trace completeness, nested dependency, path proof, and cleanup scenarios;
- Service Profiles: `cloudflare-warp-masque`, camouflage policy, geo constraint, redacted trace status, and promotion requirements;
- Implementation Validation: WARP-1…WARP-12, WARP-C1…WARP-C10, causal-trace and validation-of-observability meta-tests.

The current repository records these contracts and does not claim target validation or production promotion.

