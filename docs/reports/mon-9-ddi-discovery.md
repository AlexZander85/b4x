# MON-9 — DDI, Discovery, and recommendation integration

`DDIProfileRef` binds a reusable network diagnostic profile to the exact monitor scope, network context, configuration generation, compatibility hash, expiry, and authoritative ABD run. `GuidedDiscoveryRequest` requires that profile to be fresh and all mandatory baselines to be present; passive state alone cannot invoke Discovery.

`TransportRecommendation` is an explanation-bearing, scoped handoff. It requires a DDI reference and non-empty IP path evidence for every entry. It is a recommendation only; WARP/transport availability and action authorization remain in their owning control planes.

Validation: `go test ./monitor` passes. Stale/incompatible DDI and pathless recommendation tests are included.

