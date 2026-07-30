# ABD-11 — DDI adapter and guided planner priors

`NetworkDiagnosticProfileEnvelope` embeds the immutable ABD `BlockingProfile` and binds it to exact scope, expiry, and compatibility context. `BuildDiscoverySearchPrior` requires a fresh envelope and current mandatory baseline before producing a bounded prior.

The prior changes search ordering only. Coverage denominator includes excluded targets with reasons, mandatory baselines remain first, and `MergeBaseline` retains explicit fallback candidates. No second optimizer is introduced, and no monitor/detector object can authorize Discovery, WARP, packet mutation, promotion, or rollback.

Validation: `go test ./detector` passes.

