# ABD-2 — user target plan and service components

`CompileDiagnosticTargetPlan` is the only path from a user/service selection or monitor overlay to an active detector plan. It validates the monitor request, exact scope, freshness, and bounded target count; deduplicates targets deterministically; and preserves same-service controls plus a clean baseline as separate roles.

Controls are evidence controls, not action targets. Quick/deep budgets are explicit and bounded, and the compiler never creates a production rule, strategy, or transport authorization.

Validation: `go test ./detector` passes for deterministic compilation, scope/freshness rejection, and mandatory-control preservation.

