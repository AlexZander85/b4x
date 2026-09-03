# DDI/TGB companion release register

Implemented and unit-validated stages:

- DDI-1…DDI-10: versioned profile schema, context freshness, bounded persistence, revalidation, Discovery snapshots, deterministic hint planning, observability, causal validation, and release matrix.
- TGB-1…TGB-10: baseline fixtures, structured outcomes, progress-aware first-data state, pending budgets, prefix handoff, route ladder, config migration, diagnostics, packet-path gates, and Keenetic/Android release matrix.

Combined package validation passes:

```text
go test ./detector ./discovery ./monitor ./mtproto
```

The DDI/TGB implementation does not claim external field verdicts. `DDI_TARGET_VALIDATED`, `DDI_PRODUCTION_READY`, `TGB_ANDROID_VALIDATED`, `TGB_PRODUCTION_READY`, `ISSUE_277_RESOLVED`, `ISSUE_278_RESOLVED`, and the combined release verdict require real target/router/Android evidence and measured search/bridge behavior. No profile hint or bridge observation directly authorizes production mutation, routing, packet action, or promotion.

