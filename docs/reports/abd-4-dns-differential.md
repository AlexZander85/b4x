# ABD-4 — DNS differential evidence

`DNSDifferentialEvidence` binds every exact-endpoint attempt to an immutable client-observed `ClientResolutionSnapshot` and the exact network/config generation. Independent-current resolution is stored as a separate experiment, never silently replacing the client answer or CNAME chain.

The per-address outcome vector preserves every A/AAAA result and failure attribution; no first-success aggregation is performed. Stale snapshots and generation mismatches remain explicit suppressors rather than being converted into confirmed spoofing or blocking claims.

Validation: `go test ./detector` passes.

