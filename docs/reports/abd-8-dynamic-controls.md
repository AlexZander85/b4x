# ABD-8 — dynamic infrastructure controls

`DynamicControlTargetProvider` accepts only bounded selector results from an injected local/signed source. It validates provenance and expiry, applies a configured maximum, caches last-good results with TTL, and uses a deterministic sampling seed. No network scanner or unbounded public-address discovery is introduced.

Dynamic target failures are returned as provider errors and do not become service-level proof automatically.

Validation: `go test ./detector` passes.

