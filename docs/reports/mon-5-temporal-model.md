# MON-5 — temporal recurrence, independence, decay, and hysteresis

The monitor now retains a bounded, generation-scoped temporal accumulator. Evidence is bucketed by observation time, bounded by both a bucket count and a four-half-life horizon, and exposed as a passive snapshot.

Recurrence counts repeated failures; independence counts distinct source, endpoint, flow, fingerprint, and WAN-interval dimensions. Duplicate reports from one source therefore do not masquerade as independent corroboration. Weighted values decay with age and are not an authorization signal.

State transitions use configurable hysteresis (`unknown/healthy → degraded → failing → recovering → healthy`) and require successes to demote a failing state. The accumulator has no imports from action, policy, transport, or configuration mutation packages.

Validation: `go test ./monitor` passes. The separation boundary is covered by `temporal_test.go`; integration with source-health suppressors is MON-6.

