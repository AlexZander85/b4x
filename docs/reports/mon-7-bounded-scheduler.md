# MON-7 — provisional fast lane and scheduler

`DiagnosticScheduler` provides separate bounded quick/deep queues. Requests are coalesced by an explicit idempotency key, leases expire and can be reaped, failures back off, and queue capacity returns an observable overload error. Cancellation and context cancellation are non-destructive to unrelated requests.

The scheduler carries only a `DiagnosticRequest`; it cannot construct a `BlockingProfile`, authorize a transport, mutate policy, or apply a candidate. MON-8 supplies the ABD adapter for an acquired lease.

Validation: `go test ./monitor` passes, including duplicate/coalescing, lease exclusivity, backoff, and overload tests.

