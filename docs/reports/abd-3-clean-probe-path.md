# ABD-3 — clean probe path and network context

The active detector now validates a dedicated `ProbeContext` containing exact scope, native/production/candidate/transport path identity, an unexpired budget token, request expiry, and matching configuration generation. Self-interference is an explicit invalid state.

`ObserverCapability` and `ObserverHealthLease` describe stage/protocol/IP-family capability and bounded health. `CompareVantage` only compares stage- and identity-aligned observations; an unavailable, stale, or mismatched observer produces no opinion and cannot imply `host_dead`, routing permission, or action authorization.

Validation: `go test ./detector` passes.

