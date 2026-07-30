# ABD-1 — baseline audit and compatibility fixtures

The built-in detector remains the owner of active probe execution. The current compatibility surface is preserved: `DetectorSuite`, existing `TestType` values (DNS, DNS availability, domains, TCP, SNI, Telegram), suite status/history persistence, cancellation, progress counters, and the existing HTTP handlers remain unchanged.

Current behavior map:

- `src/detector/detector.go` owns suite lifecycle and test ordering;
- `src/detector/dns.go`, `domains.go`, `tcp.go`, `sni.go`, `telegram.go` own protocol probes;
- `src/detector/targets.go` and `targets.json` provide the static target catalog;
- `src/detector/history.go` persists redacted suite history;
- detector marks/path selection is inherited from the suite constructor and remains a compatibility boundary;
- monitoring and Watchdog compatibility adapters are outside this package and cannot mutate detector results.

The v1.2 layer is additive: new request/plan/evidence/profile contracts live beside the legacy suite API, and no legacy API field is silently reinterpreted. Pinned behavior provenance is recorded in the companion architecture reports (Ladon `8af5e68cadea16c177f17fb6a50f1e0b6931aa8d`, plus the addendum's read-only references).

Validation: existing detector tests and `go test ./monitor` remain green. ABD-2 introduces the typed plan compiler without changing legacy suite execution.

