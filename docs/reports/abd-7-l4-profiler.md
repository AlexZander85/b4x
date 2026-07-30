# ABD-7 — L4 packet/byte threshold profiler

The profiler stores packet and unique-byte experiments as independent dimensions, retaining direction and fresh/persistent flow mode. It returns intervals rather than a single universal threshold and marks server-limited samples as suppressed.

No byte threshold is inferred from packet evidence (or vice versa), and a single origin cannot create a high-confidence production claim. The resulting profile is an evidence input for ABD-9/ABD-10 only.

Validation: `go test ./detector` passes.

