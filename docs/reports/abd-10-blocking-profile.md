# ABD-10 — BlockingProfile compiler

`CompileBlockingProfile` is a deterministic, immutable compiler from an evidence graph to a redacted `BlockingProfile`. It requires complete authoritative ABD evidence, exact assessment/request/scope/config-generation linkage, and non-empty evidence references. Cancelled, partial, suppressed, provisional, or passive-only runs produce a typed non-ready result and no profile ID.

The content hash is stable for the same normalized graph inputs. The resulting profile is evidence and a DDI payload only; it is not `ActionAuthorization`, `TransportAuthorization`, or permission to mutate production config.

Validation: `go test ./detector` passes.

