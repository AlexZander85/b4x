# ABD-12 — UX, field validation, and release gate

The internal monitor handoff is idempotent and validates assessment ID, request ID, scope, and configuration generation before accepting a result. A conflicting duplicate is rejected. `DeepCheckpoint` resumes only inside the same network/config context and within a short lease; an interrupted or incompatible run cannot emit a complete profile.

`DetectorCapacityProfile` uses a conservative static fallback and only calibrates when drops and latency are within safe limits. `ABDReleaseGate` requires detector tests, monitor adapter, client-resolution, multi-vantage, capacity, router, Android, privacy, and direct-apply gates; the verdict is not production-ready until all external evidence is present.

Validation: `go test ./detector` and `go test ./monitor` pass. The repository-wide baseline still has the previously documented generated `ui/dist/*` and `capture/ppe` test issues outside ABD.

