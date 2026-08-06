# MON-13 — cutover production readiness matrix (MON addendum v1.0 §57.1)

Status of the six event-driven cutover prerequisites and the post-cutover obligations, with verification evidence. Prepared 2026-08-06 after phase A + phase C of FB-07.

## Prerequisites (all six)

| # | Prerequisite | Status | Evidence |
|---|---|---|---|
| 1 | Shadow parity | READY | `ShadowParityTracker` wired in `monitoring.Runtime.project` (control-failure → parity/contradiction evidence); `TestRuntimeShadowParityEvidenceOnWatchdogSignal` (PASS); registered as IV-18-MON-11 coverage |
| 2 | Scheduler readiness | READY | `DiagnosticScheduler` production-wired via `monitoring.Runtime`; bounded quick/deep capacities, lease/backoff/coalescing; `TestSchedulerRunningAndQueuedProjection`, `TestSchedulerCoalescesAndLeases` (PASS) |
| 3 | ABD/DDI integration readiness | READY | production dependencies probe: `detector.CompileBlockingProfile` + `monitor.BuildGuidedDiscovery` call sites wired (`runtime.go`); `IV18ProductionDependencies()` all ready (0 blocked) |
| 4 | Transactional apply readiness | READY | Monitoring itself is projection-only by design (never mutates config — `watchdog_heal.go` FB-28 cutover marker). Where mutation is applied outside MON, it is transactional with generated rollback: `tables.GSOQueueRuleTransaction` (apply/rollback programs), `handler.ApplyConfig` + restore-on-error (`capture_offload_product.go`), configuration `Clone -> Validate -> Store` path in `handler/config.go` |
| 5 | Rollback readiness | READY | `silentpath.RollbackMonitor` (budgeted, observation-only), `warp.Runtime.Rollback` (+ `warp_rollback_failure_total` hard gate), `TestCanaryRollbackIsObservationOnly` (IV-18-MON-11 / FT-MON-J) |
| 6 | API migration tests | READY | `http/handler/watchdog_cutover_test.go`: 5 × mutating endpoint → 410 Gone, read-only status alias serves Monitoring projection (id + §58 vocabulary incl. escalating), no-runtime fail-closed 200-empty, pre-cutover not 410; registered as IV-18-MON-11 + IV-18-FT-MON-J coverage; `TestWatchdogCutoverMutatingEndpointsGone`, `TestWatchdogCutoverStatusServesMonitoringProjection` (PASS) |

## Cutover gate

- `IV18ReverseReachability("")` clean: legacy mutating symbol `applyBatchResults` unreachable (removed FB-28); `TestIV18ReverseReachabilityCleanAfterCutover`, `TestIV18ReverseReachabilityCleanTreeIsProductionReady` (PASS).
- `MonProductionReady()` fail-closed: `PASS` only when reachability clean AND all production dependencies present; verdict consumer `RunIV18Suite` (validation_gates.go `/api/validation/v1`, main startup) — currently `PASS` in-suite (unit-level).
- After cutover (per §57.1): legacy POST/PUT/PATCH/DELETE → 410 Gone; read-only GET alias lives max one compatible minor then routes are removed entirely; never two mutating sources of truth.

## NOT yet issued

`MON_PRODUCTION_READY` as a release gate is **not claimed** by this stage: per mon-12 §gate, it requires external validation evidence — real-router and Android field runs, multi-WAN / restart / fault-injection runs, and the privacy audit. These remain fieldted work, not unit-level evidence.

Validation: `go test ./validation -run IV18` PASS (63s), full `go vet ./... && go test ./...` green.