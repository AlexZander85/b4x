# MON-12 — field validation and production release gate

## Automated validation

| Check | Result |
|---|---|
| `go test ./monitor` | PASS |
| monitor schema/bus/subject/correlation tests | PASS |
| temporal recurrence/independence/decay/hysteresis tests | PASS |
| visibility heartbeat/suppressor tests | PASS |
| bounded scheduler lease/coalescing/overload tests | PASS |
| ABD partial/scope lifecycle tests | PASS |
| DDI freshness/baseline/path evidence tests | PASS |
| canary Android/rollback observation tests | PASS |
| compatibility projection/checkpoint tests | PASS |

The repository-wide `go test ./...` was also run. Existing environment/repository failures remain outside MON: the root/http packages require the generated `ui/dist/*` embed, and `capture/ppe/product_bundle_test.go` has a pre-existing `config.Config` versus `*config.Config` mismatch. All other packages, including `monitor`, passed.

## Gate status

- `MON_OBSERVATION_READY`, `MON_DEMAND_INTAKE_READY`, `MON_RESOLUTION_CORRELATION_READY`, `MON_TEMPORAL_MODEL_READY`, `MON_VISIBILITY_SUPPRESSORS_READY`, `MON_TRIGGER_PLANNER_READY`, `MON_ABD_ESCALATION_READY`, and `MON_LEGACY_WATCHDOG_MIGRATED`: **implemented and unit-validated**.
- `MON_PRODUCTION_READY`: **not issued by this stage**. The addendum requires real-router/Android evidence, multi-WAN/restart/fault-injection runs, privacy audit, and umbrella hard-gate zeroes. This report intentionally does not claim those external validations.

No monitor observation or provisional health state authorizes a profile, action, transport, promotion, or rollback. The legacy Watchdog direct-apply path does not exist: `applyBatchResults` was **removed** (FB-28, 2026-08-02) and the legacy Watchdog writes the in-memory health state only — it never mutates configuration (verified: `watchdog/watchdog_heal.go` projection-only outcome handling; reverse-reachability scan `TestIV18ReverseReachabilityBlocksProductionReadyWhileLegacyReachable`). The `legacy_watchdog_direct_apply` config field (MON addendum v1.0 §59) defaults to `false`; when set to `true` (unsafe development/migration only) b4 emits a startup warning and increments the zero-tolerance counter `monitor_legacy_watchdog_direct_apply_total`, which blocks production readiness.

