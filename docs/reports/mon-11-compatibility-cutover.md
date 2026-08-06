# MON-11 — API/UI/persistence and Watchdog compatibility cutover

`MonitorAPIProjection` is the source-of-truth read model for the new monitor surface. `LegacyWatchdogAdapter` preserves status and force-check compatibility, but maps force-check to the bounded quick diagnostic scheduler and exposes no configuration mutation or applier callback.

`MonitorCheckpoint` provides a versioned JSON persistence envelope with an explicit cutover version and strict validation. Expired leases and diagnostic state are not restored as action authorization. Existing Watchdog endpoints can therefore remain as adapters while the legacy mutating `applyBatchResults` path is **removed** (FB-28, 2026-08-02): the legacy Watchdog now writes the in-memory health state only and never mutates configuration (see `watchdog/watchdog_heal.go`). The `legacy_watchdog_direct_apply` config field (MON addendum v1.0 §59, default `false`) exists and re-enables direct-apply semantics only in explicit unsafe development/migration mode: it emits a startup warning and increments the zero-tolerance counter `monitor_legacy_watchdog_direct_apply_total`, blocking production readiness (FB-07).

Validation: `go test ./monitor` passes, including bounded force-check and checkpoint round-trip tests.

