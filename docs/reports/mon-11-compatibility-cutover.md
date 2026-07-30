# MON-11 — API/UI/persistence and Watchdog compatibility cutover

`MonitorAPIProjection` is the source-of-truth read model for the new monitor surface. `LegacyWatchdogAdapter` preserves status and force-check compatibility, but maps force-check to the bounded quick diagnostic scheduler and exposes no configuration mutation or applier callback.

`MonitorCheckpoint` provides a versioned JSON persistence envelope with an explicit cutover version and strict validation. Expired leases and diagnostic state are not restored as action authorization. Existing Watchdog endpoints can therefore remain as adapters while direct `applyBatchResults` is disabled in the production-safe path.

Validation: `go test ./monitor` passes, including bounded force-check and checkpoint round-trip tests.

