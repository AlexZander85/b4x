# SPF-2 — Unique TCP flow-progress accounting

Status: IMPLEMENTED_NOT_TARGET_VALIDATED

`silentpath.ProgressStore` is a bounded, observation-only per-flow store.
It counts TCP sequence-space bytes once per direction, rather than summing
packet sizes. Sequence coordinates are signed deltas from the first segment;
this preserves ordering across `uint32` wrap and accepts nearby out-of-order
segments. Duplicate and overlapping retransmissions do not advance useful
progress.

The store is bounded to 4096 flows and 64 merged ranges per direction by
default. Capacity/range pressure removes only accounting state and never
changes traffic. FIN/RST callers use `Close`; generation invalidation and idle
GC remove stale entries. No raw client or hostname is exported in statistics.

Validated with unit coverage for duplicates, overlap, out-of-order packets,
sequence wrap, GSO/MSS representation parity, lifecycle cleanup, and range
bounds. Target packet-path validation remains SPF-10 work.
