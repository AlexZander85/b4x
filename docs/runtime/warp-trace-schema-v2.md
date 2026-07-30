# WARP trace schema v2

`TransportTraceEnvelope` carries schema version, boot/process/session identity, parent/session generation, monotonic sequence, priority, event, redacted payload, timestamp, and checksum. Required-event loss, stale generation, checksum failure, or sequence regression blocks causal promotion and remains observable.

