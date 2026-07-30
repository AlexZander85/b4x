# MON-6 — source health, visibility, and suppressors

`SourceHealthStore` records bounded source heartbeats and produces a visibility snapshot for the exact required source set. A stale, invisible, expired, partial, or invalid capture/PPE view is explicitly represented and never interpreted as service blocking evidence.

`SuppressorEngine` is a diagnostic scheduling gate only. It records expiring explanations for stale sources, invalid visibility, infrastructure transitions, configuration/WAN transitions, and global outages. Suppressors are observable through `SuppressionDecision`, are scoped by `MonitorScopeKey`, and are removed after their TTL. They cannot create a `BlockingProfile`, authorize transport, mutate configuration, or trigger rollback.

Validation: `go test ./monitor` passes. MON-7 consumes `CanAutoDiagnose` when scheduling bounded diagnostic work.

