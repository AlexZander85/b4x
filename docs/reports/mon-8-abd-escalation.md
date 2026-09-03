# MON-8 — ABD escalation adapter

`MonitorDiagnosticRequest` is the only handoff from monitoring to ABD. It carries the exact scope, bounded lease, client-resolution snapshot reference, target/control hashes, visibility snapshot reference, and configuration generation. The overlay is invalid without fresh resolution and visibility references.

`ABDEscalationAdapter` tracks requested/running/completed/partial/cancelled runs and rejects scope mismatches. A partial, cancelled, incomplete, or evidence-free result is never marked authoritative, even if a caller supplies an authoritative flag. Active probes and evidence-graph/profile construction remain ABD responsibilities.

Validation: `go test ./monitor` passes. MON-9 consumes only completed authoritative run references.

