# MON-10 — canary, recovery, and rollback observation

`CanarySummaryAdapter` keys observations by exact scope, binding, and path. It records router binding, target/control health, Android milestone, and rollback signal as separate observations. A router-origin milestone never sets the Android gate; an Android milestone must be observed with an Android origin.

Rollback signals are published as observations only. The adapter has no action-plane dependency and cannot promote, rollback, or authorize a transport. Recovery is therefore linked to the exact binding/path while decision ownership remains with the control plane.

Validation: `go test ./monitor` passes.

