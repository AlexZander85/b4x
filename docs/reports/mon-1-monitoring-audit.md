# MON-1 — Current monitoring audit and compatibility freeze

Status: IMPLEMENTED_NOT_TARGET_VALIDATED

## Ownership map

| Surface | Current responsibility | MON migration rule |
|---|---|---|
| `src/tables/monitor.go` | iptables/nftables, NFQUEUE hooks, marks, routing and masquerade integrity | remains infrastructure-integrity monitor; never emits service blocking proof |
| `src/watchdog` | pinned domain probes, status, retry cadence and legacy healing path | becomes compatibility adapter; diagnosis/promotion authority moves to `monitor` |
| `src/diagnostics/failure_inbox.go` | bounded failure candidate/evidence intake | remains projection/intake; not temporal source of truth |
| `src/observability` | metrics, redacted trace and issue bundle sinks | never stores temporal monitoring truth |
| `src/nfq/canary_monitor.go` | candidate-flow canary accounting | remains candidate/canary plane; SYN-ACK alone is not health proof |
| `src/nfq/scoped_failure_state.go` | short-lived exact-scope attempts/escalation/RST state | remains enforcement helper; publishes observations only |

## Legacy write-path freeze

The legacy watchdog still contains `checker` and `applier` compatibility code.
No new monitoring implementation may call those writers directly. Production
safe MON mode must translate force-check to a bounded diagnostic request and
must not overwrite `SetConfig` from passive or provisional evidence. A future
MON-11 cutover will disable the direct applier and retain only status/API
projection compatibility.

## Pinned provenance

Clean-room behavioural reference: `belotserkovtsev/ladon` commit
`8af5e68cadea16c177f17fb6a50f1e0b6931aa8d`, MIT. Only demand-driven intake,
client-observed resolution provenance, bounded queueing and temporal lessons
are retained; no tunnel or direct-action semantics are imported.

## MON-1 exit gates

- legacy monitoring surfaces are inventoried;
- infrastructure integrity is separated from service health;
- direct mutation ownership is explicitly marked for MON-11 removal;
- rollback remains possible because no existing writer was changed in MON-1.

Target router/Android and resource validation are deferred to MON-12.
