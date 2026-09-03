# PPE Stage 4 Validation Report

## Verdict

`PASS_WITH_LIMITATIONS`

## Passed

- Simulated mangle-table wipe is detected by exact active-generation assertion.
- The active generation is reapplied and reverified exactly once.
- A subsequent healthy periodic assertion causes no duplicate reapply.
- A second wipe inside the minimum interval is suppressed rather than creating a reapply storm.
- A failed reapply enters the longer failure-backoff window.
- Queued NDM events are coalesced by the bounded event channel.
- Reapply after a wipe uses the existing transactional rollback path.
- NDM hook installation is atomic and idempotent.
- Non-NDM platforms do not receive the hook.
- A foreign file at the hook path is neither overwritten nor removed.
- Hook shell syntax validation passes where `/bin/sh` is available.
- Dependency-isolated `go test`, `go test -race`, and `go vet` pass for the actual PPE package.
- `gofmt` and `git diff --check` pass.

## Limitations

- The full repository test suite remains blocked by the unavailable Go 1.25.3 toolchain and uncached external modules.
- The real Keenetic NDM hook has not been executed on a router in this environment.
- This stage proves lifecycle behavior with injected command runners; functional packet visibility remains PPE-6.
- Product API/UI activation and persisted migration remain PPE-8.
