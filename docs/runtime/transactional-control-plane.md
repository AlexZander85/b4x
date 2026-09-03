# Transactional runtime control prerequisite

## Audit/assumptions

Stage 36 requires an executable `prepare → canary → promote → rollback` path. The existing `runtimecontrol.Manager` was previously library-only and the Stage 35 UI therefore correctly disabled rollout actions.

This prerequisite connects the manager to the real NFQUEUE/config runtime. It is limited to NFQUEUE mode and to classifier plus set changes that do not alter the kernel capture port envelope.

## Files changed

- `runtimecontrol`: staged pending generation lifecycle and live runtime adapter.
- `nfq`: isolated candidate queue and bounded flow-only canary monitor.
- `tables`: source-scoped, percentage-based candidate steering with persisted conntrack decisions.
- `http/handler`: transactional runtime API and atomic config apply hooks.
- `config` / `packetmark`: atomic persistence and dependency-free reserved mark contract.
- `http/ui`: functional rollout workflow.
- `main`: manager ownership, startup registration and shutdown cleanup.

## Design and invariants

- The production generation remains active during prepare and canary.
- Candidate traffic uses a separate NFQUEUE and fixed reserved control-mark mask.
- Selected/direct decisions are persisted in conntrack and are not re-sampled on retransmission.
- Candidate generated packets carry the processed provenance bit and bypass all B4 queues.
- Canary monitoring stores flow metadata only; packet payloads are never retained.
- Promotion permits only classifier and set changes and rejects capture-port changes.
- Config persistence uses prepare+fsync followed by one atomic rename.
- Persistence failure restores the previous runtime generation.
- Discovery and Watchdog cannot mutate configuration while a candidate is pending.
- Shutdown aborts and closes a pending generation before production queue cleanup.

## Tests added

- staged prepare/canary/promote and abort paths;
- commit failure restores previous runtime;
- candidate scope validation;
- candidate flow monitor accounting;
- firewall steering mark and selector validation;
- atomic config prepare/commit/abort;
- API diff restrictions;
- reserved mark disjointness.

## Commands/results

The repository requires Go 1.25.3. This environment cannot download that toolchain or uncached modules because outbound DNS is unavailable. `gofmt`, `git diff --check`, dependency-free Go package tests, Python field-validation tests and UI contract validation remain locally executable.

## Benchmarks/resource bounds

- one candidate NFQUEUE worker;
- bounded canary flow table with TTL cleanup;
- no payload capture and no goroutine per packet;
- one canary ticker, timer and cancellation path per active canary;
- candidate steering applies only to new flows in the requested client/set/protocol scope.

## Compatibility/migration

Transactional runtime control remains disabled unless `transactional_apply_enabled` is explicitly enabled. Existing configuration and direct config-update APIs keep their prior behavior when no candidate is pending.

## Risks and follow-up

- iptables/nftables syntax, NFQUEUE ownership and mark propagation require the Stage 36 Keenetic target run.
- TUN mode is intentionally rejected for candidate queues.
- Stage 36 must verify zero double-enqueue, queue drops, stale chains and held-flow state across promote, rollback and restart.

## Proposed commit

`feat(runtime): connect transactional canary promote and rollback control plane`
