# PPE Stage 7 Validation Report

## Verdict

PASS_WITH_LIMITATIONS

## Local validation

- Visibility state-machine unit tests: PASS.
- Visibility lifecycle degradation/reapply tests: PASS.
- Controlled self-test to visibility-gate integration tests: PASS.
- Non-PASS self-test cannot publish `complete`: PASS.
- TCP hold immediate fail-open release on degradation: PASS.
- TCP reassembly state abort and no new state while visibility is unknown: PASS.
- ActionToken ACK-dependent closure blocked until proof: PASS.
- Automatic Discovery blocked while manual diagnostics remain available: PASS.
- Guarded runtime canary/promotion tests: PASS.
- Runtime manager wrapper and initial proof requirement contract checks: PASS.
- Isolated Go tests with race detector: PASS.
- Isolated `go vet`: PASS.
- `gofmt` and whitespace checks: PASS.
- Reconstructed `rollout_manager_state.go`, with the two intended visibility additions removed, matches remote PPE-6 blob SHA `74977174ddea6158f5fba685edee1906af8b15e8`: PASS.

## Full-module limitation

The full repository build cannot start in this workstation environment because the required Go 1.25.3 toolchain and external module cache are unavailable and outbound dependency retrieval is blocked. The available dependency-light package harnesses compile and pass; this report does not claim a complete repository build.

## Deferred target validation

The following addendum DoD items require a real Keenetic/MediaTek run and remain deferred:

- remove an active PPE rule during a held split ClientHello;
- prove every held packet is released unchanged;
- prove no repeated hold loop follows degradation;
- re-run the controlled self-test and restore `complete` after NDM regeneration;
- demonstrate automatic Discovery and promotion remain blocked until the new proof succeeds.
