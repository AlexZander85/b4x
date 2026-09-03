# PPE Stage 3 Validation Report

## Verdict

`PASS_WITH_LIMITATIONS`

## Passed

- Interrupted second-family apply restores both previous family snapshots.
- Verification failure restores the previous generation.
- Interrupted remove restores the previous generation.
- Rollback uses a fresh context after request cancellation.
- Unproven `iptables -w` support blocks mutation.
- Duplicate owned jumps and rules are reduced to one canonical set.
- Previous jump positions are restored from snapshot metadata.
- Foreign chain references are rejected before mutation.
- Exact verify checks owned chains, one jump per hook, position 1, and ordered rule equality.
- Dependency-isolated `go test -race` and `go vet` pass for the actual PPE package.
- `gofmt` and `git diff --check` pass.

## Limitations

- Full repository tests remain blocked by the unavailable Go 1.25.3 toolchain and uncached external modules.
- Tests use an injected in-memory xtables runner; the Keenetic firmware target is not available in this environment.
- NDM table-regeneration recovery is PPE-4 and is not claimed by this stage.
- Functional bidirectional packet visibility is PPE-6 and is not inferred from successful rule verification.
