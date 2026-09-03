# PPE Stage 2 Validation Report

## Verdict

`PASS_WITH_LIMITATIONS`

## Passed

- Dependency-isolated Go unit tests for the actual PPE package.
- Deterministic compile and generation hash.
- Golden IPv4 `iptables-restore` fixture.
- Effective TCP/UDP port intersection.
- Exactly one owned PREROUTING and FORWARD jump in a compiled generation.
- Managed-device source scope requirement.
- IPv6 `auto` skip and explicit `on` failure.
- No `CONNMARK`, `--set-mark`, or processed-packet mark persistence in compiled PPE rules.
- Dependency-isolated config validation/defaulting tests.
- Go parser, `gofmt`, and `git diff --check`.

## Limitations

- The full repository Go test suite cannot start because the required Go 1.25.3 toolchain and uncached modules cannot be downloaded in the current network-restricted environment.
- Restore fixtures are compiler tests only; actual apply/verify/rollback is PPE-3.
- No real Keenetic firmware target was exercised, so this stage does not claim functional packet visibility.
