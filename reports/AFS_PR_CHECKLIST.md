# AFS draft PR checklist

- [x] Scope limited to behavioral fingerprinting + constrained strategy synthesis addendum.
- [x] Default-off user opt-in and hard preflight gates.
- [x] Behavioral evidence integrated into existing ABD/DDI profile graph.
- [x] Finite grammar and canonical synthesized candidate identity.
- [x] Deterministic bounded evolution and static validation.
- [x] Existing ActionPlanner primitives reused; no second executor.
- [x] Existing Discovery scoring reused; no second optimizer.
- [x] Existing transactional runtime apply reused; no second promotion path.
- [x] Exact-context winner reuse and quarantine.
- [x] Focused tests and PR CI added.
- [x] Focused CI green (`35085703795`).
- [x] Zero-tolerance mutation/fault-injection guard coverage green.
- [x] AFS-13 evidence artifacts generated with target-dependent sections marked blocked.
- [x] Principal verdicts issued at implementation/lab evidence level.
- [ ] Router + forwarded Android target evidence captured.
- [ ] Keenetic resource/cleanup evidence captured on target hardware.
- [ ] Failed-canary rollback drill captured on target runtime.
- [ ] `AUTONOMOUS_DPI_ADAPTATION_READY == PASS`.

Current release status: `IMPLEMENTED / LAB_VALIDATED / BLOCKED_BY_TARGET_EVIDENCE`.

Draft PR must remain unmerged while the target-evidence items above are unchecked.
