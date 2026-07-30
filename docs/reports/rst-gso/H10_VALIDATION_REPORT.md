# H10 RST/GSO hardening validation report

## Verdict

`BLOCKED_TARGET_VALIDATION`

## Implemented code-level gate

- Machine-readable 45-scenario GSO, passive-RST and combined target matrix.
- Declarative metric assertions and target resource budgets.
- SHA-256 artifact index that does not copy packet captures, raw ClientHello bytes, Android logs or router command output into the run JSON.
- Fail-closed code/preflight/scenario recording.
- Automatic rejection of claimed PASS with missing metrics or artifact kinds.
- Explicit checks for queue, mark, token, held-packet and control-service leaks.
- Privacy-safe Markdown report generator.
- Standard-library unit tests for manifest completeness, privacy, false-PASS rejection, leak rejection and complete-run certification logic.

## Blocking evidence

No physical target run is included. The following remain mandatory before release promotion:

- real GSO skb and NFQUEUE metadata captures;
- Keenetic PPE/firewall/queue/resource evidence;
- Android official YouTube/ReVanced and negative controls;
- Chrome cold-run A/B traces;
- legitimate and forged passive-RST packet captures;
- rollback, crash, restart and sustained-pressure proof;
- raw code-gate/benchmark logs indexed in the target run.

The committed machine status is `docs/validation/rst-gso-h10-status.json`. It deliberately states that production readiness is not claimed.
