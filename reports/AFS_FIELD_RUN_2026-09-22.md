# AFS field run — 2026-09-22

Scope: `bd b4x-x43` (AFS field validation L5–L7) on the live Keenetic router.
Code phase: `b4x-x4px` / `b4x-va8u` (AFS runtime API + wiring, P1.1–P1.5), pushed on
`agent/classifier-v2.3-capture-envelope`.

## Outcome

| Item | Verdict |
|---|---|
| L0 health (live) | **GREEN** — fd < 200, cfg `e629da1e`, bin `5627c147`, `/tmp` 2% |
| Gate A (default-off / §76 gate / revert) | **PASS (field)** |
| §76 run path fail-closed (no ABD inputs) | **PASS (field)** |
| promote / rollback procedure | **PASS (field)** |
| Gates B–F (behavioral evidence, bounded run, winner, promotion) | **CODE-VALIDATED (CI)** — not field-reachable safely |
| `AUTONOMOUS_DPI_ADAPTATION_READY` | **BLOCKED_BY_TARGET_EVIDENCE** |

## Field evidence — Gate A

Test instance: the AFS candidate binary (`$F/bin/b4.exp-afs`) run on the live
router (production-promote window, restore point on flash).

- AFS off: `GET /api/synthesis/v1/status` → `{"enabled":false,"grammar_version":"afs-grammar-v1","statuses":[]}`.
- §76 `adaptive_synthesis.allowed=true` while off → **HTTP 403** `adaptive strategy synthesis is disabled`.
- AFS on (config `automation.adaptive_strategy_synthesis.enabled=true`): `status` → `enabled=true`.
- §76 `allowed=true` + `authorized=true` + probe targets → **HTTP 409** `no retained ABD inputs for the requested scope` (canonical preflight, fail-closed; inputs are never fabricated).
- §76 `allowed=false` → **HTTP 202** (field ignored; ordinary discovery starts).
- `POST /api/synthesis/v1/revert` (valid scope) → **HTTP 200** `{"success":true,"quarantined_winners":0,"lifecycle_reset":true}`.

## Why Gates B–F are code-validated, not field

The AFS cycle triggers on a **capture-visibility block** (`monitoring.observePpeBlocked`).
On a healthy router visibility is `complete` → no observations → no retained ABD
inputs → the run path correctly fails closed. Inducing a visibility block safely is
not possible on this router:

- `EnsureRequired` / `Degrade` are gated by `offload_policy == "exclude"` (forbidden)
  or `system.tables.skip_setup=true` (removes the live packet path) or PPE rule loss
  (perturbation).
- PPE self-test/apply perturbs live capture.

Gates B–F are therefore covered by the focused Go/CI suite (panel, gate, orchestrator,
runners, nfq override, promotion proof), not by live target evidence.

## Incident (recorded as pitfall 31)

An earlier attempt ran a test instance with the **live config**, which hung on
shutdown and caused a router reboot. The isolated method is impossible (b4
single-instance `flock`). The production-promote window used here was reverted
cleanly with no reboot.

## Restore / rollback

- Restore point: `$F/bin/b4.restore-20260922` (`5627c147`), `$F/b4/b4.restore-20260922.json` (`e629da1e`).
- After the window the live stack was restored bit-identical: `/opt/sbin/b4`=`5627c147`, `/opt/etc/b4/b4.json`=`e629da1e`, `S99b4 selfcheck OK`, no test artifacts.

## Artifacts

- This report: `$F/b4/afs-field-2026-09-22/AFS_FIELD_RUN_2026-09-22.md`.
- Detailed session log: `.ag/research/afs-field-report.md` (Addenda 1–5).
- AFS candidate: `$F/bin/b4.exp-afs` sha256 `2b14c6bf19da3b9472a0b4b9cac9eb7ddabbbd8d8ac4f4b283978a43b1f28c5c`.

## Next (for real B–F)

Second router/VM as a stand, or an explicitly approved destructive capture
perturbation. No production change is left in place.
