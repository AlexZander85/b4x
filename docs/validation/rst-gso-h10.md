# H10 — Combined RST/GSO target validation

## Current verdict

`BLOCKED_TARGET_VALIDATION`

The H10 matrix, fail-closed evaluator, privacy-safe artifact index and report generator are implemented. No physical Keenetic or Android/Chrome evidence is present in the repository, so this stage does **not** claim target PASS or production readiness.

A CI/workstation result cannot establish:

- delivery of a real target GSO skb to NFQUEUE;
- target `NFQA_CAP_LEN` and checksum-offload behavior;
- Keenetic PPE visibility, queue ownership, CPU/RAM or queue-drop bounds;
- legitimate-versus-forged RST behavior on real paths;
- Android official YouTube/ReVanced and control-service behavior;
- Chrome cold-run A/B results;
- cleanup after router/listener crash, hot rollback or restart.

## Machine-readable matrix

`tools/field_validation/rst_gso_manifest.json` contains three suites:

- GSO kernel/integration cases;
- passive RST cases;
- combined GSO/RST/topology/pressure cases.

Every case declares mandatory metrics, raw artifact kinds and executable assertions. A requested `pass` is automatically changed to `fail` when required data is missing or an invariant is violated.

## Create a target run

Choose budgets for the exact Keenetic model and deployed generation:

```sh
python3 tools/field_validation/rst_gso_field_validation.py init \
  --run field-runs/rst-gso-h10.json \
  --router-url https://192.168.1.1:7000 \
  --architecture arm64 \
  --target-client 'mac:aa:bb:cc:dd:ee:ff' \
  --expected-generation '<runtime generation>' \
  --commit '<deployed commit>' \
  --max-cpu-pct 75 \
  --max-memory-mib 96 \
  --max-queue-drops 1 \
  --min-throughput-bps 5000000 \
  --max-latency-regression-pct 15
```

The router URL and target client are stored only as truncated SHA-256 identifiers.

## Capture bounded control-plane snapshots

```sh
B4_API_TOKEN='<token>' python3 tools/field_validation/rst_gso_field_validation.py snapshot \
  --run field-runs/rst-gso-h10.json \
  --router-url https://192.168.1.1:7000 \
  --label before-gso-netns
```

The snapshot fetches the hardening status, observability metrics, issue bundle, runtime-control status, system information and deployed version. Sensitive values are sanitized. Packet captures and raw target logs are not copied into the run file.

## Record raw evidence by hash

Artifacts use `kind=path`. The tool reads each file only to calculate SHA-256 and size; the raw file remains in the operator-controlled directory.

```sh
python3 tools/field_validation/rst_gso_field_validation.py record-code-gate \
  --run field-runs/rst-gso-h10.json \
  --gate race --status pass \
  --artifact test-log=artifacts/go-race.log

python3 tools/field_validation/rst_gso_field_validation.py record-preflight \
  --run field-runs/rst-gso-h10.json \
  --gate target_keenetic --status pass \
  --artifact command-log=artifacts/router-commands.log \
  --artifact router-diagnostics=artifacts/router-diagnostics.json

python3 tools/field_validation/rst_gso_field_validation.py record-scenario \
  --run field-runs/rst-gso-h10.json \
  --scenario gso_netns_real_skb --status pass \
  --metrics-json measurements/gso-netns.json \
  --artifact command-log=artifacts/gso-netns-commands.log \
  --artifact router-diagnostics=artifacts/gso-netns-router.json \
  --artifact metrics=artifacts/gso-netns-metrics.json \
  --artifact packet-capture=artifacts/gso-netns.pcapng
```

## Certification

```sh
python3 tools/field_validation/rst_gso_field_validation.py certify \
  --run field-runs/rst-gso-h10.json \
  --markdown field-runs/rst-gso-h10.md
```

Possible verdicts:

- `PASS` — every code gate, preflight gate, target scenario, artifact requirement and assertion passed;
- `FAIL` — an explicit failure, unsafe metric, leak, regression or false claim was recorded;
- `BLOCKED_TARGET_VALIDATION` — target evidence is incomplete or unavailable.

## Non-negotiable release conditions

H10 cannot pass when any of the following is non-zero or unproven:

```text
queue_leaks
stale_marks
token_leaks
held_packets_leaked
control_regressions
cross-scope actions/evidence/tokens
suppression-only Discovery successes
```

CPU, RAM, queue drops, throughput and Chrome latency regression are checked against the budgets selected at run initialization. Any commit, config generation, kernel/offload change or router model change requires a new run.
