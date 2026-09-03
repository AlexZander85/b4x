# B4 controlled field validation

This standard-library-only harness implements Stage 36 without pretending that a workstation test is a Keenetic certification. It records the exact configuration generation, mandatory preflight gates, all fourteen Android scenarios and bounded resource/body/throughput metrics.

## 1. Create a run

Choose target-specific budgets before testing. Certification remains `BLOCKED` if any budget is omitted.

```sh
python3 tools/field_validation/b4_field_validation.py init \
  --run field-runs/keenetic-arm64.json \
  --router-url https://192.168.1.1:7000 \
  --architecture arm64 \
  --target-client 'mac:aa:bb:cc:dd:ee:ff' \
  --expected-generation '<runtime_generation from /api/v2/classifier/config>' \
  --commit '<deployed commit>' \
  --min-body-bytes 1048576 \
  --min-throughput-bps 5000000 \
  --max-cpu-pct 75 \
  --max-memory-mib 96
```

The URL and client identity are stored only as truncated SHA-256 identifiers.

## 2. Controlled preflight

Disable Watchdog/Discovery noise, stop other YouTube clients, cleanly restart B4 and confirm the target phone identity. The command verifies queue readiness, processed-mark bypass, offload visibility and generation identity from bounded HTTP diagnostics.

```sh
B4_API_TOKEN='<token>' python3 tools/field_validation/b4_field_validation.py preflight \
  --run field-runs/keenetic-arm64.json \
  --router-url https://192.168.1.1:7000 \
  --target-identity-confirmed \
  --other-clients-idle \
  --clean-restart-confirmed
```

Do not use `--insecure` outside an isolated management LAN.

## 3. Snapshot and record scenarios

Capture bounded metrics immediately before and after each manual Android action:

```sh
python3 tools/field_validation/b4_field_validation.py snapshot --run field-runs/keenetic-arm64.json --router-url https://192.168.1.1:7000 --label official-before
# Perform the exact scenario from manifest.json.
python3 tools/field_validation/b4_field_validation.py snapshot --run field-runs/keenetic-arm64.json --router-url https://192.168.1.1:7000 --label official-after
```

Record measured values; a claimed `pass` is automatically converted to `fail` when required metrics are missing or an invariant is violated:

```sh
python3 tools/field_validation/b4_field_validation.py record \
  --run field-runs/keenetic-arm64.json \
  --scenario official_youtube_cold_start \
  --status pass \
  --metrics-json measurements/official.json \
  --before field-runs/snapshots/official-before.json \
  --after field-runs/snapshots/official-after.json
```

## 4. Certify and render the target table

```sh
python3 tools/field_validation/b4_field_validation.py certify \
  --run field-runs/keenetic-arm64.json \
  --markdown field-runs/keenetic-arm64.md
```

Certification requires every preflight gate, every scenario and every required coverage tag. Queue drops, collateral failures, unclassified first flows and cross-client leakage must be zero. A logical ClientHello may receive at most one action. ECH must resolve through scoped DNS or QUIC evidence. CPU, memory, body and throughput are checked against the target budgets supplied at initialization.

Raw packets, raw ClientHello bytes, IP addresses and MAC addresses are excluded or redacted from run files and reports.

## RST/GSO hardening H10

The post-v2.3 RST/GSO addendum uses a separate fail-closed matrix because Stage 36 Android scenarios do not prove kernel GSO metadata, normalizer topology or passive-RST safety.

```sh
python3 tools/field_validation/rst_gso_field_validation.py validate-manifest
python3 tools/field_validation/rst_gso_field_validation.py init --help
```

See:

- `docs/validation/rst-gso-h10.md` for the workflow and current blocked verdict;
- `tools/field_validation/rst_gso_target_commands.md` for command/artifact templates;
- `tools/field_validation/rst_gso_manifest.json` for the normative 45-scenario matrix.

A missing physical target run is reported as `BLOCKED_TARGET_VALIDATION`, never as PASS.
