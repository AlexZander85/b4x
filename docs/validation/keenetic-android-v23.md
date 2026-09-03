# Stage 36 — Controlled router validation

## Current execution status

The validation harness is implemented and locally verified. Target certification is **BLOCKED** until a Keenetic/Entware router, the target Android phone identity and a known deployed configuration generation are connected to the run.

This status is intentional: workstation fixtures cannot establish NFQUEUE ownership, hardware-offload visibility, Android first-flow timing, body/throughput stability, CPU/RAM budget or transactional cleanup on the target router.

## Required preparation

- Watchdog and Discovery noise disabled unless explicitly under test.
- Target phone identity present and source-scoped.
- Other YouTube clients idle.
- Clean B4 restart.
- Queue owner, processed mark and offload self-check all pass.
- Deployed commit and immutable config generation recorded.
- `/api/v2/runtime-control/status` available, enabled, with a validated active generation and committed last-good manifest.
- No pending runtime candidate before the controlled run.
- Positive CPU, memory, body and throughput budgets selected for the target model.

## Target scenarios

The normative 14-scenario matrix is machine-readable in `tools/field_validation/manifest.json` and covers:

- official YouTube and ReVanced cold starts;
- API/UI and first VIDEO CDN flow;
- CDN switch, stall/resume and background/foreground;
- QUIC enabled/reject/handoff and app QUIC disabled;
- ECH plus split ClientHello;
- two simultaneous Android clients;
- IPv4/IPv6 and DoH/system DNS;
- hot apply, scoped canary, promote, rollback and restart cleanup.

## Acceptance invariants

- No unclassified first API/UI/VIDEO flow.
- Clean SYN remains direct unless an explicit SYN technique is configured.
- ECH uses fresh source-scoped DNS/QUIC evidence.
- Split ClientHello completes bounded reassembly.
- No cross-client evidence leakage.
- At most one action per logical ClientHello.
- Queue drops and collateral failures remain zero during the controlled run.
- Body and sustained throughput meet the selected target budgets through CDN switch/resume.
- CPU and memory remain inside the selected Keenetic budget.
- Rollback/restart leave no stale queue, chains, hold, token or flow state.

Run and report commands are documented in `tools/field_validation/README.md`. The generated Markdown report is the required target test table with explicit `PASS`, `FAIL` or `BLOCKED` for every gate and scenario.
