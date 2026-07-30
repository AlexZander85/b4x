# TGB-10 — Keenetic and Android validation

The TGB hardening contracts are unit-validated for structured dispositions, delayed first-data state, bounded pending handshakes, prefix replay, route fallback, config generation, privacy-safe diagnostics, and packet-path gates.

Required field matrix:

- Keenetic TPROXY IPv4/IPv6 and original-destination proof;
- delayed first byte beyond five seconds with no zero-byte destructive drop;
- successful bridge or explicit bounded fallback;
- explicit proxy control and no recursive route;
- WAN flap/reload/reboot cleanup and bounded 1000-connection stress.

Real router/Android execution and issue #277 reproduction are external gates. This stage therefore records `TGB_STATE_MACHINE_READY`, `TGB_PENDING_BUDGET_READY`, and `TGB_PREFIX_HANDOFF_READY`; `TGB_ANDROID_VALIDATED`, `TGB_PRODUCTION_READY`, `ISSUE_277_RESOLVED`, and combined release verdicts remain pending field evidence.

