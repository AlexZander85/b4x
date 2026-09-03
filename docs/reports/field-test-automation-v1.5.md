# B4 Field Test Automation v1.5 implementation report

Source addendum SHA-256: `5b7cac0255e255bc65fde33982571e290a7fe6cef574b1044ecbdd4f544e5a60`

Implemented contracts and fail-closed gates for FT-A…FT-AE in `src/fieldtest`:

- session/event JSONL schema, monotonic ordering, redacted reports and API capabilities;
- local controller lifecycle, clock sync, ADB/Companion boundaries and marker provenance;
- adaptive component ranking, hard gates, A/B, canary, rollback and promotion scopes;
- same-client controls and authorization audit with zero unrelated actions;
- GSO/MSS parity, single-consume tokens and passive RST safety budgets;
- WARP base lifecycle/path counters, camouflage candidate selection, nested non-RU geo/DNS/IPv6 proof, fault matrix and cleanup ownership;
- silent recovery observation, suppression, differential proof, leases and rollback;
- detector target plans, protocol evidence, immutable dynamic evidence, DDI guided/full A/B and Telegram delayed-first-data fixtures;
- causal trace event-order validation and exact Android `TestSessionID → BindingID → RouteTokenID → SessionGen` correlation.

Verified locally:

```text
go test ./fieldtest/... ./serviceprofile/... ./detector ./discovery ./monitor ./mtproto ./warp
```

The implementation is fail-closed: missing field artifacts, unproduced counters, stale generations, absent forwarded proof or incomplete cleanup cannot yield a release PASS. Real Keenetic path counters, Android forwarded-flow evidence, WAN fault runs and geo-provider observations remain required field inputs.
