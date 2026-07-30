# Service Profiles v1.6 implementation report

Implemented SP-1 through SP-32 as a declarative `serviceprofile` control-plane package.

## Automated coverage

- schema validation, canonical safety hashing and migration defaults (SP-1/SP-2)
- deterministic compilation, ownership-aware diff, transactional apply/rollback (SP-3/SP-4)
- catalog trust/signature boundary and secret-free import/export (SP-5/SP-12)
- per-component objectives, delivery modes, starter packs and beginner/advanced view models (SP-6…SP-11)
- capability, GSO/RST, same-client controls and built-in WARP projections (SP-13…SP-19)
- bounded silent-recovery policies, leases, false-positive UX and promotion evidence (SP-20…SP-23)
- detector target plans, capability downgrade, evidence UX, guided budgets and Telegram bridge policy (SP-24…SP-29)
- typed scoped base-WARP recommendation, test/production authorization separation, cleanup and release gates (SP-30…SP-32)

Verified:

```text
go test ./serviceprofile/... ./detector ./discovery ./monitor ./mtproto ./warp
```

## Release boundary

The package does not own packet marks, routes, sockets, WARP lifecycle, credentials, ActionAuthorization or TransportAuthorization. `PROFILE_WARP_RECOMMENDATION_READY` is emitted only when current ABD/DDI/WARP trace, path proof, forwarded-client canary and umbrella gates are supplied by runtime. Android, multi-client, CDN-switch, Telegram failover and WAN churn evidence remain field-test inputs and are not claimed by unit tests.
