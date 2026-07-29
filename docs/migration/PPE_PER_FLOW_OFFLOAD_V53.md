# PPE per-flow offload product migration

## Compatibility contract

PPE productization increments the configuration format from version 52 to 53.
The PPE schema first appeared in v52; the v52→v53 migration adds the explicit
product safety contract and preserves monitoring mode for every existing
installation.

Existing installations migrate to:

```yaml
system:
  classifier:
    runtime:
      capture:
        offload_policy: detect
```

The migration never enables `exclude` automatically and converts a legacy
`disable-global` value to `detect`. Operators must explicitly enable the
beginner-facing **Hardware offload: per-flow exclusion** control.

## Upgrade behavior

- `detect`: capability and passive visibility diagnostics only; no rule mutation.
- `exclude`: install B4-owned per-flow PPE rules and require a controlled
  bidirectional proof before visibility-dependent features are enabled.
- `disable-global`: retained as a configuration vocabulary value for manual
  advanced/debug workflows, but the product API and UI never perform a global
  offload change automatically.

## Rollback

The UI rollback action returns the system to `detect`, removes only B4-owned
chains/jumps, keeps unrelated hardware offload available, and preserves all
other classifier settings.

## Privacy

PPE issue bundles contain platform metadata, capability evidence, redacted
B4-owned rules, counters, passive direction summaries, the self-test timeline,
and visibility decisions. They do not include packet payloads, domains, client
identifiers, secrets, or raw captures.
