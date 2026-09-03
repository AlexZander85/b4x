# SPF-1 — Silent path failure taxonomy and safety model

Status: IMPLEMENTED_NOT_TARGET_VALIDATED

## Frozen reference and lessons

The field-behaviour reference is `necronicle/z2k` at
`8cffe4e2c9eb27175b4bd55a713d656b5c79f4b2`. It is a behavioural reference
only: B4 does not port its Lua/shell rotation state machine. Repeated
ClientHello, a timeout, or a single flow stall cannot by themselves rotate a
strategy. Fast parallel flows, prefetch, and fresh compatible-path success are
suppressors, not confirming evidence.

## Implemented contract

- `silentpath` defines the six normative failure classes, confidence ladder,
  non-attributing reason codes, evidence expiry, and scope-complete recovery
  model.
- `Scope.ValidForRecovery` requires exact client, set, component, domain,
  config generation, IP family, transport path, and final existing
  `ActionAuthorization`; a destination-only key is rejected.
- `ObserveAssessment` always has `RecoveryAllowed=false`; SPF-1 has no packet,
  route, or binding side effect.
- `system.classifier.runtime.silent_path_failure` defaults to `enabled: false`,
  `mode: observe`, a five-second grace floor, two independent evidence
  families, and all active-mode proof gates enabled.
- `auto-canary` rejects missing differential, visibility, authorization,
  control-probe, or auto-demotion gates.

## Validation

`go test ./config ./silentpath` covers schema defaults, invalid active
configuration, observe-only taxonomy, exact scope checks, and evidence expiry.
Router and Android validation is deferred to SPF-10.
