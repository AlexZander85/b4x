# AFS Reference Audit

Status: `LAB_VALIDATED`
Branch: `agent/afs-addendum-v1`
Base: `agent/classifier-v2.3-capture-envelope`
Validated CI run: `35085703795`

## Ownership and reuse audit

AFS does not introduce a second packet executor, scoring engine, promotion manager, evidence store, or generic Discovery runtime.

| Concern | Existing owner reused | AFS integration |
|---|---|---|
| ordinary diagnostic profile | ABD/DDI profile + evidence graph | `BehavioralFingerprintEvidence` is attached to the existing profile revision |
| candidate ordering | `GuidedSearchPlan` / causal eligibility | synthesized IDs are merged as immutable references |
| packet planning | `action` planners | synthesized operations compile through existing ActionPlanner/TLS-record/FakeMix primitives |
| candidate evaluation | adaptive Discovery matrix | synthesized candidate uses the same `RunAdaptiveDiscovery` / `ScoreOutcome` path |
| promotion | `runtimecontrol.Manager` | synthesized proof is attached to the existing Prepare -> Canary -> Promote/Rollback transaction |
| winner history | Discovery history | exact-context synthesized winner records are stored alongside Discovery history, not in the loose legacy cache |
| metrics | observability registry | AFS zero-tolerance counters use the existing bounded registry |

## Boundary findings

- Ordinary FB-24 adaptive Discovery remains usable without an AFS behavioral prior; AFS strictness lives in `RunSynthesizedDiscovery` and `CheckAutomaticSynthesisGate`.
- Automatic synthesis is default-off and service-profile policy can only narrow user permission.
- Synthesized evaluation is diagnostic-only. A direct apply result is rejected and counted as a zero-tolerance violation.
- Runtime promotion requires the same transactional runtime path, current authorization evidence, target/control evidence, rollback readiness, cleanup readiness, and a passed forwarded-client canary.
- Candidate reuse is exact-context and bounded; stale or quarantined winners are not universal presets.

## Validation evidence

Focused PR CI passed `gofmt` plus Go tests for `config`, `detector`, `discovery`, `observability`, and `runtimecontrol` on run `35085703795`.

Real router/target validation is not represented by this audit and remains a release blocker for `AUTONOMOUS_DPI_ADAPTATION_READY`.
