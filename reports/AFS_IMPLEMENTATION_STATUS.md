# AFS implementation status checkpoint

Branch: `agent/afs-addendum-v1`
Base: `agent/classifier-v2.3-capture-envelope`
Draft PR: `#8`
Last code-bearing focused CI: `35098015343` (`AFS Addendum CI` #93) — `PASS`
Validated code commit: `fa8a7c8da3fc6563d2349697e76933a89f85583a`

This checkpoint records implementation progress for `B4X_POST_V23_BEHAVIORAL_FINGERPRINTING_AND_CONSTRAINED_STRATEGY_SYNTHESIS_ADDENDUM_v1.0.md` only.

## Implemented and lab-validated

- canonical adaptive strategy synthesis config with default-off user opt-in and service-profile narrowing;
- Advanced Settings UI toggle with first-enable confirmation, backed by the canonical automation setting rather than a UI-only flag;
- bounded four-way behavioral fingerprint panel and `BehavioralFingerprintEvidence` embedded in the existing ABD profile/evidence graph;
- DDI projection from behavioral features to supported/penalized/excluded operator families;
- finite versioned strategy grammar and canonical `SynthesizedCandidatePlan` identity;
- all eight automatic grammar-v1 families wired through existing Action-layer primitives: TCP split, TLS-record split, bounded disorder, safe duplicate, pre/post ClientHello padding, bounded per-flow jitter, and existing endpoint-safe fake profiles;
- `pre_padding` / `post_padding` reuse the existing `action.ApplyClientHelloPadding` `ActionPlan` transform; safe fake synthesis reuses an existing validated `FakeMixRequest` template and does not create a second fake-profile registry;
- deterministic bounded seed/mutation/crossover planner with static validation and dedupe;
- final emission boundary rejecting grammar escape and non-automatic-safe operators;
- synthesized candidate integration into the existing adaptive Discovery matrix and scoring path with no direct apply;
- ordinary FB-24 adaptive runtime compatibility preserved outside the AFS synthesized path;
- exact shared-matrix probe accounting inside the existing Discovery budget;
- transient synthesis run store for immutable candidate references with collision/bound enforcement;
- exact-context synthesized winner persistence with bounded per-scope reuse and quarantine;
- automatic synthesis preflight gate for opt-in, persistent regression, fresh profile/prior, generation, rollout, visibility, controls, catalog exhaustion, resource budget, resource ownership, cleanup, cooldown, and conflicting-run suppression;
- synthesized promotion proof attached to the existing transactional runtime apply request, preserving one promotion path and requiring forwarded-client canary, action authorization, mandatory controls, rollback readiness, cleanup readiness, and stable observation;
- synthesis lifecycle integrated into the existing Monitoring correlation scope, including persistent-regression recurrence, cooldown, stale-context cancellation, progress projection, and post-promotion stability observation;
- monitor terminal/stability helpers preserve monotonic candidate/generation progress instead of weakening the lifecycle invariant;
- fault-injection coverage for all zero-tolerance invariant families, including grammar/unsafe/direct-apply/collision/foreign-resource paths;
- focused pull-request CI passes Go tests for `action`, `config`, `detector`, `discovery`, `monitor`, `monitoring`, `observability`, `runtimecontrol`, `validation`, plus generated defaults and UI build;
- all eight required AFS-13 evidence artifacts are present with target-dependent sections explicitly blocked rather than fabricated;
- principal verdicts are recorded in `AFS_PRINCIPAL_VERDICTS.json`.

## Current verdict

`IMPLEMENTED / LAB_VALIDATED / BLOCKED_BY_TARGET_EVIDENCE`

`BEHAVIORAL_FINGERPRINT_BOUNDED_READY`, `CONSTRAINED_SYNTHESIS_READY`, and `SYNTHESIZED_DISCOVERY_READY` are PASS at implementation/lab evidence level.

`AUTONOMOUS_DPI_ADAPTATION_READY` is **not PASS**. It remains `BLOCKED_BY_TARGET_EVIDENCE` until a real Keenetic/router run plus forwarded Android-client canary demonstrates target recovery, controls, resource bounds, cleanup, stability, and rollback.

## Remaining contract hardening before merge review

- keep AFS-13 reports synchronized with code/CI as the branch changes;
- preserve exact-context winner reuse (including explicit resolver/TLS and capability-generation context at runtime call sites);
- keep Monitoring terminal/suppression reasons machine-readable enough for the structured recovery handoff; do not collapse safety failures into an apparent success state;
- do not mark autonomous production readiness from CI or synthetic matrix evidence alone.

## Remaining external validation

1. run the bounded panel/search against an authorized real target from the target router;
2. capture Keenetic CPU/memory/queue/resource ownership and cleanup evidence;
3. run forwarded Android client canary with target + same-service + unrelated controls;
4. exercise rollback after an induced failed candidate/canary;
5. update the target-dependent AFS-13 artifacts and only then reconsider `AUTONOMOUS_DPI_ADAPTATION_READY`.

No claim of production readiness is made by this checkpoint.
