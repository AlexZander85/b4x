# AFS validation plan

This plan is scoped only to the behavioral fingerprinting and constrained strategy synthesis addendum.

## L0-L2: model and static invariants

- config default-off and service-profile upper-bound semantics;
- four-way R1/R2/R3/R4 behavioral evidence freshness and exact-scope checks;
- DDI feature-to-operator support/penalty/exclusion projection;
- finite grammar registry validation and parameter-domain rejection;
- canonical candidate identity stability, collision detection, dedupe, and generation bounds;
- ActionPlanner bridge compilation without direct execution or promotion.

## L3-L4: Discovery integration

- catalog escalation precedes automatic synthesis;
- synthesized candidates enter the existing adaptive matrix and ScoreOutcome pipeline;
- mandatory baselines and controls remain present;
- direct-apply remains impossible;
- stale generation, stale evidence, scope escape, and missing controls fail closed.

## L5-L6: runtime safety and cleanup

- existing transactional runtime manager remains the only promotion path;
- synthesized promotion proof requires action authorization, forwarded-client canary, mandatory controls, and rollback readiness;
- candidate failure triggers cooldown/quarantine;
- cleanup is complete and bounded;
- no foreign resource mutation is permitted.

## L7: router and Android forwarded-client canary

- evaluate router-origin and forwarded-client traffic separately;
- require Android/forwarded-client success before promotion of router-origin synthesized winners;
- record stability, latency, resource, collateral, and recovery evidence;
- verify rollback under induced failure.

## L8: release evidence

Generate the required AFS-13 artifacts and principal verdicts. `AUTONOMOUS_DPI_ADAPTATION_READY` may be PASS only after real target evidence; otherwise use `IMPLEMENTED / LAB_VALIDATED / BLOCKED_BY_TARGET_EVIDENCE`.
