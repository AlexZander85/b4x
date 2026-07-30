# DDI-10 — router/target release validation

The DDI implementation is unit-validated through schema, context, persistence, revalidation, API snapshot, planner, observability, and causal A/B records. The required field matrix remains explicit:

1. Detector profile disabled baseline;
2. exact fresh profile enabled;
3. deliberately stale/conflicting profile;
4. same target controls and exhaustive fallback in every run;
5. target-specific validation before any candidate canary.

`CausalABComparison` rejects a result that drops controls, hides excluded targets, accepts stale/conflicting hints, or reports false production promotion. Real router/target runs and measured probe savings are external gates and are not claimed by this commit.

Verdict: `DDI_SCHEMA_READY`, `DDI_REVALIDATION_READY`, `DDI_HINT_PLANNER_READY`; `DDI_TARGET_VALIDATED` and `DDI_PRODUCTION_READY` remain pending external field evidence.

