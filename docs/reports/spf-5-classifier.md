# SPF-5 — Silent failure classifier

Status: IMPLEMENTED_NOT_TARGET_VALIDATED

Classifier keeps a single evidence family at suspicion, requires two distinct
live families for correlation, and applies suppressors before any recovery
eligibility. It remains observe-only; adaptive baselines are deferred until
target validation data is available.
