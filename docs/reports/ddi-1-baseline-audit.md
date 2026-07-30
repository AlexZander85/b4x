# DDI-1 — baseline audit and fixtures

The existing `discovery` lifecycle remains the compatibility boundary: `NewDiscoverySuite` parses domain inputs, `RunDiscovery` owns baseline/strategy/optimization phases, history/cache persistence is handled by the existing discovery store, and HTTP handlers expose the current suite/status APIs. Detector suite lifecycle and history remain owned by `src/detector`.

The DDI layer is additive. It selects immutable diagnostic envelopes and produces planner inputs; it does not replace the Discovery optimizer, mutate `config.SetConfig`, or bypass capture visibility gates. Negative fixtures cover stale, cross-WAN, generation-mismatched, conflicting, and action-unauthorized profiles.

Validation: existing Discovery/Detector tests remain compatibility fixtures. DDI-2 adds the versioned profile schema without changing legacy request fields.

