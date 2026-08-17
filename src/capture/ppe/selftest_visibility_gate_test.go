package ppe

import (
	"context"
	"testing"
)

func TestControlledSelfTestPublishesCompleteVisibility(t *testing.T) {
	gate := NewVisibilityGate()
	gate.EnsureRequired("generation-1", "test requires proof")
	bus := NewObservationBus()
	controller := NewSelfTestController(
		func(context.Context) (CapabilityReport, error) { return supportedCapability(), nil },
		func() string { return "exclude" },
		testHealth{},
		scriptedProbe{bus: bus},
		testIsolation{},
		&testCounters{values: []map[string]uint64{{"tcp": 1}, {"tcp": 5}}},
		bus,
		nil,
	)
	runner := WrapSelfTestRunnerWithVisibility(controller, gate)
	result := runner.Run(context.Background(), baseRequest())
	if result.Verdict != VerdictPASS || !result.ProductionReady {
		t.Fatalf("self-test did not pass: %+v", result)
	}
	state := gate.Snapshot()
	if state.Mode != VisibilityComplete || !state.Enforced || state.Generation != "generation-1" || state.LastVerdict != VerdictPASS {
		t.Fatalf("unexpected visibility state: %+v", state)
	}
	for _, feature := range []VisibilityFeature{
		VisibilityFeatureReassembly,
		VisibilityFeatureHoldReplay,
		VisibilityFeatureACKReplay,
		VisibilityFeatureAutomaticDiscovery,
		VisibilityFeatureCanary,
		VisibilityFeaturePromotion,
	} {
		if decision := gate.Decision(feature); !decision.Allowed {
			t.Fatalf("feature %q remained blocked after proof: %+v", feature, decision)
		}
	}
}

func TestNonPassingSelfTestNeverPublishesCompleteVisibility(t *testing.T) {
	gate := NewVisibilityGate()
	gate.EnsureRequired("generation-1", "test requires proof")
	bus := NewObservationBus()
	controller := NewSelfTestController(
		func(context.Context) (CapabilityReport, error) { return supportedCapability(), nil },
		nil,
		testHealth{},
		scriptedProbe{bus: bus, mode: "both-complete"},
		testIsolation{},
		nil,
		bus,
		nil,
	)
	runner := WrapSelfTestRunnerWithVisibility(controller, gate)
	result := runner.Run(context.Background(), baseRequest())
	if result.Verdict != VerdictPASSWithLimitations {
		t.Fatalf("expected limited result, got %+v", result)
	}
	state := gate.Snapshot()
	if state.Mode == VisibilityComplete || gate.Decision(VisibilityFeaturePromotion).Allowed {
		t.Fatalf("limited test incorrectly enabled visibility-dependent features: %+v", state)
	}
}

func TestLimitedSelfTestPublishesCompleteVisibilityWhenLimitedApplyIsAllowed(t *testing.T) {
	gate := NewVisibilityGate()
	gate.EnsureRequired("generation-1", "test requires proof")
	bus := NewObservationBus()
	controller := NewSelfTestController(
		func(context.Context) (CapabilityReport, error) { return supportedCapability(), nil },
		nil,
		testHealth{},
		scriptedProbe{bus: bus, mode: "both-complete"},
		testIsolation{},
		nil,
		bus,
		nil,
	)
	runner := WrapSelfTestRunnerWithVisibility(controller, gate)
	request := baseRequest()
	request.AllowLimitedApply = true
	result := runner.Run(context.Background(), request)
	if result.Verdict != VerdictPASSWithLimitations || !result.ProductionReady {
		t.Fatalf("expected limited result with production-ready, got %+v", result)
	}
	state := gate.Snapshot()
	if state.Mode != VisibilityComplete || !state.Enforced || state.Generation != "generation-1" || state.LastVerdict != VerdictPASSWithLimitations {
		t.Fatalf("unexpected visibility state: %+v", state)
	}
	if decision := gate.Decision(VisibilityFeaturePromotion); !decision.Allowed {
		t.Fatalf("promotion remained blocked after limited apply: %+v", decision)
	}
}
