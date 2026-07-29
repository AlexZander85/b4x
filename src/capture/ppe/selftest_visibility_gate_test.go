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
