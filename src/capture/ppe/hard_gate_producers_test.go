package ppe

// Hard-gate producer fixtures for the capture/ppe family: each test drives
// the real production emission site of the registered metric and asserts the
// counter moved. Referenced from specs/registries/hard_gates.yaml and
// FB03_GATE_PRODUCER_CONSUMER_MATRIX.md.

import (
	"context"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

func ppeCounterValue(t *testing.T, name string) uint64 {
	t.Helper()
	snap := observability.Default().Metrics.Snapshot(time.Now())
	for _, counter := range snap.Counters {
		if counter.Name == name {
			return counter.Value
		}
	}
	return 0
}

// TestHardGateProducer_CaptureVisibilityDegrade is the negative fixture for
// b4_capture_visibility_degrade_total and b4_hold_disabled_visibility_total
// (zero-tolerance gates). It drives the production subscription installed by
// NewProductService through the default visibility gate.
func TestHardGateProducer_CaptureVisibilityDegrade(t *testing.T) {
	observability.Default().Metrics.Reset()
	service := NewProductService(nil, nil, "")
	defer service.Stop(context.Background())

	gate := DefaultVisibilityGate()
	gate.EnsureRequired("hard-gate-producer-test", "self-test required")
	gate.Degrade("hard-gate-producer-test", "rules disappeared")
	if got := ppeCounterValue(t, observability.MetricCaptureVisibilityDegrade); got == 0 {
		t.Fatal("b4_capture_visibility_degrade_total not incremented on visibility degradation (zero-tolerance gate)")
	}
	if got := ppeCounterValue(t, observability.MetricHoldDisabledVisibility); got == 0 {
		t.Fatal("b4_hold_disabled_visibility_total not incremented on visibility degradation (zero-tolerance gate)")
	}

	// Restore global gate state so subsequent tests see complete visibility.
	gate.PublishSelfTest(CaptureVisibilityResult{Verdict: VerdictPASS, ProductionReady: true})
}

// TestHardGateProducer_PPESelfTest is the positive fixture for
// b4_ppe_self_test_total.
func TestHardGateProducer_PPESelfTest(t *testing.T) {
	observability.Default().Metrics.Reset()
	bus := NewObservationBus()
	store := NewMemorySelfTestStore(8)
	controller := NewSelfTestController(
		func(context.Context) (CapabilityReport, error) { return supportedCapability(), nil },
		func() string { return "exclude" },
		testHealth{},
		scriptedProbe{bus: bus},
		testIsolation{},
		&testCounters{values: []map[string]uint64{{"tcp": 1}, {"tcp": 5}}},
		bus,
		store,
	)
	service := &ProductService{selfTest: controller}
	if _, err := service.RunSelfTest(context.Background(), baseRequest()); err != nil {
		t.Fatalf("RunSelfTest: %v", err)
	}
	if got := ppeCounterValue(t, observability.MetricPPESelfTest); got == 0 {
		t.Fatal("b4_ppe_self_test_total not incremented by RunSelfTest")
	}
}

type hardGateReapplyLifecycle struct{}

func (hardGateReapplyLifecycle) Current() (DesiredState, bool) { return DesiredState{}, false }
func (hardGateReapplyLifecycle) Assert(context.Context) error  { return nil }
func (hardGateReapplyLifecycle) Reapply(context.Context) (TransactionResult, error) {
	return TransactionResult{}, nil
}

// TestHardGateProducer_PPERuleReapply is the positive fixture for
// b4_ppe_rule_reapply_total.
func TestHardGateProducer_PPERuleReapply(t *testing.T) {
	observability.Default().Metrics.Reset()
	metrics := productLifecycleMetrics{next: hardGateReapplyLifecycle{}}
	if _, err := metrics.Reapply(context.Background()); err != nil {
		t.Fatalf("Reapply: %v", err)
	}
	if got := ppeCounterValue(t, observability.MetricPPERuleReapply); got == 0 {
		t.Fatal("b4_ppe_rule_reapply_total not incremented by lifecycle reapply")
	}
}
