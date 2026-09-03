package handler

// Hard-gate producer fixture for nfqueue_gso_transition_total: drives the real
// production emission site (runtime topology apply defer) and asserts the
// counter moved. Referenced from specs/registries/hard_gates.yaml and
// FB03_GATE_PRODUCER_CONSUMER_MATRIX.md.

import (
	"context"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/runtimecontrol"
)

func topologyCounterValue(t *testing.T, name string) uint64 {
	t.Helper()
	snap := observability.Default().Metrics.Snapshot(time.Now())
	var total uint64
	for _, counter := range snap.Counters {
		if counter.Name == name {
			total += counter.Value
		}
	}
	return total
}

// TestHardGateProducer_GSOTransition is the positive fixture for
// nfqueue_gso_transition_total. The emission site is the deferred counter in
// ApplyRuntimeControlTopology; an invalid invocation still records the
// transition attempt (result=rollback), which is the honest telemetry for an
// aborted switch.
func TestHardGateProducer_GSOTransition(t *testing.T) {
	observability.Default().Metrics.Reset()
	api := &API{}
	if err := api.ApplyRuntimeControlTopology(context.Background(), nil, nil, runtimecontrol.GenerationMeta{}); err == nil {
		t.Fatal("expected error for nil active/candidate configs")
	}
	if got := topologyCounterValue(t, observability.MetricNFQueueGSOTransition); got == 0 {
		t.Fatal("nfqueue_gso_transition_total not incremented by ApplyRuntimeControlTopology defer")
	}
}
