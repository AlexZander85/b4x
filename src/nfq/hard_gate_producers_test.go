package nfq

// Hard-gate producer fixtures: each test drives the real production function
// that emits a registered hard-gate metric and asserts the counter moved.
// Negative fixtures (zero-tolerance gates) prove the violation path reaches
// the counter; positive fixtures (telemetry gates) prove the happy path emits.
//
// These tests are referenced from specs/registries/hard_gates.yaml
// (test_producer / mutation_test / evidence_artifact) and from
// FB03_GATE_PRODUCER_CONSUMER_MATRIX.md.

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

func hardGateCounterValue(t *testing.T, name string) uint64 {
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

// TestHardGateProducer_GSOOffloadMetadata is the negative fixture for
// nfqueue_gso_truncated_total and nfqueue_gso_csum_not_ready_total and the
// positive fixture for nfqueue_gso_packets_total / nfqueue_gso_bytes_total.
func TestHardGateProducer_GSOOffloadMetadata(t *testing.T) {
	observability.Default().Metrics.Reset()
	worker := NewWorkerWithQueue(nil, 0)
	metadata := OffloadMetadata{
		IsGSO:            true,
		Truncated:        true,
		ChecksumNotReady: true,
		PayloadLength:    512,
		OriginalLength:   1514,
	}
	worker.observeOffloadMetadata(metadata)

	if got := hardGateCounterValue(t, observability.MetricNFQueueGSOPackets); got == 0 {
		t.Fatal("nfqueue_gso_packets_total not incremented by observeOffloadMetadata")
	}
	if got := hardGateCounterValue(t, observability.MetricNFQueueGSOBytes); got == 0 {
		t.Fatal("nfqueue_gso_bytes_total not incremented by observeOffloadMetadata")
	}
	if got := hardGateCounterValue(t, observability.MetricNFQueueGSOTruncated); got == 0 {
		t.Fatal("nfqueue_gso_truncated_total not incremented for truncated metadata (zero-tolerance gate)")
	}
	if got := hardGateCounterValue(t, observability.MetricNFQueueGSOCsumNotReady); got == 0 {
		t.Fatal("nfqueue_gso_csum_not_ready_total not incremented for checksum-not-ready metadata (zero-tolerance gate)")
	}
}

// TestHardGateProducer_GSOFastPathDecisions is the positive fixture for
// nfqueue_gso_decision_total / nfqueue_gso_normalized_total and
// nfqueue_gso_action_suppressed_total.
func TestHardGateProducer_GSOFastPathDecisions(t *testing.T) {
	observability.Default().Metrics.Reset()
	pkt := &pktInfo{offload: OffloadMetadata{PayloadLength: 512, OriginalLength: 512}}

	traceGSOFastPath(pkt, "protect", gsoPathNormalizeQueued, "", 42)
	if got := hardGateCounterValue(t, observability.MetricNFQueueGSODecision); got == 0 {
		t.Fatal("nfqueue_gso_decision_total not incremented by traceGSOFastPath")
	}
	if got := hardGateCounterValue(t, observability.MetricNFQueueGSONormalized); got == 0 {
		t.Fatal("nfqueue_gso_normalized_total not incremented for normalize-queued path")
	}

	observability.Default().Metrics.Reset()
	traceGSOFastPath(pkt, "protect", gsoPathActionSuppressed, "suppression budget exhausted", 43)
	if got := hardGateCounterValue(t, observability.MetricNFQueueGSODecision); got == 0 {
		t.Fatal("nfqueue_gso_decision_total not incremented for suppressed path")
	}
	if got := hardGateCounterValue(t, observability.MetricNFQueueGSOActionSuppressed); got == 0 {
		t.Fatal("nfqueue_gso_action_suppressed_total not incremented for suppressed path")
	}
}

// TestHardGateProducer_GSOTokenMiss is the negative fixture for
// nfqueue_gso_token_miss_total (zero-tolerance gate).
func TestHardGateProducer_GSOTokenMiss(t *testing.T) {
	observability.Default().Metrics.Reset()
	traceGSONormalizerMiss(classifier.FlowKey{}, 42, 7, "no-pass-token")
	if got := hardGateCounterValue(t, observability.MetricNFQueueGSOTokenMiss); got == 0 {
		t.Fatal("nfqueue_gso_token_miss_total not incremented by traceGSONormalizerMiss")
	}
}

// TestHardGateProducer_PassiveRSTMetrics is the negative fixture for
// passive_rst_fail_open_total / passive_rst_budget_exhausted_total and the
// positive fixture for passive_rst_observed_total / passive_rst_decision_total
// / passive_rst_suppressed_total / passive_rst_baseline_quality_total.
func TestHardGateProducer_PassiveRSTMetrics(t *testing.T) {
	observability.Default().Metrics.Reset()
	evidence := PassiveRSTEvidence{
		Flow: PassiveRSTFlowSnapshot{SetID: "set-a", DeviceScope: "dev-1"},
		Signals: []PassiveRSTSignalObservation{
			{Signal: PassiveRSTSignalBurst, Strength: PassiveRSTStrengthStrong},
			{Signal: PassiveRSTSignalTTLMismatch, Strength: PassiveRSTStrengthCorroborating},
		},
		Baseline: PassiveRSTBaselineSnapshot{Quality: PassiveRSTBaselineWeak},
	}

	recordPassiveRSTMetrics(evidence, PassiveRSTEnforcementResult{Decision: PassiveRSTDecisionObserve, EffectiveMode: "observe"})
	if got := hardGateCounterValue(t, observability.MetricPassiveRSTObserved); got != 2 {
		t.Fatalf("passive_rst_observed_total = %d, want 2", got)
	}
	if got := hardGateCounterValue(t, observability.MetricPassiveRSTDecision); got == 0 {
		t.Fatal("passive_rst_decision_total not incremented")
	}
	if got := hardGateCounterValue(t, observability.MetricPassiveRSTBaselineQuality); got == 0 {
		t.Fatal("passive_rst_baseline_quality_total not incremented")
	}

	recordPassiveRSTMetrics(evidence, PassiveRSTEnforcementResult{Decision: PassiveRSTDecisionSuppress, EffectiveMode: "protect", Reason: "budget"})
	if got := hardGateCounterValue(t, observability.MetricPassiveRSTSuppressed); got == 0 {
		t.Fatal("passive_rst_suppressed_total not incremented for suppress decision")
	}

	recordPassiveRSTMetrics(evidence, PassiveRSTEnforcementResult{Decision: PassiveRSTDecisionFailOpen, EffectiveMode: "protect", Reason: "budget"})
	if got := hardGateCounterValue(t, observability.MetricPassiveRSTFailOpen); got == 0 {
		t.Fatal("passive_rst_fail_open_total not incremented for fail-open decision (zero-tolerance gate)")
	}
	if got := hardGateCounterValue(t, observability.MetricPassiveRSTBudgetExhausted); got == 0 {
		t.Fatal("passive_rst_budget_exhausted_total not incremented for budget fail-open")
	}
}

// TestHardGateProducer_PassiveRSTRollback is the negative fixture for
// passive_rst_reconnect_regression_total and passive_rst_rollback_total
// (zero-tolerance gate).
func TestHardGateProducer_PassiveRSTRollback(t *testing.T) {
	observability.Default().Metrics.Reset()
	cfg := config.PassiveRSTRuntimeConfig{
		Mode:                      config.PassiveRSTConservative,
		ReconnectFailureThreshold: 2,
		ControlFailureThreshold:   999,
		NoProgressThreshold:       999,
		RollbackWindowSeconds:     3600,
	}
	now := time.Unix(2000, 0)
	store := NewPassiveRSTStore(cfg, clock.NewFixed(now))
	sample := PassiveRSTHealthSample{
		SetID:             "set-a",
		DeviceScope:       "dev-1",
		ConfigGeneration:  7,
		Environment:       PassiveRSTEnvironmentProduction,
		ReconnectFailures: 3,
		ObservedAt:        now,
	}
	state, triggered := store.RecordHealth(cfg, sample)
	if !triggered || state.Reason != "reconnect failure regression" {
		t.Fatalf("rollback not triggered: triggered=%v state=%+v", triggered, state)
	}
	if got := hardGateCounterValue(t, observability.MetricPassiveRSTRollback); got == 0 {
		t.Fatal("passive_rst_rollback_total not incremented by RecordHealth")
	}
	if got := hardGateCounterValue(t, observability.MetricPassiveRSTReconnectRegression); got == 0 {
		t.Fatal("passive_rst_reconnect_regression_total not incremented for reconnect regression (zero-tolerance gate)")
	}
}

// TestHardGateProducer_ClassifierLayoutParity is the negative fixture for
// classifier_layout_parity_fail_total and the positive fixture for
// classifier_reassembled_sni_total.
func TestHardGateProducer_ClassifierLayoutParity(t *testing.T) {
	observability.Default().Metrics.Reset()
	decision := classifier.ClassificationDecision{
		Phase:         classifier.PhaseInspecting,
		Selected:      &classifier.Evidence{Source: classifier.EvidenceReassembledSNI, SetID: "set-a", Domain: "example.test"},
		ClientHelloID: 0,
		Confidence:    90,
	}
	recordObservabilityDecision(decision, "test")
	if got := hardGateCounterValue(t, observability.MetricClassifierLayoutParityFail); got == 0 {
		t.Fatal("classifier_layout_parity_fail_total not incremented for reassembled-SNI without logical ID (zero-tolerance gate)")
	}

	observability.Default().Metrics.Reset()
	decision.ClientHelloID = 123
	recordObservabilityDecision(decision, "test")
	if got := hardGateCounterValue(t, observability.MetricClassifierReassembledSNI); got == 0 {
		t.Fatal("classifier_reassembled_sni_total not incremented for reassembled-SNI selection")
	}
	if got := hardGateCounterValue(t, observability.MetricClassifierLayoutParityFail); got != 0 {
		t.Fatalf("classifier_layout_parity_fail_total = %d, want 0 for complete logical ID", got)
	}
}
