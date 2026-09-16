package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

func TestBoundedSynthesisSearchDoesNotGenerateBeforeOptInGate(t *testing.T) {
	now := time.Now()
	cfg, req := synthesisSearchRequest(t, now)
	cfg.Automation.AdaptiveStrategySynthesis.Enabled = false
	observability.Default().Metrics.Reset()

	probeCalls := 0
	baseline := func(context.Context, DiscoveryVariant) ProbeOutcome {
		probeCalls++
		return ProbeOutcome{}
	}
	synthesized := func(context.Context, DiscoveryVariant, SynthesizedCandidatePlan, CompiledSynthesizedAction) ProbeOutcome {
		probeCalls++
		return ProbeOutcome{}
	}

	result, err := (&Runtime{}).RunBoundedSynthesisSearch(context.Background(), cfg, req, baseline, synthesized)
	if err == nil {
		t.Fatal("bounded synthesis started while canonical user opt-in was disabled")
	}
	if result.Generated != 0 || len(req.Store.IDs()) != 0 || probeCalls != 0 {
		t.Fatalf("preflight failure generated or evaluated candidates: generated=%d stored=%d probes=%d", result.Generated, len(req.Store.IDs()), probeCalls)
	}
	requireSynthesisCounter(t, observability.MetricSynthesisWithoutUserOptIn)
}

func TestBoundedSynthesisSearchRejectsExpiredRequestBeforeGeneration(t *testing.T) {
	now := time.Now()
	cfg, req := synthesisSearchRequest(t, now)
	req.Synthesis.ExpiresAt = now.Add(-time.Second)
	observability.Default().Metrics.Reset()

	probeCalls := 0
	baseline := func(context.Context, DiscoveryVariant) ProbeOutcome {
		probeCalls++
		return ProbeOutcome{}
	}
	synthesized := func(context.Context, DiscoveryVariant, SynthesizedCandidatePlan, CompiledSynthesizedAction) ProbeOutcome {
		probeCalls++
		return ProbeOutcome{}
	}

	result, err := (&Runtime{}).RunBoundedSynthesisSearch(context.Background(), cfg, req, baseline, synthesized)
	if err == nil {
		t.Fatal("expired synthesis request generated a population")
	}
	if result.Generated != 0 || len(req.Store.IDs()) != 0 || probeCalls != 0 {
		t.Fatalf("expired request generated or evaluated candidates: generated=%d stored=%d probes=%d", result.Generated, len(req.Store.IDs()), probeCalls)
	}
	requireSynthesisCounter(t, observability.MetricSynthesisStaleGenerationUsed)
}
