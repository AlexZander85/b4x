package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/config"
)

func synthesisSearchRequest(t *testing.T, now time.Time) (*config.Config, BoundedSynthesisSearchRequest) {
	t.Helper()
	gate := validSynthesisGateInput(t, now)
	cfg := config.NewConfig()
	cfg.Automation.AdaptiveStrategySynthesis.Enabled = true
	cfg.Automation.AdaptiveStrategySynthesis.RunTimeout = time.Minute
	cfg.System.Classifier.Runtime.Discovery.MaxProbes = 32
	cfg.System.Classifier.Runtime.Discovery.SamplesPerVariant = 1
	cfg.System.Classifier.Runtime.Discovery.StableSuccesses = 2
	cfg.System.Classifier.Runtime.Discovery.MaxConcurrency = 1

	synthesis := SynthesisRequest{
		RequestID:             "afs-search-a",
		Scope:                 gate.Profile.Scope,
		ConfigGeneration:      gate.Profile.Scope.ConfigGeneration,
		BlockingProfileID:     gate.Profile.ProfileID,
		BehavioralEvidenceID:  gate.Prior.BehavioralEvidenceID,
		BaselineCandidateIDs:  []string{"baseline-none", "baseline-production"},
		AllowedGrammarVersion: SynthesisGrammarV1,
		Limits:                DefaultSynthesisLimits(),
		RequestedAt:           now,
		ExpiresAt:             now.Add(time.Minute),
		DeterministicSeed:     77,
	}
	payload := []byte{
		0x16, 0x03, 0x03, 0x00, 0x08,
		0x01, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00,
	}
	markers := action.MarkerSet{
		Host: "example.com", Complete: true,
		Markers: []action.LogicalMarker{
			{Kind: action.MarkerClientHelloStart, Offset: 0, Available: true},
			{Kind: action.MarkerClientHelloEnd, Offset: uint64(len(payload)), Available: true},
			{Kind: action.MarkerSNIExtensionStart, Offset: 7, Available: true},
			{Kind: action.MarkerHostStart, Offset: 9, Available: true},
			{Kind: action.MarkerHostEnd, Offset: 11, Available: true},
			{Kind: action.MarkerSLDMiddle, Offset: 10, Available: true},
		},
	}
	actionContext := SynthesisActionContext{
		Input: action.PlanInput{
			BaseSequence: 1000, Payload: payload, Markers: markers,
			MTU: 1500, IPHeaderLen: 20, TCPHeaderLen: 20,
			ProcessedMark: 1, MaxWrites: 16, MaxBytes: 64 * 1024,
			ConfigGen: synthesis.ConfigGeneration,
		},
		Confidence: 90, TCPPhase: "first-flight", CompleteClientHello: true,
		ConfigGen: synthesis.ConfigGeneration, Budgets: action.DefaultActionBudgets(),
	}
	request := BoundedSynthesisSearchRequest{
		Gate: gate, Synthesis: synthesis,
		Store:               NewSynthesisRunStore(synthesis.RequestID, int(synthesis.Limits.MaxCandidates)),
		ActionContext:       actionContext,
		Targets:             []string{"target"},
		SameServiceControls: []string{"same-control"},
		UnrelatedControls:   []string{"unrelated-control"},
		FailureFamily:       "tls_fingerprint_specific",
		Authority:           "authoritative-abd",
		BaselineStrategyID:  "baseline-production",
	}
	return &cfg, request
}

func synthesisSearchAvailable(profile string) ProbeOutcome {
	outcome := availableOutcome(1.1)
	outcome.TargetProfile = profile
	return outcome
}

func TestBoundedSynthesisSearchEarlyStopsOnlyAfterAllControls(t *testing.T) {
	now := time.Now()
	cfg, req := synthesisSearchRequest(t, now)
	baseline := func(_ context.Context, variant DiscoveryVariant) ProbeOutcome {
		return synthesisSearchAvailable(variant.TargetProfile)
	}
	synthesized := func(_ context.Context, variant DiscoveryVariant, _ SynthesizedCandidatePlan, _ CompiledSynthesizedAction) ProbeOutcome {
		return synthesisSearchAvailable(variant.TargetProfile)
	}
	result, err := (&Runtime{}).RunBoundedSynthesisSearch(context.Background(), cfg, req, baseline, synthesized)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if result.ViableCandidate == nil || result.StopReason != "discovery-viable-candidate" {
		t.Fatalf("viable candidate missing: %+v", result)
	}
	if len(result.TestedCandidates) != 1 {
		t.Fatalf("early stop tested %d candidates, want 1", len(result.TestedCandidates))
	}
	if result.ProbesUsed != 10 {
		t.Fatalf("probe use = %d, want 10 ((2 baselines + 3 profiles) x 2 stable samples)", result.ProbesUsed)
	}
	if result.Applied {
		t.Fatal("bounded synthesis search applied candidate directly")
	}
}

func TestBoundedSynthesisSearchTargetOnlySuccessCannotWinAndSharesProbeBudget(t *testing.T) {
	now := time.Now()
	cfg, req := synthesisSearchRequest(t, now)
	baseline := func(_ context.Context, variant DiscoveryVariant) ProbeOutcome {
		return synthesisSearchAvailable(variant.TargetProfile)
	}
	synthesized := func(_ context.Context, variant DiscoveryVariant, _ SynthesizedCandidatePlan, _ CompiledSynthesizedAction) ProbeOutcome {
		outcome := synthesisSearchAvailable(variant.TargetProfile)
		if variant.TargetProfile == "unrelated-control" {
			outcome.Verdict = DiagnosticDPIDrop
		}
		return outcome
	}
	result, err := (&Runtime{}).RunBoundedSynthesisSearch(context.Background(), cfg, req, baseline, synthesized)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if result.ViableCandidate != nil {
		t.Fatalf("target-only success produced winner %s", result.ViableCandidate.CandidateID)
	}
	for _, evaluation := range result.Evaluations {
		if evaluation.Verdict == CandidateVerdictDiscoveryViable {
			t.Fatalf("candidate %s escaped control gate", evaluation.CandidateID)
		}
	}
	if result.ProbesUsed > cfg.System.Classifier.Runtime.Discovery.MaxProbes {
		t.Fatalf("AFS used %d probes from a %d-probe Discovery budget", result.ProbesUsed, cfg.System.Classifier.Runtime.Discovery.MaxProbes)
	}
	if result.StopReason != "probe-budget" && result.StopReason != "generation-budget-no-solution" && result.StopReason != "no-measured-parents" {
		t.Fatalf("unexpected no-solution stop reason %q", result.StopReason)
	}
}
