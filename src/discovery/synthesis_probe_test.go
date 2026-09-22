package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/fixtures"
)

func probeTestCandidate(t *testing.T, now time.Time) (SynthesizedCandidatePlan, SynthesisRequest) {
	t.Helper()
	req, _ := synthesisPlannerTestInput(now)
	candidate, err := newSynthesizedCandidate(
		req,
		0,
		nil,
		CandidateTrigger{Phase: "complete-reassembled-clienthello", Marker: "host-start"},
		[]CandidateOperation{{Family: detector.OperatorPerFlowJitter, Params: map[string]string{"jitter_ms": "1"}}},
		action.RepresentationNormalTCP,
		[]string{"current-action-authorization"},
		CandidateCost{Actions: 1, EstimatedPackets: 1, Amplification: 1},
		CandidateRisk{Tier: "endpoint-safe", AutomaticOK: true},
		[]string{"test-seed"},
		now,
	)
	if err != nil {
		t.Fatalf("candidate: %v", err)
	}
	return candidate, req
}

// TestSynthesisCandidateCompilerBuildsExecutablePlan proves the production
// runner compiles a candidate against the real probe packet (payload+seq), not
// the engine's dry-run compilation.
func TestSynthesisCandidateCompilerBuildsExecutablePlan(t *testing.T) {
	now := time.Unix(33000, 0)
	candidate, req := probeTestCandidate(t, now)
	base := SynthesisActionContext{
		Confidence:          90,
		TCPPhase:            "first-flight",
		CompleteClientHello: true,
		ConfigGen:           req.ConfigGeneration,
		Budgets:             action.DefaultActionBudgets(),
	}
	compiler := SynthesisCandidateCompiler(candidate, base)

	payload := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	plan, err := compiler(action.PlanInput{
		BaseSequence:  1000,
		Payload:       payload,
		MTU:           1500,
		IPHeaderLen:   20,
		TCPHeaderLen:  20,
		ProcessedMark: 1,
	})
	if err != nil {
		t.Fatalf("compiler: %v", err)
	}
	if !plan.Valid || plan.StrategyID != candidate.CandidateID {
		t.Fatalf("compiled plan invalid: %+v", plan)
	}
}

// TestSynthesisCandidateCompilerFailsClosedOnGenerationMismatch proves a stale
// base context cannot silently produce a plan.
func TestSynthesisCandidateCompilerFailsClosedOnGenerationMismatch(t *testing.T) {
	now := time.Unix(34000, 0)
	candidate, _ := probeTestCandidate(t, now)
	compiler := SynthesisCandidateCompiler(candidate, SynthesisActionContext{
		Confidence: 90,
		TCPPhase:   "first-flight",
		ConfigGen:  0, // mismatched generation
		Budgets:    action.DefaultActionBudgets(),
	})
	if _, err := compiler(action.PlanInput{BaseSequence: 1, Payload: []byte{1, 2, 3}, ProcessedMark: 1, ConfigGen: 0}); err == nil {
		t.Fatal("compiler must fail closed on generation mismatch")
	}
}

// TestProductionSynthesisRunnersFailClosedWithoutTarget proves the runners are
// bounded and never fabricate availability for an unknown target profile.
func TestProductionSynthesisRunnersFailClosedWithoutTarget(t *testing.T) {
	baseline, synthesized := ProductionSynthesisRunners(map[string]SynthesisProbeTarget{}, SynthesisActionContext{}, SynthesisProbeConfig{})
	if baseline == nil || synthesized == nil {
		t.Fatal("runners must not be nil")
	}
	out := baseline(context.Background(), DiscoveryVariant{TargetProfile: "unknown"})
	if out.Verdict == DiagnosticAvailable {
		t.Fatalf("unknown target must not report available: %+v", out)
	}
}
