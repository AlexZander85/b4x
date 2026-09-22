package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/fixtures"
)

func behavioralTestBase(t *testing.T, now time.Time) BehavioralMutationBase {
	t.Helper()
	_, req := probeTestCandidate(t, now)
	return BehavioralMutationBase{
		Scope:                req.Scope,
		ConfigGeneration:     req.ConfigGeneration,
		BlockingProfileID:    req.BlockingProfileID,
		BehavioralEvidenceID: req.BehavioralEvidenceID,
		GrammarVersion:       req.AllowedGrammarVersion,
		ActionContext: SynthesisActionContext{
			Confidence:          90,
			TCPPhase:            "first-flight",
			CompleteClientHello: true,
			ConfigGen:           req.ConfigGeneration,
			Budgets:             action.DefaultActionBudgets(),
		},
	}
}

// TestBehavioralMutationCompilerBuildsPlan proves a mutated panel leg compiles
// through the canonical candidate/ActionPlanner path (no second executor).
func TestBehavioralMutationCompilerBuildsPlan(t *testing.T) {
	now := time.Unix(37000, 0)
	base := behavioralTestBase(t, now)
	compiler, err := behavioralMutationCompiler(detector.BehavioralProbeCase{
		ProbeID: "p1", Attempt: 1, Role: "target", Mutated: true,
		Family: detector.OperatorPerFlowJitter, Params: map[string]string{"jitter_ms": "1"},
	}, base)
	if err != nil {
		t.Fatalf("mutation compiler: %v", err)
	}
	payload := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 512)
	plan, err := compiler(action.PlanInput{
		BaseSequence: 1000, Payload: payload, MTU: 1500,
		IPHeaderLen: 20, TCPHeaderLen: 20, ProcessedMark: 1,
	})
	if err != nil || !plan.Valid {
		t.Fatalf("compiled mutation plan invalid: %+v (%v)", plan, err)
	}
}

func TestBehaviorOutcomeFromProbe(t *testing.T) {
	cases := []struct {
		verdict DiagnosticVerdict
		want    detector.BehaviorOutcome
	}{
		{DiagnosticAvailable, detector.BehaviorOutcomeOK},
		{DiagnosticMidstreamReset, detector.BehaviorOutcomeReset},
		{DiagnosticDPIRest, detector.BehaviorOutcomeReset},
		{DiagnosticThrottled, detector.BehaviorOutcomeStall},
		{DiagnosticCaptureIncomplete, detector.BehaviorOutcomeInconclusive},
		{DiagnosticClassifierUnresolved, detector.BehaviorOutcomeInconclusive},
		{DiagnosticDPIDrop, detector.BehaviorOutcomeFail},
	}
	for _, tc := range cases {
		if got := behaviorOutcomeFromProbe(ProbeOutcome{Verdict: tc.verdict}); got != tc.want {
			t.Fatalf("verdict %s -> %s, want %s", tc.verdict, got, tc.want)
		}
	}
}

// TestProductionBehavioralRunnerFailsClosedWithoutTarget proves an unresolved
// leg yields an inconclusive outcome, never a fabricated success.
func TestProductionBehavioralRunnerFailsClosedWithoutTarget(t *testing.T) {
	base := behavioralTestBase(t, time.Unix(38000, 0))
	runner := ProductionBehavioralRunner(BehavioralProbeTargets{}, base, SynthesisProbeConfig{})
	res, err := runner(context.Background(), detector.BehavioralProbeCase{ProbeID: "p", Attempt: 1, Role: "target", Mutated: false})
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	if res.Outcome != detector.BehaviorOutcomeInconclusive {
		t.Fatalf("outcome = %s, want inconclusive", res.Outcome)
	}
}
