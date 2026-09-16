package discovery

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
)

func synthesisFitnessCandidate(t *testing.T, now time.Time) SynthesizedCandidatePlan {
	t.Helper()
	req, _ := synthesisPlannerTestInput(now)
	candidate, err := newSynthesizedCandidate(
		req,
		0,
		nil,
		CandidateTrigger{Phase: "complete-reassembled-clienthello", Marker: "host-start"},
		[]CandidateOperation{{Family: detector.OperatorTCPSplit, Params: map[string]string{"marker": string(action.MarkerHostStart)}}},
		action.RepresentationNormalTCP,
		[]string{"current-action-authorization"},
		CandidateCost{Actions: 1, EstimatedPackets: 2, Amplification: 1},
		CandidateRisk{Tier: "endpoint-safe", AutomaticOK: true},
		[]string{"test-seed"},
		now,
	)
	if err != nil {
		t.Fatalf("candidate: %v", err)
	}
	return candidate
}

func synthesisFitnessRun(candidate SynthesizedCandidatePlan, outcomes map[string]ProbeOutcome) AdaptiveRunResult {
	samples := make([]MatrixSample, 0, len(outcomes))
	for _, profile := range []string{"target", "same-control", "unrelated-control"} {
		outcome, ok := outcomes[profile]
		if !ok {
			continue
		}
		outcome.TargetProfile = profile
		samples = append(samples, MatrixSample{
			Variant: DiscoveryVariant{Mode: SandboxCandidate, StrategyID: candidate.CandidateID, TargetProfile: profile, Complexity: uint8(len(candidate.Operations))},
			Attempt: 1,
			Outcome: outcome,
			Score: ScoreOutcome(outcome, uint8(len(candidate.Operations)), DefaultScoreWeights()),
		})
	}
	return AdaptiveRunResult{RunID: "afs-eval", Policy: AdaptivePolicy{StableSuccesses: 1}, Matrix: MatrixResult{Samples: samples}}
}

func availableOutcome(amplification float64) ProbeOutcome {
	return ProbeOutcome{Verdict: DiagnosticAvailable, TCPConnected: true, TLSResponseType: TLSResponseServerHello, HTTPHeaders: true, BodyBytes: 32 << 10, BodySuccessThreshold: 32 << 10, PacketAmplification: amplification, TTFB: 10 * time.Millisecond}
}

func TestSynthesizedFitnessRejectsTargetOnlySuccess(t *testing.T) {
	now := time.Unix(33000, 0)
	candidate := synthesisFitnessCandidate(t, now)
	failedControl := availableOutcome(1)
	failedControl.Verdict = DiagnosticDPIDrop
	run := synthesisFitnessRun(candidate, map[string]ProbeOutcome{
		"target":            availableOutcome(1),
		"same-control":      availableOutcome(1),
		"unrelated-control": failedControl,
	})
	evaluation := EvaluateSynthesizedCandidate(candidate, run, []string{"target"}, []string{"same-control"}, []string{"unrelated-control"}, 1.5)
	if evaluation.Verdict != CandidateVerdictControlsFailed {
		t.Fatalf("target-only success verdict = %q", evaluation.Verdict)
	}
	if evaluation.Fitness == 0 {
		t.Fatal("fitness should still project existing matrix scores for ranking")
	}
}

func TestSynthesizedFitnessRequiresAllGroupsForViableVerdict(t *testing.T) {
	now := time.Unix(34000, 0)
	candidate := synthesisFitnessCandidate(t, now)
	run := synthesisFitnessRun(candidate, map[string]ProbeOutcome{
		"target":            availableOutcome(1.1),
		"same-control":      availableOutcome(1.1),
		"unrelated-control": availableOutcome(1.1),
	})
	evaluation := EvaluateSynthesizedCandidate(candidate, run, []string{"target"}, []string{"same-control"}, []string{"unrelated-control"}, 1.5)
	if evaluation.Verdict != CandidateVerdictDiscoveryViable {
		t.Fatalf("all-group success verdict = %q", evaluation.Verdict)
	}
	if evaluation.StabilityScore != 1 || evaluation.CollateralScore != 1 || evaluation.ResourceScore != 1 {
		t.Fatalf("unexpected safety projections: %+v", evaluation)
	}
}

func TestSynthesizedFitnessRejectsMeasuredAmplificationEscape(t *testing.T) {
	now := time.Unix(35000, 0)
	candidate := synthesisFitnessCandidate(t, now)
	run := synthesisFitnessRun(candidate, map[string]ProbeOutcome{
		"target":            availableOutcome(2),
		"same-control":      availableOutcome(1),
		"unrelated-control": availableOutcome(1),
	})
	evaluation := EvaluateSynthesizedCandidate(candidate, run, []string{"target"}, []string{"same-control"}, []string{"unrelated-control"}, 1.5)
	if evaluation.Verdict != CandidateVerdictResourceUnsafe {
		t.Fatalf("measured amplification escape verdict = %q", evaluation.Verdict)
	}
}

func TestSynthesisEvaluationProfilesRejectRoleAliasing(t *testing.T) {
	if _, err := synthesisEvaluationProfiles([]string{"shared"}, []string{"shared"}, []string{"other"}); err == nil {
		t.Fatal("same endpoint accepted as target and control")
	}
}
