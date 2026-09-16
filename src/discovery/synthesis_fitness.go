package discovery

import (
	"sort"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

const (
	CandidateVerdictIncomplete      = "incomplete-evidence"
	CandidateVerdictTargetFailed    = "target-failed"
	CandidateVerdictControlsFailed  = "controls-failed"
	CandidateVerdictResourceUnsafe  = "resource-unsafe"
	CandidateVerdictDiscoveryViable = "discovery-viable"
)

// CandidateEvaluation is an AFS projection of the existing adaptive matrix.
// Fitness is the mean of the matrix's already-computed ScoreOutcome values;
// this type does not introduce a second scoring pipeline.
type CandidateEvaluation struct {
	CandidateID     string                  `json:"candidate_id"`
	Scope           monitor.MonitorScopeKey `json:"scope"`
	TestSessionID   string                  `json:"test_session_id"`
	TargetOutcomes  []ProbeOutcome          `json:"target_outcomes"`
	ControlOutcomes []ProbeOutcome          `json:"control_outcomes"`
	AndroidCanary   *ProbeOutcome           `json:"android_canary,omitempty"`

	StabilityScore  float64 `json:"stability_score"`
	LatencyScore    float64 `json:"latency_score"`
	ResourceScore   float64 `json:"resource_score"`
	CollateralScore float64 `json:"collateral_score"`
	Fitness         float64 `json:"fitness"`

	Verdict      string   `json:"verdict"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
}

type candidateGroupedSample struct {
	profile string
	role    string
	sample  MatrixSample
}

// EvaluateSynthesizedCandidate groups only samples produced for the exact
// synthesized CandidateID. Target/control role lists are supplied by the AFS
// request, while all numeric fitness comes from the existing MatrixSample.Score.
// A target-only success can never become discovery-viable.
func EvaluateSynthesizedCandidate(
	candidate SynthesizedCandidatePlan,
	run AdaptiveRunResult,
	targetProfiles, sameServiceControls, unrelatedControls []string,
	maxAmplification float64,
) CandidateEvaluation {
	evaluation := CandidateEvaluation{
		CandidateID:   candidate.CandidateID,
		Scope:         candidate.Scope,
		TestSessionID: run.RunID,
	}
	role := map[string]string{}
	for _, profile := range targetProfiles {
		role[profile] = "target"
	}
	for _, profile := range sameServiceControls {
		role[profile] = "same-service-control"
	}
	for _, profile := range unrelatedControls {
		role[profile] = "unrelated-control"
	}
	if maxAmplification <= 0 {
		maxAmplification = 1.5
	}

	grouped := make([]candidateGroupedSample, 0)
	var scoreSum float64
	var scoreCount int
	var latencySum time.Duration
	var latencySamples int
	var amplificationSafe, controlAvailable, controlSamples int
	for _, sample := range run.Matrix.Samples {
		if sample.Variant.StrategyID != candidate.CandidateID {
			continue
		}
		kind, ok := role[sample.Variant.TargetProfile]
		if !ok {
			continue
		}
		grouped = append(grouped, candidateGroupedSample{profile: sample.Variant.TargetProfile, role: kind, sample: sample})
		scoreSum += sample.Score
		scoreCount++
		if sample.Outcome.TTFB > 0 {
			latencySum += sample.Outcome.TTFB
			latencySamples++
		}
		if sample.Outcome.PacketAmplification <= 0 || sample.Outcome.PacketAmplification <= maxAmplification {
			amplificationSafe++
		}
		if kind == "target" {
			evaluation.TargetOutcomes = append(evaluation.TargetOutcomes, sample.Outcome)
		} else {
			evaluation.ControlOutcomes = append(evaluation.ControlOutcomes, sample.Outcome)
			controlSamples++
			if sample.Outcome.Verdict == DiagnosticAvailable {
				controlAvailable++
			}
		}
	}
	if scoreCount == 0 {
		evaluation.Verdict = CandidateVerdictIncomplete
		return evaluation
	}
	evaluation.Fitness = scoreSum / float64(scoreCount)
	evaluation.ResourceScore = float64(amplificationSafe) / float64(scoreCount)
	if controlSamples > 0 {
		evaluation.CollateralScore = float64(controlAvailable) / float64(controlSamples)
	}
	if latencySamples > 0 {
		avgMS := float64(latencySum.Microseconds()) / 1000 / float64(latencySamples)
		evaluation.LatencyScore = 1 / (1 + avgMS)
	}

	requiredStable := run.Policy.StableSuccesses
	if requiredStable <= 0 {
		requiredStable = 1
	}
	allProfiles := append(append(append([]string(nil), targetProfiles...), sameServiceControls...), unrelatedControls...)
	availableProfiles := 0
	for _, profile := range allProfiles {
		if availableCount(grouped, profile) >= requiredStable {
			availableProfiles++
		}
	}
	if len(allProfiles) > 0 {
		evaluation.StabilityScore = float64(availableProfiles) / float64(len(allProfiles))
	}

	switch {
	case len(targetProfiles) == 0 || len(sameServiceControls) == 0 || len(unrelatedControls) == 0:
		evaluation.Verdict = CandidateVerdictIncomplete
	case !profilesStable(grouped, targetProfiles, requiredStable):
		evaluation.Verdict = CandidateVerdictTargetFailed
	case !profilesStable(grouped, sameServiceControls, requiredStable) || !profilesStable(grouped, unrelatedControls, requiredStable):
		evaluation.Verdict = CandidateVerdictControlsFailed
	case evaluation.ResourceScore < 1:
		evaluation.Verdict = CandidateVerdictResourceUnsafe
	default:
		evaluation.Verdict = CandidateVerdictDiscoveryViable
	}
	evaluation.EvidenceRefs = candidateEvaluationRefs(run.RunID, grouped)
	return evaluation
}

func availableCount(samples []candidateGroupedSample, profile string) int {
	count := 0
	for _, grouped := range samples {
		if grouped.profile == profile && grouped.sample.Outcome.Verdict == DiagnosticAvailable {
			count++
		}
	}
	return count
}

func profilesStable(samples []candidateGroupedSample, profiles []string, required int) bool {
	if len(profiles) == 0 || required <= 0 {
		return false
	}
	for _, profile := range profiles {
		if availableCount(samples, profile) < required {
			return false
		}
	}
	return true
}

func candidateEvaluationRefs(runID string, samples []candidateGroupedSample) []string {
	refs := make([]string, 0, len(samples))
	seen := map[string]struct{}{}
	for _, grouped := range samples {
		ref := runID + "/" + grouped.role + "/" + grouped.profile
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}
