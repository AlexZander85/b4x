package discovery

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

type BoundedSynthesisSearchRequest struct {
	Gate                    SynthesisGateInput
	Synthesis               SynthesisRequest
	Store                   *SynthesisRunStore
	ActionContext           SynthesisActionContext
	Targets                 []string
	SameServiceControls     []string
	UnrelatedControls       []string
	FailureFamily           string
	Authority               string
	Hints                   []SearchHint
	BaselineStrategyID      string
	Axes                    []VariantAxis
	ShadowVariants          []DiscoveryVariant
	ExistingCanonicalHashes map[string]struct{}
}

type BoundedSynthesisSearchResult struct {
	RequestID        string                    `json:"request_id"`
	Evaluations      []CandidateEvaluation     `json:"evaluations"`
	TestedCandidates []string                  `json:"tested_candidates"`
	BestCandidateID  string                    `json:"best_candidate_id,omitempty"`
	ViableCandidate  *SynthesizedCandidatePlan `json:"viable_candidate,omitempty"`
	ProbesUsed       int                       `json:"probes_used"`
	Generated        int                       `json:"generated"`
	Rejected         map[string]string         `json:"rejected,omitempty"`
	StopReason       string                    `json:"stop_reason"`
	Applied          bool                      `json:"applied"`
}

type measuredSynthesisCandidate struct {
	plan       SynthesizedCandidatePlan
	evaluation CandidateEvaluation
}

// RunBoundedSynthesisSearch implements AFS score -> prune -> mutate/crossover
// under Discovery ownership. Network outcomes choose the next generation's
// parents, but canonical candidate identity remains deterministic. Every
// candidate is still compiled and evaluated through RunSynthesizedDiscovery.
// This method never canaries, promotes or applies a winner.
func (m *Runtime) RunBoundedSynthesisSearch(ctx context.Context, cfg *config.Config, req BoundedSynthesisSearchRequest, baselineRunner ProbeRunner, synthesizedRunner SynthesizedProbeRunner) (BoundedSynthesisSearchResult, error) {
	result := BoundedSynthesisSearchResult{RequestID: req.Synthesis.RequestID, Rejected: map[string]string{}, Applied: false}
	if m == nil || cfg == nil || ctx == nil || baselineRunner == nil || synthesizedRunner == nil {
		return result, errors.New("bounded synthesis search requires runtime, config, context and probe runners")
	}
	if req.Store == nil {
		return result, errors.New("bounded synthesis search requires run-scoped candidate store")
	}
	if _, err := synthesisEvaluationProfiles(req.Targets, req.SameServiceControls, req.UnrelatedControls); err != nil {
		return result, err
	}

	limits := req.Synthesis.Limits.normalized()
	policy := AdaptivePolicyFromRuntimeConfig(cfg.System.Classifier.Runtime.Discovery)
	if req.Synthesis.ResourceBudget.MaxProbes > 0 && req.Synthesis.ResourceBudget.MaxProbes < policy.MaxProbes {
		policy.MaxProbes = req.Synthesis.ResourceBudget.MaxProbes
	}
	if policy.MaxProbes <= 0 {
		return result, errors.New("existing Discovery probe budget unavailable")
	}
	req.Synthesis.ResourceBudget = policy

	runCtx := ctx
	cancel := func() {}
	if timeout := cfg.Automation.AdaptiveStrategySynthesis.RunTimeout; timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	defer cancel()

	planner := NewSynthesisPlanner()
	state := NewSynthesisPopulationState(req.Synthesis, req.ExistingCanonicalHashes)
	population, err := planner.SeedPopulation(req.Synthesis, req.Gate.Prior, state)
	if err != nil {
		return result, err
	}
	if len(population) == 0 {
		result.Rejected = state.Rejected
		result.StopReason = "no-valid-seed-population"
		return result, nil
	}

	remainingProbes := policy.MaxProbes
	var best *measuredSynthesisCandidate
	for generation := uint8(0); generation < limits.MaxGenerations && len(population) > 0; generation++ {
		if err := runCtx.Err(); err != nil {
			result.Generated = state.Generated
			result.Rejected = state.Rejected
			result.StopReason = "cancelled-or-timeout"
			return result, err
		}
		measured := make([]measuredSynthesisCandidate, 0, len(population))
		for _, candidate := range population {
			if len(result.TestedCandidates) >= int(limits.MaxCandidates) {
				result.StopReason = "candidate-budget"
				break
			}
			minimum := minimumSynthesizedMatrixProbes(cfg, len(req.Targets)+len(req.SameServiceControls)+len(req.UnrelatedControls))
			if remainingProbes < minimum {
				result.StopReason = "probe-budget"
				break
			}

			candidateCfg := *cfg
			candidateCfg.System.Classifier.Runtime.Discovery.MaxProbes = remainingProbes
			gate := req.Gate
			gate.Now = time.Now()
			if !req.Synthesis.Valid(gate.Now) {
				observability.RecordSynthesisViolation(observability.MetricSynthesisStaleGenerationUsed)
				return result, errors.New("synthesis request expired during bounded search")
			}
			discoveryReq := SynthesizedDiscoveryRequest{
				Gate: gate, Synthesis: req.Synthesis, Candidate: candidate, Store: req.Store, ActionContext: req.ActionContext,
				Targets: append([]string(nil), req.Targets...), SameServiceControls: append([]string(nil), req.SameServiceControls...), UnrelatedControls: append([]string(nil), req.UnrelatedControls...),
				FailureFamily: req.FailureFamily, Authority: req.Authority, Hints: append([]SearchHint(nil), req.Hints...), BaselineStrategyID: req.BaselineStrategyID,
				Axes: append([]VariantAxis(nil), req.Axes...), ShadowVariants: append([]DiscoveryVariant(nil), req.ShadowVariants...),
			}
			discoveryResult, runErr := m.RunSynthesizedDiscoveryEvaluated(runCtx, &candidateCfg, discoveryReq, baselineRunner, synthesizedRunner)
			if runErr != nil {
				state.FailedIDs[candidate.CandidateID] = struct{}{}
				state.Rejected[candidate.CandidateID] = runErr.Error()
				continue
			}
			used := len(discoveryResult.Adaptive.Matrix.Samples) + len(discoveryResult.Adaptive.Matrix.Shadows)
			if used <= 0 || used > remainingProbes {
				observability.RecordSynthesisViolation(observability.MetricSynthesisUnboundedExecution)
				return result, errors.New("synthesized Discovery reported invalid probe consumption")
			}
			remainingProbes -= used
			result.ProbesUsed += used
			result.TestedCandidates = append(result.TestedCandidates, candidate.CandidateID)
			result.Evaluations = append(result.Evaluations, discoveryResult.Evaluation)
			current := measuredSynthesisCandidate{plan: candidate, evaluation: discoveryResult.Evaluation}
			measured = append(measured, current)
			if best == nil || betterMeasuredCandidate(current, *best) {
				copy := current
				best = &copy
				result.BestCandidateID = candidate.CandidateID
			}
			if discoveryResult.Evaluation.Verdict == CandidateVerdictDiscoveryViable {
				winner := candidate
				result.ViableCandidate = &winner
				result.Generated = state.Generated
				result.Rejected = state.Rejected
				result.StopReason = "discovery-viable-candidate"
				return result, nil
			}
			state.FailedIDs[candidate.CandidateID] = struct{}{}
		}
		if result.StopReason == "probe-budget" || result.StopReason == "candidate-budget" {
			break
		}
		parents := measuredParents(measured)
		if len(parents) == 0 {
			result.StopReason = "no-measured-parents"
			break
		}
		population, err = planner.NextPopulation(req.Synthesis, req.Gate.Prior, parents, generation+1, state)
		if err != nil {
			return result, err
		}
	}
	result.Generated = state.Generated
	result.Rejected = state.Rejected
	if result.StopReason == "" {
		if remainingProbes < minimumSynthesizedMatrixProbes(cfg, len(req.Targets)+len(req.SameServiceControls)+len(req.UnrelatedControls)) {
			result.StopReason = "probe-budget"
		} else {
			result.StopReason = "generation-budget-no-solution"
		}
	}
	return result, nil
}

func minimumSynthesizedMatrixProbes(cfg *config.Config, profileCount int) int {
	if cfg == nil || profileCount <= 0 {
		return 0
	}
	discoveryCfg := cfg.System.Classifier.Runtime.Discovery
	samples := discoveryCfg.SamplesPerVariant
	if samples <= 0 {
		samples = 1
	}
	if discoveryCfg.StableSuccesses > samples {
		samples = discoveryCfg.StableSuccesses
	}
	// RunAdaptiveMatrix samples both mandatory baselines and each target/control
	// profile with SamplesPerVariant. Count exactly what the shared evaluator
	// will consume so AFS never under-reserves the Discovery probe budget.
	return (2 + profileCount) * samples
}

func measuredParents(measured []measuredSynthesisCandidate) []SynthesizedCandidatePlan {
	eligible := make([]measuredSynthesisCandidate, 0, len(measured))
	for _, candidate := range measured {
		if candidate.evaluation.Verdict == CandidateVerdictIncomplete || candidate.evaluation.Verdict == CandidateVerdictResourceUnsafe {
			continue
		}
		eligible = append(eligible, candidate)
	}
	sort.SliceStable(eligible, func(i, j int) bool { return betterMeasuredCandidate(eligible[i], eligible[j]) })
	if len(eligible) > maxSynthesisParents {
		eligible = eligible[:maxSynthesisParents]
	}
	parents := make([]SynthesizedCandidatePlan, 0, len(eligible))
	for _, candidate := range eligible {
		parents = append(parents, candidate.plan)
	}
	return parents
}

func betterMeasuredCandidate(left, right measuredSynthesisCandidate) bool {
	if left.evaluation.Fitness != right.evaluation.Fitness {
		return left.evaluation.Fitness > right.evaluation.Fitness
	}
	if left.evaluation.StabilityScore != right.evaluation.StabilityScore {
		return left.evaluation.StabilityScore > right.evaluation.StabilityScore
	}
	return left.plan.CandidateID < right.plan.CandidateID
}
