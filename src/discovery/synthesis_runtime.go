package discovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

type SynthesizedProbeRunner func(context.Context, DiscoveryVariant, SynthesizedCandidatePlan, CompiledSynthesizedAction) ProbeOutcome

type SynthesizedDiscoveryRequest struct {
	Gate                SynthesisGateInput
	Synthesis           SynthesisRequest
	Candidate           SynthesizedCandidatePlan
	Store               *SynthesisRunStore
	ActionContext       SynthesisActionContext
	Targets             []string
	SameServiceControls []string
	UnrelatedControls   []string
	FailureFamily       string
	Authority           string
	Hints               []SearchHint
	BaselineStrategyID  string
	Axes                 []VariantAxis
	ShadowVariants      []DiscoveryVariant
}

type SynthesizedDiscoveryResult struct {
	Adaptive   AdaptiveRunResult   `json:"adaptive"`
	Evaluation CandidateEvaluation `json:"evaluation"`
}

// RunSynthesizedDiscovery is an adapter into the existing adaptive matrix. It
// performs the AFS hard/static gates and dry-run ActionPlanner compilation,
// then reuses RunAdaptiveDiscovery and ScoreOutcome unchanged. It never
// applies/promotes the candidate and returns Applied=false through the existing
// result contract.
func (m *Runtime) RunSynthesizedDiscovery(ctx context.Context, cfg *config.Config, req SynthesizedDiscoveryRequest, baselineRunner ProbeRunner, synthesizedRunner SynthesizedProbeRunner) (AdaptiveRunResult, error) {
	if m == nil || cfg == nil {
		return AdaptiveRunResult{}, errors.New("discovery runtime and config are required")
	}
	if ctx == nil || baselineRunner == nil || synthesizedRunner == nil {
		return AdaptiveRunResult{}, errors.New("synthesized discovery requires context and probe runners")
	}
	if req.Store == nil {
		return AdaptiveRunResult{}, errors.New("bounded synthesis run store required")
	}
	if len(req.Targets) == 0 || len(req.SameServiceControls) == 0 || len(req.UnrelatedControls) == 0 {
		observability.RecordSynthesisViolation(observability.MetricSynthesisMissingMandatoryControl)
		return AdaptiveRunResult{}, errors.New("synthesized discovery requires target, same-service control and unrelated control profiles")
	}
	allProfiles, err := synthesisEvaluationProfiles(req.Targets, req.SameServiceControls, req.UnrelatedControls)
	if err != nil {
		observability.RecordSynthesisViolation(observability.MetricSynthesisScopeEscape)
		return AdaptiveRunResult{}, err
	}

	// User opt-in comes from the canonical config policy, never from a caller
	// boolean. Service-profile policy may only narrow this permission.
	req.Gate.UserOptIn = cfg.AdaptiveSynthesisAllowed(req.Candidate.Scope.ServiceProfileID)
	if err := CheckAutomaticSynthesisGate(req.Gate); err != nil {
		return AdaptiveRunResult{}, err
	}
	if !req.Synthesis.Valid(req.Gate.Now) {
		observability.RecordSynthesisViolation(observability.MetricSynthesisStaleGenerationUsed)
		return AdaptiveRunResult{}, errors.New("synthesis request is stale or expired")
	}
	if req.Synthesis.Scope != req.Candidate.Scope || req.Synthesis.BlockingProfileID != req.Gate.Profile.ProfileID || req.Synthesis.BehavioralEvidenceID != req.Gate.Prior.BehavioralEvidenceID {
		return AdaptiveRunResult{}, errors.New("synthesis request does not match gated profile/prior/candidate")
	}
	validation := NewSynthesisPlanner().ValidateCandidate(req.Synthesis, req.Gate.Prior, req.Candidate)
	if !validation.Valid {
		return AdaptiveRunResult{}, fmt.Errorf("synthesized candidate static validation failed: %s", validation.Reason)
	}

	dryContext := req.ActionContext
	dryContext.Input.DryRun = true
	compiled, err := CompileSynthesizedCandidate(req.Candidate, dryContext)
	if err != nil {
		return AdaptiveRunResult{}, fmt.Errorf("synthesized candidate does not compile through ActionPlanner: %w", err)
	}
	if err := req.Store.Put(req.Candidate); err != nil {
		return AdaptiveRunResult{}, err
	}
	for _, axis := range req.Axes {
		if axis.Dimension == DimensionStrategy {
			return AdaptiveRunResult{}, errors.New("synthesized evaluation cannot replace canonical candidate through strategy axis")
		}
	}

	candidate := DiscoveryVariant{Mode: SandboxCandidate, StrategyID: req.Candidate.CandidateID, Complexity: uint8(len(req.Candidate.Operations)), TargetProfile: allProfiles[0]}
	adaptive := AdaptiveRunRequest{
		Profile: req.Gate.Profile, Prior: req.Gate.Prior, Targets: allProfiles,
		EligibilityCandidates: []string{req.Candidate.CandidateID},
		FailureFamily: req.FailureFamily, Authority: req.Authority, Hints: append([]SearchHint(nil), req.Hints...),
		BaselineStrategyID: req.BaselineStrategyID, Candidate: candidate, Axes: append([]VariantAxis(nil), req.Axes...),
		ShadowVariants: append([]DiscoveryVariant(nil), req.ShadowVariants...),
	}
	runner := func(runCtx context.Context, variant DiscoveryVariant) ProbeOutcome {
		if variant.StrategyID == req.Candidate.CandidateID {
			outcome := synthesizedRunner(runCtx, variant, req.Candidate, compiled)
			if outcome.TargetProfile == "" {
				outcome.TargetProfile = variant.TargetProfile
			}
			return outcome
		}
		outcome := baselineRunner(runCtx, variant)
		if outcome.TargetProfile == "" {
			outcome.TargetProfile = variant.TargetProfile
		}
		return outcome
	}

	// AFS stability must be achievable in one bounded matrix run. If the
	// generic Discovery config asks for more stable successes than samples per
	// variant, raise samples only to that existing stability threshold. This
	// consumes the same MaxProbes pool; it does not create a synthesis budget.
	runCfg := *cfg
	discoveryCfg := &runCfg.System.Classifier.Runtime.Discovery
	if discoveryCfg.StableSuccesses > 0 && discoveryCfg.SamplesPerVariant < discoveryCfg.StableSuccesses {
		discoveryCfg.SamplesPerVariant = discoveryCfg.StableSuccesses
	}
	minimumProbes := 2 + len(allProfiles)*maxInt(discoveryCfg.SamplesPerVariant, 1)
	if discoveryCfg.MaxProbes > 0 && minimumProbes > discoveryCfg.MaxProbes {
		observability.RecordSynthesisViolation(observability.MetricSynthesisUnboundedExecution)
		return AdaptiveRunResult{}, fmt.Errorf("existing Discovery probe budget %d cannot cover mandatory AFS matrix minimum %d", discoveryCfg.MaxProbes, minimumProbes)
	}
	result, err := m.RunAdaptiveDiscovery(ctx, &runCfg, adaptive, runner)
	if err != nil {
		return AdaptiveRunResult{}, err
	}
	result.Applied = false
	result.Explanation += "; synthesized candidate passed static ActionPlanner dry-run and shared target/control scoring; no direct apply"
	return result, nil
}

// RunSynthesizedDiscoveryEvaluated keeps the network execution and fitness
// projection separate while exposing the canonical AFS evaluation object.
func (m *Runtime) RunSynthesizedDiscoveryEvaluated(ctx context.Context, cfg *config.Config, req SynthesizedDiscoveryRequest, baselineRunner ProbeRunner, synthesizedRunner SynthesizedProbeRunner) (SynthesizedDiscoveryResult, error) {
	run, err := m.RunSynthesizedDiscovery(ctx, cfg, req, baselineRunner, synthesizedRunner)
	if err != nil {
		return SynthesizedDiscoveryResult{}, err
	}
	maxAmplification := req.Synthesis.Limits.normalized().MaxAmplification
	evaluation := EvaluateSynthesizedCandidate(req.Candidate, run, req.Targets, req.SameServiceControls, req.UnrelatedControls, maxAmplification)
	return SynthesizedDiscoveryResult{Adaptive: run, Evaluation: evaluation}, nil
}

func synthesisEvaluationProfiles(targets, sameServiceControls, unrelatedControls []string) ([]string, error) {
	seen := map[string]string{}
	out := make([]string, 0, len(targets)+len(sameServiceControls)+len(unrelatedControls))
	appendRole := func(role string, profiles []string) error {
		for _, profile := range profiles {
			if profile == "" || len(profile) > 64 {
				return errors.New("synthesized evaluation profile is empty or too long")
			}
			if previous, exists := seen[profile]; exists {
				if previous != role {
					return fmt.Errorf("evaluation profile %q cannot serve both %s and %s roles", profile, previous, role)
				}
				continue
			}
			seen[profile] = role
			out = append(out, profile)
		}
		return nil
	}
	if err := appendRole("target", targets); err != nil { return nil, err }
	if err := appendRole("same-service-control", sameServiceControls); err != nil { return nil, err }
	if err := appendRole("unrelated-control", unrelatedControls); err != nil { return nil, err }
	return out, nil
}
