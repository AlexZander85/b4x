package discovery

import (
	"context"
	"errors"
	"fmt"

	"github.com/daniellavrushin/b4/config"
)

type SynthesizedProbeRunner func(context.Context, DiscoveryVariant, SynthesizedCandidatePlan, CompiledSynthesizedAction) ProbeOutcome

type SynthesizedDiscoveryRequest struct {
	Gate               SynthesisGateInput
	Synthesis          SynthesisRequest
	Candidate          SynthesizedCandidatePlan
	Store              *SynthesisRunStore
	ActionContext      SynthesisActionContext
	Targets            []string
	FailureFamily      string
	Authority          string
	Hints              []SearchHint
	BaselineStrategyID string
	Axes               []VariantAxis
	ShadowVariants     []DiscoveryVariant
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

	// User opt-in comes from the canonical config policy, never from a caller
	// boolean. Service-profile policy may only narrow this permission.
	req.Gate.UserOptIn = cfg.AdaptiveSynthesisAllowed(req.Candidate.Scope.ServiceProfileID)
	if err := CheckAutomaticSynthesisGate(req.Gate); err != nil {
		return AdaptiveRunResult{}, err
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

	candidate := DiscoveryVariant{Mode: SandboxCandidate, StrategyID: req.Candidate.CandidateID, Complexity: len(req.Candidate.Operations)}
	if len(req.Targets) > 0 {
		candidate.TargetProfile = req.Targets[0]
	}
	adaptive := AdaptiveRunRequest{
		Profile: req.Gate.Profile, Prior: req.Gate.Prior, Targets: append([]string(nil), req.Targets...),
		FailureFamily: req.FailureFamily, Authority: req.Authority, Hints: append([]SearchHint(nil), req.Hints...),
		BaselineStrategyID: req.BaselineStrategyID, Candidate: candidate, Axes: append([]VariantAxis(nil), req.Axes...),
		ShadowVariants: append([]DiscoveryVariant(nil), req.ShadowVariants...),
	}
	runner := func(runCtx context.Context, variant DiscoveryVariant) ProbeOutcome {
		if variant.StrategyID == req.Candidate.CandidateID {
			return synthesizedRunner(runCtx, variant, req.Candidate, compiled)
		}
		return baselineRunner(runCtx, variant)
	}
	result, err := m.RunAdaptiveDiscovery(ctx, cfg, adaptive, runner)
	if err != nil {
		return AdaptiveRunResult{}, err
	}
	result.Applied = false
	result.Explanation += "; synthesized candidate passed static ActionPlanner dry-run and shared adaptive scoring; no direct apply"
	return result, nil
}
