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
	Axes                []VariantAxis
	ShadowVariants      []DiscoveryVariant
}

type SynthesizedDiscoveryResult struct {
	Adaptive   AdaptiveRunResult   `json:"adaptive"`
	Evaluation CandidateEvaluation `json:"evaluation"`
}

// constrainSynthesisLimitsToConfig keeps the canonical automation config as an
// upper bound. A request may narrow limits or disable an operator family, but
// it can never widen configured numeric budgets or re-enable a disabled family.
func constrainSynthesisLimitsToConfig(requested SynthesisLimits, policy config.AdaptiveStrategySynthesisConfig) SynthesisLimits {
	defaults := DefaultSynthesisLimits()
	effective := SynthesisLimits{
		MaxCandidates:    policy.MaxCandidates,
		MaxGenerations:   policy.MaxGenerations,
		MaxActions:       policy.MaxActions,
		MaxBranches:      policy.MaxBranches,
		MaxAmplification: policy.MaxAmplification,
		AllowSafeFake:    policy.AllowSafeFake,
		AllowDisorder:    policy.AllowBoundedDisorder,
		AllowJitter:      policy.AllowJitter,
	}
	if effective.MaxCandidates == 0 {
		effective.MaxCandidates = defaults.MaxCandidates
	}
	if effective.MaxGenerations == 0 {
		effective.MaxGenerations = defaults.MaxGenerations
	}
	if effective.MaxActions == 0 {
		effective.MaxActions = defaults.MaxActions
	}
	if effective.MaxBranches == 0 {
		effective.MaxBranches = defaults.MaxBranches
	}
	if effective.MaxAmplification == 0 {
		effective.MaxAmplification = defaults.MaxAmplification
	}

	r := requested.normalized()
	if r.MaxCandidates < effective.MaxCandidates {
		effective.MaxCandidates = r.MaxCandidates
	}
	if r.MaxGenerations < effective.MaxGenerations {
		effective.MaxGenerations = r.MaxGenerations
	}
	if r.MaxActions < effective.MaxActions {
		effective.MaxActions = r.MaxActions
	}
	if r.MaxBranches < effective.MaxBranches {
		effective.MaxBranches = r.MaxBranches
	}
	if r.MaxAmplification < effective.MaxAmplification {
		effective.MaxAmplification = r.MaxAmplification
	}
	effective.AllowSafeFake = effective.AllowSafeFake && requested.AllowSafeFake
	effective.AllowDisorder = effective.AllowDisorder && requested.AllowDisorder
	effective.AllowJitter = effective.AllowJitter && requested.AllowJitter
	return effective
}

// bindSafeFakeProfiles projects the already-selected endpoint-safe fake
// template into the existing synthesis request envelope. The synthesizer never
// owns a second fake-profile registry and cannot invent raw profile IDs.
func bindSafeFakeProfiles(request *SynthesisRequest, ctx SynthesisActionContext) {
	if request == nil {
		return
	}
	request.SafeFakeProfileIDs = nil
	if !request.Limits.AllowSafeFake || ctx.FakeMixTemplate == nil {
		return
	}
	profileID := ctx.FakeMixTemplate.Profile.Profile.ID
	if profileID != "" {
		request.SafeFakeProfileIDs = []string{profileID}
	}
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

	// The persisted automation policy is an upper bound over caller-provided
	// request limits. This is applied before any static validation or planning.
	req.Synthesis.Limits = constrainSynthesisLimitsToConfig(req.Synthesis.Limits, cfg.Automation.AdaptiveStrategySynthesis)
	bindSafeFakeProfiles(&req.Synthesis, req.ActionContext)

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
	if err := CheckSynthesizedEmission(req.Candidate); err != nil {
		return AdaptiveRunResult{}, err
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
		FailureFamily:         req.FailureFamily, Authority: req.Authority, Hints: append([]SearchHint(nil), req.Hints...),
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
	samples := maxInt(discoveryCfg.SamplesPerVariant, 1)
	minimumProbes := (2 + len(allProfiles)) * samples
	if discoveryCfg.MaxProbes > 0 && minimumProbes > discoveryCfg.MaxProbes {
		observability.RecordSynthesisViolation(observability.MetricSynthesisUnboundedExecution)
		return AdaptiveRunResult{}, fmt.Errorf("existing Discovery probe budget %d cannot cover mandatory AFS matrix minimum %d", discoveryCfg.MaxProbes, minimumProbes)
	}
	result, err := m.RunAdaptiveDiscovery(ctx, &runCfg, adaptive, runner)
	if err != nil {
		return AdaptiveRunResult{}, err
	}
	if err := RejectSynthesizedDirectApply(result); err != nil {
		return AdaptiveRunResult{}, err
	}
	result.Explanation += "; synthesized candidate passed static ActionPlanner dry-run and shared target/control scoring; no direct apply"
	return result, nil
}

// RunSynthesizedDiscoveryEvaluated keeps the network execution and fitness
// projection separate while exposing the canonical AFS evaluation object.
func (m *Runtime) RunSynthesizedDiscoveryEvaluated(ctx context.Context, cfg *config.Config, req SynthesizedDiscoveryRequest, baselineRunner ProbeRunner, synthesizedRunner SynthesizedProbeRunner) (SynthesizedDiscoveryResult, error) {
	if cfg != nil {
		req.Synthesis.Limits = constrainSynthesisLimitsToConfig(req.Synthesis.Limits, cfg.Automation.AdaptiveStrategySynthesis)
		bindSafeFakeProfiles(&req.Synthesis, req.ActionContext)
	}
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
	if err := appendRole("target", targets); err != nil {
		return nil, err
	}
	if err := appendRole("same-service-control", sameServiceControls); err != nil {
		return nil, err
	}
	if err := appendRole("unrelated-control", unrelatedControls); err != nil {
		return nil, err
	}
	return out, nil
}
