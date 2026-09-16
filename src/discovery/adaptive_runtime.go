package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/observability"
)

type AdaptiveRunRequest struct {
	Profile               NetworkDiagnosticProfile
	Prior                 detector.DiscoverySearchPrior
	Targets               []string
	EligibilityCandidates []string
	FailureFamily         string
	Authority             string
	Hints                 []SearchHint
	BaselineStrategyID    string
	Candidate             DiscoveryVariant
	Axes                  []VariantAxis
	ShadowVariants        []DiscoveryVariant
}

type AdaptiveRunResult struct {
	RunID       string           `json:"run_id"`
	ProfileID   string           `json:"profile_id,omitempty"`
	Scope       string           `json:"scope,omitempty"`
	Plan        GuidedSearchPlan `json:"plan"`
	Policy      AdaptivePolicy   `json:"policy"`
	Matrix      MatrixResult     `json:"matrix"`
	Applied     bool             `json:"applied"`
	Explanation string           `json:"explanation"`
	CreatedAt   time.Time        `json:"created_at"`
}

func AdaptivePolicyFromRuntimeConfig(cfg config.DiscoveryRuntimeConfig) AdaptivePolicy {
	policy := DefaultAdaptivePolicy()
	if cfg.MaxProbes > 0 {
		policy.MaxProbes = cfg.MaxProbes
	}
	if cfg.MaxConcurrency > 0 {
		policy.MaxConcurrency = cfg.MaxConcurrency
	}
	if cfg.SamplesPerVariant > 0 {
		policy.SamplesPerVariant = cfg.SamplesPerVariant
	}
	if cfg.StableSuccesses > 0 {
		policy.StableSuccesses = cfg.StableSuccesses
	}
	if cfg.MaxShadowProbes > 0 {
		policy.MaxShadowProbes = cfg.MaxShadowProbes
	}
	return policy.normalized()
}

// RunAdaptiveDiscovery preserves the existing FB-24 adaptive/shadow matrix.
// Ordinary adaptive callers may run without a DDI prior. AFS callers pass
// EligibilityCandidates and are hard-gated by RunSynthesizedDiscovery before
// reaching this shared evaluator. Promotion remains external in all cases.
func (r *Runtime) RunAdaptiveDiscovery(ctx context.Context, cfg *config.Config, req AdaptiveRunRequest, runner ProbeRunner) (AdaptiveRunResult, error) {
	var out AdaptiveRunResult
	if r == nil || cfg == nil {
		return out, errors.New("discovery runtime and config are required")
	}
	if ctx == nil {
		return out, errors.New("discovery context is required")
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	if runner == nil {
		return out, errors.New("adaptive probe runner is required")
	}
	if len(req.Targets) == 0 {
		return out, errors.New("adaptive discovery requires bounded target profiles")
	}
	for _, target := range req.Targets {
		if target == "" || len(target) > 64 {
			return out, errors.New("adaptive discovery target profile is empty or too long")
		}
	}
	if err := req.Candidate.Validate(); err != nil {
		return out, fmt.Errorf("adaptive run candidate: %w", err)
	}

	now := time.Now()
	if req.Profile.ProfileID != "" {
		if !req.Profile.Valid(now) {
			return out, errors.New("adaptive run profile is not current compatible")
		}
		req.Profile.Blocking.Scope = req.Profile.Scope
	}
	if req.Prior.Valid() && req.Profile.ProfileID != "" {
		if req.Profile.ProfileID != req.Prior.ProfileID || req.Profile.Scope != req.Prior.Scope {
			return out, errors.New("adaptive run prior is not compatible with current profile")
		}
	}

	eligibility := req.EligibilityCandidates
	targetProfiles := append([]string(nil), req.Targets...)
	if len(eligibility) == 0 {
		eligibility = append([]string(nil), req.Targets...)
	}
	plan := CompileEligiblePlan(req.FailureFamily, req.Authority, req.Prior, eligibility, append([]SearchHint(nil), req.Hints...))
	if !plan.Valid() {
		return out, fmt.Errorf("adaptive guided plan invalid: %s", plan.Explanation)
	}
	if len(req.EligibilityCandidates) == 0 && len(plan.Ordered) > 0 {
		targetProfiles = append([]string(nil), plan.Ordered...)
	}
	if req.Prior.Valid() {
		if !containsCandidate(req.Prior.MandatoryBaselines, "baseline-none") || !containsCandidate(req.Prior.MandatoryBaselines, "baseline-production") {
			return out, errors.New("adaptive discovery prior is missing mandatory baselines")
		}
	}

	baselineProduction := strings.TrimSpace(req.BaselineStrategyID)
	if baselineProduction == "" {
		baselineProduction = "direct"
	}
	policy := AdaptivePolicyFromRuntimeConfig(cfg.System.Classifier.Runtime.Discovery)
	if policy.MaxProbes < 2 {
		return out, errors.New("adaptive run policy leaves no probe budget")
	}
	input := AdaptiveMatrixInput{
		BaselineNone: DiscoveryVariant{
			Mode:          SandboxBaselineNone,
			StrategyID:    "none",
			TargetProfile: targetProfiles[0],
		},
		BaselineProduction: DiscoveryVariant{
			Mode:          SandboxBaselineProduction,
			StrategyID:    baselineProduction,
			TargetProfile: targetProfiles[0],
		},
		Candidate:      req.Candidate,
		Axes:           append([]VariantAxis(nil), req.Axes...),
		TargetProfiles: targetProfiles,
		ShadowVariants: append([]DiscoveryVariant(nil), req.ShadowVariants...),
	}
	if input.Candidate.TargetProfile == "" {
		input.Candidate.TargetProfile = targetProfiles[0]
	}
	matrix, err := RunAdaptiveMatrix(ctx, input, runner, policy)
	if err != nil {
		return out, err
	}

	out = AdaptiveRunResult{
		RunID:       fmt.Sprintf("adaptive/%s/%d", req.Candidate.StrategyID, now.UnixNano()),
		ProfileID:   req.Profile.ProfileID,
		Plan:        plan,
		Policy:      policy,
		Matrix:      matrix,
		Applied:     false,
		Explanation: "adaptive matrix published evidence; winner not applied (canary/runtimecontrol owns promotion)",
		CreatedAt:   now,
	}
	if req.Profile.Scope.Valid() {
		out.Scope = fmt.Sprintf("client=%s/%s target=%s net=%s gen=%d",
			req.Profile.Scope.ClientScope.ID, req.Profile.Scope.ClientScope.Role,
			req.Profile.Scope.TargetRole, req.Profile.Scope.NetworkContextID,
			req.Profile.Scope.ConfigGeneration)
	}
	if req.Prior.Valid() {
		out.Explanation += "; DDI prior ranked the bounded non-baseline search"
	}
	observability.Default().Metrics.Inc(observability.MetricDiscoveryAdaptiveRun, map[string]string{"stop_reason": matrix.StopReason}, 1)
	return out, nil
}
