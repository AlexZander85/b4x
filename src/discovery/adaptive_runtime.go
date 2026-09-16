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
	Profile                NetworkDiagnosticProfile
	Prior                  detector.DiscoverySearchPrior
	Targets                []string
	EligibilityCandidates  []string
	FailureFamily          string
	Authority              string
	Hints                   []SearchHint
	BaselineStrategyID      string
	Candidate               DiscoveryVariant
	Axes                    []VariantAxis
	ShadowVariants          []DiscoveryVariant
}

type AdaptiveRunResult struct {
	RunID       string           `json:"run_id"`
	Plan        GuidedSearchPlan `json:"plan"`
	Policy      AdaptivePolicy   `json:"policy"`
	Matrix      MatrixResult     `json:"matrix"`
	Applied     bool             `json:"applied"`
	Explanation string           `json:"explanation"`
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

// RunAdaptiveDiscovery executes the FB-24 adaptive/shadow matrix as the
// production DiscoveryService implementation. It intentionally does not apply
// the resulting candidate: canary/runtimecontrol owns promotion.
func (r *Runtime) RunAdaptiveDiscovery(ctx context.Context, cfg *config.Config, req AdaptiveRunRequest, runner ProbeRunner) (AdaptiveRunResult, error) {
	var out AdaptiveRunResult
	if r == nil || cfg == nil {
		return out, errors.New("discovery runtime and config are required")
	}
	if ctx == nil {
		return out, errors.New("discovery context is required")
	}
	if runner == nil {
		return out, errors.New("adaptive probe runner is required")
	}
	if !req.Profile.Valid(time.Now()) || !req.Prior.Valid() || req.Profile.ProfileID != req.Prior.ProfileID || req.Profile.Scope != req.Prior.Scope {
		return out, errors.New("fresh matching diagnostic profile and DDI prior are required")
	}
	if len(req.Targets) == 0 {
		return out, errors.New("adaptive discovery requires bounded target profiles")
	}
	eligibility := req.EligibilityCandidates
	if len(eligibility) == 0 {
		// Backward compatibility for pre-AFS callers where Targets historically
		// served both roles. New callers should keep endpoint profiles and
		// candidate-family eligibility distinct.
		eligibility = req.Targets
	}
	plan := CompileEligiblePlan(req.FailureFamily, req.Authority, req.Prior, append([]string(nil), eligibility...), append([]SearchHint(nil), req.Hints...))
	if !plan.Valid() {
		return out, fmt.Errorf("adaptive guided plan invalid: %s", plan.Explanation)
	}
	if !containsCandidate(req.Prior.MandatoryBaselines, "baseline-none") || !containsCandidate(req.Prior.MandatoryBaselines, "baseline-production") {
		return out, errors.New("adaptive discovery requires mandatory baseline-none and baseline-production")
	}
	baselineProduction := strings.TrimSpace(req.BaselineStrategyID)
	if baselineProduction == "" {
		baselineProduction = "baseline-production"
	}
	policy := AdaptivePolicyFromRuntimeConfig(cfg.System.Classifier.Runtime.Discovery)
	input := AdaptiveMatrixInput{
		BaselineNone: DiscoveryVariant{
			Mode:          SandboxBaselineNone,
			StrategyID:    "baseline-none",
			TargetProfile: req.Targets[0],
		},
		BaselineProduction: DiscoveryVariant{
			Mode:          SandboxBaselineProduction,
			StrategyID:    baselineProduction,
			TargetProfile: req.Targets[0],
		},
		Candidate:      req.Candidate,
		Axes:           append([]VariantAxis(nil), req.Axes...),
		TargetProfiles: append([]string(nil), req.Targets...),
		ShadowVariants: append([]DiscoveryVariant(nil), req.ShadowVariants...),
	}
	if input.Candidate.TargetProfile == "" {
		input.Candidate.TargetProfile = req.Targets[0]
	}
	matrix, err := RunAdaptiveMatrix(ctx, input, runner, policy)
	if err != nil {
		return out, err
	}
	out = AdaptiveRunResult{
		RunID:       fmt.Sprintf("adaptive-%d", time.Now().UnixNano()),
		Plan:        plan,
		Policy:      policy,
		Matrix:      matrix,
		Applied:     false,
		Explanation: "FB-24 adaptive matrix completed; result is diagnostic-only until ordinary canary/runtimecontrol promotion",
	}
	observability.Default().Metrics.Inc(observability.MetricDiscoveryAdaptiveRun, map[string]string{"stop_reason": matrix.StopReason}, 1)
	return out, nil
}
