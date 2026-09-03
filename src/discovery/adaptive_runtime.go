package discovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/log"
)

// AdaptiveRunRequest is the production entry input for the adaptive matrix
// on the registered Discovery runtime. It carries the current compatible
// blocking profile/prior (ABD/DDI output) and the bounded candidate family.
//
// FB-24 invariants (see B4X_AUDIT_FIX_TASKS):
//   - the prior is used for ordering/budget only; it can never add or
//     remove candidates (FB-05 semantics, shared with CompileEligiblePlan);
//   - mandatory baselines and the full fallback family are retained;
//   - the matrix never applies the winner directly (no promotion here).
type AdaptiveRunRequest struct {
	// Profile is the current compatible blocking profile (signed-ready,
	// fresh). Optional: when zero, the matrix runs without a prior but the
	// mandatory baselines are still enforced.
	Profile NetworkDiagnosticProfile
	// Prior is the detector search prior derived from the profile. Optional:
	// used only for ranking/budget of the non-baseline extension.
	Prior detector.DiscoverySearchPrior
	// Targets are the candidate target profiles (domains/families) to
	// evaluate. The baseline prefix always stays first and complete.
	Targets []string
	// FailureFamily and Authority drive the FB-31 causal eligibility gate.
	FailureFamily string
	Authority     string
	// Hints are optional provenanced search hints (boost/penalty/defer).
	Hints []SearchHint
	// BaselineStrategyID is the strategy used for the mandatory
	// baseline-production variant. Empty means "direct" (passive default).
	BaselineStrategyID string
	// Candidate is the adaptive candidate variant explored after the two
	// mandatory baselines.
	Candidate DiscoveryVariant
	// Axes are the one-dimension search axes (TLS profile, IP family,
	// resolver, ...). Bounded by validateMatrixInput.
	Axes []VariantAxis
	// ShadowVariants are the causal shadow probes; bounded by the policy
	// MaxShadowProbes budget.
	ShadowVariants []DiscoveryVariant
}

func (r AdaptiveRunRequest) validate() error {
	if len(r.Targets) == 0 {
		return errors.New("adaptive run requires at least one target")
	}
	for _, target := range r.Targets {
		if len(target) == 0 || len(target) > 64 {
			return errors.New("adaptive run target is empty or too long")
		}
	}
	if r.Candidate.StrategyID == "" {
		return errors.New("adaptive run candidate strategy is required")
	}
	if len(r.BaselineStrategyID) == 0 {
		r.BaselineStrategyID = "direct"
	}
	if err := r.Candidate.Validate(); err != nil {
		return fmt.Errorf("adaptive run candidate: %w", err)
	}
	return nil
}

// AdaptiveRunResult is the production matrix outcome. Applied is always
// false: the matrix only publishes evidence and a winner candidate; actual
// promotion is handled by canary/runtimecontrol outside this package.
type AdaptiveRunResult struct {
	RunID       string         `json:"run_id"`
	ProfileID   string         `json:"profile_id,omitempty"`
	Scope       string         `json:"scope,omitempty"`
	Matrix      MatrixResult   `json:"matrix"`
	Policy      AdaptivePolicy `json:"policy"`
	Applied     bool           `json:"applied"`
	Explanation string         `json:"explanation"`
	CreatedAt   time.Time      `json:"created_at"`
}

// AdaptivePolicyFromRuntimeConfig maps the persisted discovery runtime
// config into the bounded adaptive matrix policy. This is the single
// production consumption point for MaxProbes/MaxConcurrency/
// SamplesPerVariant/StableSuccesses/MaxShadowProbes: the matrix engine
// receives its budgets from the config, and AdaptivePolicy.normalized()
// enforces the absolute bounds (maxAdaptiveProbes, maxAdaptiveConcurrency,
// maxAdaptiveSamples, maxAdaptiveShadowProbes).
func AdaptivePolicyFromRuntimeConfig(dc config.DiscoveryRuntimeConfig) AdaptivePolicy {
	p := DefaultAdaptivePolicy()
	if dc.MaxProbes > 0 {
		p.MaxProbes = dc.MaxProbes
	}
	if dc.MaxConcurrency > 0 {
		p.MaxConcurrency = dc.MaxConcurrency
	}
	if dc.SamplesPerVariant > 0 {
		p.SamplesPerVariant = dc.SamplesPerVariant
	}
	if dc.StableSuccesses > 0 {
		p.StableSuccesses = dc.StableSuccesses
	}
	if dc.MaxShadowProbes > 0 {
		p.MaxShadowProbes = dc.MaxShadowProbes
	}
	p.Clock = clock.RealClock{}
	return p.normalized()
}

// RunAdaptiveDiscovery is the production controller entry: it consumes the
// current compatible blocking profile/prior, retains the mandatory baselines
// and the full fallback family, applies the bounded policy from config, and
// runs the adaptive matrix with the provided probe runner. The winner is
// never applied here (FB-24: no direct promotion; canary/runtimecontrol
// owns promotion).
//
// The runner is injected by the caller (tests, HTTP API, monitoring chain).
// It must be bounded itself; the matrix additionally caps concurrency,
// total probes, samples per variant and shadow probes.
func (m *Runtime) RunAdaptiveDiscovery(ctx context.Context, cfg *config.Config, req AdaptiveRunRequest, runner ProbeRunner) (AdaptiveRunResult, error) {
	if m == nil {
		return AdaptiveRunResult{}, errors.New("discovery runtime is nil")
	}
	if cfg == nil {
		return AdaptiveRunResult{}, errors.New("discovery config is nil")
	}
	if runner == nil {
		return AdaptiveRunResult{}, errors.New("adaptive probe runner is nil")
	}
	if ctx == nil {
		return AdaptiveRunResult{}, errors.New("adaptive run context is nil")
	}
	if err := req.validate(); err != nil {
		return AdaptiveRunResult{}, err
	}

	now := time.Now()
	if req.Profile.ProfileID != "" {
		if !req.Profile.Valid(now) {
			return AdaptiveRunResult{}, errors.New("adaptive run profile is not current compatible")
		}
		req.Profile.Blocking.Scope = req.Profile.Scope
	}

	// FB-31 eligibility gate + FB-05 prior ordering: mandatory narrower
	// families and the current baseline stay; the prior only reorders the
	// non-baseline extension and never removes candidates.
	plan := CompileEligiblePlan(req.FailureFamily, req.Authority, req.Prior, req.Targets, req.Hints)
	if len(plan.Baseline) == 0 {
		return AdaptiveRunResult{}, errors.New("adaptive run: " + plan.Explanation)
	}
	targets := plan.Ordered
	if len(targets) == 0 {
		targets = append([]string(nil), req.Targets...)
	}

	policy := AdaptivePolicyFromRuntimeConfig(cfg.System.Classifier.Runtime.Discovery)
	if policy.MaxProbes < 2 {
		return AdaptiveRunResult{}, errors.New("adaptive run policy leaves no probe budget")
	}

	baselineNone := DiscoveryVariant{
		Mode:          SandboxBaselineNone,
		StrategyID:    "none",
		TargetProfile: targets[0],
	}
	baselineProduction := DiscoveryVariant{
		Mode:          SandboxBaselineProduction,
		StrategyID:    req.BaselineStrategyID,
		TargetProfile: targets[0],
	}
	if baselineProduction.StrategyID == "" {
		baselineProduction.StrategyID = "direct"
	}

	input := AdaptiveMatrixInput{
		BaselineNone:       baselineNone,
		BaselineProduction: baselineProduction,
		Candidate:          req.Candidate,
		TargetProfiles:     targets,
		Axes:               req.Axes,
		ShadowVariants:     req.ShadowVariants,
	}
	if input.Candidate.TargetProfile == "" {
		input.Candidate.TargetProfile = targets[0]
	}

	result, err := RunAdaptiveMatrix(ctx, input, runner, policy)
	if err != nil {
		return AdaptiveRunResult{}, err
	}

	runID := fmt.Sprintf("adaptive/%s/%d", req.Candidate.StrategyID, now.UnixNano())
	explanation := "adaptive matrix published evidence; winner not applied (canary/runtimecontrol owns promotion)"
	if req.Profile.ProfileID != "" {
		explanation += "; profile " + req.Profile.ProfileID
	}
	if req.Prior.Valid() {
		explanation += "; prior ranked non-baseline extension only"
	}

	out := AdaptiveRunResult{
		RunID:       runID,
		ProfileID:   req.Profile.ProfileID,
		Matrix:      result,
		Policy:      policy,
		Applied:     false,
		Explanation: explanation,
		CreatedAt:   now,
	}
	if req.Profile.Scope.Valid() {
		out.Scope = fmt.Sprintf("client=%s/%s target=%s net=%s gen=%d",
			req.Profile.Scope.ClientScope.ID, req.Profile.Scope.ClientScope.Role,
			req.Profile.Scope.TargetRole, req.Profile.Scope.NetworkContextID,
			req.Profile.Scope.ConfigGeneration)
	}

	log.Infof("Adaptive discovery %s: %d samples, %d shadows, stop=%s, applied=false",
		runID, len(result.Samples), len(result.Shadows), result.StopReason)
	return out, nil
}
