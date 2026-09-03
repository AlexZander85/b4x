package discovery

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/observability"
)

const (
	maxAdaptiveProbes       = 256
	maxAdaptiveConcurrency  = 8
	maxAdaptiveSamples      = 8
	maxAdaptiveShadowProbes = 16
)

type IPFamilyMode string

const (
	IPFamilyAuto IPFamilyMode = "auto"
	IPFamilyV4   IPFamilyMode = "ipv4"
	IPFamilyV6   IPFamilyMode = "ipv6"
)

type VariantDimension string

const (
	DimensionStrategy    VariantDimension = "strategy"
	DimensionFakeProfile VariantDimension = "fake_profile"
	DimensionFakeSNI     VariantDimension = "fake_sni"
	DimensionResolver    VariantDimension = "resolver"
	DimensionIPFamily    VariantDimension = "ip_family"
	DimensionTLSProfile  VariantDimension = "tls_profile"
	DimensionTarget      VariantDimension = "target_profile"
)

type DiscoveryVariant struct {
	Mode          SandboxMode  `json:"mode"`
	StrategyID    string       `json:"strategy_id"`
	FakeProfileID string       `json:"fake_profile_id,omitempty"`
	FakeSNI       string       `json:"fake_sni,omitempty"`
	ResolverID    string       `json:"resolver_id,omitempty"`
	IPFamily      IPFamilyMode `json:"ip_family,omitempty"`
	TLSProfileID  string       `json:"tls_profile_id,omitempty"`
	TargetProfile string       `json:"target_profile"`
	Complexity    uint8        `json:"complexity"`
}

func (v DiscoveryVariant) Validate() error {
	if len(v.StrategyID) == 0 || len(v.StrategyID) > 64 || len(v.TargetProfile) == 0 || len(v.TargetProfile) > 64 {
		return errors.New("discovery variant strategy and target profile are required and bounded")
	}
	if v.Mode != "" && v.Mode != SandboxBaselineNone && v.Mode != SandboxBaselineProduction && v.Mode != SandboxCandidate {
		return fmt.Errorf("unsupported discovery variant mode %q", v.Mode)
	}
	for name, value := range map[string]string{"fake_profile": v.FakeProfileID, "fake_sni": v.FakeSNI, "resolver": v.ResolverID, "tls_profile": v.TLSProfileID} {
		if len(value) > 128 {
			return fmt.Errorf("discovery variant %s is too long", name)
		}
	}
	switch v.IPFamily {
	case "", IPFamilyAuto, IPFamilyV4, IPFamilyV6:
	default:
		return fmt.Errorf("unsupported IP family %q", v.IPFamily)
	}
	return nil
}

func (v DiscoveryVariant) ID() string {
	return strings.Join([]string{
		string(v.Mode), v.StrategyID, v.FakeProfileID, v.FakeSNI, v.ResolverID,
		string(v.IPFamily), v.TLSProfileID, v.TargetProfile,
	}, "|")
}

type VariantAxis struct {
	Dimension VariantDimension `json:"dimension"`
	Values    []string         `json:"values"`
}

type AdaptiveMatrixInput struct {
	BaselineNone       DiscoveryVariant
	BaselineProduction DiscoveryVariant
	Candidate          DiscoveryVariant
	Axes               []VariantAxis
	TargetProfiles     []string
	ShadowVariants     []DiscoveryVariant
}

type AdaptivePolicy struct {
	Seed              int64
	MaxProbes         int
	MaxConcurrency    int
	SamplesPerVariant int
	StableSuccesses   int
	MaxShadowProbes   int
	EarlyStop         bool
	Weights           ScoreWeights
	Clock             clock.Clock
}

func DefaultAdaptivePolicy() AdaptivePolicy {
	return AdaptivePolicy{Seed: 23, MaxProbes: 32, MaxConcurrency: 2, SamplesPerVariant: 1, StableSuccesses: 2, MaxShadowProbes: 3, EarlyStop: true, Weights: DefaultScoreWeights(), Clock: clock.RealClock{}}
}

func (p AdaptivePolicy) normalized() AdaptivePolicy {
	d := DefaultAdaptivePolicy()
	if p.MaxProbes <= 0 {
		p.MaxProbes = d.MaxProbes
	}
	if p.MaxProbes > maxAdaptiveProbes {
		p.MaxProbes = maxAdaptiveProbes
	}
	if p.MaxConcurrency <= 0 {
		p.MaxConcurrency = d.MaxConcurrency
	}
	if p.MaxConcurrency > maxAdaptiveConcurrency {
		p.MaxConcurrency = maxAdaptiveConcurrency
	}
	if p.SamplesPerVariant <= 0 {
		p.SamplesPerVariant = d.SamplesPerVariant
	}
	if p.SamplesPerVariant > maxAdaptiveSamples {
		p.SamplesPerVariant = maxAdaptiveSamples
	}
	if p.StableSuccesses <= 0 {
		p.StableSuccesses = d.StableSuccesses
	}
	if p.MaxShadowProbes <= 0 {
		p.MaxShadowProbes = d.MaxShadowProbes
	}
	if p.MaxShadowProbes > maxAdaptiveShadowProbes {
		p.MaxShadowProbes = maxAdaptiveShadowProbes
	}
	if p.Weights == (ScoreWeights{}) {
		p.Weights = d.Weights
	}
	if p.Clock == nil {
		p.Clock = d.Clock
	}
	return p
}

type ScoreWeights struct {
	Success        float64
	Body           float64
	Throughput     float64
	LatencyPenalty float64
	RetryPenalty   float64
	Amplification  float64
	CPU            float64
	Complexity     float64
	FailurePenalty float64
}

func DefaultScoreWeights() ScoreWeights {
	return ScoreWeights{Success: 100, Body: 25, Throughput: 20, LatencyPenalty: 0.01, RetryPenalty: 4, Amplification: 5, CPU: 0.001, Complexity: 1, FailurePenalty: 20}
}

func ScoreOutcome(outcome ProbeOutcome, complexity uint8, weights ScoreWeights) float64 {
	if weights == (ScoreWeights{}) {
		weights = DefaultScoreWeights()
	}
	score := -float64(complexity) * weights.Complexity
	if outcome.Verdict == DiagnosticAvailable {
		score += weights.Success
	} else if outcome.TLSResponseType != TLSResponseNone {
		score += weights.Success * 0.2
		score -= weights.FailurePenalty
	}
	threshold := outcome.BodySuccessThreshold
	if threshold <= 0 {
		threshold = 32 << 10
	}
	bodyRatio := float64(outcome.BodyBytes) / float64(threshold)
	if bodyRatio > 1 {
		bodyRatio = 1
	}
	if bodyRatio > 0 {
		score += bodyRatio * weights.Body
	}
	if outcome.ThroughputBps > 0 {
		throughputRatio := float64(outcome.ThroughputBps) / float64(threshold)
		if throughputRatio > 1 {
			throughputRatio = 1
		}
		score += throughputRatio * weights.Throughput
	}
	score -= float64(outcome.TTFB.Milliseconds()) * weights.LatencyPenalty
	score -= float64(outcome.Retransmissions+outcome.FlowRetries) * weights.RetryPenalty
	if outcome.PacketAmplification > 1 {
		score -= (outcome.PacketAmplification - 1) * weights.Amplification
	}
	score -= float64(outcome.CPUTime.Microseconds()) * weights.CPU
	return score
}

type MatrixSample struct {
	Variant   DiscoveryVariant `json:"variant"`
	Attempt   int              `json:"attempt"`
	Outcome   ProbeOutcome     `json:"outcome"`
	Score     float64          `json:"score"`
	Shadow    bool             `json:"shadow"`
	StartedAt time.Time        `json:"started_at"`
}

type ShadowSample struct {
	Dimension     VariantDimension  `json:"dimension"`
	Sample        MatrixSample      `json:"sample"`
	BaseVerdict   DiagnosticVerdict `json:"base_verdict"`
	CausalVerdict DiagnosticVerdict `json:"causal_verdict"`
}

type MatrixResult struct {
	Seed       int64          `json:"seed"`
	Samples    []MatrixSample `json:"samples"`
	Shadows    []ShadowSample `json:"shadows,omitempty"`
	Best       *MatrixSample  `json:"best,omitempty"`
	StopReason string         `json:"stop_reason"`
}

type ProbeRunner func(context.Context, DiscoveryVariant) ProbeOutcome

func RunAdaptiveMatrix(ctx context.Context, input AdaptiveMatrixInput, runner ProbeRunner, policy AdaptivePolicy) (MatrixResult, error) {
	if runner == nil {
		return MatrixResult{}, errors.New("adaptive matrix probe runner is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	policy = policy.normalized()
	if err := validateMatrixInput(input); err != nil {
		return MatrixResult{}, err
	}
	result := MatrixResult{Seed: policy.Seed, Samples: make([]MatrixSample, 0, policy.MaxProbes), Shadows: make([]ShadowSample, 0, policy.MaxShadowProbes)}
	probes := 0
	appendSamples := func(samples []MatrixSample) {
		for _, sample := range samples {
			if probes >= policy.MaxProbes {
				return
			}
			result.Samples = append(result.Samples, sample)
			probes++
			if result.Best == nil || betterSample(sample, *result.Best) {
				copy := sample
				result.Best = &copy
			}
		}
	}

	// The two baselines are deliberately serialized and always precede any
	// candidate. This makes causal comparisons reproducible and keeps the
	// cheapest diagnostic path first.
	for _, baseline := range []DiscoveryVariant{input.BaselineNone, input.BaselineProduction} {
		if probes >= policy.MaxProbes {
			break
		}
		samples := runVariantBatch(ctx, []DiscoveryVariant{baseline}, policy.SamplesPerVariant, policy, runner, probes)
		appendSamples(samples)
	}

	candidate := input.Candidate
	targets := input.TargetProfiles
	if len(targets) == 0 {
		targets = []string{candidate.TargetProfile}
	}
	for _, target := range targets {
		if probes >= policy.MaxProbes {
			break
		}
		variant := candidate
		variant.TargetProfile = target
		samples := runVariantBatch(ctx, []DiscoveryVariant{variant}, policy.SamplesPerVariant, policy, runner, probes)
		appendSamples(samples)
		if policy.EarlyStop && stableAcrossTarget(result.Samples, candidate.StrategyID, targets, policy.StableSuccesses) {
			result.StopReason = "stable-candidate"
			return finishMatrix(result)
		}
	}

	variants := oneDimensionVariants(candidate, input.Axes)
	if len(variants) > 0 && probes < policy.MaxProbes {
		samples := runVariantBatch(ctx, variants, policy.SamplesPerVariant, policy, runner, probes)
		appendSamples(samples)
	}
	if len(result.Shadows) < policy.MaxShadowProbes {
		base := candidate
		if result.Best != nil {
			base = result.Best.Variant
		}
		for _, shadow := range input.ShadowVariants {
			if len(result.Shadows) >= policy.MaxShadowProbes || probes >= policy.MaxProbes {
				break
			}
			if !needsShadow(result.Samples, base) {
				break
			}
			sample := runVariantBatch(ctx, []DiscoveryVariant{shadow}, 1, policy, runner, probes)
			if len(sample) == 0 {
				break
			}
			probes++
			sample[0].Shadow = true
			dimension := shadowDimension(base, shadow)
			baseOutcome := outcomeForVariant(result.Samples, base)
			result.Shadows = append(result.Shadows, ShadowSample{
				Dimension:     dimension,
				Sample:        sample[0],
				BaseVerdict:   baseOutcome.Verdict,
				CausalVerdict: causalShadowVerdict(baseOutcome.Verdict, sample[0].Outcome.Verdict, dimension),
			})
		}
	}
	if result.StopReason == "" {
		if probes >= policy.MaxProbes {
			result.StopReason = "probe-budget"
		} else {
			result.StopReason = "matrix-exhausted"
		}
	}
	return finishMatrix(result)
}

func validateMatrixInput(input AdaptiveMatrixInput) error {
	for _, variant := range []DiscoveryVariant{input.BaselineNone, input.BaselineProduction, input.Candidate} {
		if err := variant.Validate(); err != nil {
			return err
		}
	}
	if len(input.Axes) > 7 || len(input.ShadowVariants) > 32 || len(input.TargetProfiles) > 16 {
		return errors.New("adaptive matrix input exceeds bounded dimensions")
	}
	for _, axis := range input.Axes {
		if !validVariantDimension(axis.Dimension) {
			return fmt.Errorf("unsupported adaptive axis dimension %q", axis.Dimension)
		}
		if len(axis.Values) == 0 || len(axis.Values) > 16 {
			return fmt.Errorf("adaptive axis %s is empty or too large", axis.Dimension)
		}
		for _, value := range axis.Values {
			if len(value) == 0 || len(value) > 128 {
				return fmt.Errorf("adaptive axis %s contains an unbounded value", axis.Dimension)
			}
		}
	}
	for _, target := range input.TargetProfiles {
		if len(target) == 0 || len(target) > 64 {
			return errors.New("adaptive target profile is empty or too long")
		}
	}
	for _, variant := range input.ShadowVariants {
		if err := variant.Validate(); err != nil {
			return fmt.Errorf("shadow variant: %w", err)
		}
	}
	return nil
}

func oneDimensionVariants(base DiscoveryVariant, axes []VariantAxis) []DiscoveryVariant {
	ordered := append([]VariantAxis(nil), axes...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Dimension < ordered[j].Dimension })
	variants := make([]DiscoveryVariant, 0, len(ordered)*2)
	seen := make(map[string]struct{})
	for _, axis := range ordered {
		values := append([]string(nil), axis.Values...)
		sort.Strings(values)
		for _, value := range values {
			variant := replaceDimension(base, axis.Dimension, value)
			if variant.ID() == base.ID() {
				continue
			}
			if _, exists := seen[variant.ID()]; exists {
				continue
			}
			seen[variant.ID()] = struct{}{}
			variants = append(variants, variant)
		}
	}
	return variants
}

func replaceDimension(v DiscoveryVariant, dimension VariantDimension, value string) DiscoveryVariant {
	switch dimension {
	case DimensionStrategy:
		v.StrategyID = value
	case DimensionFakeProfile:
		v.FakeProfileID = value
	case DimensionFakeSNI:
		v.FakeSNI = value
	case DimensionResolver:
		v.ResolverID = value
	case DimensionIPFamily:
		v.IPFamily = IPFamilyMode(value)
	case DimensionTLSProfile:
		v.TLSProfileID = value
	case DimensionTarget:
		v.TargetProfile = value
	}
	return v
}

func validVariantDimension(dimension VariantDimension) bool {
	switch dimension {
	case DimensionStrategy, DimensionFakeProfile, DimensionFakeSNI, DimensionResolver,
		DimensionIPFamily, DimensionTLSProfile, DimensionTarget:
		return true
	default:
		return false
	}
}

func runVariantBatch(ctx context.Context, variants []DiscoveryVariant, attempts int, policy AdaptivePolicy, runner ProbeRunner, offset int) []MatrixSample {
	if len(variants) == 0 || attempts <= 0 || offset >= policy.MaxProbes {
		return nil
	}
	remaining := policy.MaxProbes - offset
	jobs := make(chan struct {
		variant DiscoveryVariant
		attempt int
	}, minInt(len(variants)*attempts, remaining))
	results := make(chan MatrixSample, minInt(len(variants)*attempts, remaining))
	ordered := append([]DiscoveryVariant(nil), variants...)
	sort.SliceStable(ordered, func(i, j int) bool {
		left, right := seededVariantRank(policy.Seed, ordered[i].ID()), seededVariantRank(policy.Seed, ordered[j].ID())
		if left != right {
			return left < right
		}
		return ordered[i].ID() < ordered[j].ID()
	})
	queued := 0
	for _, variant := range ordered {
		for attempt := 1; attempt <= attempts; attempt++ {
			if queued >= remaining {
				break
			}
			jobs <- struct {
				variant DiscoveryVariant
				attempt int
			}{variant, attempt}
			queued++
		}
		if queued >= remaining {
			break
		}
	}
	close(jobs)
	workerCount := policy.MaxConcurrency
	if workerCount > len(variants)*attempts {
		workerCount = len(variants) * attempts
	}
	if workerCount < 1 {
		return nil
	}
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if err := ctx.Err(); err != nil {
					return
				}
				started := policy.Clock.Now()
				outcome := runner(ctx, job.variant)
				results <- MatrixSample{Variant: job.variant, Attempt: job.attempt, Outcome: outcome, Score: ScoreOutcome(outcome, job.variant.Complexity, policy.Weights), StartedAt: started}
			}
		}()
	}
	wg.Wait()
	close(results)
	out := make([]MatrixSample, 0, len(results))
	for sample := range results {
		out = append(out, sample)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Variant.ID() == out[j].Variant.ID() {
			return out[i].Attempt < out[j].Attempt
		}
		return out[i].Variant.ID() < out[j].Variant.ID()
	})
	return out
}

func seededVariantRank(seed int64, id string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(strconv.FormatInt(seed, 10)))
	_, _ = h.Write([]byte{0})
	_, _ = h.Write([]byte(id))
	return h.Sum64()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func stableAcrossTarget(samples []MatrixSample, strategy string, targets []string, stable int) bool {
	if stable <= 0 {
		return false
	}
	counts := make(map[string]int)
	for _, sample := range samples {
		if sample.Variant.StrategyID == strategy && sample.Outcome.Verdict == DiagnosticAvailable {
			counts[sample.Variant.TargetProfile]++
		}
	}
	for _, target := range targets {
		if counts[target] < stable {
			return false
		}
	}
	return true
}

func needsShadow(samples []MatrixSample, base DiscoveryVariant) bool {
	for _, sample := range samples {
		if sample.Variant.ID() != base.ID() {
			continue
		}
		switch sample.Outcome.Verdict {
		case DiagnosticDPIRest, DiagnosticDPIDrop, DiagnosticIPBlockSuspected, DiagnosticThrottled:
			return true
		}
	}
	return false
}

func outcomeForVariant(samples []MatrixSample, variant DiscoveryVariant) ProbeOutcome {
	for _, sample := range samples {
		if sample.Variant.ID() == variant.ID() {
			return sample.Outcome
		}
	}
	return ProbeOutcome{Verdict: DiagnosticClassifierUnresolved}
}

func causalShadowVerdict(base, shadow DiagnosticVerdict, dimension VariantDimension) DiagnosticVerdict {
	if shadow != DiagnosticAvailable || base == DiagnosticAvailable {
		return DiagnosticClassifierUnresolved
	}
	switch dimension {
	case DimensionTLSProfile:
		return DiagnosticTLSProfileSpecific
	case DimensionResolver:
		return DiagnosticResolverSpecific
	case DimensionIPFamily:
		return DiagnosticIPFamilySpecific
	default:
		return DiagnosticClassifierUnresolved
	}
}

func shadowDimension(base, shadow DiscoveryVariant) VariantDimension {
	if base.TLSProfileID != shadow.TLSProfileID {
		return DimensionTLSProfile
	}
	if base.IPFamily != shadow.IPFamily {
		return DimensionIPFamily
	}
	if base.ResolverID != shadow.ResolverID {
		return DimensionResolver
	}
	if base.FakeProfileID != shadow.FakeProfileID {
		return DimensionFakeProfile
	}
	if base.FakeSNI != shadow.FakeSNI {
		return DimensionFakeSNI
	}
	return DimensionStrategy
}

func betterSample(a, b MatrixSample) bool {
	if a.Score != b.Score {
		return a.Score > b.Score
	}
	if a.Outcome.Verdict == DiagnosticAvailable && b.Outcome.Verdict != DiagnosticAvailable {
		return true
	}
	if a.Variant.Complexity != b.Variant.Complexity {
		return a.Variant.Complexity < b.Variant.Complexity
	}
	return a.Variant.ID() < b.Variant.ID()
}

func finishMatrix(result MatrixResult) (MatrixResult, error) {
	if len(result.Samples) == 0 {
		return result, errors.New("adaptive matrix produced no probe samples")
	}
	labels := map[string]string{"stop_reason": result.StopReason}
	observability.Default().Trace.Record(observability.TraceEvent{Kind: "discovery_matrix", Fields: map[string]string{"seed": strconv.FormatInt(result.Seed, 10), "samples": strconv.Itoa(len(result.Samples)), "stop_reason": result.StopReason}})
	observability.Default().Metrics.Inc(observability.MetricDiscoveryProbe, labels, uint64(len(result.Samples)))
	for _, shadow := range result.Shadows {
		observability.Default().Metrics.Inc(observability.MetricDiscoveryShadowProbe, map[string]string{"dimension": string(shadow.Dimension), "causal_verdict": string(shadow.CausalVerdict)}, 1)
	}
	return result, nil
}
