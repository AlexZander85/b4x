package discovery

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

func testDiscoveryVariant(mode SandboxMode, strategy, target string, complexity uint8) DiscoveryVariant {
	return DiscoveryVariant{Mode: mode, StrategyID: strategy, TargetProfile: target, Complexity: complexity}
}

func testProbeOutcome(target string, verdict DiagnosticVerdict) ProbeOutcome {
	outcome := ProbeOutcome{
		TargetProfile:        target,
		DNSResolved:          true,
		TCPConnected:         true,
		TLSResponseType:      TLSResponseServerHello,
		HTTPHeaders:          true,
		HTTPStatus:           200,
		BodyBytes:            32 << 10,
		BodySuccessThreshold: 32 << 10,
		ThroughputBps:        1 << 20,
		Verdict:              verdict,
	}
	if verdict != DiagnosticAvailable {
		outcome.TCPReset = verdict == DiagnosticDPIRest
		outcome.FailureOffsetKnown = true
		outcome.FailureOffset = outcome.BodyBytes
	}
	return outcome
}

func TestAdaptiveMatrixBaselineCandidateEarlyStop(t *testing.T) {
	fixed := clock.NewFixed(time.Unix(123, 0))
	var mu sync.Mutex
	var calls []string
	runner := func(_ context.Context, variant DiscoveryVariant) ProbeOutcome {
		mu.Lock()
		calls = append(calls, variant.ID())
		mu.Unlock()
		return testProbeOutcome(variant.TargetProfile, DiagnosticAvailable)
	}
	input := AdaptiveMatrixInput{
		BaselineNone:       testDiscoveryVariant(SandboxBaselineNone, "none", "youtube-api", 0),
		BaselineProduction: testDiscoveryVariant(SandboxBaselineProduction, "production", "youtube-api", 1),
		Candidate:          testDiscoveryVariant(SandboxCandidate, "candidate", "youtube-api", 2),
		TargetProfiles:     []string{"youtube-api"},
		Axes:               []VariantAxis{{Dimension: DimensionTLSProfile, Values: []string{"tls13-standard", "tls13-large"}}},
	}
	policy := DefaultAdaptivePolicy()
	policy.Clock = fixed
	policy.StableSuccesses = 1
	policy.MaxConcurrency = 1

	result, err := RunAdaptiveMatrix(context.Background(), input, runner, policy)
	if err != nil {
		t.Fatalf("RunAdaptiveMatrix() error = %v", err)
	}
	if result.StopReason != "stable-candidate" {
		t.Fatalf("unexpected stop reason %q", result.StopReason)
	}
	if len(result.Samples) != 3 {
		t.Fatalf("early stop ran %d samples, want 3", len(result.Samples))
	}
	if result.Samples[0].Variant.Mode != SandboxBaselineNone || result.Samples[1].Variant.Mode != SandboxBaselineProduction || result.Samples[2].Variant.Mode != SandboxCandidate {
		t.Fatalf("baseline ordering was not preserved: %+v", result.Samples)
	}
	for _, sample := range result.Samples {
		if !sample.StartedAt.Equal(fixed.Now()) {
			t.Fatalf("sample timestamp is not controlled by policy clock: %v", sample.StartedAt)
		}
	}
	if len(calls) != 3 {
		t.Fatalf("runner received %d calls after early stop, want 3", len(calls))
	}
}

func TestAdaptiveMatrixOneDimensionSearchAndBoundedShadow(t *testing.T) {
	fixed := clock.NewFixed(time.Unix(456, 0))
	base := testDiscoveryVariant(SandboxCandidate, "candidate", "youtube-video-cdn", 2)
	input := AdaptiveMatrixInput{
		BaselineNone:       testDiscoveryVariant(SandboxBaselineNone, "none", "youtube-video-cdn", 0),
		BaselineProduction: testDiscoveryVariant(SandboxBaselineProduction, "production", "youtube-video-cdn", 1),
		Candidate:          base,
		Axes: []VariantAxis{
			{Dimension: DimensionTLSProfile, Values: []string{"tls13-standard", "tls13-large"}},
			{Dimension: DimensionIPFamily, Values: []string{"ipv4", "ipv6"}},
		},
		ShadowVariants: []DiscoveryVariant{
			{Mode: SandboxCandidate, StrategyID: "candidate", TLSProfileID: "tls13-standard", TargetProfile: base.TargetProfile, Complexity: 99},
			{Mode: SandboxCandidate, StrategyID: "candidate", IPFamily: IPFamilyV4, TargetProfile: base.TargetProfile, Complexity: 99},
			{Mode: SandboxCandidate, StrategyID: "candidate", FakeProfileID: "standard", TargetProfile: base.TargetProfile, Complexity: 99},
		},
	}
	policy := DefaultAdaptivePolicy()
	policy.Clock = fixed
	policy.MaxConcurrency = 2
	policy.MaxProbes = 9
	policy.MaxShadowProbes = 2
	policy.EarlyStop = false

	runner := func(_ context.Context, variant DiscoveryVariant) ProbeOutcome {
		if variant.Complexity == 99 {
			return testProbeOutcome(variant.TargetProfile, DiagnosticAvailable)
		}
		return testProbeOutcome(variant.TargetProfile, DiagnosticDPIRest)
	}
	result, err := RunAdaptiveMatrix(context.Background(), input, runner, policy)
	if err != nil {
		t.Fatalf("RunAdaptiveMatrix() error = %v", err)
	}
	if len(result.Samples) != 7 {
		t.Fatalf("matrix ran %d samples, want baselines + candidate + four one-dimension variants", len(result.Samples))
	}
	if len(result.Shadows) != 2 {
		t.Fatalf("matrix ran %d shadows, want bounded 2", len(result.Shadows))
	}
	if result.StopReason != "probe-budget" {
		t.Fatalf("unexpected stop reason %q", result.StopReason)
	}
	for _, shadow := range result.Shadows {
		if !shadow.Sample.Shadow {
			t.Fatalf("shadow sample was not marked: %+v", shadow)
		}
		if shadow.Dimension == "" {
			t.Fatalf("shadow dimension is empty: %+v", shadow)
		}
		if shadow.CausalVerdict != DiagnosticTLSProfileSpecific && shadow.CausalVerdict != DiagnosticIPFamilySpecific {
			t.Fatalf("shadow contrast did not produce a causal verdict: %+v", shadow)
		}
	}
	for _, sample := range result.Samples[3:] {
		if changedDimensions(base, sample.Variant) != 1 {
			t.Fatalf("variant changed more than one dimension: base=%+v variant=%+v", base, sample.Variant)
		}
	}
}

func TestAdaptiveMatrixSeedAndPolicyBounds(t *testing.T) {
	fixed := clock.NewFixed(time.Unix(789, 0))
	input := AdaptiveMatrixInput{
		BaselineNone:       testDiscoveryVariant(SandboxBaselineNone, "none", "youtube-ui", 0),
		BaselineProduction: testDiscoveryVariant(SandboxBaselineProduction, "production", "youtube-ui", 1),
		Candidate:          testDiscoveryVariant(SandboxCandidate, "candidate", "youtube-ui", 2),
		Axes:               []VariantAxis{{Dimension: DimensionTLSProfile, Values: []string{"z", "a", "m"}}},
	}
	policy := AdaptivePolicy{Seed: 77, MaxProbes: 999999, MaxConcurrency: 999, SamplesPerVariant: 999, MaxShadowProbes: 999, StableSuccesses: 1, EarlyStop: false, Clock: fixed}
	normalized := policy.normalized()
	if normalized.MaxProbes != maxAdaptiveProbes || normalized.MaxConcurrency != maxAdaptiveConcurrency || normalized.SamplesPerVariant != maxAdaptiveSamples || normalized.MaxShadowProbes != maxAdaptiveShadowProbes {
		t.Fatalf("adaptive policy was not bounded: %+v", normalized)
	}
	runner := func(_ context.Context, variant DiscoveryVariant) ProbeOutcome {
		return testProbeOutcome(variant.TargetProfile, DiagnosticAvailable)
	}
	first, err := RunAdaptiveMatrix(context.Background(), input, runner, policy)
	if err != nil {
		t.Fatalf("first matrix error = %v", err)
	}
	second, err := RunAdaptiveMatrix(context.Background(), input, runner, policy)
	if err != nil {
		t.Fatalf("second matrix error = %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("same seed and fake clock were not reproducible:\nfirst=%+v\nsecond=%+v", first, second)
	}
	if len(first.Samples) > maxAdaptiveProbes {
		t.Fatalf("probe budget exceeded: %d", len(first.Samples))
	}
}

func TestAdaptiveMatrixRejectsUnknownDimension(t *testing.T) {
	variant := testDiscoveryVariant(SandboxCandidate, "candidate", "youtube-api", 1)
	input := AdaptiveMatrixInput{
		BaselineNone:       testDiscoveryVariant(SandboxBaselineNone, "none", "youtube-api", 0),
		BaselineProduction: testDiscoveryVariant(SandboxBaselineProduction, "production", "youtube-api", 0),
		Candidate:          variant,
		Axes:               []VariantAxis{{Dimension: VariantDimension("cartesian"), Values: []string{"x"}}},
	}
	_, err := RunAdaptiveMatrix(context.Background(), input, func(context.Context, DiscoveryVariant) ProbeOutcome {
		return testProbeOutcome("youtube-api", DiagnosticAvailable)
	}, DefaultAdaptivePolicy())
	if err == nil || !strings.Contains(err.Error(), "unsupported adaptive axis dimension") {
		t.Fatalf("unknown axis was accepted: %v", err)
	}
}

func changedDimensions(a, b DiscoveryVariant) int {
	changed := 0
	if a.StrategyID != b.StrategyID {
		changed++
	}
	if a.FakeProfileID != b.FakeProfileID {
		changed++
	}
	if a.FakeSNI != b.FakeSNI {
		changed++
	}
	if a.ResolverID != b.ResolverID {
		changed++
	}
	if a.IPFamily != b.IPFamily {
		changed++
	}
	if a.TLSProfileID != b.TLSProfileID {
		changed++
	}
	if a.TargetProfile != b.TargetProfile {
		changed++
	}
	return changed
}

func FuzzDiscoveryVariantValidation(f *testing.F) {
	f.Add("candidate", "youtube-api", "tls13-standard", uint8(1))
	f.Add("", "", strings.Repeat("x", 128), uint8(255))
	f.Fuzz(func(t *testing.T, strategy, target, tls string, family uint8) {
		variant := DiscoveryVariant{StrategyID: strategy, TargetProfile: target, TLSProfileID: tls, IPFamily: IPFamilyMode(string([]byte{family}))}
		_ = variant.Validate()
		_ = variant.ID()
	})
}

func BenchmarkOneDimensionVariants(b *testing.B) {
	base := testDiscoveryVariant(SandboxCandidate, "candidate", "youtube-video-cdn", 2)
	axes := []VariantAxis{
		{Dimension: DimensionTLSProfile, Values: []string{"tls12-compact", "tls13-standard", "tls13-large"}},
		{Dimension: DimensionIPFamily, Values: []string{"auto", "ipv4", "ipv6"}},
		{Dimension: DimensionResolver, Values: []string{"system", "doh"}},
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = oneDimensionVariants(base, axes)
	}
}
