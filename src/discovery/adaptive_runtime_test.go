package discovery

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
)

func testRuntimeConfigForDiscovery() config.Config {
	cfg := config.NewConfig()
	dc := cfg.System.Classifier.Runtime.Discovery
	dc.MaxProbes = 32
	dc.MaxConcurrency = 2
	dc.SamplesPerVariant = 1
	dc.StableSuccesses = 2
	dc.MaxShadowProbes = 3
	cfg.System.Classifier.Runtime.Discovery = dc
	return cfg
}

func adaptiveRequest(profile NetworkDiagnosticProfile) AdaptiveRunRequest {
	return AdaptiveRunRequest{
		Profile:            profile,
		Targets:            []string{"youtube-api"},
		FailureFamily:      "dns_interception",
		Authority:          "authoritative-abd",
		BaselineStrategyID: "direct",
		Candidate: DiscoveryVariant{
			Mode:          SandboxCandidate,
			StrategyID:    "candidate",
			TargetProfile: "youtube-api",
			Complexity:    2,
		},
		Axes: []VariantAxis{
			{Dimension: DimensionTLSProfile, Values: []string{"tls13-standard"}},
		},
		ShadowVariants: []DiscoveryVariant{
			{Mode: SandboxCandidate, StrategyID: "candidate", TLSProfileID: "tls13-standard", TargetProfile: "youtube-api", Complexity: 99},
		},
	}
}

func TestRunAdaptiveDiscoveryRootToMatrix(t *testing.T) {
	now := time.Now()
	profile, err := NewNetworkDiagnosticProfile(sampleDDIBlocking(now), now.Add(time.Minute), now)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	cfg := testRuntimeConfigForDiscovery()

	var calls int64
	runner := func(_ context.Context, variant DiscoveryVariant) ProbeOutcome {
		atomic.AddInt64(&calls, 1)
		return testProbeOutcome(variant.TargetProfile, DiagnosticAvailable)
	}

	rt := NewRuntime()
	result, err := rt.RunAdaptiveDiscovery(context.Background(), &cfg, adaptiveRequest(profile), runner)
	if err != nil {
		t.Fatalf("RunAdaptiveDiscovery() error = %v", err)
	}
	if result.Applied {
		t.Fatal("matrix must never apply the winner directly (FB-24 no direct promotion)")
	}
	if result.Matrix.StopReason == "" {
		t.Fatal("matrix has no stop reason")
	}
	if len(result.Matrix.Samples) == 0 {
		t.Fatal("matrix produced no samples")
	}
	if atomic.LoadInt64(&calls) == 0 {
		t.Fatal("runner was never invoked")
	}
	// Mandatory baselines always precede the candidate.
	if len(result.Matrix.Samples) < 2 {
		t.Fatalf("expected two mandatory baselines first, got %d samples", len(result.Matrix.Samples))
	}
	if result.Matrix.Samples[0].Variant.Mode != SandboxBaselineNone || result.Matrix.Samples[1].Variant.Mode != SandboxBaselineProduction {
		t.Fatalf("mandatory baseline order lost: %+v", result.Matrix.Samples)
	}
}

func TestRunAdaptiveDiscoveryBaselineAndShadowBounds(t *testing.T) {
	now := time.Now()
	profile, err := NewNetworkDiagnosticProfile(sampleDDIBlocking(now), now.Add(time.Minute), now)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	base := testDiscoveryVariant(SandboxCandidate, "candidate", "youtube-api", 2)

	runWithShadowBudget := func(maxShadow int) AdaptiveRunResult {
		dc := testRuntimeConfigForDiscovery()
		dc.System.Classifier.Runtime.Discovery.MaxShadowProbes = maxShadow
		req := adaptiveRequest(profile)
		req.Candidate = base
		runner := func(_ context.Context, variant DiscoveryVariant) ProbeOutcome {
			if variant.Complexity == 99 {
				return testProbeOutcome(variant.TargetProfile, DiagnosticAvailable)
			}
			return testProbeOutcome(variant.TargetProfile, DiagnosticDPIRest)
		}
		res, err := NewRuntime().RunAdaptiveDiscovery(context.Background(), &dc, req, runner)
		if err != nil {
			t.Fatalf("RunAdaptiveDiscovery() error = %v", err)
		}
		return res
	}

	small := runWithShadowBudget(1)
	if len(small.Matrix.Shadows) > 1 {
		t.Fatalf("shadow budget 1 violated, got %d", len(small.Matrix.Shadows))
	}
	sized := runWithShadowBudget(3)
	if len(sized.Matrix.Shadows) > 3 {
		t.Fatalf("shadow budget 3 violated, got %d", len(sized.Matrix.Shadows))
	}
}

func TestRunAdaptiveDiscoveryRejectsStaleProfile(t *testing.T) {
	now := time.Now()
	profile, err := NewNetworkDiagnosticProfile(sampleDDIBlocking(now.Add(-time.Hour)), now.Add(-time.Minute), now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	cfg := testRuntimeConfigForDiscovery()
	_, err = NewRuntime().RunAdaptiveDiscovery(context.Background(), &cfg, adaptiveRequest(profile), func(context.Context, DiscoveryVariant) ProbeOutcome {
		return testProbeOutcome("youtube-api", DiagnosticAvailable)
	})
	if err == nil || !strings.Contains(err.Error(), "not current compatible") {
		t.Fatalf("stale profile was accepted: %v", err)
	}
}

func TestRunAdaptiveDiscoveryCancellation(t *testing.T) {
	now := time.Now()
	profile, err := NewNetworkDiagnosticProfile(sampleDDIBlocking(now), now.Add(time.Minute), now)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	cfg := testRuntimeConfigForDiscovery()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // canceled before start
	_, err = NewRuntime().RunAdaptiveDiscovery(ctx, &cfg, adaptiveRequest(profile), func(context.Context, DiscoveryVariant) ProbeOutcome {
		return testProbeOutcome("youtube-api", DiagnosticAvailable)
	})
	if err == nil {
		t.Fatal("canceled context was accepted")
	}
}

func TestRunAdaptiveDiscoveryNoDirectPromotion(t *testing.T) {
	now := time.Now()
	profile, err := NewNetworkDiagnosticProfile(sampleDDIBlocking(now), now.Add(time.Minute), now)
	if err != nil {
		t.Fatalf("profile: %v", err)
	}
	cfg := testRuntimeConfigForDiscovery()
	result, err := NewRuntime().RunAdaptiveDiscovery(context.Background(), &cfg, adaptiveRequest(profile), func(_ context.Context, _ DiscoveryVariant) ProbeOutcome {
		return testProbeOutcome("youtube-api", DiagnosticAvailable)
	})
	if err != nil {
		t.Fatalf("RunAdaptiveDiscovery() error = %v", err)
	}
	if result.Applied {
		t.Fatal("matrix must not promote directly")
	}
	// MatrixResult must not contain any promotion/apply state.
	if result.Matrix.Best == nil {
		t.Fatal("expected a best candidate")
	}
}
