package config

import (
	"testing"
)

func TestLegacyConfigGetsPassiveClassifierDefaults(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier = ClassifierConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.System.Classifier.SchemaVersion != ClassifierSchemaV23 {
		t.Fatalf("schema version = %d, want %d", cfg.System.Classifier.SchemaVersion, ClassifierSchemaV23)
	}
	if cfg.System.Classifier.DomainOnlyMode != DomainOnlyLegacy {
		t.Fatalf("DomainOnly mode = %q, want %q", cfg.System.Classifier.DomainOnlyMode, DomainOnlyLegacy)
	}
	if cfg.System.Classifier.Flags.TCPReassemblyMode != ReassemblyOff {
		t.Fatalf("reassembly mode = %q, want %q", cfg.System.Classifier.Flags.TCPReassemblyMode, ReassemblyOff)
	}
	if cfg.System.Classifier.Flags.TCPHoldReplayMode != HoldReplayOff {
		t.Fatalf("hold/replay mode = %q, want %q", cfg.System.Classifier.Flags.TCPHoldReplayMode, HoldReplayOff)
	}
	if cfg.System.Classifier.Flags.ClassifierV2Enabled || cfg.System.Classifier.Flags.CaptureEnvelopeEnabled {
		t.Fatal("legacy defaults must not enable runtime classifier/capture")
	}
	if cfg.System.Classifier.Runtime.SilentPath.Enabled || cfg.System.Classifier.Runtime.SilentPath.Mode != SilentPathFailureObserve {
		t.Fatalf("silent-path must remain disabled/observe by default: %+v", cfg.System.Classifier.Runtime.SilentPath)
	}
}

func TestClassifierValidationRejectsUnsupportedModes(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Flags.TCPReassemblyMode = "active"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unsupported reassembly mode error")
	}

	cfg = NewConfig()
	cfg.System.Classifier.DomainOnlyMode = "v2"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected unsupported DomainOnly mode error")
	}

	for _, mode := range []string{DomainStrict, DomainScopedHints, DomainLegacy, DomainDisabled} {
		cfg = NewConfig()
		cfg.System.Classifier.DomainOnlyMode = mode
		if err := cfg.Validate(); err != nil {
			t.Fatalf("DomainOnly mode %q rejected: %v", mode, err)
		}
	}

	for _, mode := range []string{HoldReplayOff, HoldReplayObserve, HoldReplayAuto, HoldReplayDebug} {
		cfg = NewConfig()
		cfg.System.Classifier.Flags.TCPHoldReplayMode = mode
		if err := cfg.Validate(); err != nil {
			t.Fatalf("hold/replay mode %q rejected: %v", mode, err)
		}
	}

	cfg = NewConfig()
	cfg.System.Classifier.Flags.TCPHoldReplayMode = ""
	cfg.System.Classifier.Flags.AutoHoldReplayEnabled = true
	if err := cfg.Validate(); err != nil {
		t.Fatalf("legacy auto hold/replay config rejected: %v", err)
	}
	if cfg.System.Classifier.Flags.TCPHoldReplayMode != HoldReplayAuto {
		t.Fatalf("legacy auto hold/replay migration = %q", cfg.System.Classifier.Flags.TCPHoldReplayMode)
	}
}

func TestRuntimeGenerationLifecycle(t *testing.T) {
	cfg := NewConfig()
	first := cfg.EnsureRuntimeGeneration()
	if first == "" || first != cfg.EnsureRuntimeGeneration() {
		t.Fatalf("generation is not stable: %q", first)
	}

	clone := cfg.Clone()
	if clone.RuntimeGeneration != first {
		t.Fatalf("Clone changed generation: got %q want %q", clone.RuntimeGeneration, first)
	}
	updated := cfg.CloneForRuntimeUpdate()
	if updated.RuntimeGeneration == "" || updated.RuntimeGeneration == first {
		t.Fatalf("runtime update did not create a new generation: %q", updated.RuntimeGeneration)
	}
}

func TestClassifierV23RuntimeDefaultsAndSafety(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Runtime = ClassifierRuntimeConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate defaults: %v", err)
	}
	r := cfg.System.Classifier.Runtime
	if cfg.System.Classifier.APIVersion != ClassifierAPIV23 {
		t.Fatalf("api version = %q", cfg.System.Classifier.APIVersion)
	}
	if r.Confidence.Destructive <= r.Confidence.Mutate || r.Confidence.Mutate <= r.Confidence.Classify {
		t.Fatalf("unsafe confidence ordering: %+v", r.Confidence)
	}
	if !r.HoldReplay.ReleaseOnPressure || !r.Discovery.NoAutomaticApply || !r.Rollout.RequireReadiness {
		t.Fatalf("fail-open/manual rollout defaults were not preserved: %+v %+v %+v", r.HoldReplay, r.Discovery, r.Rollout)
	}
	if r.Capture.ProcessedMark&(1<<27) == 0 || r.Capture.ProcessedMarkMask != 1<<27 {
		t.Fatalf("processed mark contract not derived: %#x/%#x", r.Capture.ProcessedMark, r.Capture.ProcessedMarkMask)
	}
	if r.Privacy.IncludeRawInExport || r.Privacy.AutomaticRawUpload {
		t.Fatal("raw export/upload must be disabled by default")
	}
}

func TestClassifierV23RejectsUnsafeRuntimeConfig(t *testing.T) {
	tests := []struct {
		name string
		edit func(*ClassifierConfig)
	}{
		{"threshold order", func(c *ClassifierConfig) { c.Runtime.Confidence.Mutate = 90; c.Runtime.Confidence.Destructive = 80 }},
		{"hold pressure", func(c *ClassifierConfig) { c.Runtime.HoldReplay.ReleaseOnPressure = false }},
		{"automatic discovery apply", func(c *ClassifierConfig) { c.Runtime.Discovery.NoAutomaticApply = false }},
		{"automatic raw upload", func(c *ClassifierConfig) { c.Runtime.Privacy.AutomaticRawUpload = true }},
		{"ungated optional strategy", func(c *ClassifierConfig) { c.Runtime.Strategies.ControlledRST = true }},
		{"proxy without isolation", func(c *ClassifierConfig) {
			c.Flags.ProxyFallbackEnabled = true
			c.Runtime.Fallback.Enabled = true
			c.Runtime.Fallback.Policy = FallbackProxy
			c.Runtime.Fallback.ProxyRouteID = "socks"
		}},
		{"silent auto missing proof gates", func(c *ClassifierConfig) {
			c.Runtime.SilentPath.Enabled = true
			c.Runtime.SilentPath.Mode = SilentPathFailureAutoCanary
			c.Runtime.SilentPath.RequireDifferentialForAuto = false
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := NewConfig()
			tc.edit(&cfg.System.Classifier)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
