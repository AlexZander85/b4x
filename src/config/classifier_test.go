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
