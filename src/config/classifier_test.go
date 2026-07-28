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
