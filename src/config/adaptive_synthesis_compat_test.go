package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdaptiveSynthesisLegacyConfigKeepsSafeDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(path, []byte(`{"version":53,"sets":[]}`), 0o600); err != nil {
		t.Fatalf("write legacy config: %v", err)
	}

	cfg := NewConfig()
	if err := cfg.LoadFromFile(path); err != nil {
		t.Fatalf("load legacy config: %v", err)
	}

	policy := cfg.Automation.AdaptiveStrategySynthesis
	if policy.Enabled {
		t.Fatal("adaptive synthesis must remain default-off for legacy configs")
	}
	if !policy.AllowBoundedDisorder || !policy.AllowJitter {
		t.Fatalf("legacy config lost synthesis defaults: disorder=%t jitter=%t", policy.AllowBoundedDisorder, policy.AllowJitter)
	}
	if policy.MaxCandidates != DefaultAdaptiveStrategySynthesisConfig.MaxCandidates || policy.MaxGenerations != DefaultAdaptiveStrategySynthesisConfig.MaxGenerations {
		t.Fatalf("legacy config lost bounded defaults: candidates=%d generations=%d", policy.MaxCandidates, policy.MaxGenerations)
	}
}

func TestAdaptiveSynthesisExplicitBooleanOverridesSurviveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "explicit.json")
	data := `{"version":53,"sets":[],"automation":{"adaptive_strategy_synthesis":{"enabled":false,"allow_bounded_disorder":false,"allow_jitter":false}}}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("write explicit config: %v", err)
	}

	cfg := NewConfig()
	if err := cfg.LoadFromFile(path); err != nil {
		t.Fatalf("load explicit config: %v", err)
	}

	policy := cfg.Automation.AdaptiveStrategySynthesis
	if policy.AllowBoundedDisorder || policy.AllowJitter {
		t.Fatalf("explicit false overrides were not preserved: disorder=%t jitter=%t", policy.AllowBoundedDisorder, policy.AllowJitter)
	}
}
