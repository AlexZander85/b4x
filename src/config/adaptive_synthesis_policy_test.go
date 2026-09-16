package config

import "testing"

func TestAdaptiveSynthesisPolicyUsesServiceProfileID(t *testing.T) {
	cfg := NewConfig()
	cfg.Automation.AdaptiveStrategySynthesis.Enabled = true
	cfg.Automation.AdaptiveStrategySynthesis.ServiceProfilePolicy = map[string]string{
		"youtube": AdaptiveSynthesisProfileDisabled,
	}

	// Service-profile identities come from the existing serviceprofile catalog,
	// not from Config.Sets. Config must not invent a shadow catalog constraint.
	if err := cfg.Validate(); err != nil {
		t.Fatalf("service-profile policy should not require a matching SetConfig ID: %v", err)
	}
	if cfg.AdaptiveSynthesisAllowed("youtube") {
		t.Fatal("disabled service profile unexpectedly allowed synthesis")
	}
	if !cfg.AdaptiveSynthesisAllowed("discord") {
		t.Fatal("unmentioned service profile should inherit global opt-in")
	}

	cfg.Automation.AdaptiveStrategySynthesis.Enabled = false
	if cfg.AdaptiveSynthesisAllowed("discord") {
		t.Fatal("service profile must not widen a disabled global policy")
	}
}

func TestAdaptiveSynthesisPolicyRejectsInvalidPolicyValue(t *testing.T) {
	cfg := NewConfig()
	cfg.Automation.AdaptiveStrategySynthesis.ServiceProfilePolicy = map[string]string{
		"youtube": "enabled",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("service profile must not be allowed to widen policy with an enabled override")
	}
}
