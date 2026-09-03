package config

import "testing"

func TestPassiveRSTDefaultsObserveAndBounded(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Runtime.PassiveRST = PassiveRSTRuntimeConfig{}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate defaults: %v", err)
	}
	got := cfg.System.Classifier.Runtime.PassiveRST
	if got.Mode != PassiveRSTObserve {
		t.Fatalf("mode=%q want observe", got.Mode)
	}
	if got.MaxFlows != 4096 || got.BaselineSamples != 8 || got.MinTTLTolerance != 3 || got.SuppressionBudgetPerFlow != 2 {
		t.Fatalf("unexpected passive RST defaults: %+v", got)
	}
}

func TestPassiveRSTValidationRejectsUnsafeEnvelope(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*PassiveRSTRuntimeConfig)
	}{
		{"mode", func(c *PassiveRSTRuntimeConfig) { c.Mode = "automatic" }},
		{"flows", func(c *PassiveRSTRuntimeConfig) { c.MaxFlows = 2 }},
		{"samples", func(c *PassiveRSTRuntimeConfig) { c.BaselineSamples = 2 }},
		{"burst", func(c *PassiveRSTRuntimeConfig) { c.BurstThreshold = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := NewConfig()
			tc.mutate(&cfg.System.Classifier.Runtime.PassiveRST)
			if err := cfg.Validate(); err == nil {
				t.Fatal("unsafe passive RST config accepted")
			}
		})
	}
}

func TestPassiveRSTActiveModesRequireScopesAndAggressiveConfirmation(t *testing.T) {
	cfg := NewConfig()
	cfg.System.Classifier.Runtime.PassiveRST.Mode = PassiveRSTConservative
	if err := cfg.Validate(); err == nil {
		t.Fatal("unscoped conservative mode accepted")
	}
	cfg = NewConfig()
	cfg.System.Classifier.Runtime.PassiveRST.Mode = PassiveRSTAggressive
	cfg.System.Classifier.Runtime.PassiveRST.SetScopes = []string{" YouTube ", "youtube"}
	cfg.System.Classifier.Runtime.PassiveRST.DeviceScopes = []string{"AA:BB:CC:DD:EE:01"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("unconfirmed aggressive mode accepted")
	}
	cfg.System.Classifier.Runtime.PassiveRST.AggressiveConfirmationToken = PassiveRSTAggressiveConfirmation
	if err := cfg.Validate(); err != nil {
		t.Fatalf("confirmed aggressive mode rejected: %v", err)
	}
	got := cfg.System.Classifier.Runtime.PassiveRST
	if len(got.SetScopes) != 1 || got.SetScopes[0] != "youtube" || got.DeviceScopes[0] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("scopes not normalized: %+v", got)
	}
}

func TestPassiveRSTRollbackThresholdDefaultsAndValidation(t *testing.T) {
	cfg := NewConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	rst := cfg.System.Classifier.Runtime.PassiveRST
	if rst.RollbackWindowSeconds != 60 || rst.ReconnectFailureThreshold != 3 || rst.QueueDropThreshold != 1 {
		t.Fatalf("rollback defaults=%+v", rst)
	}
	cfg = NewConfig()
	cfg.System.Classifier.Runtime.PassiveRST.RollbackWindowSeconds = 1
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsafe rollback window accepted")
	}
}
