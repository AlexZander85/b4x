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
