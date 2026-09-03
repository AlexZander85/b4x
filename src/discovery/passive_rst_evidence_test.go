package discovery

import "testing"

func TestPassiveRSTSuppressionAloneIsNeverSuccessProof(t *testing.T) {
	result, err := ComparePassiveRSTTrial(PassiveRSTTrial{Variant: PassiveRSTVariantConservative, Environment: "candidate", Samples: 3, Suppressions: 3})
	if err != nil || result.Eligible || result.SuccessProof || !result.SuppressionOnly {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestPassiveRSTDiscoveryRequiresIndependentProgressAndIsolation(t *testing.T) {
	result, err := ComparePassiveRSTTrial(PassiveRSTTrial{Variant: PassiveRSTVariantObserve, Environment: "discovery", Samples: 4, TransportSuccess: 3, ServerProgress: 3, Suppressions: 1})
	if err != nil || !result.Eligible || !result.SuccessProof {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := ComparePassiveRSTTrial(PassiveRSTTrial{Variant: PassiveRSTVariantObserve, Environment: "production", Samples: 1}); err == nil {
		t.Fatal("production and sandbox evidence were allowed to mix")
	}
}

func TestPassiveRSTDiscoveryRejectsRegressionAndAggressiveVariant(t *testing.T) {
	result, err := ComparePassiveRSTTrial(PassiveRSTTrial{Variant: PassiveRSTVariantConservative, Environment: "candidate", Samples: 4, TransportSuccess: 4, ServerProgress: 4, ControlFailure: 1})
	if err != nil || result.Eligible {
		t.Fatalf("control regression eligible: %+v err=%v", result, err)
	}
	if _, err := ComparePassiveRSTTrial(PassiveRSTTrial{Variant: PassiveRSTVariant("candidate-passive-rst-aggressive"), Environment: "candidate", Samples: 4}); err == nil {
		t.Fatal("aggressive auto-promotion variant accepted")
	}
}
