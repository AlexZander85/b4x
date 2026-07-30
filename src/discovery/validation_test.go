package discovery

import (
	"testing"
	"time"
)

func TestCausalComparisonRequiresSafetyControls(t *testing.T) {
	now := time.Unix(26000, 0)
	c := CausalABComparison{Seed: 1, WithoutProfile: SearchSavingsReport{BaselineProbes: 10, GuidedProbes: 10, SavedProbes: 0}, WithProfile: SearchSavingsReport{BaselineProbes: 10, GuidedProbes: 6, SavedProbes: 4}, StaleSuppressed: true, ConflictSuppressed: true, SameControls: true, CreatedAt: now}
	if !c.Valid() {
		t.Fatal(c)
	}
	c.FalsePromotion = true
	if c.Valid() {
		t.Fatal("false promotion accepted")
	}
}
