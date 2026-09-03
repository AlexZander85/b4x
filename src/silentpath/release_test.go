package silentpath

import "testing"

func TestNoTargetValidationNoPromotion(t *testing.T) {
	if Verdict(true, false) != NotTargetValidated {
		t.Fatal("unsafe promotion")
	}
}
