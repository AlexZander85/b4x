package silentpath

import "testing"

func TestStatusRedactsIdentifiers(t *testing.T) {
	s := BuildStatus("auto-canary", CapabilitySnapshot{}, 1, 2, 1, 2)
	if s.EffectiveMode != "observe" || s.RemainingBudget != 1 {
		t.Fatal(s)
	}
}
