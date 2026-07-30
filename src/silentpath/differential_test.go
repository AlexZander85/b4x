package silentpath

import "testing"

func TestDifferentialNeedsCandidateAndControl(t *testing.T) {
	r := ComparePaths(ProbeResult{}, ProbeResult{ReachedMilestone: true}, ProbeResult{ReachedMilestone: true, ControlHealthy: true})
	if !r.Confirmed {
		t.Fatal(r)
	}
	if ComparePaths(ProbeResult{}, ProbeResult{ReachedMilestone: true}, ProbeResult{}).Confirmed {
		t.Fatal("control bypass")
	}
}
