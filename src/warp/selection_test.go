package warp

import "testing"

func TestSelectionRequiresForwardedAndStabilityEvidence(t *testing.T) {
	r := SelectLeastInvasive([]Candidate{{ID: "bad", Invasive: 0, Protocol: true, Router: true, Stable: true}, {ID: "good", Invasive: 2, Protocol: true, Router: true, Forwarded: true, Stable: true}})
	if r.CandidateID != "good" {
		t.Fatal(r)
	}
}
