package warp

import (
	"testing"
	"time"
)

func TestSelectionRequiresForwardedAndStabilityEvidence(t *testing.T) {
	now := time.Unix(32000, 0)
	r := SelectLeastInvasive([]Candidate{{ID: "bad", Invasive: 0, Protocol: true, Router: true, Stable: true}, {ID: "good", Invasive: 2, Protocol: true, Router: true, Forwarded: true, Stable: true}}, now)
	if r.CandidateID != "good" {
		t.Fatal(r)
	}
	if !r.Winner {
		t.Fatal("winner not flagged")
	}
	if want := now.Add(candidateSelectionTTL).Unix(); r.ExpiresAt != want {
		t.Fatalf("ExpiresAt not filled: got=%d want=%d", r.ExpiresAt, want)
	}
}

func TestSelectionNoStableCandidateStillCarriesExpiry(t *testing.T) {
	now := time.Unix(32000, 0)
	r := SelectLeastInvasive([]Candidate{{ID: "bad", Invasive: 0, Protocol: true, Router: true, Stable: true}}, now)
	if r.Winner {
		t.Fatal("non-stable candidate selected")
	}
	if want := now.Add(candidateSelectionTTL).Unix(); r.ExpiresAt != want {
		t.Fatalf("ExpiresAt not filled on rejection: got=%d want=%d", r.ExpiresAt, want)
	}
}
