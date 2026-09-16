package monitor

import (
	"testing"
	"time"
)

func TestAdaptiveSynthesisStalePreservesProgress(t *testing.T) {
	now := time.Now().UTC()
	scope := afsMonitorScope()
	correlator := NewFlowCorrelator()
	seedFailingCorrelation(t, correlator, scope, now)

	if err := correlator.OpenAdaptiveSynthesis(afsFailingAssessment(scope, now), "run-stale", true, true, now.Add(time.Minute), now); err != nil {
		t.Fatalf("open synthesis: %v", err)
	}
	if err := correlator.UpdateAdaptiveSynthesis(scope, AdaptiveSynthesisUpdate{
		RunID:                "run-stale",
		State:                SynthesisPlanning,
		BlockingProfileID:    "bp-stale",
		BehavioralEvidenceID: "bf-stale",
		CandidatesGenerated:  7,
		CandidatesRejected:   2,
		CandidatesTested:     3,
		CurrentGeneration:    2,
		BestCandidateID:      "candidate-best",
		Reason:               "bounded-search-progress",
	}, now.Add(time.Second)); err != nil {
		t.Fatalf("record progress: %v", err)
	}

	if err := correlator.MarkAdaptiveSynthesisStale(scope, "run-stale", "network-context-changed", now.Add(2*time.Second)); err != nil {
		t.Fatalf("mark stale: %v", err)
	}
	status, ok := correlator.AdaptiveSynthesisStatus(scope)
	if !ok {
		t.Fatal("missing synthesis status")
	}
	if status.State != SynthesisStaleContext {
		t.Fatalf("expected stale context, got %s", status.State)
	}
	if status.CandidatesGenerated != 7 || status.CandidatesRejected != 2 || status.CandidatesTested != 3 || status.CurrentGeneration != 2 {
		t.Fatalf("progress was not preserved: %+v", status)
	}
	if status.BlockingProfileID != "bp-stale" || status.BehavioralEvidenceID != "bf-stale" || status.BestCandidateID != "candidate-best" {
		t.Fatalf("bound identities were not preserved: %+v", status)
	}
}
