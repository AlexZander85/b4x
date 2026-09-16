package monitor

import (
	"testing"
	"time"
)

func afsMonitorScope() MonitorScopeKey {
	return MonitorScopeKey{
		ClientScope:      ClientScopeKey{ID: "client-a", Role: "forwarded"},
		ServiceProfileID: "youtube",
		ComponentID:      "video",
		TargetRole:       "target",
		NetworkContextID: "wan-a",
		ConfigGeneration: 7,
	}
}

func seedFailingCorrelation(t *testing.T, correlator *FlowCorrelator, scope MonitorScopeKey, now time.Time) {
	t.Helper()
	for i := 0; i < 3; i++ {
		correlator.Observe(MonitorObservation{
			SchemaVersion: SchemaVersion,
			ObservationID: "fail-" + string(rune('a'+i)),
			Scope:         scope,
			Source:        SourceTCPSYNACK,
			OutcomeCode:   "blocked",
			Authority:     AuthorityPassiveObservation,
			ObservedAt:    now.Add(time.Duration(i) * time.Second),
		}, "target-a", false)
	}
}

func afsFailingAssessment(scope MonitorScopeKey, now time.Time) MonitorAssessment {
	return MonitorAssessment{
		SchemaVersion:          SchemaVersion,
		AssessmentID:           "assessment-afs-1",
		SubjectID:              "youtube/video",
		Scope:                  scope,
		Health:                 AxisFailing,
		IndependentSourceCount: 2,
		EvidenceRefs:           []string{"evidence-1", "evidence-2"},
		AssessedAt:             now,
		ExpiresAt:              now.Add(time.Minute),
	}
}

func TestAdaptiveSynthesisLifecycleReusesCorrelationScope(t *testing.T) {
	now := time.Now().UTC()
	scope := afsMonitorScope()
	correlator := NewFlowCorrelator()
	seedFailingCorrelation(t, correlator, scope, now)

	if err := correlator.OpenAdaptiveSynthesis(afsFailingAssessment(scope, now), "run-1", true, true, now.Add(2*time.Minute), now); err != nil {
		t.Fatalf("open synthesis: %v", err)
	}
	steps := []AdaptiveSynthesisUpdate{
		{RunID: "run-1", State: SynthesisBehavioralProfiling, BlockingProfileID: "bp-1", Reason: "ordinary-abd-revalidated"},
		{RunID: "run-1", State: SynthesisPlanning, BlockingProfileID: "bp-1", BehavioralEvidenceID: "bf-1", CandidatesGenerated: 4, CurrentGeneration: 0, Reason: "behavioral-profile-ready"},
		{RunID: "run-1", State: SynthesisDiscoveryTest, BlockingProfileID: "bp-1", BehavioralEvidenceID: "bf-1", CandidatesGenerated: 8, CandidatesRejected: 2, CurrentGeneration: 1, Reason: "bounded-candidates-ready"},
		{RunID: "run-1", State: SynthesisAndroidCanary, CandidatesGenerated: 8, CandidatesRejected: 2, CandidatesTested: 6, CurrentGeneration: 1, BestCandidateID: "candidate-1", Reason: "target-control-matrix-passed"},
		{RunID: "run-1", State: SynthesisRollout, CandidatesGenerated: 8, CandidatesRejected: 2, CandidatesTested: 6, CurrentGeneration: 1, BestCandidateID: "candidate-1", RolloutGeneration: "runtime-gen-1", Reason: "forwarded-canary-passed"},
		{RunID: "run-1", State: SynthesisStabilityObserve, CandidatesGenerated: 8, CandidatesRejected: 2, CandidatesTested: 6, CurrentGeneration: 1, BestCandidateID: "candidate-1", RolloutGeneration: "runtime-gen-1", Reason: "promotion-complete"},
	}
	for _, step := range steps {
		if err := correlator.UpdateAdaptiveSynthesis(scope, step, now.Add(time.Second)); err != nil {
			t.Fatalf("transition to %s: %v", step.State, err)
		}
	}

	cooldownUntil := now.Add(5 * time.Minute)
	if err := correlator.ObserveAdaptiveSynthesisStability(scope, "run-1", "candidate-1", true, cooldownUntil, "", now.Add(2*time.Second)); err != nil {
		t.Fatalf("stability observation: %v", err)
	}
	status, ok := correlator.AdaptiveSynthesisStatus(scope)
	if !ok {
		t.Fatal("missing synthesis status")
	}
	if status.State != SynthesisCooldown || status.WinnerCandidateID != "candidate-1" || status.BlockingProfileID != "bp-1" || status.BehavioralEvidenceID != "bf-1" {
		t.Fatalf("unexpected status: %+v", status)
	}
	if status.CandidatesGenerated != 8 || status.CandidatesRejected != 2 || status.CandidatesTested != 6 {
		t.Fatalf("candidate counters lost: %+v", status)
	}
	if err := correlator.ResetAdaptiveSynthesis(scope, now.Add(3*time.Second)); err == nil {
		t.Fatal("cooldown reset was accepted before deadline")
	}
	if err := correlator.ResetAdaptiveSynthesis(scope, cooldownUntil.Add(time.Second)); err != nil {
		t.Fatalf("reset after cooldown: %v", err)
	}
}

func TestAdaptiveSynthesisLifecycleRejectsConflictAndIllegalTransition(t *testing.T) {
	now := time.Now().UTC()
	scope := afsMonitorScope()
	correlator := NewFlowCorrelator()
	seedFailingCorrelation(t, correlator, scope, now)
	assessment := afsFailingAssessment(scope, now)

	if err := correlator.OpenAdaptiveSynthesis(assessment, "run-1", true, true, now.Add(time.Minute), now); err != nil {
		t.Fatalf("open synthesis: %v", err)
	}
	if err := correlator.OpenAdaptiveSynthesis(assessment, "run-2", true, true, now.Add(time.Minute), now); err == nil {
		t.Fatal("conflicting run was accepted")
	}
	if err := correlator.UpdateAdaptiveSynthesis(scope, AdaptiveSynthesisUpdate{RunID: "run-1", State: SynthesisRollout}, now.Add(time.Second)); err == nil {
		t.Fatal("illegal transition to rollout was accepted")
	}
	if err := correlator.UpdateAdaptiveSynthesis(scope, AdaptiveSynthesisUpdate{RunID: "wrong-run", State: SynthesisBehavioralProfiling}, now.Add(time.Second)); err == nil {
		t.Fatal("run ownership mismatch was accepted")
	}
}

func TestAdaptiveSynthesisCancelIsIdempotentAndStaleIsTerminal(t *testing.T) {
	now := time.Now().UTC()
	scope := afsMonitorScope()
	correlator := NewFlowCorrelator()
	seedFailingCorrelation(t, correlator, scope, now)
	if err := correlator.OpenAdaptiveSynthesis(afsFailingAssessment(scope, now), "run-1", true, true, now.Add(time.Minute), now); err != nil {
		t.Fatalf("open synthesis: %v", err)
	}
	if err := correlator.MarkAdaptiveSynthesisStale(scope, "run-1", "network-context-changed", now.Add(time.Second)); err != nil {
		t.Fatalf("mark stale: %v", err)
	}
	status, _ := correlator.AdaptiveSynthesisStatus(scope)
	if status.State != SynthesisStaleContext {
		t.Fatalf("expected stale context, got %s", status.State)
	}
	if err := correlator.CancelAdaptiveSynthesis(scope, "run-1", "cleanup-complete", now.Add(30*time.Second), now.Add(2*time.Second)); err != nil {
		t.Fatalf("cancel stale run: %v", err)
	}
	if err := correlator.CancelAdaptiveSynthesis(scope, "run-1", "cleanup-complete", now.Add(30*time.Second), now.Add(3*time.Second)); err != nil {
		t.Fatalf("idempotent cancel: %v", err)
	}
	status, _ = correlator.AdaptiveSynthesisStatus(scope)
	if status.State != SynthesisCancelled {
		t.Fatalf("expected cancelled state, got %s", status.State)
	}
}
