package monitor

import (
	"testing"
	"time"
)

func TestClassifyParity(t *testing.T) {
	scope := validAssessmentScope()
	now := time.Now().UTC()

	// Watchdog failing + monitoring healthy = contradiction (the two
	// pipelines disagree on the same scope).
	a := MonitorAssessment{
		SchemaVersion: SchemaVersion,
		AssessmentID:  "assessment/1",
		Scope:         scope,
		Health:        AxisHealthy,
		AssessedAt:    now,
		ExpiresAt:     now.Add(time.Minute),
	}
	if got := classifyParity("failing", a.Health); got != ParityContradiction {
		t.Fatalf("watchdog failing vs monitor healthy must be a contradiction, got %s", got)
	}

	// Watchdog healthy + monitoring healthy = match.
	if got := classifyParity("healthy", a.Health); got != ParityMatch {
		t.Fatalf("watchdog healthy vs monitor healthy must match, got %s", got)
	}

	// Watchdog healthy + monitoring failing = contradiction (other side).
	a.Health = AxisFailing
	if got := classifyParity("healthy", a.Health); got != ParityContradiction {
		t.Fatalf("watchdog healthy vs monitor failing must be a contradiction, got %s", got)
	}

	// Watchdog failing + monitoring failing = match.
	if got := classifyParity("failing", a.Health); got != ParityMatch {
		t.Fatalf("watchdog failing vs monitor failing must match, got %s", got)
	}

	// Unknown sides stay unknown: no opinion, no evidence.
	if got := classifyParity("disabled", AxisHealthy); got != ParityUnknown {
		t.Fatalf("non-opinion watchdog state must be unknown, got %s", got)
	}
	if got := classifyParity("failing", AxisUnknown); got != ParityUnknown {
		t.Fatalf("unknown monitoring axis must be unknown, got %s", got)
	}
}

func TestShadowParityTrackerPerScopeAndCounts(t *testing.T) {
	tracker := NewShadowParityTracker()
	scope := validAssessmentScope()
	now := time.Now().UTC()

	if _, ok := tracker.Latest(scope); ok {
		t.Fatal("no evidence must exist before any observation")
	}

	healthy := MonitorAssessment{
		SchemaVersion: SchemaVersion,
		AssessmentID:  "assessment/1",
		Scope:         scope,
		Health:        AxisHealthy,
		AssessedAt:    now,
		ExpiresAt:     now.Add(time.Minute),
	}
	ev := tracker.Observe(scope, "failing", healthy, now)
	if ev.Parity != ParityContradiction {
		t.Fatalf("first observation must be a contradiction, got %s", ev.Parity)
	}

	failing := healthy
	failing.AssessmentID = "assessment/2"
	failing.Health = AxisFailing
	ev = tracker.Observe(scope, "failing", failing, now)
	if ev.Parity != ParityMatch {
		t.Fatalf("per-scope latest must be replaced by the new observation, got %s", ev.Parity)
	}
	latest, ok := tracker.Latest(scope)
	if !ok || latest.AssessmentID != "assessment/2" {
		t.Fatalf("latest must reflect the newest observation: %+v", latest)
	}

	total, contradictions := tracker.Counts()
	if total != 1 || contradictions != 0 {
		t.Fatalf("counts = %d/%d, want 1/0 after replacement", total, contradictions)
	}

	// A second scope with a contradiction bumps the contradiction count.
	scope2 := scope
	scope2.ClientScope.ID = "node-b"
	other := healthy
	other.AssessmentID = "assessment/3"
	other.Scope = scope2
	tracker.Observe(scope2, "healthy", other, now) // healthy vs healthy: match
	tracker.Observe(scope2, "failing", other, now) // failing vs healthy: contradiction
	total, contradictions = tracker.Counts()
	if total != 2 || contradictions != 1 {
		t.Fatalf("counts = %d/%d, want 2/1", total, contradictions)
	}
}
