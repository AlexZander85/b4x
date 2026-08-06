package monitor

import (
	"testing"
	"time"
)

func validAssessmentScope() MonitorScopeKey {
	return MonitorScopeKey{
		ClientScope:      ClientScopeKey{Role: "router-origin", ID: "node-a"},
		TargetRole:       "control",
		NetworkContextID: "net-1",
		ConfigGeneration: 1,
		IPFamily:         "ipv4",
	}
}

func TestMonitorAssessmentValid(t *testing.T) {
	now := time.Now().UTC()
	scope := validAssessmentScope()
	good := MonitorAssessment{
		SchemaVersion:  SchemaVersion,
		AssessmentID:   "assessment/1",
		Scope:          scope,
		Health:         AxisHealthy,
		AssessedAt:     now,
		ExpiresAt:      now.Add(time.Minute),
	}
	if !good.Valid(now.Add(30 * time.Second)) {
		t.Fatal("in-window assessment must be valid")
	}
	if good.Valid(now.Add(2 * time.Minute)) {
		t.Fatal("expired assessment must be invalid (decay: no authorization)")
	}
	bad := good
	bad.Scope.NetworkContextID = ""
	if bad.Valid(now) {
		t.Fatal("assessment with invalid scope must be rejected")
	}
	bad = good
	bad.AssessmentID = ""
	if bad.Valid(now) {
		t.Fatal("assessment without ID must be rejected")
	}
}

func TestMonitorAssessmentAggregateWorstAxis(t *testing.T) {
	a := MonitorAssessment{
		Health:     AxisHealthy,
		Diagnostic: map[string]AxisState{"transport": AxisFailing, "visibility": AxisDegraded},
	}
	if got := a.Aggregate(); got != AxisFailing {
		t.Fatalf("aggregate must be worst axis (failing), got %s", got)
	}
	a.Diagnostic["transport"] = AxisUnknown
	if got := a.Aggregate(); got != AxisDegraded {
		t.Fatalf("aggregate must follow remaining diagnostic axis, got %s", got)
	}
	a.Diagnostic = nil
	if got := a.Aggregate(); got != AxisHealthy {
		t.Fatalf("aggregate must fall back to health axis, got %s", got)
	}
}

func TestAxisFromHealthTotal(t *testing.T) {
	cases := map[HealthState]AxisState{
		HealthUnknown:    AxisUnknown,
		HealthHealthy:    AxisHealthy,
		HealthDegraded:   AxisDegraded,
		HealthFailing:    AxisFailing,
		HealthRecovering: AxisRecovering,
		HealthRecovered:  AxisRecovering,
	}
	for in, want := range cases {
		if got := AxisFromHealth(in); got != want {
			t.Errorf("AxisFromHealth(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestSortedContradictionsDeterministic(t *testing.T) {
	a := MonitorAssessment{Contradictions: []string{"b", "a", "c"}}
	got := a.SortedContradictions()
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("contradictions not sorted: %v", got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 contradictions, got %d", len(got))
	}
}
