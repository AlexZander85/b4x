package monitor

import (
	"testing"
	"time"
)

func temporalObservation(t time.Time, id string) MonitorObservation {
	return MonitorObservation{SchemaVersion: SchemaVersion, ObservationID: id, Scope: testScope(), Source: SourceSilentStall, Authority: AuthorityPassiveObservation, ObservedAt: t}
}

func testScope() MonitorScopeKey {
	return MonitorScopeKey{ClientScope: ClientScopeKey{ID: "client", Role: "forwarded"}, TargetRole: "target", NetworkContextID: "net", ConfigGeneration: 1}
}

func TestTemporalSeparatesRecurrenceAndIndependence(t *testing.T) {
	base := time.Unix(1000, 0)
	a := NewTemporalAccumulator(TemporalConfig{BucketWidth: time.Second, HalfLife: time.Minute, MaxBuckets: 8, MinFailureSeparation: time.Second})
	a.Add(temporalObservation(base, "1"), "tcp", "ep-a", "flow-1", "fp-1", "wan-1", false)
	a.Add(temporalObservation(base.Add(2*time.Second), "2"), "tcp", "ep-a", "flow-1", "fp-1", "wan-1", false)
	s := a.Snapshot(base.Add(3 * time.Second))
	if s.Recurrence <= 0 || s.Independence <= 0 {
		t.Fatalf("expected recurrence and independence, got %+v", s)
	}
	if s.Buckets[0].DistinctSources != 1 {
		t.Fatalf("duplicate source should remain one dimension: %+v", s.Buckets[0])
	}
	a.Add(temporalObservation(base.Add(4*time.Second), "3"), "tls", "ep-b", "flow-2", "fp-2", "wan-2", false)
	s = a.Snapshot(base.Add(5 * time.Second))
	if s.Independence <= 0.5 {
		t.Fatalf("independent dimensions should increase confidence: %f", s.Independence)
	}
}

func TestTemporalHysteresisAndBoundedBuckets(t *testing.T) {
	base := time.Unix(2000, 0)
	a := NewTemporalAccumulator(TemporalConfig{BucketWidth: time.Second, HalfLife: time.Minute, MaxBuckets: 2, FailureToDegraded: 2, FailuresToFailing: 3, SuccessesToRecovering: 1, SuccessesToHealthy: 2})
	for i := 0; i < 3; i++ {
		a.Add(temporalObservation(base.Add(time.Duration(i)*time.Second), string(rune('a'+i))), "tcp", "ep", "flow", "fp", "wan", false)
	}
	if s := a.Snapshot(base.Add(3 * time.Second)); s.State != HealthFailing {
		t.Fatalf("expected failing, got %s", s.State)
	}
	a.Add(temporalObservation(base.Add(4*time.Second), "s1"), "tcp", "ep", "flow", "fp", "wan", true)
	if s := a.Snapshot(base.Add(4 * time.Second)); s.State != HealthRecovering {
		t.Fatalf("expected recovering, got %s", s.State)
	}
	a.Add(temporalObservation(base.Add(5*time.Second), "s2"), "tcp", "ep", "flow", "fp", "wan", true)
	if s := a.Snapshot(base.Add(5 * time.Second)); s.State != HealthHealthy {
		t.Fatalf("expected healthy, got %s", s.State)
	}
	if len(a.Snapshot(base.Add(10*time.Second)).Buckets) > 2 {
		t.Fatal("bucket limit exceeded")
	}
}
