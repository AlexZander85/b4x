package monitor

import (
	"testing"
	"time"
)

func TestLegacyForceCheckOnlyQueuesBoundedDiagnostic(t *testing.T) {
	now := time.Unix(9000, 0)
	s := NewDiagnosticScheduler(SchedulerConfig{QuickCapacity: 1})
	p := NewMonitorAPIProjection()
	a := NewLegacyWatchdogAdapter(s, p)
	if err := a.ForceCheck(testScope(), "req", now); err != nil {
		t.Fatal(err)
	}
	if s.Depth(DiagnosticQuick) != 1 {
		t.Fatal("force-check did not enter scheduler")
	}
	if err := a.ForceCheck(testScope(), "req2", now); err != ErrSchedulerOverloaded {
		t.Fatal("legacy adapter bypassed bounded queue")
	}
}

func TestCheckpointRoundTripAndProjection(t *testing.T) {
	now := time.Unix(9000, 0)
	c := MonitorCheckpoint{SchemaVersion: SchemaVersion, SavedAt: now, CutoverVersion: "mon-v1", Statuses: []MonitorStatus{{SchemaVersion: SchemaVersion, Scope: testScope(), Health: HealthDegraded, UpdatedAt: now}}}
	b, err := EncodeCheckpoint(c)
	if err != nil {
		t.Fatal(err)
	}
	d, err := DecodeCheckpoint(b)
	if err != nil || !d.Valid() {
		t.Fatalf("checkpoint failed: %+v %v", d, err)
	}
	p := NewMonitorAPIProjection()
	p.Update(c.Statuses[0])
	if s, ok := p.Get(testScope()); !ok || s.Health != HealthDegraded {
		t.Fatalf("projection missing status: %+v %v", s, ok)
	}
}
