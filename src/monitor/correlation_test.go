package monitor

import (
	"testing"
	"time"
)

func TestCorrelationKeepsAddressFailuresAndDoesNotTreatSYNACKAsSuccess(t *testing.T) {
	c := NewFlowCorrelator()
	s := MonitorScopeKey{ClientScope: ClientScopeKey{ID: "c", Role: "forwarded"}, TargetRole: "target", NetworkContextID: "w", ConfigGeneration: 1}
	o := MonitorObservation{SchemaVersion: SchemaVersion, ObservationID: "1", Scope: s, Source: SourceTCPSYNACK, OutcomeCode: "syn_ack", Authority: AuthorityPassiveObservation, ObservedAt: time.Now()}
	c.Observe(o, "a", false)
	o.ObservationID = "2"
	c.Observe(o, "b", true)
	v, _ := c.Snapshot(s)
	if v.Successes != 1 || len(v.Endpoints) != 2 {
		t.Fatal(v)
	}
	if v.Health != HealthDegraded {
		t.Fatal(v.Health)
	}
}
