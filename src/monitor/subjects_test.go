package monitor

import (
	"testing"
	"time"
)

func TestDemandInboxBoundedAndResolutionFreshness(t *testing.T) {
	b := NewDemandInbox(IntakeConfig{MaxSubjects: 1, MaxPerClient: 1})
	n := time.Now()
	if !b.PutResolution(ClientResolutionSnapshot{SchemaVersion: SchemaVersion, SnapshotID: "r", ClientKeyHash: "c", NetworkContextID: "w", ConfigGeneration: 1, ValidUntil: n.Add(time.Second)}) {
		t.Fatal("resolution")
	}
	if _, ok := b.Resolution("r", n); !ok {
		t.Fatal("fresh resolution")
	}
	d := ObservedDemandTarget{ObservationID: "o", ClientKeyHash: "c", DomainIdentityID: "d", ComponentID: "video", ConfigGeneration: 1, LastObservedAt: n, ExpiresAt: n.Add(time.Minute)}
	if _, ok := b.Demand(d); !ok {
		t.Fatal("demand")
	}
	d.ClientKeyHash = "other"
	if _, ok := b.Demand(d); ok {
		t.Fatal("budget bypass")
	}
}
