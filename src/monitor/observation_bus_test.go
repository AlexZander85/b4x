package monitor

import (
	"context"
	"testing"
	"time"
)

func testObservation(source ObservationSource) MonitorObservation {
	return MonitorObservation{SchemaVersion: SchemaVersion, ObservationID: "o1", Scope: MonitorScopeKey{ClientScope: ClientScopeKey{ID: "client", Role: "forwarded"}, TargetRole: "target", NetworkContextID: "wan", ConfigGeneration: 1}, Source: source, Authority: AuthorityPassiveObservation, ObservedAt: time.Unix(1, 0)}
}
func TestBusValidatesScopeAndPreservesSafetyLane(t *testing.T) {
	b := NewObservationBus(BusConfig{Capacity: 1, P0Capacity: 1, Clock: func() time.Time { return time.Unix(1, 0) }})
	if !b.Publish(testObservation(SourceUniqueProgress)) {
		t.Fatal("normal publish")
	}
	if !b.Publish(testObservation(SourceQueueDrop)) {
		t.Fatal("safety publish")
	}
	if o, ok := b.Next(context.Background()); !ok || o.Source != SourceQueueDrop {
		t.Fatalf("safety=%+v", o)
	}
	if b.Publish(MonitorObservation{SchemaVersion: SchemaVersion}) {
		t.Fatal("invalid accepted")
	}
}
