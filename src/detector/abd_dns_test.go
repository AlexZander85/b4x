package detector

import (
	"github.com/daniellavrushin/b4/monitor"
	"testing"
	"time"
)

func TestDNSDifferentialPreservesPerAddressOutcomes(t *testing.T) {
	now := time.Unix(12000, 0)
	scope := monitor.MonitorScopeKey{ClientScope: monitor.ClientScopeKey{ID: "c", Role: "forwarded"}, TargetRole: "target", NetworkContextID: "wan", ConfigGeneration: 1}
	client := monitor.ClientResolutionSnapshot{SchemaVersion: monitor.SchemaVersion, SnapshotID: "client", NetworkContextID: "wan", ConfigGeneration: 1, OriginalQNameHash: "q", ValidUntil: now.Add(time.Minute), Answers: []monitor.ResolvedEndpoint{{IPHash: "a", IPFamily: "v4", AddressIndex: 0}, {IPHash: "b", IPFamily: "v4", AddressIndex: 1}}}
	e, err := BuildDNSDifferential(scope, client, monitor.ClientResolutionSnapshot{SnapshotID: "independent", NetworkContextID: "wan", ConfigGeneration: 1, Answers: []monitor.ResolvedEndpoint{{IPHash: "b"}}}, []DNSAddressOutcome{{SnapshotID: "client", IPHash: "a", AddressIndex: 0, Success: false, FailureCode: FailureTransportTimeout, ObservedAt: now}, {SnapshotID: "client", IPHash: "b", AddressIndex: 1, Success: true, ObservedAt: now}}, now)
	if err != nil || !e.Valid() {
		t.Fatalf("evidence invalid: %+v %v", e, err)
	}
	if len(e.OutcomeVector()) != 2 || e.OutcomeVector()[0].IPHash != "a" {
		t.Fatalf("address vector collapsed: %+v", e)
	}
}

func TestDNSDifferentialRejectsGenerationMismatch(t *testing.T) {
	now := time.Unix(12000, 0)
	scope := monitor.MonitorScopeKey{ClientScope: monitor.ClientScopeKey{ID: "c", Role: "forwarded"}, TargetRole: "target", NetworkContextID: "wan", ConfigGeneration: 2}
	client := monitor.ClientResolutionSnapshot{SchemaVersion: monitor.SchemaVersion, SnapshotID: "client", NetworkContextID: "wan", ConfigGeneration: 1, ValidUntil: now.Add(time.Minute), Answers: []monitor.ResolvedEndpoint{{IPHash: "a"}}}
	if _, err := BuildDNSDifferential(scope, client, monitor.ClientResolutionSnapshot{}, []DNSAddressOutcome{{IPHash: "a", ObservedAt: now}}, now); err == nil {
		t.Fatal("mismatched generation accepted")
	}
}
