package warp

import (
	"testing"
	"time"
)

func TestGeoQuorumRequiresFreshPathProof(t *testing.T) {
	now := time.Unix(32000, 0)
	obs := []GeoObservation{{Provider: "a", PublicIP: "ip", PathID: "p", Class: GeoNonRU, DNSProof: true, IPv6Proof: true, CounterDelta: 1, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}, {Provider: "b", PublicIP: "ip", PathID: "p", Class: GeoNonRU, DNSProof: true, CounterDelta: 1, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}}
	a := BuildGeoAttestation(obs, now)
	if !a.Valid(now) {
		t.Fatal(a)
	}
	if want := now.Add(120 * time.Second); !a.FreshUntil.Equal(want) {
		t.Fatalf("geo TTL wrong: got=%v want=%v", a.FreshUntil, want)
	}
	obs[1].Class = GeoRU
	if !BuildGeoAttestation(obs, now).Revoked {
		t.Fatal("RU disagreement not revoked")
	}
}
