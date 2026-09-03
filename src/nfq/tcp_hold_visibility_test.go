package nfq

import (
	"net/netip"
	"testing"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/classifier"
)

func TestTCPHoldReleasesImmediatelyWhenVisibilityDegrades(t *testing.T) {
	gate := ppe.DefaultVisibilityGate()
	gate.DisableRequirement("test reset")
	defer gate.DisableRequirement("test cleanup")
	store := NewTCPHoldStore(DefaultTCPHoldConfig())
	key := classifier.FlowKey{SrcIP: netip.MustParseAddr("192.0.2.1"), DstIP: netip.MustParseAddr("203.0.113.1"), SrcPort: 50000, DstPort: 443, Proto: 6}
	if !store.Hold(key, 1, nil, 1, 10) {
		t.Fatal("initial hold failed")
	}
	gate.EnsureRequired("gen-1", "proof required")
	if store.Len() != 0 || store.Bytes() != 0 {
		t.Fatalf("held state survived degradation len=%d bytes=%d", store.Len(), store.Bytes())
	}
	store.ReleaseAll(tcpHoldAbortShutdown)
}
