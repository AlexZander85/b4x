package detector

import (
	"testing"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

func TestEncryptedStallFamilyFilteredWithClassicControl(t *testing.T) {
	paths := map[string]dnspath.DNSPathID{
		"p-dot": {Family: dnspath.DNSPathDoT, ResolverID: "r-dot", EndpointID: "e-dot", IPFamily: "ipv4"},
		"p-udp": {Family: dnspath.DNSPathUDP, ResolverID: "r-udp", EndpointID: "e-udp", IPFamily: "ipv4"},
	}
	// Encrypted family stalled on every attempt; classic DNS works.
	stats := map[string]verifiedPathStats{
		"p-dot": {Pass: 0, Fail: 3, Timeouts: 3},
		"p-udp": {Pass: 3, CorrectnessPass: true, ControlsPass: true},
	}
	_, _, _, _, _, filtered := classifyDiagnosisFlags(nil, paths, stats, 3)
	found := false
	for _, f := range filtered {
		if f == dnspath.DNSPathDoT {
			found = true
		}
	}
	if !found {
		t.Fatalf("a stalled encrypted family with a healthy classic control must be filtered, got %v", filtered)
	}

	// Without any passing classic corroborator a generic outage must NOT
	// quarantine the encrypted family.
	stats2 := map[string]verifiedPathStats{
		"p-dot": {Pass: 0, Fail: 3, Timeouts: 3},
		"p-udp": {Pass: 0, Fail: 3, Timeouts: 3},
	}
	_, _, _, _, _, filtered2 := classifyDiagnosisFlags(nil, paths, stats2, 3)
	for _, f := range filtered2 {
		if f == dnspath.DNSPathDoT {
			t.Fatalf("stall without a classic control must not be family-filtered, got %v", filtered2)
		}
	}
}
