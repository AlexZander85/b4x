package dns

import (
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
)

func TestDNSHintCorrelatorCreatesTCPAndUDPFirstFlowHints(t *testing.T) {
	clk := clock.NewFixed(time.Unix(100, 0))
	store := classifier.NewHostHintStore(classifier.HostHintStoreConfig{MaxEntries: 32, MaxEntriesPerClient: 8, MaxCandidatesPerKey: 8}, clk)
	resolver := HintSetResolverFunc(func(domain string, client classifier.ClientKey, sourceDevice string, protocol uint8) []HintSetCandidate {
		if sourceDevice != "aa:bb:cc:dd:ee:ff" || client.SourceIP != netip.MustParseAddr("192.0.2.20") {
			return nil
		}
		if domain == "api.youtube.com" {
			return []HintSetCandidate{{SetID: "youtube-api", Confidence: 88}}
		}
		return nil
	})
	correlator := NewDNSHintCorrelator(store, resolver)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.20"), VLAN: 10}
	observation := DNSObservation{
		Client:       client,
		QueryName:    "api.youtube.com",
		Canonical:    "api.youtube.com",
		Timestamp:    clk.Now(),
		Answers:      []DNSAddress{{Name: "api.youtube.com", CanonicalName: "api.youtube.com", IP: netip.MustParseAddr("203.0.113.20"), TTL: time.Minute, TTLSeconds: 60}},
		HTTPSRecords: []HTTPSRecord{{Name: "api.youtube.com", TTL: time.Minute, TTLSeconds: 60, HasECHConfig: true, ECHConfig: []byte{1, 2}}},
	}
	result, err := correlator.ObserveResponse(observation, "aa:bb:cc:dd:ee:ff", 11)
	if err != nil || result.PositiveHints != 4 {
		// DNS answer and HTTPS metadata are mirrored to TCP and UDP.
		t.Fatalf("correlation result=%+v err=%v", result, err)
	}
	if result.PositiveHints != 4 {
		t.Fatalf("expected four source-scoped hints, got %+v", result)
	}
	for _, protocol := range []uint8{6, 17} {
		hints := store.LookupForGeneration(client, netip.MustParseAddr("203.0.113.20"), protocol, 11)
		if len(hints) != 2 {
			t.Fatalf("protocol %d hints=%+v", protocol, hints)
		}
		if hints[0].Source != classifier.EvidenceDNSAnswer || !hints[1].ECHRelated {
			t.Fatalf("protocol %d evidence=%+v", protocol, hints)
		}
	}
}

func TestDNSHintCorrelatorKeepsCNAMEAndClientScopeSeparate(t *testing.T) {
	clk := clock.NewFixed(time.Unix(200, 0))
	store := classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, clk)
	resolver := HintSetResolverFunc(func(domain string, client classifier.ClientKey, sourceDevice string, protocol uint8) []HintSetCandidate {
		if domain == "rr.googlevideo.com" && sourceDevice == "client-a" {
			return []HintSetCandidate{{SetID: "youtube-video", Confidence: 89}}
		}
		return nil
	})
	correlator := NewDNSHintCorrelator(store, resolver, 6)
	clientA := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.21"), VLAN: 10}
	clientB := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.22"), VLAN: 10}
	observation := DNSObservation{
		Client:    clientA,
		QueryName: "r1.example",
		Canonical: "rr.googlevideo.com",
		Timestamp: clk.Now(),
		Answers:   []DNSAddress{{Name: "rr.googlevideo.com", CanonicalName: "rr.googlevideo.com", IP: netip.MustParseAddr("203.0.113.21"), TTL: time.Minute}},
	}
	if result, err := correlator.ObserveResponse(observation, "client-a", 1); err != nil || result.PositiveHints != 1 {
		t.Fatalf("CNAME correlation result=%+v err=%v", result, err)
	}
	observation.Client = clientB
	if result, err := correlator.ObserveResponse(observation, "client-b", 1); err != nil || result.PositiveHints != 0 {
		t.Fatalf("cross-client correlation result=%+v err=%v", result, err)
	}
	if got := store.Lookup(clientB, netip.MustParseAddr("203.0.113.21"), 6); len(got) != 0 {
		t.Fatalf("CNAME hint leaked to second client: %+v", got)
	}
}

func TestDNSHintCorrelatorNegativeAndTruncatedAreDiagnosticOnly(t *testing.T) {
	clk := clock.NewFixed(time.Unix(300, 0))
	store := classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, clk)
	resolver := HintSetResolverFunc(func(string, classifier.ClientKey, string, uint8) []HintSetCandidate {
		return []HintSetCandidate{{SetID: "should-not-appear", Confidence: 89}}
	})
	correlator := NewDNSHintCorrelator(store, resolver, 6)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.23")}
	base := DNSObservation{
		Client:    client,
		QueryName: "missing.example",
		Timestamp: clk.Now(),
		Answers:   []DNSAddress{{Name: "missing.example", IP: netip.MustParseAddr("203.0.113.23"), TTL: time.Minute}},
	}
	base.RCode = 3
	result, err := correlator.ObserveResponse(base, "client", 1)
	if err != nil || !result.Negative || result.PositiveHints != 0 {
		t.Fatalf("NXDOMAIN result=%+v err=%v", result, err)
	}
	base.RCode = 0
	base.Truncated = true
	result, err = correlator.ObserveResponse(base, "client", 1)
	if err != nil || !result.Truncated || result.PositiveHints != 0 {
		t.Fatalf("truncated result=%+v err=%v", result, err)
	}
	if got := store.Lookup(client, netip.MustParseAddr("203.0.113.23"), 6); len(got) != 0 {
		t.Fatalf("negative response created hint: %+v", got)
	}
}

func TestDNSHintCorrelatorConfigGenerationAndResolverFailover(t *testing.T) {
	clk := clock.NewFixed(time.Unix(400, 0))
	store := classifier.NewHostHintStore(classifier.HostHintStoreConfig{}, clk)
	available := true
	resolver := HintSetResolverFunc(func(string, classifier.ClientKey, string, uint8) []HintSetCandidate {
		if !available {
			return nil
		}
		return []HintSetCandidate{{SetID: "youtube-api", Confidence: 89}}
	})
	correlator := NewDNSHintCorrelator(store, resolver, 6)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.24")}
	observation := DNSObservation{
		Client:    client,
		QueryName: "api.youtube.com",
		Timestamp: clk.Now(),
		Answers:   []DNSAddress{{Name: "api.youtube.com", IP: netip.MustParseAddr("203.0.113.24"), TTL: time.Minute}},
	}
	if _, err := correlator.ObserveResponse(observation, "client", 7); err != nil {
		t.Fatal(err)
	}
	available = false
	if result, err := correlator.ObserveResponse(observation, "client", 8); err != nil || result.PositiveHints != 0 {
		t.Fatalf("resolver failover result=%+v err=%v", result, err)
	}
	if got := store.LookupForGeneration(client, netip.MustParseAddr("203.0.113.24"), 6, 8); len(got) != 0 {
		t.Fatalf("stale generation survived revalidation: %+v", got)
	}
}
