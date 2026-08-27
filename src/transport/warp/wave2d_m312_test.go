package transportwarp

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// ---- M3-12: provider independence is enforced by DNS-path proof ----

// Rule (a): a config of only a correlated cf-trace class has no dns-authority
// provider and cannot form a DNS-path-proven quorum — rejected at config time
// (honors the promise "single-cloudflare-trace-is-not-enough").
func TestNonRUGateConfigRequiresDNSAuthority(t *testing.T) {
	h := newGeoHarness(t)
	var gen atomic.Uint64
	log := &eventLog{}

	pa := newStubProvider("cf-1", deResult(t, testIP1))
	pb := newStubProvider("cf-2", deResult(t, testIP2))
	pa.class = ProviderClassCloudflareTrace
	pb.class = ProviderClassCloudflareTrace

	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, &gen)
	if _, err := NewNonRUGate(cfg); !errors.Is(err, ErrGeoConfig) {
		t.Fatalf("cf-only config must be rejected (no dns-authority), got %v", err)
	}
}

// A dns-authority provider alongside a cf-trace corroborator is a VALID config.
func TestNonRUGateConfigAcceptsDNSPlusCF(t *testing.T) {
	h := newGeoHarness(t)
	var gen atomic.Uint64
	log := &eventLog{}

	pa := newStubProvider("prov-a", deResult(t, testIP1))
	pb := newStubProvider("cf-1", deResult(t, testIP2))
	pa.class = ProviderClassDNSResolverAuthority
	pb.class = ProviderClassCloudflareTrace

	cfg := geoTestConfig(h, log, []GeoProvider{pa, pb}, &gen)
	if _, err := NewNonRUGate(cfg); err != nil {
		t.Fatalf("dns+cf config must be valid, got %v", err)
	}
}

// The DNSProof gate: only a dns-path-proven (DNSProof=true) observation votes.
// Two observations where only one is DNS-proven cannot satisfy a quorum of 2.
func TestNonRUGateDNSProofGate(t *testing.T) {
	now := time.Now()
	fresh := now.Add(time.Minute)
	vote := func(dns bool) GeoObservation {
		return GeoObservation{
			Provider: "p", Class: geoClassNonRU, Country: "DE",
			PublicIPHash: "h1", CounterDelta: 1, ExpiresAt: fresh, DNSProof: dns,
		}
	}
	dnsVote := vote(true)
	cfVote := vote(false)

	// 2 DNS-proven votes -> pass.
	if q := EvaluateGeoQuorum([]GeoObservation{dnsVote, dnsVote}, 2, now); q.Verdict != VerdictPassNonRU {
		t.Fatalf("2 dns-proof votes want pass, got %s", q.Verdict)
	}
	// dns-proof + non-dns-proof -> only 1 valid vote -> insufficient (fail-closed).
	q := EvaluateGeoQuorum([]GeoObservation{dnsVote, cfVote}, 2, now)
	if q.Valid != 1 {
		t.Fatalf("want 1 valid vote (dns proof only), got %d", q.Valid)
	}
	if !q.Insufficient || q.Verdict != VerdictInconclusive {
		t.Fatalf("1-proven/1-cf want insufficient/inconclusive, got ins=%v verdict=%s", q.Insufficient, q.Verdict)
	}
	// 2 non-dns-proof votes -> not enough -> never passes on cf-trace alone.
	if q := EvaluateGeoQuorum([]GeoObservation{cfVote, cfVote}, 2, now); q.Verdict == VerdictPassNonRU {
		t.Fatal("cf-only observations must never form a pass quorum")
	}
}
