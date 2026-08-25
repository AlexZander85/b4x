package dnspath

import (
	"testing"
	"time"
)

func path(f DNSPathFamily, resolver string) DNSPathID {
	return DNSPathID{Family: f, ResolverID: resolver, EndpointID: "e-" + resolver, IPFamily: "ipv4"}
}

func policyFixture() AdaptivePolicy {
	p := DefaultAdaptivePolicy()
	p.Enabled = true
	p.AllowManagedDNSCrypt = true
	return p
}

func TestDeterministicOrdering(t *testing.T) {
	pol := policyFixture()
	cands := []CandidateEvidence{
		{Path: path(DNSPathDoH, "r-b"), CorrectnessPass: true, ControlsPass: true, Stability: 0.9, Latency: 50 * time.Millisecond, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true},
		{Path: path(DNSPathTCP, "r-a"), CorrectnessPass: true, ControlsPass: true, Stability: 0.9, Latency: 50 * time.Millisecond, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true},
	}
	first := RankCandidates(cands, pol)
	second := RankCandidates(cands, pol)
	if len(first) != 2 || len(second) != 2 {
		t.Fatal("both candidates must rank")
	}
	if first[0].Candidate.Path.Canonical() != second[0].Candidate.Path.Canonical() {
		t.Fatal("ordering must be deterministic for identical inputs")
	}
	// equal scores → canonical DNSPathID tie-break
	if first[0].Candidate.Path.Canonical() > first[1].Candidate.Path.Canonical() {
		t.Fatal("tie-break must be canonical path ordering")
	}
}

func TestCorrectnessIsGateNotScore(t *testing.T) {
	pol := policyFixture()
	cands := []CandidateEvidence{
		{Path: path(DNSPathDoH, "r-fast"), CorrectnessPass: false, ControlsPass: true, Stability: 1.0, Latency: time.Millisecond, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true},
		{Path: path(DNSPathTCP, "r-slow"), CorrectnessPass: true, ControlsPass: true, Stability: 0.5, Latency: 500 * time.Millisecond, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true},
	}
	ranked := RankCandidates(cands, pol)
	if len(ranked) != 1 || ranked[0].Candidate.Path.ResolverID != "r-slow" {
		t.Fatal("correctness failure must exclude candidate regardless of latency")
	}
}

func TestPolicyExclusions(t *testing.T) {
	pol := policyFixture()
	pol.AllowManagedDNSCrypt = false
	cands := []CandidateEvidence{
		{Path: path(DNSPathDNSCrypt, "r-m"), CorrectnessPass: true, ControlsPass: true, Stability: 1, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true},
	}
	if len(RankCandidates(cands, pol)) != 0 {
		t.Fatal("policy-disabled family must be excluded")
	}
	pol.AllowManagedDNSCrypt = true
	pol.ManualExclusions = []string{path(DNSPathDNSCrypt, "r-m").Hash()}
	if len(RankCandidates(cands, pol)) != 0 {
		t.Fatal("manual exclusion must be honored")
	}
}

func TestMinimumComplexityPreference(t *testing.T) {
	pol := policyFixture()
	pol.Preference = PreferenceMinimumDependency
	cands := []CandidateEvidence{
		{Path: path(DNSPathAnonymizedDNSCrypt, "r-anon"), CorrectnessPass: true, ControlsPass: true, Stability: 0.9, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true},
		{Path: path(DNSPathUDP, "r-plain"), CorrectnessPass: true, ControlsPass: true, Stability: 0.9, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true},
	}
	ranked := RankCandidates(cands, pol)
	if ranked[0].Candidate.Path.Family != DNSPathUDP {
		t.Fatal("minimum-dependency must prefer simplest native path at equal correctness/stability")
	}
}

func TestFallbackDiversity(t *testing.T) {
	pol := policyFixture()
	// primary DoH provider A endpoint 1; two same-resolver alternates + one TCP
	primary := path(DNSPathDoH, "r-a")
	cands := []CandidateEvidence{
		{Path: primary, CorrectnessPass: true, ControlsPass: true, Stability: 1, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true, CorrelatedGroup: "a"},
		{Path: path(DNSPathDoH, "r-a"), CorrectnessPass: true, ControlsPass: true, Stability: 0.99, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true, CorrelatedGroup: "a"},
		{Path: path(DNSPathTCP, "r-c"), CorrectnessPass: true, ControlsPass: true, Stability: 0.8, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true, CorrelatedGroup: "c"},
	}
	ranked := RankCandidates(cands, pol)
	_, fallbacks := CompileProfileSelection(ranked, 2, 20)
	for _, fb := range fallbacks {
		if fb.Candidate.Path.SamePathAlias(primary) {
			t.Fatal("fallback must not be an alias of primary")
		}
	}
	if len(fallbacks) == 0 || fallbacks[0].Candidate.Path.Family != DNSPathTCP {
		t.Fatal("diverse TCP fallback must outrank same-resolver DoH alias")
	}
}

func TestFailurePriorEarlyInjection(t *testing.T) {
	p := PriorFromEvidence(true, false, false, false, false, false, false, false)
	if p.Boost[DNSPathTCP] == 0 || p.Boost[DNSPathDoH] == 0 || p.Boost[DNSPathDNSCrypt] == 0 {
		t.Fatal("early injection must boost TCP/DoH/DNSCrypt")
	}
	if p.Penalize[DNSPathUDP] == 0 || p.Penalize[DNSPathSystemForward] == 0 {
		t.Fatal("early injection must penalize UDP/system paths")
	}
}

func TestFailurePriorUDP443Blocked(t *testing.T) {
	p := PriorFromEvidence(false, false, false, false, true, false, false, false)
	if !p.Exclude[DNSPathDoH3] || !p.Exclude[DNSPathDoQ] {
		t.Fatal("udp/443 blocked must exclude DoH3/DoQ")
	}
}

func TestPriorApplyIsDeterministic(t *testing.T) {
	pol := policyFixture()
	cands := []CandidateEvidence{
		{Path: path(DNSPathUDP, "r-u"), CorrectnessPass: true, ControlsPass: true, Stability: 0.9, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true},
		{Path: path(DNSPathDoH, "r-d"), CorrectnessPass: true, ControlsPass: true, Stability: 0.9, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true},
	}
	ranked := RankCandidates(cands, pol)
	prior := PriorFromEvidence(true, false, false, false, false, false, false, false)
	out1 := prior.ApplyTo(ranked)
	out2 := prior.ApplyTo(ranked)
	if out1[0].Candidate.Path.Canonical() != out2[0].Candidate.Path.Canonical() {
		t.Fatal("prior application must be deterministic")
	}
	if out1[0].Candidate.Path.Family == DNSPathUDP {
		t.Fatal("injection prior must demote UDP below DoH")
	}
}

func TestPreferenceNeverLowersCorrectness(t *testing.T) {
	for _, pref := range []Preference{PreferenceLowestLatency, PreferenceBalanced, PreferencePrivacy, PreferenceMinimumDependency} {
		pol := policyFixture()
		pol.Preference = pref
		c := CandidateEvidence{Path: path(DNSPathUDP, "r-x"), CorrectnessPass: false, ControlsPass: true, Stability: 1, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true}
		if c.Eligible(pol) {
			t.Fatalf("preference %s must never admit correctness-failing candidate", pref)
		}
	}
}
