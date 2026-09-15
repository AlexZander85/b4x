package detector

import (
	"testing"

	"github.com/daniellavrushin/b4/monitor"
)

func pathOutcome(mode ProbePathMode, ok bool) PathProbeOutcome {
	return PathProbeOutcome{
		Scope: testScope(),
		Mode:  mode,
		Observation: VantageObservation{
			TargetID:      "target-a",
			Stage:         StageTLS,
			ExactEndpoint: true,
			Available:     true,
			Success:       ok,
		},
		EvidenceRefs: []string{string(mode) + ":evidence"},
	}
}

func dnsObservation(transport DNSControlTransport, ok bool, answers ...string) DNSControlObservation {
	return DNSControlObservation{Scope: testScope(), QNameHash: "q", Transport: transport, Success: ok, Answers: answers}
}

func TestCompareDirectAndProcessedDetectsDPIInterference(t *testing.T) {
	s := CompareDirectAndProcessed(pathOutcome(PathNativeDirect, false), pathOutcome(PathProduction, true))
	if s.Verdict != DifferentialDPIInterference || !s.SupportsDPI || s.Confidence < 0.9 {
		t.Fatalf("unexpected signal: %+v", s)
	}
}

func TestCompareDirectAndProcessedAvoidsFalseDPIClaim(t *testing.T) {
	s := CompareDirectAndProcessed(pathOutcome(PathNativeDirect, false), pathOutcome(PathProduction, false))
	if s.Verdict != DifferentialOriginOrNetwork || s.SupportsDPI || !s.DeferAggressiveEscalation {
		t.Fatalf("both-failed pair must not claim DPI: %+v", s)
	}

	s = CompareDirectAndProcessed(pathOutcome(PathNativeDirect, true), pathOutcome(PathCandidate, false))
	if s.Verdict != DifferentialProcessedRegression || s.SupportsDPI {
		t.Fatalf("processed regression misclassified: %+v", s)
	}
}

func TestCompareDirectAndProcessedRejectsMismatchedStage(t *testing.T) {
	direct := pathOutcome(PathNativeDirect, false)
	processed := pathOutcome(PathProduction, true)
	processed.Observation.Stage = StageHTTP
	s := CompareDirectAndProcessed(direct, processed)
	if s.Verdict != DifferentialNoOpinion || s.SupportsDPI {
		t.Fatalf("mismatched stage accepted: %+v", s)
	}
}

func TestCompareDirectAndProcessedRejectsCrossGeneration(t *testing.T) {
	direct := pathOutcome(PathNativeDirect, false)
	processed := pathOutcome(PathProduction, true)
	processed.Scope.ConfigGeneration++
	s := CompareDirectAndProcessed(direct, processed)
	if s.Verdict != DifferentialNoOpinion || s.SupportsDPI {
		t.Fatalf("cross-generation path evidence accepted: %+v", s)
	}
}

func TestDNSControlBogusClassicVsDoHSupportsHijack(t *testing.T) {
	classic := dnsObservation(DNSControlClassic, true, "stub")
	classic.Bogus = true
	classic.EvidenceRefs = []string{"udp"}
	doh := dnsObservation(DNSControlDoH, true, "real-a", "real-b")
	doh.EvidenceRefs = []string{"doh"}
	s := CompareClassicDNSWithEncrypted(classic, doh)
	if s.Verdict != DifferentialDNSHijackSuspected || !s.SupportsDPI || s.Confidence < 0.9 {
		t.Fatalf("bogus-vs-DoH not detected: %+v", s)
	}
}

func TestDNSControlClassicFailureVsDoTSupportsInterference(t *testing.T) {
	classic := dnsObservation(DNSControlClassic, false)
	dot := dnsObservation(DNSControlDoT, true, "a")
	s := CompareClassicDNSWithEncrypted(classic, dot)
	if s.Verdict != DifferentialDNSClassicInterference || !s.SupportsDPI {
		t.Fatalf("classic failure vs DoT not detected: %+v", s)
	}
}

func TestDNSControlCDNDivergenceNeedsCorroboration(t *testing.T) {
	classic := dnsObservation(DNSControlClassic, true, "edge-a")
	doh := dnsObservation(DNSControlDoH, true, "edge-b")
	s := CompareClassicDNSWithEncrypted(classic, doh)
	if s.Verdict != DifferentialDNSDivergence || s.SupportsDPI || !s.DeferAggressiveEscalation {
		t.Fatalf("CDN variance became a false hijack claim: %+v", s)
	}
}

func TestDNSControlSameSetIsConsistentRegardlessOfOrder(t *testing.T) {
	classic := dnsObservation(DNSControlClassic, true, "b", "a", "a")
	doh := dnsObservation(DNSControlDoH, true, "a", "b")
	s := CompareClassicDNSWithEncrypted(classic, doh)
	if s.Verdict != DifferentialDNSConsistent || s.SupportsDPI {
		t.Fatalf("same DNS set not recognized: %+v", s)
	}
}

func TestDNSControlRejectsCrossGeneration(t *testing.T) {
	classic := dnsObservation(DNSControlClassic, false)
	doh := dnsObservation(DNSControlDoH, true, "a")
	doh.Scope.ConfigGeneration++
	s := CompareClassicDNSWithEncrypted(classic, doh)
	if s.Verdict != DifferentialNoOpinion || s.SupportsDPI {
		t.Fatalf("cross-generation DNS control accepted: %+v", s)
	}
}

func TestRecommendAlternativeEndpointBeforeAggressiveEscalation(t *testing.T) {
	outcomes := []DNSAddressOutcome{
		{SnapshotID: "snap", IPHash: "dead", IPFamily: "ipv4", AddressIndex: 0, Success: false, FailureCode: FailureTransportTimeout, Experiment: ClientObservedExactEndpoint, EvidenceRefs: []string{"dead-ref"}},
		{SnapshotID: "snap", IPHash: "slow", IPFamily: "ipv4", AddressIndex: 1, Success: true, Experiment: ClientObservedExactEndpoint, LatencyMS: 90, EvidenceRefs: []string{"slow-ref"}},
		{SnapshotID: "snap", IPHash: "fast", IPFamily: "ipv4", AddressIndex: 2, Success: true, Experiment: ClientObservedExactEndpoint, LatencyMS: 30, EvidenceRefs: []string{"fast-ref"}},
		{SnapshotID: "snap", IPHash: "v6", IPFamily: "ipv6", AddressIndex: 0, Success: true, Experiment: ClientObservedExactEndpoint, LatencyMS: 10},
	}
	d := RecommendAlternativeEndpoint("dead", outcomes)
	if d.Signal.Verdict != DifferentialAlternativeAvailable || d.AlternativeHash != "fast" || !d.Signal.DeferAggressiveEscalation {
		t.Fatalf("unexpected alternative decision: %+v", d)
	}
}

func TestRecommendAlternativeEndpointDoesNotCrossSnapshot(t *testing.T) {
	outcomes := []DNSAddressOutcome{
		{SnapshotID: "snap-a", IPHash: "dead", IPFamily: "ipv4", Success: false, Experiment: ClientObservedExactEndpoint},
		{SnapshotID: "snap-b", IPHash: "other", IPFamily: "ipv4", Success: true, Experiment: ClientObservedExactEndpoint, LatencyMS: 1},
	}
	d := RecommendAlternativeEndpoint("dead", outcomes)
	if d.Signal.Verdict != DifferentialNoOpinion || d.AlternativeHash != "" {
		t.Fatalf("cross-snapshot endpoint accepted: %+v", d)
	}
}

func testScope() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{ID: "client", Role: "forwarded"},
		TargetRole:       "target",
		NetworkContextID: "net",
		ConfigGeneration: 7,
	}
}

func TestAddDPISupportToGraphPreservesAuthority(t *testing.T) {
	s := DifferentialSignal{Kind: DifferentialPathPair, Verdict: DifferentialDPIInterference, SupportsDPI: true, Confidence: 0.95}

	g := NewEvidenceGraph()
	if !AddDPISupportToGraph(g, testScope(), "provisional", "dpi", monitor.AuthorityProvisionalFast, s) {
		t.Fatal("failed to add provisional signal")
	}
	if got := g.Confidence("dpi"); got.Supports != 0 || got.Score != 0 {
		t.Fatalf("provisional signal was silently upgraded: %+v", got)
	}

	if !AddDPISupportToGraph(g, testScope(), "authoritative", "dpi", monitor.AuthorityAuthoritativeABD, s) {
		t.Fatal("failed to add authoritative signal")
	}
	got := g.Confidence("dpi")
	if got.Supports != 1 || got.Score < 0.9 {
		t.Fatalf("authoritative differential signal missing: %+v", got)
	}
}

func TestAddDPISupportToGraphRejectsNonDPISignal(t *testing.T) {
	g := NewEvidenceGraph()
	s := DifferentialSignal{Kind: DifferentialAltEndpoint, Verdict: DifferentialAlternativeAvailable, SupportsDPI: false, Confidence: 0.9}
	if AddDPISupportToGraph(g, testScope(), "alt", "dpi", monitor.AuthorityAuthoritativeABD, s) {
		t.Fatal("non-DPI signal entered DPI support graph")
	}
}
