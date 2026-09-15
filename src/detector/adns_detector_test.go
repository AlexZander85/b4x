package detector

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/monitor"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/faultlab"
	"github.com/daniellavrushin/b4/transport/dns/providers"
)

func diagnosisPolicy() dnspath.AdaptivePolicy {
	p := dnspath.DefaultAdaptivePolicy()
	p.Enabled = true
	p.RequireNoLogClaim = false
	p.RequireNoFilterClaim = false
	return p
}

type scriptedADNSProvider struct {
	id       dnspath.DNSPathID
	fail     dnspath.OutcomeClass
	calls    int
	prepared bool
}

func newScriptedADNSProvider(family dnspath.DNSPathFamily, resolver string) *scriptedADNSProvider {
	return &scriptedADNSProvider{id: dnspath.DNSPathID{
		Family: family, ResolverID: resolver, EndpointID: "e-" + resolver,
		IPFamily: "ipv4", CatalogVersion: "catalog-test",
	}}
}

func (p *scriptedADNSProvider) ID() dnspath.DNSPathID { return p.id }
func (p *scriptedADNSProvider) Capabilities() dnspath.DNSPathCapabilities {
	return dnspath.DNSPathCapabilities{State: dnspath.CapAvailable, IPv4: true}
}
func (p *scriptedADNSProvider) Prepare(_ context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	p.prepared = true
	return dnspath.PreparedDNSPath{PathID: p.id, Generation: req.Generation, PreparedAt: time.Now()}, nil
}
func (p *scriptedADNSProvider) Probe(_ context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	p.calls++
	out := dnspath.DNSPathProbeOutcome{
		PathID: prepared.PathID, QuerySuiteID: q.SuiteCase,
		Stage: dnspath.StageAnswer, Class: dnspath.OutcomeInconclusive,
		Latency: 10 * time.Millisecond, ResponseCount: 1, ObservedAt: time.Now(),
	}
	if p.fail != "" {
		out.Class = p.fail
		return out, nil
	}
	switch q.SuiteCase {
	case "NXDOMAIN":
		out.RCode = 3
		out.EvidenceRefs = []string{"authority-soa"}
	case "CNAME":
		out.CNAMEFingerprint = "cname-good"
	case "HTTPS":
		out.HTTPSFingerprint = "https-good"
	default:
		out.AnswerFingerprint = "addr-good"
	}
	return out, nil
}
func (p *scriptedADNSProvider) Resolve(_ context.Context, _ dnspath.PreparedDNSPath, _ dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	return dnspath.DNSResponse{}, nil
}
func (p *scriptedADNSProvider) Health(_ context.Context, _ dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return dnspath.DNSPathHealth{State: dnspath.CapReady}
}
func (p *scriptedADNSProvider) Retire(_ context.Context, _ dnspath.PreparedDNSPath) error { return nil }

func runQuorumDiagnosis(t *testing.T, providersList []dnspath.DNSPathProvider, deep bool) *ADNSDiagnosis {
	t.Helper()
	diag, err := RunADNSDiagnosis(context.Background(), ADNSDiagnosisInput{
		Providers: providersList, Policy: diagnosisPolicy(),
		Suite: CanonicalSuite("example.com", "control.example.net"),
		AttemptsQuick: 2, AttemptsValid: 5, Deep: deep,
		NetworkContext: "wan-lab", Generation: 3, RuntimeEpoch: "e1",
		CatalogVersion: "catalog-test", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return diag
}

func TestADNSDiagnosisRequiresIndependentResolverQuorum(t *testing.T) {
	only := newScriptedADNSProvider(dnspath.DNSPathTCP, "r-a")
	diag := runQuorumDiagnosis(t, []dnspath.DNSPathProvider{only}, false)
	if diag.Profile == nil || diag.Profile.Status != dnspath.ProfileStatusInvalid {
		t.Fatalf("one structurally valid resolver must not produce READY profile: %+v", diag.Profile)
	}
	for _, out := range diag.Outcomes {
		if out.Class.Pass() {
			t.Fatalf("single-resolver evidence must remain unpromoted: %+v", out)
		}
	}
}

func TestADNSDiagnosisBuildsReadyProfileAfterIndependentQuorum(t *testing.T) {
	a := newScriptedADNSProvider(dnspath.DNSPathTCP, "r-a")
	b := newScriptedADNSProvider(dnspath.DNSPathDoH, "r-b")
	diag := runQuorumDiagnosis(t, []dnspath.DNSPathProvider{a, b}, false)
	if diag.Profile == nil || diag.Profile.Status != dnspath.ProfileStatusReady {
		t.Fatalf("independent matching resolvers must produce READY profile: %+v", diag.Profile)
	}
	if err := diag.Profile.Valid(time.Now()); err != nil {
		t.Fatalf("compiled quorum profile must be valid: %v", err)
	}
	if diag.Profile.Confidence.Supports == 0 || diag.Profile.Confidence.Contradictions != 0 {
		t.Fatalf("unexpected confidence: %+v", diag.Profile.Confidence)
	}
	for _, out := range diag.Outcomes {
		if !out.Class.Pass() {
			t.Fatalf("quorum-confirmed canonical suite must pass, got %+v", out)
		}
	}
}

func TestADNSDiagnosisPrefersValidatedTCPWhenUDPBlocked(t *testing.T) {
	udp := newScriptedADNSProvider(dnspath.DNSPathUDP, "r-u")
	udp.fail = dnspath.OutcomeTimeout
	a := newScriptedADNSProvider(dnspath.DNSPathTCP, "r-a")
	b := newScriptedADNSProvider(dnspath.DNSPathTCP, "r-b")
	diag := runQuorumDiagnosis(t, []dnspath.DNSPathProvider{udp, a, b}, false)
	if diag.Profile.Status != dnspath.ProfileStatusReady || diag.Profile.Primary.Family != dnspath.DNSPathTCP {
		t.Fatalf("blocked UDP with validated TCP quorum must yield TCP primary: %+v", diag.Profile)
	}
	if !diag.UDPDropDetected {
		t.Fatal("repeated UDP timeouts must set udp-drop evidence")
	}
}

func TestADNSDiagnosisFakeNXDOMAINNeverBecomesCorrectnessProof(t *testing.T) {
	fx, addr, err := faultlab.StartTCP(faultlab.ModeFakeNXDOMAIN)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	ip := netip.MustParseAddr("127.0.0.1")
	tcp := providers.NewTCPProvider(ip, faultlab.PortOf(addr), 0, "catalog-test")
	tcp.Timeout = time.Second

	diag := runQuorumDiagnosis(t, []dnspath.DNSPathProvider{tcp}, false)
	if diag.Profile.Status != dnspath.ProfileStatusInvalid {
		t.Fatalf("forged NXDOMAIN resolver must not be promotable: %+v", diag.Profile)
	}
	sawNegativeProofFailure := false
	for _, out := range diag.Outcomes {
		if out.Class.Pass() {
			t.Fatalf("forged NXDOMAIN must never be PASS_CORRECT: %+v", out)
		}
		if out.QuerySuiteID == "NXDOMAIN" && out.FailureCode == "negative_without_authority_soa" {
			sawNegativeProofFailure = true
		}
	}
	if !sawNegativeProofFailure {
		t.Fatal("NXDOMAIN without authority SOA must be recorded as proof failure")
	}
}

func TestADNSDiagnosisDeepUsesValidationAttemptBudget(t *testing.T) {
	a := newScriptedADNSProvider(dnspath.DNSPathTCP, "r-a")
	b := newScriptedADNSProvider(dnspath.DNSPathDoH, "r-b")
	_ = runQuorumDiagnosis(t, []dnspath.DNSPathProvider{a, b}, true)
	want := len(CanonicalSuite("example.com", "control.example.net")) * 5
	if a.calls != want || b.calls != want {
		t.Fatalf("deep validation must use AttemptsValid: calls=(%d,%d) want=%d", a.calls, b.calls, want)
	}
}

func TestADNSDiagnosisDeterministic(t *testing.T) {
	run := func() *ADNSDiagnosis {
		a := newScriptedADNSProvider(dnspath.DNSPathTCP, "r-a")
		b := newScriptedADNSProvider(dnspath.DNSPathDoH, "r-b")
		return runQuorumDiagnosis(t, []dnspath.DNSPathProvider{a, b}, false)
	}
	d1 := run()
	d2 := run()
	if d1.Profile.Primary.Canonical() != d2.Profile.Primary.Canonical() {
		t.Fatal("identical inputs must produce identical primary (no random shuffle)")
	}
}

func TestADNSPriorFromProfile(t *testing.T) {
	now := time.Now()
	primary := dnspath.DNSPathID{Family: dnspath.DNSPathDoH, ResolverID: "r-a", EndpointID: "e-1", IPFamily: "ipv4"}
	fallback := dnspath.DNSPathID{Family: dnspath.DNSPathTCP, ResolverID: "r-b", EndpointID: "e-2", IPFamily: "ipv4"}
	profile := &dnspath.DNSPathProfile{
		ProfileID: "dnsprof-prior", Status: dnspath.ProfileStatusReady,
		NetworkContextID: "wan-1", ConfigGeneration: 5, RuntimeEpoch: "e1",
		QuerySuiteVersion: "adns-suite-v1",
		Primary:           primary, Fallbacks: []dnspath.DNSPathID{fallback},
		CandidateOutcomes: []dnspath.DNSPathProbeOutcome{
			{PathID: primary, Class: dnspath.OutcomePassCorrect},
			{PathID: fallback, Class: dnspath.OutcomePassCorrect},
		},
		InjectionDetected: true,
		CreatedAt:         now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
	}
	if err := profile.Seal(); err != nil {
		t.Fatal(err)
	}
	scope := monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{ID: "c1", Role: "forwarded"},
		TargetRole:       "target",
		NetworkContextID: "wan-1", ConfigGeneration: 5,
	}
	prior, err := BuildDNSDiscoveryPrior(profile, scope, []string{"baseline-current"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !prior.Valid() {
		t.Fatal("prior must satisfy existing DiscoverySearchPrior contract")
	}
	if len(prior.TargetOrder) != 2 || prior.TargetOrder[0] != primary.Hash() {
		t.Fatal("prior must order primary first")
	}
	found := false
	for _, h := range prior.Hypotheses {
		if h == "dns_early_injection" {
			found = true
		}
	}
	if !found {
		t.Fatal("injection hypothesis must propagate")
	}
	if len(prior.MandatoryBaselines) != 1 || prior.MandatoryBaselines[0] != "baseline-current" {
		t.Fatal("mandatory baselines must be retained")
	}
}

func TestADNSPriorRejectsStaleProfile(t *testing.T) {
	now := time.Now()
	profile := &dnspath.DNSPathProfile{
		ProfileID: "dnsprof-stale", Status: dnspath.ProfileStatusStale,
		NetworkContextID: "wan-1", ConfigGeneration: 5, RuntimeEpoch: "e1",
		QuerySuiteVersion: "adns-suite-v1",
		Primary:           dnspath.DNSPathID{Family: dnspath.DNSPathUDP, ResolverID: "r", IPFamily: "ipv4"},
		CreatedAt:         now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
	}
	profile.Seal()
	scope := monitor.MonitorScopeKey{
		ClientScope: monitor.ClientScopeKey{ID: "c1", Role: "forwarded"},
		TargetRole:  "target", NetworkContextID: "wan-1", ConfigGeneration: 5,
	}
	if _, err := BuildDNSDiscoveryPrior(profile, scope, []string{"b"}, now); err == nil {
		t.Fatal("stale profile must not feed Discovery")
	}
}
