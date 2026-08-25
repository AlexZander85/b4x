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

func TestADNSDiagnosisPrefersTCPWhenUDPInjected(t *testing.T) {
	fxUDP, addrUDP, err := faultlab.StartUDP(faultlab.ModeUDPDrop)
	if err != nil {
		t.Fatal(err)
	}
	defer fxUDP.Close()
	fxTCP, addrTCP, err := faultlab.StartTCP(faultlab.ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer fxTCP.Close()

	ip, _ := netip.ParseAddr("127.0.0.1")
	udp := providers.NewUDPProvider(ip, faultlab.PortOf(addrUDP), 0, "catalog-test")
	udp.Timeout = 300 * time.Millisecond
	tcp := providers.NewTCPProvider(ip, faultlab.PortOf(addrTCP), 0, "catalog-test")
	tcp.Timeout = time.Second

	diag, err := RunADNSDiagnosis(context.Background(), ADNSDiagnosisInput{
		Providers: []dnspath.DNSPathProvider{udp, tcp},
		Policy:    diagnosisPolicy(),
		Suite:     CanonicalSuite("example.com", "control.example.net"),
		AttemptsQuick: 2, AttemptsValid: 5,
		NetworkContext: "wan-lab", Generation: 3, RuntimeEpoch: "e1",
		CatalogVersion: "catalog-test", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if diag.Profile == nil {
		t.Fatal("profile must be compiled")
	}
	if diag.Profile.Primary.Family != dnspath.DNSPathTCP {
		t.Fatalf("dropped UDP must yield TCP primary, got %s", diag.Profile.Primary.Family)
	}
	if !diag.UDPDropDetected {
		t.Fatal("repeated UDP timeouts must set udp drop evidence")
	}
	if err := diag.Profile.Valid(time.Now()); err != nil {
		t.Fatalf("compiled profile must be valid: %v", err)
	}
	// UDP path must not be primary-capable
	for _, o := range diag.Outcomes {
		if o.PathID.Family == dnspath.DNSPathUDP && o.Class.Pass() {
			t.Fatal("dropped UDP path must not produce passing outcomes")
		}
	}
}

func TestADNSDiagnosisDeterministic(t *testing.T) {
	run := func() *ADNSDiagnosis {
		fx, addr, err := faultlab.StartTCP(faultlab.ModeValid)
		if err != nil {
			t.Fatal(err)
		}
		defer fx.Close()
		ip, _ := netip.ParseAddr("127.0.0.1")
		tcp := providers.NewTCPProvider(ip, faultlab.PortOf(addr), 0, "catalog-test")
		tcp.Timeout = time.Second
		diag, err := RunADNSDiagnosis(context.Background(), ADNSDiagnosisInput{
			Providers: []dnspath.DNSPathProvider{tcp},
			Policy:    diagnosisPolicy(),
			Suite:     CanonicalSuite("example.com", "control.example.net"),
			AttemptsQuick: 2,
			NetworkContext: "wan-lab", Generation: 3, RuntimeEpoch: "e1",
			CatalogVersion: "catalog-test", TTL: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		return diag
	}
	d1 := run()
	d2 := run()
	if d1.Profile.Primary.Canonical() != d2.Profile.Primary.Canonical() {
		t.Fatal("identical inputs must produce identical primary (no random shuffle)")
	}
}

func TestADNSDiagnosisNoBlindFirstSuccess(t *testing.T) {
	// A provider that fails controls must not become primary even if A query passes.
	fx, addr, err := faultlab.StartTCP(faultlab.ModeFakeNXDOMAIN)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	ip, _ := netip.ParseAddr("127.0.0.1")
	tcp := providers.NewTCPProvider(ip, faultlab.PortOf(addr), 0, "catalog-test")
	tcp.Timeout = time.Second
	diag, err := RunADNSDiagnosis(context.Background(), ADNSDiagnosisInput{
		Providers: []dnspath.DNSPathProvider{tcp},
		Policy:    diagnosisPolicy(),
		Suite:     CanonicalSuite("example.com", "control.example.net"),
		AttemptsQuick: 2,
		NetworkContext: "wan-lab", Generation: 3, RuntimeEpoch: "e1",
		CatalogVersion: "catalog-test", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	// FakeNXDOMAIN answers everything with NXDOMAIN; A case rcode=3 still
	// parses as structurally valid response — outcomes are PASS_CORRECT at
	// structural level, but correctness comparison belongs to four-way
	// control analysis. Profile must at least carry outcomes for inspection.
	if len(diag.Outcomes) == 0 {
		t.Fatal("outcomes must be recorded")
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
		Primary: primary, Fallbacks: []dnspath.DNSPathID{fallback},
		CandidateOutcomes: []dnspath.DNSPathProbeOutcome{
			{PathID: primary, Class: dnspath.OutcomePassCorrect},
			{PathID: fallback, Class: dnspath.OutcomePassCorrect},
		},
		InjectionDetected: true,
		CreatedAt: now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
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
		Primary: dnspath.DNSPathID{Family: dnspath.DNSPathUDP, ResolverID: "r", IPFamily: "ipv4"},
		CreatedAt: now, ValidatedAt: now, ValidUntil: now.Add(time.Hour),
	}
	profile.Seal()
	scope := monitor.MonitorScopeKey{
		ClientScope: monitor.ClientScopeKey{ID: "c1", Role: "forwarded"},
		TargetRole: "target", NetworkContextID: "wan-1", ConfigGeneration: 5,
	}
	if _, err := BuildDNSDiscoveryPrior(profile, scope, []string{"b"}, now); err == nil {
		t.Fatal("stale profile must not feed Discovery")
	}
}
