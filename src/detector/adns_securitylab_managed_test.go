package detector

import (
	"context"
	"testing"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

type securityLabTrustedProvider struct{ *securityLabProvider }

func (p *securityLabTrustedProvider) Capabilities() dnspath.DNSPathCapabilities {
	return dnspath.DNSPathCapabilities{
		State: dnspath.CapAvailable, IPv4: true,
		DNSSEC: true, NoLogClaim: true, NoFilterClaim: true, CatalogTrusted: true,
	}
}

func TestSecurityLabUDPInterceptionHasEncryptedBypassUnderDefaultPrivacyPolicy(t *testing.T) {
	victimUDP := &securityLabProvider{poisoned: true, id: dnspath.DNSPathID{
		Family: dnspath.DNSPathUDP, ResolverID: "resolver-victim", EndpointID: "victim-53", IPFamily: "ipv4", CatalogVersion: "securitylab-test",
	}}
	victimTCP := &securityLabProvider{id: dnspath.DNSPathID{
		Family: dnspath.DNSPathTCP, ResolverID: "resolver-victim", EndpointID: "victim-53", IPFamily: "ipv4", CatalogVersion: "securitylab-test",
	}}
	managedA := &securityLabTrustedProvider{&securityLabProvider{id: dnspath.DNSPathID{
		Family: dnspath.DNSPathDNSCrypt, ResolverID: "resolver-managed-a", EndpointID: "managed-a", IPFamily: "ipv4", CatalogVersion: "managed-test",
	}}}
	managedB := &securityLabTrustedProvider{&securityLabProvider{id: dnspath.DNSPathID{
		Family: dnspath.DNSPathDNSCrypt, ResolverID: "resolver-managed-b", EndpointID: "managed-b", IPFamily: "ipv4", CatalogVersion: "managed-test",
	}}}

	policy := dnspath.DefaultAdaptivePolicy()
	diag, err := RunADNSDiagnosis(context.Background(), ADNSDiagnosisInput{
		Providers: []dnspath.DNSPathProvider{victimUDP, victimTCP, managedA, managedB},
		Policy:    policy,
		Suite:     CanonicalSuiteWithControls("blocked.example", "www.blocked.example", "control.example"),
		Deep:      true, AttemptsQuick: 2, AttemptsValid: 3,
		NetworkContext: "wan-securitylab", Generation: 1, RuntimeEpoch: "test",
		CatalogVersion: "catalog-set-test", PolicyDigest: policy.Digest(), TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !diag.PoisoningDetected {
		t.Fatal("forged UDP NXDOMAIN must remain attributable even when encrypted bypass exists")
	}
	if diag.Profile == nil || diag.Profile.Status != dnspath.ProfileStatusReady {
		t.Fatalf("default privacy policy with verified managed paths must yield READY profile: %+v", diag.Profile)
	}
	if diag.Profile.Primary.Family != dnspath.DNSPathDNSCrypt {
		t.Fatalf("default privacy policy should promote verified encrypted bypass, got %s", diag.Profile.Primary.Family)
	}
	if len(diag.Profile.Fallbacks) == 0 || diag.Profile.Fallbacks[0].Family != dnspath.DNSPathDNSCrypt {
		t.Fatalf("verified independent encrypted fallback required, got %+v", diag.Profile.Fallbacks)
	}
	for _, selected := range append([]dnspath.DNSPathID{diag.Profile.Primary}, diag.Profile.Fallbacks...) {
		if selected.Hash() == victimUDP.id.Hash() {
			t.Fatal("poisoned UDP path must never enter production ladder")
		}
	}
}
