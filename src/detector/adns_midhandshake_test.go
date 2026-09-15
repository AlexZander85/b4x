package detector

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/faultlab"
	"github.com/daniellavrushin/b4/transport/dns/providers"
)

// relabeledProbeProvider gives a second controlled fixture an independent
// resolver identity while preserving the real provider implementation. The
// fixtures are separate server instances; only their loopback address is the
// same, which would otherwise collapse NewUDPProvider's identity hash.
type relabeledProbeProvider struct {
	inner dnspath.DNSPathProvider
	id    dnspath.DNSPathID
}

func (p *relabeledProbeProvider) ID() dnspath.DNSPathID { return p.id }
func (p *relabeledProbeProvider) Capabilities() dnspath.DNSPathCapabilities {
	return p.inner.Capabilities()
}
func (p *relabeledProbeProvider) Prepare(ctx context.Context, req dnspath.DNSPrepareRequest) (dnspath.PreparedDNSPath, error) {
	prepared, err := p.inner.Prepare(ctx, req)
	if err == nil {
		prepared.PathID = p.id
	}
	return prepared, err
}
func (p *relabeledProbeProvider) Probe(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSProbeQuery) (dnspath.DNSPathProbeOutcome, error) {
	out, err := p.inner.Probe(ctx, prepared, q)
	out.PathID = p.id
	return out, err
}
func (p *relabeledProbeProvider) Resolve(ctx context.Context, prepared dnspath.PreparedDNSPath, q dnspath.DNSQuery) (dnspath.DNSResponse, error) {
	return p.inner.Resolve(ctx, prepared, q)
}
func (p *relabeledProbeProvider) Health(ctx context.Context, prepared dnspath.PreparedDNSPath) dnspath.DNSPathHealth {
	return p.inner.Health(ctx, prepared)
}
func (p *relabeledProbeProvider) Retire(ctx context.Context, prepared dnspath.PreparedDNSPath) error {
	return p.inner.Retire(ctx, prepared)
}

// The 2026-08 DPI family filter: TCP connects, RST after TLS ClientHello on
// the DoT path, while plaintext UDP stays alive. Diagnosis must mark the DoT
// family as mid-handshake filtered and still promote independently corroborated
// UDP paths — never collapse into "no DNS" and never weaken quorum to do so.
func TestADNSDiagnosisMidHandshakeFilteredDoTFallsBackToUDP(t *testing.T) {
	fxTCP, addrTCP, err := faultlab.StartTCP(faultlab.ModeTCPResetAfterAccept)
	if err != nil {
		t.Fatal(err)
	}
	defer fxTCP.Close()
	fxUDP, addrUDP, err := faultlab.StartUDP(faultlab.ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer fxUDP.Close()
	fxUDP2, addrUDP2, err := faultlab.StartUDP(faultlab.ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer fxUDP2.Close()

	_, portTCP, _ := net.SplitHostPort(addrTCP)
	var portTCPNum int
	for _, c := range portTCP {
		portTCPNum = portTCPNum*10 + int(c-'0')
	}

	dot := providers.NewDoTProvider("dns.example.test", []net.IP{net.ParseIP("127.0.0.1")}, portTCPNum, 0, "catalog-test")
	dot.Timeout = time.Second
	ip, _ := netip.ParseAddr("127.0.0.1")
	udp := providers.NewUDPProvider(ip, faultlab.PortOf(addrUDP), 0, "catalog-test")
	udp.Timeout = time.Second
	udp2Inner := providers.NewUDPProvider(ip, faultlab.PortOf(addrUDP2), 0, "catalog-test")
	udp2Inner.Timeout = time.Second
	udp2ID := udp2Inner.ID()
	udp2ID.ResolverID = "r-independent-udp"
	udp2ID.EndpointID = "e-independent-udp"
	udp2 := &relabeledProbeProvider{inner: udp2Inner, id: udp2ID}

	diag, err := RunADNSDiagnosis(context.Background(), ADNSDiagnosisInput{
		Providers:     []dnspath.DNSPathProvider{dot, udp, udp2},
		Policy:        diagnosisPolicy(),
		Suite:         CanonicalSuite("example.com", "control.example.net"),
		AttemptsQuick: 2, AttemptsValid: 5,
		NetworkContext: "wan-lab", Generation: 4, RuntimeEpoch: "e1",
		CatalogVersion: "catalog-test", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	// DoT family must be flagged as mid-handshake filtered.
	found := false
	for _, fam := range diag.EncryptedFamiliesFiltered {
		if fam == dnspath.DNSPathDoT {
			found = true
		}
		if fam == dnspath.DNSPathUDP {
			t.Fatal("plaintext UDP must never be listed as encrypted-filtered")
		}
	}
	if !found {
		t.Fatalf("dot family must be in EncryptedFamiliesFiltered, got %v", diag.EncryptedFamiliesFiltered)
	}

	// Outcomes must carry the precise class+stage signature.
	sawClass := false
	for _, out := range diag.Outcomes {
		if out.PathID.Family == dnspath.DNSPathDoT && out.Class == dnspath.OutcomeTLSMidHandshakeReset {
			sawClass = true
			if out.Stage != dnspath.StageTLS {
				t.Fatalf("mid-handshake cut must be attributed to tls stage, got %s", out.Stage)
			}
		}
	}
	if !sawClass {
		t.Fatal("no TLS_MID_HANDSHAKE_RESET outcome for dot path")
	}

	// Plaintext UDP remains a valid candidate only after independent quorum.
	if diag.Profile == nil {
		t.Fatal("profile must be compiled")
	}
	if diag.Profile.Primary.Family != dnspath.DNSPathUDP {
		t.Fatalf("udp must be primary after dot family filter, got %s", diag.Profile.Primary.Family)
	}
}
