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

// The 2026-08 DPI family filter: TCP connects, RST after TLS ClientHello on
// the DoT path, while plaintext UDP to the same resolver IP stays alive.
// Diagnosis must mark the DoT family as mid-handshake filtered and still
// promote the UDP path — never collapse into "no DNS".
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

	diag, err := RunADNSDiagnosis(context.Background(), ADNSDiagnosisInput{
		Providers:     []dnspath.DNSPathProvider{dot, udp},
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

	// Plaintext UDP to the same resolver stays a valid candidate and wins.
	if diag.Profile == nil {
		t.Fatal("profile must be compiled")
	}
	if diag.Profile.Primary.Family != dnspath.DNSPathUDP {
		t.Fatalf("udp must be primary after dot family filter, got %s", diag.Profile.Primary.Family)
	}
}
