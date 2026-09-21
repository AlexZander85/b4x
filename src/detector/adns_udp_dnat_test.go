package detector

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/faultlab"
	"github.com/daniellavrushin/b4/transport/dns/providers"
)

// startForgedNXDOMAINResponder models the TSPU/НСДИ UDP responder from the
// 2026-08 article: every query is answered with a bare NXDOMAIN that has the
// AA bit set and an EMPTY authority section (no SOA negative proof). TCP to the
// same apparent resolver is not intercepted and returns real answers.
func startForgedNXDOMAINResponder(t *testing.T) (string, func()) {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if resp := forgedNXDOMAIN(buf[:n]); resp != nil {
				_, _ = conn.WriteToUDP(resp, src)
			}
		}
	}()
	return conn.LocalAddr().String(), func() { _ = conn.Close() }
}

func forgedNXDOMAIN(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	out := make([]byte, 12)
	copy(out[0:2], query[0:2]) // same transaction id
	// QR=1, AA=1, RD=1, RA=1, rcode=3 (NXDOMAIN) — exactly the article header.
	binary.BigEndian.PutUint16(out[2:4], 0x8000|0x0400|0x0100|0x0080|0x0003)
	binary.BigEndian.PutUint16(out[4:6], 1) // qd; an=ns=ar=0
	return append(out, query[12:]...)
}

func TestADNSArticleUDPDNATForgedNXDOMAINBypassedByTCP(t *testing.T) {
	fakeAddr, stop := startForgedNXDOMAINResponder(t)
	defer stop()

	realUDP, addrU, err := faultlab.StartUDPOn("127.0.0.2", faultlab.ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer realUDP.Close()
	realTCP, addrT, err := faultlab.StartTCPOn("127.0.0.3", faultlab.ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer realTCP.Close()

	forged := providers.NewUDPProvider(netip.MustParseAddr("127.0.0.1"), faultlab.PortOf(fakeAddr), 0, "catalog-test")
	forged.Timeout = time.Second
	controlUDP := providers.NewUDPProvider(netip.MustParseAddr("127.0.0.2"), faultlab.PortOf(addrU), 0, "catalog-test")
	controlTCP := providers.NewTCPProvider(netip.MustParseAddr("127.0.0.3"), faultlab.PortOf(addrT), 0, "catalog-test")

	diag, err := RunADNSDiagnosis(context.Background(), ADNSDiagnosisInput{
		Providers: []dnspath.DNSPathProvider{forged, controlUDP, controlTCP},
		Policy:    diagnosisPolicy(),
		Suite:     CanonicalSuite("blocked.example", "control.example.net"),
		Deep:      true, AttemptsQuick: 2, AttemptsValid: 3,
		NetworkContext: "wan-article", Generation: 1, RuntimeEpoch: "t",
		CatalogVersion: "catalog-test", TTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}

	if !diag.PoisoningDetected {
		t.Fatal("repeated forged UDP NXDOMAIN must set poisoning evidence")
	}
	if diag.Profile == nil || diag.Profile.Status != dnspath.ProfileStatusReady {
		t.Fatalf("independently validated TCP/UDP paths must keep a READY bypass profile: %+v", diag.Profile)
	}
	selected := append([]dnspath.DNSPathID{diag.Profile.Primary}, diag.Profile.Fallbacks...)
	for _, p := range selected {
		if p.Hash() == forged.ID().Hash() {
			t.Fatal("the DNAT-forged UDP path must never be selected")
		}
	}
	for _, out := range diag.Outcomes {
		if out.PathID.Hash() != forged.ID().Hash() {
			continue
		}
		if out.Class.Pass() {
			t.Fatalf("forged UDP evidence must never pass: %+v", out)
		}
		if out.QuerySuiteID == "A" && out.FailureCode != "forged_nxdomain_aa_empty_authority" {
			t.Fatalf("article signature must be attributed to forged AA/empty-authority NXDOMAIN, got %q", out.FailureCode)
		}
	}
}
