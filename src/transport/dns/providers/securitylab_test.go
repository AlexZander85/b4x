package providers

import (
	"context"
	"net/netip"
	"testing"
	"time"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/faultlab"
)

func TestTCPProviderRejectsForgedBareNXDOMAIN(t *testing.T) {
	fx, addr, err := faultlab.StartTCP(faultlab.ModeFakeNXDOMAIN)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := NewTCPProvider(netip.MustParseAddr("127.0.0.1"), faultlab.PortOf(addr), 0, "catalog-test")
	p.Timeout = time.Second
	prepared, err := p.Prepare(context.Background(), dnspath.DNSPrepareRequest{Generation: 1})
	if err != nil {
		t.Fatal(err)
	}

	out, err := p.Probe(context.Background(), prepared, dnspath.DNSProbeQuery{
		Name: "missing.example", NameHash: dnspath.HashQName("missing.example"),
		QType: 1, SuiteCase: "NXDOMAIN", Timeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Class.Pass() || out.FailureCode != "negative_without_authority_soa" {
		t.Fatalf("forged NXDOMAIN probe = %+v", out)
	}
	if _, err := p.Resolve(context.Background(), prepared, dnspath.DNSQuery{
		Name: "missing.example", NameHash: dnspath.HashQName("missing.example"), QType: 1, TxID: 1,
	}); err == nil {
		t.Fatal("production resolve must reject bare forged NXDOMAIN")
	}
}

func TestTCPProviderAcceptsAuthoritativeNXDOMAIN(t *testing.T) {
	fx, addr, err := faultlab.StartTCP(faultlab.ModeValid)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	p := NewTCPProvider(netip.MustParseAddr("127.0.0.1"), faultlab.PortOf(addr), 0, "catalog-test")
	p.Timeout = time.Second
	prepared, err := p.Prepare(context.Background(), dnspath.DNSPrepareRequest{Generation: 1})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.Resolve(context.Background(), prepared, dnspath.DNSQuery{
		Name: "nonexistent.example.com", NameHash: dnspath.HashQName("nonexistent.example.com"), QType: 1, TxID: 2,
	})
	if err != nil {
		t.Fatalf("SOA-backed NXDOMAIN must be accepted: %v", err)
	}
	if resp.RCode != 3 {
		t.Fatalf("rcode=%d want NXDOMAIN", resp.RCode)
	}
}

func TestSplitHostPortSupportsIPv4AndIPv6(t *testing.T) {
	for _, tc := range []struct {
		in   string
		host string
		port int
	}{
		{"127.0.0.1:5300", "127.0.0.1", 5300},
		{"[::1]:5301", "::1", 5301},
	} {
		host, port, err := splitHostPort(tc.in)
		if err != nil {
			t.Fatalf("splitHostPort(%q): %v", tc.in, err)
		}
		if host != tc.host || port != tc.port {
			t.Fatalf("splitHostPort(%q)=(%q,%d), want (%q,%d)", tc.in, host, port, tc.host, tc.port)
		}
	}
	if _, _, err := splitHostPort("127.0.0.1:not-a-port"); err == nil {
		t.Fatal("invalid listen port must be rejected")
	}
}
