package providers

import (
	"net"
	"testing"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

func TestDoHHostnameRequiresExplicitBootstrap(t *testing.T) {
	p := NewDoHProvider("https://resolver.example/dns-query", 0, "catalog-test")
	caps := p.Capabilities()
	if caps.State != dnspath.CapBlockedByBootstrap {
		t.Fatalf("hostname DoH without bootstrap state=%s want %s", caps.State, dnspath.CapBlockedByBootstrap)
	}
}

func TestDoHHostnameWithBootstrapIsAvailable(t *testing.T) {
	p := NewDoHProviderWithBootstrap(
		"https://resolver.example/dns-query",
		[]net.IP{net.ParseIP("192.0.2.53")},
		0,
		"catalog-test",
	)
	caps := p.Capabilities()
	if caps.State != dnspath.CapAvailable {
		t.Fatalf("hostname DoH with explicit bootstrap state=%s reason=%q", caps.State, caps.Reason)
	}
	if p.ServerName != "resolver.example" {
		t.Fatalf("TLS server name=%q", p.ServerName)
	}
}

func TestDoHIPLiteralDoesNotNeedSystemDNSBootstrap(t *testing.T) {
	p := NewDoHProvider("https://192.0.2.53/dns-query", 0, "catalog-test")
	if caps := p.Capabilities(); caps.State != dnspath.CapAvailable {
		t.Fatalf("IP-literal DoH must not depend on system DNS: %+v", caps)
	}
}
