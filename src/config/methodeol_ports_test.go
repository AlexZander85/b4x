package config

import (
	"slices"
	"testing"
)

func TestCollectTCPPortsAddsPort80ForHTTPMethodEOL(t *testing.T) {
	cfg := &Config{Sets: []*SetConfig{
		{Name: "m", Enabled: true, TCP: TCPConfig{HTTPMethodEOL: true}},
	}}
	ports := cfg.CollectTCPPorts()
	if !slices.Contains(ports, "80") {
		t.Fatalf("http_methodeol set must pull port 80 into the capture list, got %v", ports)
	}
}

func TestCollectTCPPortsSkipsPort80WhenMethodEOLOff(t *testing.T) {
	cfg := &Config{Sets: []*SetConfig{
		{Name: "m", Enabled: true, TCP: TCPConfig{}},
	}}
	if slices.Contains(cfg.CollectTCPPorts(), "80") {
		t.Fatal("port 80 must not be captured unless a set asks for it")
	}
}

func TestCollectTCPPortsIgnoresMethodEOLOnDisabledSet(t *testing.T) {
	cfg := &Config{Sets: []*SetConfig{
		{Name: "m", Enabled: false, TCP: TCPConfig{HTTPMethodEOL: true}},
	}}
	if slices.Contains(cfg.CollectTCPPorts(), "80") {
		t.Fatal("a disabled set must not pull in port 80")
	}
}

// TestMethodEOLAndCoalesceCountAsDestructiveActions guards the legacy
// domain-scope safety net (upstream b4 1.82 port): both rewrites alter packets
// on the wire, so a domain-scoped legacy set carrying them must keep its
// UnsafeLegacyDomainScope warning instead of silently acting on learned IPs.
func TestMethodEOLAndCoalesceCountAsDestructiveActions(t *testing.T) {
	coalesce := NewSetConfig()
	coalesce.Targets.DomainOnly = true
	coalesce.UDP.Mode = "coalesce"
	if !setHasDestructiveAction(&coalesce) {
		t.Fatal("coalesce rewrites packets and must count as a destructive action for legacy domain scope")
	}

	methodEOL := NewSetConfig()
	methodEOL.Targets.DomainOnly = true
	methodEOL.UDP.Mode = ConfigOff
	methodEOL.TCP.HTTPMethodEOL = true
	if !setHasDestructiveAction(&methodEOL) {
		t.Fatal("http_methodeol rewrites packets and must count as a destructive action for legacy domain scope")
	}
}
