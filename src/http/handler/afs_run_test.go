package handler

import (
	"net"
	"testing"
)

func TestBuildAutomaticSynthesisGuardPaths(t *testing.T) {
	SetMonitoringRuntime(nil)
	t.Cleanup(func() { SetMonitoringRuntime(nil) })
	api := afsTestAPI(t, true)
	scope := afsTestScope()
	cfg := api.getCfg()

	// Unauthorized: fail closed before anything else.
	if _, _, err := api.buildAutomaticSynthesis(scope, &DiscoveryAdaptiveSynthesisRequest{Allowed: true}, cfg); err == nil {
		t.Fatal("unauthorized run must be rejected")
	}
	// Authorized but the monitoring runtime is unavailable: no retained ABD inputs.
	req := &DiscoveryAdaptiveSynthesisRequest{
		Allowed: true, Authorized: true,
		ReferenceURL: "https://ref.example.com", TargetURL: "https://target.example.com",
		SameServiceControlURL: "https://same.example.com", UnrelatedControlURL: "https://unrelated.example.com",
	}
	if _, _, err := api.buildAutomaticSynthesis(scope, req, cfg); err == nil {
		t.Fatal("missing monitoring runtime must be rejected")
	}
}

func TestResolveProbeIP(t *testing.T) {
	ip, err := resolveProbeIP("https://203.0.113.10:443/path")
	if err != nil || !ip.Equal(net.IPv4(203, 0, 113, 10)) {
		t.Fatalf("ip=%v err=%v", ip, err)
	}
	if _, err := resolveProbeIP("https://[2001:db8::1]/"); err != nil {
		t.Fatalf("ipv6 literal should parse: %v", err)
	}
	if _, err := resolveProbeIP("not-a-url"); err == nil {
		t.Fatal("invalid probe url must error")
	}
}
