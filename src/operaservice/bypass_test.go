package operaservice

import (
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/reserve"
)

// TestRuntimeBypassDomainAntiloop: the opera runtime satisfies the reserve
// anti-loop contract, declaring its own infrastructure (*.sec-tunnel.com) as
// DIRECT — the tproxy dial path and the firewall pre-resolver consume this.
func TestRuntimeBypassDomainAntiloop(t *testing.T) {
	rt, err := Build(&config.Config{}, Options{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var checker reserve.BypassDomainChecker = rt
	for _, host := range []string{"api2.sec-tunnel.com", "eu0.sec-tunnel.com", "SEC-TUNNEL.COM"} {
		if !checker.BypassDomain(host) {
			t.Fatalf("%q must be a bypass domain", host)
		}
	}
	for _, host := range []string{"example.com", "sec-tunnel.com.evil.tld", ""} {
		if checker.BypassDomain(host) {
			t.Fatalf("%q must NOT be a bypass domain", host)
		}
	}
}
