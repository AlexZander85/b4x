package discovery

import (
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

// buildTestConfig must always add probe destination IPs to
// Targets.IPs/IpsToMatch, including for CDN domains whose set is matched via
// geoip/geosite categories. The sandbox worker matches per packet with
// MatchIPWithSource against the ipRanger built from IpsToMatch; geo
// categories do not feed the ipRanger, so without this the worker accepts
// probe packets unmodified and no preset mutation reaches the wire.
func TestBuildTestConfigGeoSetIncludesProbeIPs(t *testing.T) {
	ds := &DiscoverySuite{
		CheckSuite: NewCheckSuite([]DomainInput{{Domain: "googlevideo.com", CheckURL: "https://googlevideo.com"}}),
		cfg:        &config.Config{System: config.SystemConfig{}},
		skipDNS:    true,
		dnsResults: map[string]*DNSDiscoveryResult{
			"googlevideo.com": {
				ExpectedIPs: []string{"64.233.164.99"},
				ProbeResults: []DNSProbeResult{
					{ResolvedIP: "64.233.164.99"},
					{ResolvedIP: "142.250.74.99"},
				},
			},
		},
	}

	geoIP, geoSite := GetCDNCategories("googlevideo.com")
	if len(geoIP) == 0 && len(geoSite) == 0 {
		t.Skipf("googlevideo.com has no CDN categories in test data (geoip=%v geosite=%v)", geoIP, geoSite)
	}

	cfg := ds.buildTestConfig(ConfigPreset{
		Name: "mut-ya-ru",
		Config: config.SetConfig{
			Faking: config.FakingConfig{
				SNIMutation: config.SNIMutationConfig{
					Mode:     "substitute",
					FakeSNIs: []string{"ya.ru"},
				},
			},
		},
	})

	set := cfg.Sets[0]
	if !set.Enabled {
		t.Fatalf("expected test set enabled")
	}
	if len(set.Targets.GeoIpCategories) == 0 && len(set.Targets.GeoSiteCategories) == 0 {
		t.Fatalf("expected geo categories to be kept on the set")
	}

	joined := strings.Join(set.Targets.IpsToMatch, ",")
	for _, want := range []string{"64.233.164.99/32", "142.250.74.99/32"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected %s in IpsToMatch, got: %v", want, set.Targets.IpsToMatch)
		}
	}
	if len(set.Targets.IPs) != len(set.Targets.IpsToMatch) {
		t.Fatalf("IPs and IpsToMatch must match, got %d vs %d", len(set.Targets.IPs), len(set.Targets.IpsToMatch))
	}
}

// Non-CDN domains must keep receiving probe IPs in the matcher ranges
// (regression guard for the non-geo branch).
func TestBuildTestConfigNonGeoSetIncludesProbeIPs(t *testing.T) {
	ds := &DiscoverySuite{
		CheckSuite: NewCheckSuite([]DomainInput{{Domain: "example.com", CheckURL: "https://example.com"}}),
		cfg:        &config.Config{System: config.SystemConfig{}},
		skipDNS:    true,
		dnsResults: map[string]*DNSDiscoveryResult{
			"example.com": {
				ExpectedIPs: []string{"93.184.216.34"},
			},
		},
	}

	geoIP, geoSite := GetCDNCategories("example.com")
	if len(geoIP) > 0 || len(geoSite) > 0 {
		t.Skipf("example.com unexpectedly has CDN categories (%v/%v)", geoIP, geoSite)
	}

	cfg := ds.buildTestConfig(ConfigPreset{Name: "mut-ya-ru"})
	set := cfg.Sets[0]
	joined := strings.Join(set.Targets.IpsToMatch, ",")
	if !strings.Contains(joined, "93.184.216.34/32") {
		t.Fatalf("expected 93.184.216.34/32 in IpsToMatch, got: %v", set.Targets.IpsToMatch)
	}
}
