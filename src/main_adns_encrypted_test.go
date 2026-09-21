package main

import (
	"testing"

	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

func TestReferenceEncryptedProvidersFromKnownRefDNS(t *testing.T) {
	policy := dnspath.DefaultAdaptivePolicy()
	policy.AllowNativeEncrypted = true
	got := referenceEncryptedProviders(policy, []string{"8.8.8.8", "9.9.9.9", "127.0.0.1"}, 0)
	if len(got) != 4 { // dns.google (dot+doh) + dns.quad9.net (dot+doh)
		t.Fatalf("want 4 encrypted providers, got %d", len(got))
	}
	families := map[dnspath.DNSPathFamily]int{}
	for _, p := range got {
		families[p.ID().Family]++
		if p.ID().CatalogVersion != adnsReferenceCatalog {
			t.Fatalf("provider catalog version = %q, want %q", p.ID().CatalogVersion, adnsReferenceCatalog)
		}
	}
	if families[dnspath.DNSPathDoT] != 2 || families[dnspath.DNSPathDoH] != 2 {
		t.Fatalf("want 2 dot + 2 doh, got %+v", families)
	}
}

func TestReferenceEncryptedProvidersGatedAndUnknown(t *testing.T) {
	policy := dnspath.DefaultAdaptivePolicy()
	policy.AllowNativeEncrypted = false
	if got := referenceEncryptedProviders(policy, []string{"8.8.8.8"}, 0); got != nil {
		t.Fatal("native encrypted providers must be gated by allow_native_encrypted")
	}
	policy.AllowNativeEncrypted = true
	if got := referenceEncryptedProviders(policy, []string{"203.0.113.7"}, 0); len(got) != 0 {
		t.Fatalf("unknown reference IP must not invent encrypted endpoints, got %d", len(got))
	}
	if got := referenceEncryptedProviders(policy, nil, 0); len(got) != 0 {
		t.Fatalf("empty reference_dns must yield no encrypted providers, got %d", len(got))
	}
}
