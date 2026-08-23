package transportwarp

import (
	"net/netip"
	"testing"
)

func TestCatalogInvariants(t *testing.T) {
	// The measured gateway invariants the engine relies on:
	// 1. default endpoint is an H2-catalog address on a known port;
	def := DefaultH2Endpoint()
	if !InCatalog(KindMasqueH2, def.Addr()) || !KnownPort(def.Port()) {
		t.Fatalf("default endpoint %v outside catalog", def)
	}
	// 2. QUIC gateways are QUIC-kind only and also H2-reachable (same block);
	for _, a := range []string{"162.159.198.1", "162.159.198.2"} {
		ip := netip.MustParseAddr(a)
		if !InCatalog(KindMasqueQUIC, ip) {
			t.Fatalf("%s missing from QUIC catalog", a)
		}
		if !InCatalog(KindMasqueH2, ip) {
			t.Fatalf("%s missing from H2 catalog (same /24 must answer TCP MASQUE)", a)
		}
	}
	// 3. WG-only ranges must NOT pass as MASQUE gateways (field-measured
	// TLS alert 40 / pin mismatch there; addendum forbids scanning them).
	for _, a := range []string{"188.114.96.1", "162.159.192.1", "8.39.204.1"} {
		if InCatalog(KindMasqueH2, netip.MustParseAddr(a)) {
			t.Fatalf("%s must not be in MASQUE catalog", a)
		}
	}
	// 4. ports fixed set.
	if !KnownPort(443) || !KnownPort(8095) || KnownPort(80) || KnownPort(2408) {
		t.Fatal("port set drifted")
	}
}

func TestSeedEndpoints(t *testing.T) {
	h2 := SeedEndpoints(KindMasqueH2)
	if len(h2) != len(Ports) || h2[0] != DefaultH2Endpoint() {
		t.Fatalf("h2 seeds: first=%v n=%d", h2[0], len(h2))
	}
	q := SeedEndpoints(KindMasqueQUIC)
	if len(q) != 2 { // v4 anycast pair only for bootstrap
		t.Fatalf("quic seeds: %v", q)
	}
	for _, ep := range append(append([]netip.AddrPort{}, h2...), q...) {
		if !KnownPort(ep.Port()) || !InCatalog(KindMasqueH2, ep.Addr()) && !InCatalog(KindMasqueQUIC, ep.Addr()) {
			t.Fatalf("seed %v outside catalog", ep)
		}
	}
}
