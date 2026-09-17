package config

import (
	"net/netip"
	"testing"

	twg "github.com/daniellavrushin/b4/transport/wg"
)

// TestChainAWGEndpointUsesFieldVerified pins the bd b4x-wh6 chain fix: an AWG
// layer with no explicit endpoint resolves to the FIELD-VERIFIED list (the
// historical ZeroTrust seeds answer 0 IN from the field network), while the
// MASQUE layers keep the MASQUE catalog default, and awg+awg still terminates
// on two distinct IPs.
func TestChainAWGEndpointUsesFieldVerified(t *testing.T) {
	fv := twg.FieldVerifiedEndpoints()
	if len(fv) == 0 {
		t.Fatal("no field-verified endpoints declared")
	}
	cases := []struct {
		kind               string
		awgOuter, awgInner bool
	}{
		{ChainKindMasqueAwg, false, true},
		{ChainKindAwgMasque, true, false},
		{ChainKindAwgAwg, true, true},
		{ChainKindMasqueMasque, false, false},
	}
	for _, tc := range cases {
		ch := WarpChainConfig{Kind: tc.kind}
		outer, inner, err := ch.ResolveEndpoints()
		if err != nil {
			t.Fatalf("%s: %v", tc.kind, err)
		}
		if tc.awgOuter && !inFieldVerified(fv, outer) {
			t.Fatalf("%s outer = %s, want a field-verified endpoint", tc.kind, outer)
		}
		if tc.awgInner && !inFieldVerified(fv, inner) {
			t.Fatalf("%s inner = %s, want a field-verified endpoint", tc.kind, inner)
		}
		if !tc.awgOuter && !tc.awgInner {
			if inFieldVerified(fv, outer) || inFieldVerified(fv, inner) {
				t.Fatalf("%s: no WG layer must resolve (outer %s inner %s)", tc.kind, outer, inner)
			}
		}
		if tc.awgOuter && tc.awgInner && outer.Addr() == inner.Addr() {
			t.Fatalf("%s: layers must terminate on distinct IPs (%s)", tc.kind, outer)
		}
	}
}

func inFieldVerified(fv []netip.AddrPort, ap netip.AddrPort) bool {
	for _, v := range fv {
		if v == ap {
			return true
		}
	}
	return false
}
