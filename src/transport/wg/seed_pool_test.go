package transportwg

import (
	"net/netip"
	"testing"
)

// TestFieldVerifiedEndpointsGate pins the bd b4x-wh6 data contract: the
// field-proven endpoint list is non-empty, passes the catalog gate, and
// deliberately stays OUT of builtinSeedPool — the seek-ladder budgets and the
// "unverified regional pools never enter the default ladder" invariant
// (TestRegionalPoolsUnverifiedByDefault) must not be disturbed by it.
func TestFieldVerifiedEndpointsGate(t *testing.T) {
	fv := FieldVerifiedEndpoints()
	if len(fv) == 0 {
		t.Fatal("no field-verified endpoints declared")
	}
	for _, ap := range fv {
		if !endpointInCatalog(ap) {
			t.Fatalf("field-verified %s fails the catalog gate", ap)
		}
	}
	// The head is the default AWG endpoint (Nova's last-good).
	if fv[0].String() != "8.39.204.9:7103" {
		t.Fatalf("field-verified head = %s, want Nova last-good 8.39.204.9:7103", fv[0])
	}

	inSeed := map[netip.AddrPort]bool{}
	for _, s := range SeedEndpoints() {
		inSeed[s] = true
	}
	for _, ap := range fv {
		if inSeed[ap] {
			t.Fatalf("field-verified %s leaked into builtinSeedPool (seek-ladder invariant)", ap)
		}
	}
	if n := len(SeedEndpoints()); n != 8 {
		t.Fatalf("builtinSeedPool = %d entries, want the historical 8 (unchanged)", n)
	}
	// The returned slice is a copy: callers cannot mutate the catalog.
	fv[0] = netip.MustParseAddrPort("127.0.0.1:1")
	if FieldVerifiedEndpoints()[0].String() != "8.39.204.9:7103" {
		t.Fatal("FieldVerifiedEndpoints must return a copy")
	}
}
