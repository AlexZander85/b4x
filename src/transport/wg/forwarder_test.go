// PATCH-24 (E23): udpAddrPortOf must drop v6 addresses instead of panicking
// in As4 (latent: the forwarder binds 127.0.0.1 only, clients are v4).
package transportwg

import (
	"net/netip"
	"testing"
)

// TestUDPAddrPortOfDropsV6 (PATCH-24/E23): the As4 panic is gone — a v6
// address is dropped (single-session v4 semantics), v4 passes through.
func TestUDPAddrPortOfDropsV6(t *testing.T) {
	v4 := netip.MustParseAddrPort("127.0.0.1:51820")
	if got := udpAddrPortOf(v4); got == nil || got.Port != 51820 {
		t.Fatalf("v4 passthrough = %v", got)
	}
	v6 := netip.MustParseAddrPort("[2001:db8::1]:51820")
	if got := udpAddrPortOf(v6); got != nil {
		t.Fatalf("v6 must be dropped, got %v (As4 would have panicked before the fix)", got)
	}
}
