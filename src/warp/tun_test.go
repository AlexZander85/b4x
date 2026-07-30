package warp

import "testing"

func TestTunRegistryRejectsForeignCollisionAndLowMTU(t *testing.T) {
	r := NewTunRegistry()
	if err := r.Claim(TunLease{SessionID: "s", Interface: "warp0", Address: "100.64.0.2", MTU: 1280, State: TunVerified}); err != nil {
		t.Fatal(err)
	}
	if err := r.Claim(TunLease{SessionID: "other", Interface: "warp0", Address: "100.64.0.3", MTU: 1280, State: TunOwned}); err == nil {
		t.Fatal("foreign collision accepted")
	}
	if err := r.Claim(TunLease{SessionID: "x", Interface: "warp1", Address: "x", MTU: 1200, State: TunOwned}); err == nil {
		t.Fatal("low mtu accepted")
	}
}
