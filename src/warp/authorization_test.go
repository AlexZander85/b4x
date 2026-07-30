package warp

import "testing"

func TestAuthorizationIsScopedAndRevocable(t *testing.T) {
	a := TransportAuthorization{FlowID: "f", ServiceProfile: "svc", ClientKey: "c", DestinationHash: "d", RouteGeneration: 1, ConfigGeneration: 1, AllowForwarded: true, DNSBinding: "dns"}
	if !a.Valid() {
		t.Fatal("valid auth rejected")
	}
	if err := RevokeOnNegativeEvidence(&a, "f"); err != nil || a.AllowForwarded || a.AllowControl {
		t.Fatal("negative evidence did not revoke")
	}
}
