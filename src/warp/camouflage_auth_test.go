package warp

import "testing"

func TestCamouflageAuthorizationRequiresExactIdentityAndGeneration(t *testing.T) {
	a := TransportControlAuthorization{SocketID: "s", FlowKey: "f", EndpointHash: "e", InstanceID: "i", Purpose: PurposeCamouflage, ProcessGeneration: 2, ConfigGeneration: 3}
	if !a.Valid(2, 3) {
		t.Fatal("valid auth rejected")
	}
	if a.Valid(1, 3) || a.Valid(2, 4) {
		t.Fatal("stale generation accepted")
	}
}
