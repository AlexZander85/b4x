package warp

import "testing"

func TestEnrollmentCannotAuthorizeDataPlane(t *testing.T) {
	p := DefaultEnrollmentPolicy()
	if !p.Valid() {
		t.Fatal("default invalid")
	}
	p.DataPlaneAuthorization = true
	if p.Valid() {
		t.Fatal("enrollment authorized data plane")
	}
}
