package warp

import "testing"

func TestDialPolicyRequiresDirectPinnedControl(t *testing.T) {
	p := DialPolicy{Mark: 1, BindDevice: "eth0", EndpointPin: "pin", DirectControl: true, ProxyEnvDisabled: true, Generation: 1}
	if ValidateNoRecursion(p, 2) != nil {
		t.Fatal("valid policy rejected")
	}
	if ValidateNoRecursion(p, 1) == nil {
		t.Fatal("recursive mark accepted")
	}
}
