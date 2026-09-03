package warp

import "testing"

func TestOuterInnerStateCannotCrossAuthorize(t *testing.T) {
	r := IsolationReport{Outer: InstanceState{InstanceID: "o", Mark: 1}, Inner: InstanceState{InstanceID: "i", Mark: 2}, ParentLinkValid: true}
	if !r.Valid() {
		t.Fatal(r)
	}
	r.Inner.Mark = 1
	if r.Valid() {
		t.Fatal("cross-instance mark accepted")
	}
}

func TestInnerRevokedBeforeParentBlocksIsolation(t *testing.T) {
	r := IsolationReport{Outer: InstanceState{InstanceID: "o", Mark: 1}, Inner: InstanceState{InstanceID: "i", Mark: 2}, ParentLinkValid: true}
	if !r.Valid() {
		t.Fatal("baseline isolation invalid")
	}
	r.InnerRevokedBeforeParent = true
	if r.Valid() {
		t.Fatal("inner revoked before parent still valid")
	}
}
