package warp

import "testing"

func TestNestedBackendInvalidatesOnParentAndCleansOwnership(t *testing.T) {
	n := NestedBackend{Namespace: "ns", Veth: "v", NAT: "nat", Link: TunnelDependencyLink{ParentSession: "p", InnerSession: "i", ParentGeneration: "g", Valid: true}, CleanupOwned: true, Active: true}
	if !n.Valid() {
		t.Fatal("nested invalid")
	}
	n.InvalidateParent()
	if n.Active || n.Link.Valid {
		t.Fatal("parent invalidation missing")
	}
	n.Cleanup()
	if n.Namespace != "" || n.CleanupOwned != true {
		t.Fatal("cleanup incomplete")
	}
}
