package silentpath

import (
	"testing"
	"time"
)

func TestLeaseScopeAndRollback(t *testing.T) {
	s := NewLeaseStore()
	n := time.Now()
	l := Lease{ID: "x", Scope: Scope{SetID: "s", ComponentID: "c", DomainKey: "d", ConfigGen: 1, IPFamily: 4, TransportPath: "direct"}, From: "direct", To: "warp", ConfigGen: 1, ExpiresAt: n.Add(time.Second), MaxAttempts: 2, Rollback: "direct"}
	if !s.Put(l, n) {
		t.Fatal("put")
	}
	if _, ok := s.Get("x", l.Scope, n); !ok {
		t.Fatal("get")
	}
	l.Rollback = ""
	if s.Put(l, n) {
		t.Fatal("rollback required")
	}
}
