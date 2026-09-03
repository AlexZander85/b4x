package silentpath

import (
	"testing"
	"time"
)

func TestRollbackRevokesBudget(t *testing.T) {
	s := NewLeaseStore()
	n := time.Now()
	sc := Scope{SetID: "s", ComponentID: "c", DomainKey: "d", ConfigGen: 1, IPFamily: 4, TransportPath: "direct"}
	s.Put(Lease{ID: "x", Scope: sc, From: "direct", To: "warp", ConfigGen: 1, ExpiresAt: n.Add(time.Second), MaxAttempts: 1, Rollback: "direct"}, n)
	m := NewRollbackMonitor(s, Budget{MaxRollbacks: 1})
	if !m.Rollback("x", sc, "user", n.Unix()) || !m.ObserveOnly {
		t.Fatal("rollback")
	}
}
