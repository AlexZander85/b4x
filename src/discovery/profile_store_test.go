package discovery

import (
	"testing"
	"time"
)

func TestProfileStoreAtomicBoundedRevoke(t *testing.T) {
	now := time.Unix(22000, 0)
	p, _ := NewNetworkDiagnosticProfile(sampleDDIBlocking(now), now.Add(time.Minute), now)
	s := NewProfileStore(1)
	if err := s.Put(p, now); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(p.ProfileID, now); !ok {
		t.Fatal("stored profile unavailable")
	}
	if s.Revoke(p.ProfileID, now) && s.Len() != 0 {
		t.Fatal("revoke did not delete")
	}
	if _, ok := s.Get(p.ProfileID, now); ok {
		t.Fatal("revoked profile returned")
	}
}
