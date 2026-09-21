package dnspath

import (
	"testing"
	"time"
)

func TestRecurrenceEncryptedStallIsFast(t *testing.T) {
	tr := NewRecurrenceTracker(3)
	if !tr.Record(DNSPathDoH, KindEncryptedStall, time.Now()) {
		t.Fatal("encrypted stall must quarantine the family on the first observation")
	}
	if !tr.Record(DNSPathDoT, KindEncryptedStall, time.Now()) {
		t.Fatal("encrypted stall must be family-scoped and fast for every encrypted family")
	}
	bare := NewRecurrenceTracker(3)
	if bare.Record(DNSPathUDP, "timeout", time.Now()) {
		t.Fatal("generic threshold must still apply to a non-fast kind")
	}
}
