package dnspath

import (
	"testing"
	"time"
)

// One mid-handshake DPI cut must reach the recurrence threshold immediately
// (fast kind); generic timeouts keep the default threshold of 3.
func TestRecurrenceFastKindMidHandshake(t *testing.T) {
	tr := NewRecurrenceTracker(3)
	now := time.Now()

	if !tr.Record(DNSPathDoT, KindMidHandshakeReset, now) {
		t.Fatal("mid_handshake_reset must trigger on first observation")
	}
	if tr.Record(DNSPathDoH, "timeout", now) {
		t.Fatal("single timeout must not trigger")
	}
	if tr.Record(DNSPathDoH, "timeout", now) {
		t.Fatal("second timeout must not trigger")
	}
	if !tr.Record(DNSPathDoH, "timeout", now) {
		t.Fatal("third timeout must trigger (threshold 3)")
	}
}

// A mid-handshake cut on DoT must not poison other families — plaintext UDP
// to the same resolver stays eligible as fallback.
func TestRecurrenceMidHandshakeIsFamilyScoped(t *testing.T) {
	tr := NewRecurrenceTracker(3)
	now := time.Now()
	tr.Record(DNSPathDoT, KindMidHandshakeReset, now)

	if tr.Record(DNSPathUDP, "timeout", now) {
		t.Fatal("udp recurrence must be independent of dot quarantine")
	}
	recs := tr.Snapshot()
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %d", len(recs))
	}
}
