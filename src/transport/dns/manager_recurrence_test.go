package dnspath

import (
	"context"
	"testing"
)

func TestRecordPathFailureQuarantinesFamilyFast(t *testing.T) {
	m := NewManager(DNSModeAdaptive, DefaultAdaptivePolicy(), 1, "epoch", "wan")
	if m.IsFamilyQuarantined(DNSPathDoT) {
		t.Fatal("precondition: dot must not be quarantined")
	}
	// FastThreshold=1: the first mid-handshake RST/EOF quarantines the family.
	if !m.RecordPathFailure(DNSPathDoT, KindMidHandshakeReset) {
		t.Fatal("first mid-handshake reset must quarantine immediately")
	}
	if !m.IsFamilyQuarantined(DNSPathDoT) {
		t.Fatal("dot must be quarantined")
	}
	// Family-scoped, never resolver-wide: plaintext UDP/TCP stays eligible.
	if m.IsFamilyQuarantined(DNSPathUDP) || m.IsFamilyQuarantined(DNSPathTCP) {
		t.Fatal("quarantine must be family-scoped, not resolver-wide")
	}
	if got := m.QuarantinedFamilies(); len(got) != 1 || got[0] != DNSPathDoT {
		t.Fatalf("quarantined families = %v, want [dot]", got)
	}
	if m.QuarantineReason(DNSPathDoT) != KindMidHandshakeReset {
		t.Fatalf("reason = %q", m.QuarantineReason(DNSPathDoT))
	}
	// Release after revalidation restores eligibility.
	released := m.ReleaseAllQuarantines()
	if len(released) != 1 || released[0] != DNSPathDoT {
		t.Fatalf("released = %v, want [dot]", released)
	}
	if m.IsFamilyQuarantined(DNSPathDoT) {
		t.Fatal("dot must be released after revalidation")
	}
	if len(m.QuarantinedFamilies()) != 0 {
		t.Fatal("no family must remain quarantined")
	}
}

func TestQuarantineIsRefusedByResolveAndNotReady(t *testing.T) {
	m := NewManager(DNSModeAdaptive, DefaultAdaptivePolicy(), 1, "epoch", "wan")
	path := DNSPathID{Family: DNSPathDoT, ResolverID: "r", EndpointID: "e", IPFamily: "ipv4"}
	m.MarkPathHealth(path, DNSPathHealth{State: CapReady})
	if !m.pathReady(path) {
		t.Fatal("precondition: prepared path must be ready")
	}
	m.RecordPathFailure(DNSPathDoT, KindMidHandshakeReset)
	if m.pathReady(path) {
		t.Fatal("quarantined path must not be ready")
	}
	if _, err := m.resolveVia(context.Background(), path, DNSQuery{Name: "example.com", QType: 1}); err == nil {
		t.Fatal("quarantined family must be refused by resolveVia")
	}
	// Generic kinds use the persistent threshold (3), not the fast one.
	if m.RecordPathFailure(DNSPathUDP, "timeout") {
		t.Fatal("first generic timeout must not quarantine")
	}
	if m.IsFamilyQuarantined(DNSPathUDP) {
		t.Fatal("udp must not be quarantined after a single timeout")
	}
}

func TestDegradedReasonMarker(t *testing.T) {
	m := NewManager(DNSModeAdaptive, DefaultAdaptivePolicy(), 1, "epoch", "wan")
	if m.DegradedReason() != "" {
		t.Fatal("precondition: not degraded")
	}
	m.SetDegradedReason("classic UDP/TCP only")
	if m.DegradedReason() != "classic UDP/TCP only" {
		t.Fatal("degraded reason must be recorded")
	}
	m.SetDegradedReason("")
	if m.DegradedReason() != "" {
		t.Fatal("degraded reason must be clearable")
	}
}

func TestQuarantineDegradesTransportAxis(t *testing.T) {
	m := NewManager(DNSModeAdaptive, DefaultAdaptivePolicy(), 1, "epoch", "wan")
	m.RecordPathFailure(DNSPathDoT, KindMidHandshakeReset)
	hr := m.HealthReport()
	if hr.Axes[AxisTransport] != AxisDegraded {
		t.Fatalf("transport axis = %v, want degraded", hr.Axes[AxisTransport])
	}
	m.ReleaseAllQuarantines()
	if hr2 := m.HealthReport(); hr2.Axes[AxisTransport] == AxisDegraded {
		t.Fatal("released quarantine must not keep transport degraded")
	}
}
