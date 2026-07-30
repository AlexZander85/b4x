package mtproto

import "testing"

func TestPacketValidationBoundsStressAndDestination(t *testing.T) {
	v := PacketPathValidation{IPv4: true, IPv6: true, Mark: 1, OriginalDestination: "203.0.113.1:443", Connections: 1000, MaxPending: 128, ReloadSafe: true, ShutdownSafe: true, LeakFree: true}
	if !v.Valid() {
		t.Fatal(v)
	}
	v.Connections = 1001
	if v.Valid() {
		t.Fatal("unbounded stress accepted")
	}
}
