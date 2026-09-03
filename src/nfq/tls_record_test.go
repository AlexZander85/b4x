package nfq

import "testing"

func TestTLSHandshakeRecordIncomplete(t *testing.T) {
	// 0x06f0 = 1776, header+body = 1781 > 1396
	first := make([]byte, 1396)
	first[0], first[1], first[2] = 0x16, 0x03, 0x01
	first[3], first[4] = 0x06, 0xf0
	if !tlsHandshakeRecordIncomplete(first) {
		t.Fatal("expected incomplete ECH-sized record")
	}
	full := make([]byte, 5+1776)
	copy(full, first[:5])
	if tlsHandshakeRecordIncomplete(full) {
		t.Fatal("complete record")
	}
	if tlsHandshakeRecordIncomplete([]byte{0x17, 0x03, 0x03, 0x00, 0x10}) {
		t.Fatal("appdata is not a handshake incompleteness signal")
	}
	if tlsHandshakeRecordTotal(first) != 5+1776 {
		t.Fatalf("total %d", tlsHandshakeRecordTotal(first))
	}
}
