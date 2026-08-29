package transportwarp

import (
	"encoding/binary"
	"net"
	"testing"
)

// testV4Packet builds a minimal valid IPv4 packet (IHL 20, proto UDP).
func testV4Packet(payloadLen int) []byte {
	pkt := make([]byte, 20+payloadLen)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:], uint16(20+payloadLen))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], net.IPv4(192, 0, 2, 1).To4())
	copy(pkt[16:20], net.IPv4(192, 0, 2, 2).To4())
	return pkt
}

// ---- PATCH-18 (M-7 / B-H6): ICMPv6 Packet Too Big recipe ----

func testV6Packet(payloadLen int) []byte {
	pkt := make([]byte, 40+payloadLen)
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:], uint16(payloadLen))
	pkt[6] = 17 // UDP
	copy(pkt[8:24], net.ParseIP("2001:db8::1").To16())
	copy(pkt[24:40], net.ParseIP("2001:db8::2").To16())
	return pkt
}

func TestBuildICMPv6TooBigVector(t *testing.T) {
	orig := testV6Packet(1200)
	got := BuildICMPv6TooBig(orig, 1280)
	if got == nil {
		t.Fatal("v6 packet must produce an ICMPv6 PTB")
	}
	if len(got) != 40+8+48 { // outer hdr + icmp hdr(8) + embedded(48)
		t.Fatalf("length = %d, want 96", len(got))
	}
	if got[0]>>4 != 6 {
		t.Fatal("outer must be IPv6")
	}
	if pl := binary.BigEndian.Uint16(got[4:6]); int(pl) != len(got)-40 {
		t.Fatalf("payload length = %d, want %d", pl, len(got)-40)
	}
	if got[6] != 58 || got[7] != 64 {
		t.Fatalf("nexthdr/hop = %d/%d, want 58/64", got[6], got[7])
	}
	// ICMPv6 message fields.
	icmp := got[40:]
	if icmp[0] != 2 || icmp[1] != 0 {
		t.Fatalf("type/code = %d/%d, want 2/0", icmp[0], icmp[1])
	}
	if mtu := binary.BigEndian.Uint32(icmp[4:8]); mtu != 1232 {
		t.Fatalf("advertised mtu = %d, want 1232 (QUIC v6 floor clamp)", mtu)
	}
	// Embedded: original header + first 8 payload bytes.
	if string(icmp[8:56]) != string(orig[:48]) {
		t.Fatal("embedded data mismatch")
	}
	// Independent checksum re-computation over the pseudo-header.
	pseudo := make([]byte, 0, 40+len(icmp))
	pseudo = append(pseudo, orig[8:24]...)
	pseudo = append(pseudo, orig[24:40]...)
	plen := len(icmp)
	pseudo = append(pseudo, byte(plen>>24), byte(plen>>16), byte(plen>>8), byte(plen))
	pseudo = append(pseudo, 0, 0, 0, 58)
	pseudo = append(pseudo, icmp...)
	if sum := ^fold(checksum32(pseudo)); sum != 0 {
		t.Fatalf("checksum verify failed: wire=%x recomputed=%x (must self-verify to 0)",
			binary.BigEndian.Uint16(icmp[2:4]), binary.BigEndian.Uint16([]byte{byte(sum >> 8), byte(sum)}))
	}
	// Address swap semantics of an ICMP error.
	if string(got[8:24]) != string(orig[24:40]) || string(got[24:40]) != string(orig[8:24]) {
		t.Fatal("outer addresses must swap (reporter <- original dst)")
	}
}

func TestBuildICMPv6TooBigInvalidInputs(t *testing.T) {
	if BuildICMPv6TooBig(testV4Packet(64), 1280) != nil {
		t.Fatal("v4 packet must yield nil")
	}
	if BuildICMPv6TooBig(make([]byte, 40), 1280) != nil {
		t.Fatal("truncated packet (<40+8) must yield nil")
	}
	if BuildICMPv6TooBig(nil, 1280) != nil {
		t.Fatal("nil input must yield nil")
	}
	// A smaller requested MTU passes through unclamped.
	orig := testV6Packet(64)
	got := BuildICMPv6TooBig(orig, 1000)
	if got == nil {
		t.Fatal("valid packet must produce a message")
	}
	if mtu := binary.BigEndian.Uint32(got[44:48]); mtu != 1000 {
		t.Fatalf("mtu = %d, want 1000", mtu)
	}
}
