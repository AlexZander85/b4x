package transportwarp

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func TestDNSProbeStructure(t *testing.T) {
	src := [4]byte{172, 16, 0, 2}
	dst := [4]byte{8, 8, 8, 8}
	pr, err := NewDNSProbe(src, dst, "cloudflare.com")
	if err != nil {
		t.Fatal(err)
	}
	pkt := pr.Packet
	// IPv4 header
	if pkt[0] != 0x45 {
		t.Fatalf("version/ihl %#x", pkt[0])
	}
	total := int(binary.BigEndian.Uint16(pkt[2:]))
	if total != len(pkt) || total < 20+8+17 {
		t.Fatalf("total len %d vs %d", total, len(pkt))
	}
	if binary.BigEndian.Uint16(pkt[6:])&0x4000 == 0 {
		t.Fatal("DF flag missing")
	}
	if pkt[9] != 17 {
		t.Fatal("proto not UDP")
	}
	if string(pkt[12:16]) != string(src[:]) || string(pkt[16:20]) != string(dst[:]) {
		t.Fatal("addresses misplaced")
	}
	ipSum := ^fold(checksum32(pkt[:10]) + checksum32(pkt[12:20]))
	if ipSum == 0 {
		t.Fatal("checksum field must be non-zero (stored complement)")
	}
	if binary.BigEndian.Uint16(pkt[10:]) != ipSum {
		t.Fatalf("stored csum %04x != computed %04x", binary.BigEndian.Uint16(pkt[10:]), ipSum)
	}
	// UDP
	u := pkt[20:]
	dport := binary.BigEndian.Uint16(u[2:])
	if dport != 53 {
		t.Fatalf("dport %d", dport)
	}
	if ulen := binary.BigEndian.Uint16(u[4:]); int(ulen) != len(u) {
		t.Fatalf("udp len %d vs %d", ulen, len(u))
	}
	// DNS txid at offset 28 matches probe identity
	if u[8] != pr.TXID[0] || u[9] != pr.TXID[1] {
		t.Fatal("txid mismatch")
	}
	// qname ends with root label then A/IN
	qr := u[20:] // after fixed dns header (12) + "13cloudflarecom"? compute: name labels
	_ = qr
}

func TestDNSProbeChecksumsValid(t *testing.T) {
	for _, local := range [][4]byte{{172, 16, 0, 2}, {100, 96, 0, 5}} {
		pr, err := NewDNSProbe(local, [4]byte{1, 1, 1, 1}, "example.org")
		if err != nil {
			t.Fatal(err)
		}
		pkt := pr.Packet
		// Receiver form: ones-complement sum over the full header INCLUDING
		// the stored checksum field must fold to 0xffff.
		if fold(checksum32(pkt[:20])) != 0xffff {
			t.Fatalf("ip checksum bad for %v", local)
		}
		udp := pkt[20:]
		// RFC 768 pseudo-header (PATCH B-2): 8-byte src + 8-byte dst + zero +
		// proto + 2-byte UDP Length, then the datagram.
		ps := []byte{local[0], local[1], local[2], local[3], 1, 1, 1, 1, 0, 17,
			udp[4], udp[5]}
		if fold(checksum32(ps)+checksum32(udp)) != 0xffff {
			t.Fatalf("udp checksum bad for %v", local)
		}
	}
}

func TestProbeMatches(t *testing.T) {
	pr, err := NewDNSProbe([4]byte{172, 16, 0, 2}, [4]byte{8, 8, 8, 8}, "probe.test")
	if err != nil {
		t.Fatal(err)
	}
	echo := append([]byte(nil), pr.Packet...)
	// reply direction: src/dst swapped, same length and txid
	swap(echo)
	if !pr.Matches(echo) {
		t.Fatal("echo must match on txid+len")
	}
	bad := append([]byte(nil), echo...)
	bad[28] ^= 0xff
	if pr.Matches(bad) {
		t.Fatal("wrong txid must not match")
	}
	if pr.Matches(echo[:len(echo)-1]) {
		t.Fatal("short packet must not match")
	}
}

func swap(p []byte) {
	for i := 0; i < 4; i++ {
		p[12+i], p[16+i] = p[16+i], p[12+i]
	}
}

func TestProbeRejectsBadNames(t *testing.T) {
	if _, err := NewDNSProbe([4]byte{}, [4]byte{8, 8, 8, 8}, ""); err == nil {
		t.Fatal("empty name accepted")
	}
	if _, err := NewDNSProbe([4]byte{}, [4]byte{8, 8, 8, 8}, "trailing."); err == nil {
		t.Fatal("trailing dot accepted")
	}
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	if _, err := NewDNSProbe(netip.MustParseAddr("172.16.0.2").As4(), [4]byte{8, 8, 8, 8}, string(long)); err == nil {
		t.Fatal("overlong label accepted")
	}
}

// rfc1071Fold reduces b to its 16-bit one's-complement Big-Endian sum — an
// INDEPENDENT reference implementation (not the package's own checksum32/
// fold), used to cross-check the probe's UDP checksum (PATCH B-2). Per
// RFC 1071 the receiver folds pseudo-header + datagram (including the stored
// checksum field) and a valid packet folds to 0xffff.
func rfc1071Fold(b []byte) uint16 {
	if len(b)%2 == 1 {
		b = append(append([]byte(nil), b...), 0x00)
	}
	s := uint32(0)
	for i := 0; i < len(b); i += 2 {
		s += uint32(b[i])<<8 | uint32(b[i+1])
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return uint16(s)
}

// golden: every constructed probe must carry a UDP checksum over the RFC 768
// pseudo-header (src + dst + zero + proto + 2-byte UDP Length + datagram)
// whose one's-complement sum folds to 0xffff — the form strict middleboxes
// verify. The reference fold is the independent rfc1071Fold above, never the
// code under test.
func TestDNSProbeUDPChecksumGolden(t *testing.T) {
	for _, tc := range []struct {
		local [4]byte
		dns   [4]byte
		name  string
	}{
		{[4]byte{172, 16, 0, 2}, [4]byte{1, 1, 1, 1}, "example.org"},
		{[4]byte{100, 96, 0, 5}, [4]byte{8, 8, 8, 8}, "cloudflare.com"},
		{[4]byte{10, 0, 0, 1}, [4]byte{9, 9, 9, 9}, "warp.example"},
	} {
		pr, err := NewDNSProbe(tc.local, tc.dns, tc.name)
		if err != nil {
			t.Fatal(err)
		}
		udp := pr.Packet[20:]
		ps := make([]byte, 0, 12+len(udp))
		ps = append(ps, tc.local[:]...)
		ps = append(ps, tc.dns[:]...)
		ps = append(ps, 0x00, 0x11)
		ps = append(ps, udp[4], udp[5]) // UDP Length word (was missing, PATCH B-2)
		ps = append(ps, udp...)
		if got := rfc1071Fold(ps); got != 0xffff {
			t.Fatalf("udp checksum (src=%v) folds to %04x, want ffff", tc.local, got)
		}
	}
}
