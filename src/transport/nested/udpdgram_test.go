package nested

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestUDPDatagramRoundTrip(t *testing.T) {
	src := netip.AddrFrom4([4]byte{198, 51, 100, 7})
	dst := netip.AddrFrom4([4]byte{203, 0, 113, 9})
	payload := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	pkt, err := BuildUDPDatagram(src, dst, 40001, 51820, payload)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	tuple, got, err := SplitUDPDatagram(pkt)
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	if tuple.SrcIP != src || tuple.DstIP != dst {
		t.Fatalf("addresses = %v -> %v", tuple.SrcIP, tuple.DstIP)
	}
	if tuple.SrcPort != 40001 || tuple.DstPort != 51820 {
		t.Fatalf("ports = %d -> %d", tuple.SrcPort, tuple.DstPort)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload mismatch: % x vs % x", got, payload)
	}
}

func TestUDPDatagramChecksumsValid(t *testing.T) {
	src := netip.AddrFrom4([4]byte{198, 51, 100, 7})
	dst := netip.AddrFrom4([4]byte{203, 0, 113, 9})
	pkt, err := BuildUDPDatagram(src, dst, 40002, 53, []byte("dns-payload"))
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	u := pkt[ipv4HeaderLen:]
	ip := pkt[:ipv4HeaderLen]

	// UDP checksum: recompute over pseudo-header with the field zeroed.
	saved := binary.BigEndian.Uint16(u[6:])
	binary.BigEndian.PutUint16(u[6:], 0)
	var pseudo [12]byte
	copy(pseudo[0:4], ip[12:16])
	copy(pseudo[4:8], ip[16:20])
	pseudo[9] = 17
	want := finalize(sum32(append(pseudo[:], u...)))
	binary.BigEndian.PutUint16(u[6:], saved)
	if saved != want {
		t.Fatalf("udp checksum = %#x, want %#x", saved, want)
	}

	// IP header checksum: the full header sums (folded) to exactly 0xffff.
	if got := foldAll(sum32(ip)); got != 0xffff {
		t.Fatalf("ip header checksum invalid: folded sum = %#x", got)
	}
}

// foldAll returns the one's-complement sum WITHOUT final inversion - a
// valid IPv4 header folds to exactly 0xffff.
func foldAll(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = sum>>16 + sum&0xffff
	}
	return uint16(sum)
}

func TestUDPDatagramRejectsV6AndGarbage(t *testing.T) {
	v6 := netip.AddrFrom16([16]byte{0x20, 0x01, 0xd, 0xb8})
	if _, err := BuildUDPDatagram(v6, v6, 1, 2, nil); !errors.Is(err, ErrNotV4) {
		t.Fatalf("v6 build err = %v, want ErrNotV4", err)
	}
	if _, _, err := SplitUDPDatagram([]byte{0x45, 0x00}); !errors.Is(err, ErrDatagramMalformed) {
		t.Fatalf("short split err = %v, want ErrDatagramMalformed", err)
	}
}
