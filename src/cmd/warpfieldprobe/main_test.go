package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// The VN trigger must carry the 0x?a?a?a?a forced-negotiation version and a
// parseable DCID/SCID length structure (RFC 9000 SS6.2).
func TestCraftVNTrigger(t *testing.T) {
	pkt := craftVNTrigger()
	if len(pkt) != 1+4+1+8+1+8 {
		t.Fatalf("vn trigger len = %d", len(pkt))
	}
	if pkt[0]&0x80 == 0 {
		t.Fatal("long header form bit not set")
	}
	v := binary.BigEndian.Uint32(pkt[1:5])
	for _, b := range []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} {
		low := b & 0x0f
		if low != 0x0a {
			t.Fatalf("version %08x does not match 0x?a?a?a?a pattern", v)
		}
	}
	dcidLen := int(pkt[5])
	if dcidLen < 8 {
		t.Fatalf("dcid len %d too small", dcidLen)
	}
	scidOff := 6 + dcidLen
	scidLen := int(pkt[scidOff])
	if scidLen < 8 || scidOff+1+scidLen != len(pkt) {
		t.Fatalf("scid framing broken: off=%d len=%d total=%d", scidOff, scidLen, len(pkt))
	}

	other := craftVNTrigger()
	if bytes.Equal(pkt[6:6+dcidLen], other[6:6+dcidLen]) {
		t.Fatal("DCIDs across rounds must differ (random)")
	}
}

func TestIsVNReply(t *testing.T) {
	vn := []byte{0xff, 0, 0, 0, 0, 0x08}
	vn = append(vn, make([]byte, 20)...)
	if !isVNReply(vn) {
		t.Fatal("version-zero long header must classify as VN")
	}
	initialLike := append([]byte{0xc3}, 0x00, 0x00, 0x00, 0x01)
	initialLike = append(initialLike, make([]byte, 12)...)
	if isVNReply(initialLike) {
		t.Fatal("non-zero version must not classify as VN")
	}
	if isVNReply([]byte{0x40}) {
		t.Fatal("short/garbage input must not classify as VN")
	}
}

func TestCraftJunkSizeAndRandomness(t *testing.T) {
	a := craftJunk(92)
	b := craftJunk(92)
	if len(a) != 92 {
		t.Fatalf("junk len = %d", len(a))
	}
	if bytes.Equal(a, b) {
		t.Fatal("junk payloads must be random per round")
	}
}
