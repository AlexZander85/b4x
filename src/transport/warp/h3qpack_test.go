package transportwarp

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	hpack "golang.org/x/net/http2/hpack"
)

// RFC 9204 §4.5.2: indexed static :method CONNECT must be the single byte
// 0xCF (warp-socks pattern, design §2).
func TestQPACKConnectIndexedByte(t *testing.T) {
	out := EncodeConnectFieldSection("162.159.198.2:443", nil)
	if len(out) < 3 {
		t.Fatalf("section too short: % x", out)
	}
	if out[0] != 0x00 || out[1] != 0x00 {
		t.Errorf("field section prefix = % x, want 00 00 (RIC=0, base delta=0)", out[:2])
	}
	if out[2] != 0xCF {
		t.Errorf(":method CONNECT byte = %#x, want 0xCF", out[2])
	}
	if out[3] != 0x50 { // 01 N=0 T=1 idx=0 (:authority)
		t.Errorf(":authority first byte = %#x, want 0x50", out[3])
	}
}

func TestQPACKConnectRoundTrip(t *testing.T) {
	extras := [][2]string{
		{"cf-connect-proto", "cf-connect-ip"},
		{"cf-connect-enabled", "true"}, // name >7 chars: exercises §4.5.6 continuation
		{"pq-enabled", "false"},
		{"user-agent", ""},
	}
	sec := EncodeConnectFieldSection("162.159.198.2:443", extras)
	got, err := DecodeFieldSection(sec)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := [][2]string{
		{":method", "CONNECT"},
		{":authority", "162.159.198.2:443"},
		{"cf-connect-proto", "cf-connect-ip"},
		{"cf-connect-enabled", "true"},
		{"pq-enabled", "false"},
		{"user-agent", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines %+v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// IPv6 literals in brackets (RFC 3986) survive the round trip (design §2).
func TestQPACKAuthorityV6(t *testing.T) {
	sec := EncodeConnectFieldSection(AuthorityForEndpoint("2606:4700:103::2", 443), nil)
	got, err := DecodeFieldSection(sec)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got[1] != [2]string{":authority", "[2606:4700:103::2]:443"} {
		t.Errorf("v6 authority = %v", got[1])
	}
}

// warp-socks qpack.rs test vector (E-H3 design §8): Huffman bytes of the
// cf-warp-colo header name.
func TestQPACKHuffmanVectorWarpColo(t *testing.T) {
	raw, err := hex.DecodeString("24ab781d95ac43d07f")
	if err != nil {
		t.Fatal(err)
	}
	s, err := qpackHuffmanDecode(raw)
	if err != nil {
		t.Fatalf("huffman decode: %v", err)
	}
	if s != "cf-warp-colo" {
		t.Fatalf("huffman vector decoded to %q, want %q", s, "cf-warp-colo")
	}
}

// Dynamic references must fail closed with the typed error (we advertise
// zero table capacity; a conformant peer never sends them).
func TestQPACKDynamicRefRejected(t *testing.T) {
	cases := [][]byte{
		append([]byte{0x00, 0x00}, appendQPACKInt(nil, 0x80, 6, 5)...), // indexed dynamic
		append([]byte{0x00, 0x00}, appendQPACKInt(nil, 0x40, 4, 3)...), // literal dynamic name ref
		{0x01, 0x00},       // RIC != 0
		{0x00, 0x80, 0x00}, // negative base (sign=1)
		append([]byte{0x00, 0x00}, appendQPACKInt(nil, 0xC0, 6, 200)...), // static index OOR
		append([]byte{0x00, 0x00}, appendQPACKInt(nil, 0x10, 4, 2)...),   // post-base indexed
	}
	for i, tc := range cases {
		if _, err := DecodeFieldSection(tc); err == nil {
			t.Errorf("case %d (% x): expected error", i, tc)
		} else if !errors.Is(err, ErrQPACKDynamic) && !strings.Contains(err.Error(), "out of range") && !strings.Contains(err.Error(), "base") {
			t.Errorf("case %d: unexpected error class %v", i, err)
		}
	}
}

func TestQPACKTruncated(t *testing.T) {
	full := EncodeConnectFieldSection("162.159.198.2:443", nil)
	// Cuts from 4: shorter prefixes stay legal ({00 00} is an empty section,
	// {00 00 CF} a complete indexed line) per RFC 9204 §4.5.
	for cut := 4; cut < len(full); cut++ {
		if _, err := DecodeFieldSection(full[:cut]); err == nil {
			t.Fatalf("truncated at %d accepted", cut)
		}
	}
	if _, err := DecodeFieldSection(full); err != nil {
		t.Fatalf("full section rejected: %v", err)
	}
}

// Inbound responses may carry Huffman-encoded values (e.g. colo): the value
// string of a name-reference line with H=1 decodes through the RFC 7541 table.
func TestQPACKHuffmanInboundValue(t *testing.T) {
	huff := func(s string) []byte { return hpack.AppendHuffmanString(nil, s) }

	sec := []byte{0x00, 0x00}
	sec = append(sec, 0xCF) // :method CONNECT (noise line for realism)
	sec = append(sec, 0x50) // :authority literal...
	val := huff("cf-warp-colo")
	sec = appendQPACKInt(sec, 0x80, 7, uint64(len(val))) // H=1 + 7-bit-prefixed length
	sec = append(sec, val...)

	got, err := DecodeFieldSection(sec)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got[1] != [2]string{":authority", "cf-warp-colo"} {
		t.Errorf("huffman value line = %v", got[1])
	}
}
