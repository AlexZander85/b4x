package transportwarp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/rand"
	"testing"
)

func TestVarintRoundTrip(t *testing.T) {
	// Boundary values per RFC 9000 section 16 (max representable = 2^62-1).
	cases := []uint64{0, 1, 63, 64, 127, 128, 16383, 16384, 65535,
		268435455, 268435456, 4294967295,
		4611686018427387903}
	for _, v := range cases {
		buf := AppendVarint(nil, v)
		if got, n, err := ParseVarint(buf); err != nil || n != len(buf) || got != v {
			t.Fatalf("varint roundtrip %d: got %d (n=%d err=%v), want %d over %d bytes", v, got, n, err, v, VarintLen(v))
		}
		if want := VarintLen(v); len(buf) != want {
			t.Fatalf("varint %d encoded to %d bytes, want %d", v, len(buf), want)
		}
	}
}

func TestAppendVarintEncoding(t *testing.T) {
	// Hand-verified RFC 9000 section 16 example.
	if got := AppendVarint(nil, 15293); !bytes.Equal(got, []byte{0x7b, 0xbd}) {
		t.Fatalf("AppendVarint(15293) = % x", got)
	}
	// Length-class prefixes and boundaries (independent of literals).
	for _, tc := range []struct {
		v    uint64
		size int
		pref byte
	}{
		{63, 1, 0x00}, {64, 2, 0x40}, {16383, 2, 0x40},
		{16384, 4, 0x80}, {1<<30 - 1, 4, 0x80}, {1 << 30, 8, 0xc0},
	} {
		buf := AppendVarint(nil, tc.v)
		if len(buf) != tc.size || buf[0]>>6 != tc.pref>>6 {
			t.Fatalf("v=%d size=%d prefix=%#x", tc.v, len(buf), buf[0])
		}
		if got, n, err := ParseVarint(buf); err != nil || got != tc.v || n != len(buf) {
			t.Fatalf("boundary decode %d: %d n=%d err=%v", tc.v, got, n, err)
		}
	}
}

func TestParseVarintTruncated(t *testing.T) {
	if _, _, err := ParseVarint(nil); !errors.Is(err, ErrVarintTruncated) {
		t.Fatalf("empty input: err=%v", err)
	}
	if _, _, err := ParseVarint([]byte{0x81}); !errors.Is(err, ErrVarintTruncated) {
		t.Fatalf("truncated 2-byte: err=%v", err)
	}
	if _, _, err := ParseVarint([]byte{0xc0}); !errors.Is(err, ErrVarintTruncated) {
		t.Fatalf("truncated 8-byte: err=%v", err)
	}
}

func TestParseVarintRandomRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	const max62 = uint64(1)<<62 - 1
	for i := 0; i < 2000; i++ {
		v := rng.Uint64() & max62
		buf := AppendVarint(nil, v)
		got, n, err := ParseVarint(buf)
		if err != nil || got != v || n != len(buf) {
			t.Fatalf("roundtrip %#x: got %#x n=%d err=%v buf=% x", v, got, n, err, buf)
		}
	}
}

// TestVarintCrossCheckBinary puts the encoder against encoding/binary's
// big-endian view of the payload bits for multi-byte encodings.
func TestVarintCrossCheckBinary(t *testing.T) {
	v := uint64(0x123456)
	buf := AppendVarint(nil, v)
	if len(buf) != 4 || buf[0]>>6 != 2 {
		t.Fatalf("unexpected encoding % x", buf)
	}
	raw := binary.BigEndian.Uint32(append([]byte{buf[0] & 0x3f}, buf[1:]...))
	if uint64(raw) != v {
		t.Fatalf("binary crosscheck: %d != %d", raw, v)
	}
}
