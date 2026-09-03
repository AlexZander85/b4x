package quic

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildInitialPacket constructs a minimal long-header QUIC Initial packet
// with the given version, DCID bytes and payload (no token). Header layout:
// flags(1) + version(4) + dcidLen(1) + dcid + scidLen(1) + scid + tokenLen
// varint(0) + length varint + payload.
func buildInitialPacket(version uint32, dcid, scid, payload []byte) []byte {
	pkt := make([]byte, 0, 1+4+1+len(dcid)+1+len(scid)+1+1+len(payload))
	pkt = append(pkt, 0xC0) // long header, Initial-type bits set to 0b00 (v1)
	pkt = binary.BigEndian.AppendUint32(pkt, version)
	pkt = append(pkt, byte(len(dcid)))
	pkt = append(pkt, dcid...)
	pkt = append(pkt, byte(len(scid)))
	pkt = append(pkt, scid...)
	pkt = append(pkt, 0x00) // token length varint = 0
	pkt = append(pkt, byte(len(payload)))
	pkt = append(pkt, payload...)
	return pkt
}

func TestParseDCID(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	pkt := buildInitialPacket(versionV1, dcid, []byte{0xAA}, []byte{0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00})
	if got := ParseDCID(pkt); !bytes.Equal(got, dcid) {
		t.Fatalf("ParseDCID = %x, want %x", got, dcid)
	}
}

func TestParseDCIDRejectsShortOrShortHeader(t *testing.T) {
	if ParseDCID([]byte{0x01, 0x02}) != nil {
		t.Fatal("short packet must return nil")
	}
	// Short header (first bit clear) with enough bytes.
	short := make([]byte, 8)
	short[0] = 0x40
	if ParseDCID(short) != nil {
		t.Fatal("short-header packet must return nil")
	}
	// Truncated DCID length.
	pkt := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x01}
	if ParseDCID(pkt) != nil {
		t.Fatal("truncated DCID must return nil")
	}
}

func TestIsInitialVersioned(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	v1 := buildInitialPacket(versionV1, dcid, []byte{9}, nil)
	if !IsInitial(v1) {
		t.Fatal("v1 Initial not detected")
	}
	// v2 Initial type is 0b01 -> header byte 0xD0.
	v2 := buildInitialPacket(versionV2, dcid, []byte{9}, nil)
	v2[0] = 0xD0
	if !IsInitial(v2) {
		t.Fatal("v2 Initial not detected")
	}
	// Short header and tiny packets are never Initial.
	if IsInitial([]byte{0x40, 0, 0, 0, 0, 0, 0}) {
		t.Fatal("short header classified as Initial")
	}
	if IsInitial([]byte{0xC0, 0, 0, 0, 0}) {
		t.Fatal("tiny packet classified as Initial")
	}
	// Unknown version is not Initial regardless of type bits.
	unknown := buildInitialPacket(0xDEADBEEF, dcid, []byte{9}, nil)
	if IsInitial(unknown) {
		t.Fatal("unknown version classified as Initial")
	}
}

func TestLooksLikeQUICBounds(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	if !LooksLikeQUIC(buildInitialPacket(versionV1, dcid, []byte{9}, nil)) {
		t.Fatal("valid long header not recognized")
	}
	if LooksLikeQUIC([]byte{0x40, 0, 0, 0, 0, 0, 0}) {
		t.Fatal("short header recognized as QUIC")
	}
	// Oversized DCID/SCID ( > 20) must be rejected.
	big := make([]byte, 21)
	for i := range big {
		big[i] = 0x42
	}
	pkt := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 21}
	pkt = append(pkt, big...)
	if LooksLikeQUIC(pkt) {
		t.Fatal("oversized DCID accepted")
	}
}

func TestReadVar(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x3F}, 0x3F, 1},
		{[]byte{0x40, 0x01}, 1, 2},
		{[]byte{0x80, 0x00, 0x00, 0x01}, 1, 4},
		{[]byte{0xC0, 0, 0, 0, 0, 0, 0, 0x01}, 1, 8},
	}
	for _, c := range cases {
		got, n := readVar(c.in)
		if got != c.want || n != c.n {
			t.Fatalf("readVar(%x) = (%d,%d), want (%d,%d)", c.in, got, n, c.want, c.n)
		}
	}
	if _, n := readVar(nil); n != 0 {
		t.Fatal("empty buffer must report 0 bytes")
	}
	if _, n := readVar([]byte{0x40}); n != 0 {
		t.Fatal("truncated 2-byte varint must report 0 bytes")
	}
}

func TestExtractCrypto(t *testing.T) {
	// ExtractCrypto skips flags(1) + version(4) + CID block and then parses
	// QUIC frames immediately, so the buffer must NOT carry the QUIC
	// token/length fields (it mirrors the decrypted Initial payload).
	build := func(crypto []byte) []byte {
		pkt := make([]byte, 0, 1+4+1+4+1+1+len(crypto))
		pkt = append(pkt, 0xC0) // long header, Initial type bits
		pkt = binary.BigEndian.AppendUint32(pkt, versionV1)
		pkt = append(pkt, 0x04)
		pkt = append(pkt, 1, 2, 3, 4) // DCID
		pkt = append(pkt, 0x01)
		pkt = append(pkt, 5) // SCID
		pkt = append(pkt, crypto...)
		return pkt
	}
	// CRYPTO frame: type 0x06, offset 0, length 3, payload "abc".
	got, ok := ExtractCrypto(build([]byte{0x06, 0x00, 0x03, 'a', 'b', 'c'}))
	if !ok || string(got) != "abc" {
		t.Fatalf("ExtractCrypto = %q,%v want abc,true", got, ok)
	}
	// Non-initial packet -> not found.
	if _, ok := ExtractCrypto([]byte{0x40, 0, 0, 0, 0, 0, 0}); ok {
		t.Fatal("short header must not extract crypto")
	}
	// Truncated crypto payload -> not found.
	if _, ok := ExtractCrypto(build([]byte{0x06, 0x00, 0x05, 'a'})); ok {
		t.Fatal("truncated crypto frame must not extract")
	}
	// Non-CRYPTO frame with offset+length structure must be skipped over
	// (STREAM frame type 0x08 with offset 0, length 1, payload "z").
	if got, ok := ExtractCrypto(build([]byte{0x08, 0x00, 0x01, 'z', 0x06, 0x00, 0x01, 'w'})); !ok || string(got) != "w" {
		t.Fatalf("frame after STREAM = %q,%v want w,true", got, ok)
	}
}

func TestHkdfExpandLabelDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	a, err := hkdfExpandLabel(secret, "client in", 32)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hkdfExpandLabel(secret, "client in", 32)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatalf("hkdf not deterministic: %x vs %x (%v)", a, b, err)
	}
	if len(a) != 32 {
		t.Fatalf("hkdf length = %d, want 32", len(a))
	}
	// Different label yields different output.
	c, _ := hkdfExpandLabel(secret, "quic key", 16)
	if bytes.Equal(a[:16], c) {
		t.Fatal("different labels produced identical keys")
	}
}

func TestParseCryptoFramesSkipsPaddingPingAndStopsOnUnknown(t *testing.T) {
	// 0x00 padding, 0x01 ping, then a CRYPTO frame with offset 0 length 2 "hi".
	plain := []byte{0x00, 0x00, 0x01, 0x06, 0x00, 0x02, 'h', 'i'}
	frames := parseCryptoFrames(plain)
	if len(frames) != 1 || frames[0].off != 0 || string(frames[0].b) != "hi" {
		t.Fatalf("frames = %+v", frames)
	}
	// Unknown frame type terminates parsing safely.
	bad := []byte{0x06, 0x00, 0x02, 'x', 'y', 0x07}
	if frames := parseCryptoFrames(bad); len(frames) != 1 {
		t.Fatalf("unknown frame type must stop parsing: %+v", frames)
	}
}

func TestAssembleCryptoOrderAndBounds(t *testing.T) {
	defer ClearDCID([]byte("test-dcid"))
	// Two fragments: offset 0 "aa", offset 2 "bb" -> "aabb".
	if _, ok := AssembleCrypto([]byte("test-dcid"), []byte{0x06, 0x00, 0x02, 'a', 'a'}); !ok {
		t.Fatal("first fragment not accepted")
	}
	got, ok := AssembleCrypto([]byte("test-dcid"), []byte{0x06, 0x02, 0x02, 'b', 'b'})
	if !ok || string(got) != "aabb" {
		t.Fatalf("assembled = %q,%v want aabb,true", got, ok)
	}
	// Empty DCID / payload rejected.
	if _, ok := AssembleCrypto(nil, []byte{0x06, 0x00, 0x01, 'x'}); ok {
		t.Fatal("empty DCID must be rejected")
	}
	if _, ok := AssembleCrypto([]byte("d"), nil); ok {
		t.Fatal("empty payload must be rejected")
	}
}

func TestLocateSNIInClientHello(t *testing.T) {
	// Minimal ClientHello carrying a server_name extension for example.com.
	// Handshake: type 1, length, version 0x0303, random 32B, sid len 0,
	// cipher suites len 2 (one suite), compression len 1, extensions.
	ch := []byte{0x01, 0x00, 0x00, 0x00}
	ch = append(ch, 0x03, 0x03)
	ch = append(ch, bytes.Repeat([]byte{0x11}, 32)...)
	ch = append(ch, 0x00)       // session id len
	ch = append(ch, 0x00, 0x02) // cipher suites len
	ch = append(ch, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	ch = append(ch, 0x01)       // compression len
	ch = append(ch, 0x00)       // null
	// server_name extension: type 0x0000, len, list len, name type 0, name len, name.
	sni := []byte("example.com")
	ext := []byte{0x00, 0x00}
	ext = binary.BigEndian.AppendUint16(ext, uint16(5+len(sni)))
	ext = binary.BigEndian.AppendUint16(ext, uint16(3+len(sni)))
	ext = append(ext, 0x00) // name_type host_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(sni)))
	ext = append(ext, sni...)
	ch = binary.BigEndian.AppendUint16(ch, uint16(len(ext)))
	ch = append(ch, ext...)

	off, ln := locateSNIInClientHello(ch)
	if off < 0 || ln != len(sni) || string(ch[off:off+ln]) != "example.com" {
		t.Fatalf("locateSNIInClientHello = (%d,%d), want example.com at %d", off, ln, off)
	}
	// Non-ClientHello first byte -> not found.
	if off, _ := locateSNIInClientHello([]byte{0x02, 0x00, 0x00, 0x00}); off != -1 {
		t.Fatal("non-ClientHello must not be located")
	}
	// Truncated input -> not found, no panic.
	if off, _ := locateSNIInClientHello([]byte{0x01, 0x00}); off != -1 {
		t.Fatal("truncated input must not be located")
	}
}

func FuzzQUICParsingNeverPanics(f *testing.F) {
	f.Add([]byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01})
	f.Add([]byte{0xD0, 0x6B, 0x33, 0x43, 0xCF, 0x08, 0x01, 0x02, 0x03, 0x04})
	f.Add([]byte{0x40, 0x00})
	f.Fuzz(func(t *testing.T, b []byte) {
		ParseDCID(b)
		IsInitial(b)
		LooksLikeQUIC(b)
		readVar(b)
		ExtractCrypto(b)
		parseCryptoFrames(b)
		locateSNIInClientHello(b)
	})
}
