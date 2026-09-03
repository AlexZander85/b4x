package sni

import (
	"strings"
	"testing"
)

func ja4SyntheticHello(withSNI bool) []byte {
	var ext []byte
	if withSNI {
		// server_name: one host_name entry, "a".
		ext = append(ext, 0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x01, 'a')
	}
	// A GREASE extension, ignored entirely.
	ext = append(ext, 0x1a, 0x1a, 0x00, 0x00)
	// signature_algorithms: 0x0403, 0x0804.
	ext = append(ext, 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x03, 0x08, 0x04)
	// ALPN: "h2".
	ext = append(ext, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 'h', '2')
	// supported_versions: TLS 1.3 plus a GREASE value.
	ext = append(ext, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x0a, 0x0a, 0x03, 0x04)

	body := []byte{0x03, 0x03} // legacy version
	for i := 0; i < 32; i++ {
		body = append(body, 0x11) // random
	}
	body = append(body, 0x00)             // no session id
	body = append(body, 0x00, 0x06)       // cipher list length
	body = append(body, 0x1a, 0x1a, 0x13, 0x01, 0x13, 0x02) // GREASE + two real
	body = append(body, 0x01, 0x00)       // compression: length 1, null method
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)

	handshake := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)

	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func TestJA4GREASEPattern(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0x2a2a, 0x8a8a, 0xdada, 0xfafa} {
		if !IsGREASE(v) {
			t.Fatalf("%#04x must be GREASE", v)
		}
	}
	for _, v := range []uint16{0x1301, 0xc02b, 0x0000, 0x000d, 0x0a1a, 0x1a0a, 0xabab} {
		if IsGREASE(v) {
			t.Fatalf("%#04x must NOT be GREASE", v)
		}
	}
}

func TestJA4ParsesHandBuiltHello(t *testing.T) {
	hello, err := ParseJA4ClientHello(ja4SyntheticHello(true))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(hello.Ciphers) != 2 || hello.Ciphers[0] != 0x1301 || hello.Ciphers[1] != 0x1302 {
		t.Fatalf("ciphers %v (GREASE must be removed)", hello.Ciphers)
	}
	for _, e := range hello.Extensions {
		if e == 0x1a1a {
			t.Fatal("GREASE extension leaked into list")
		}
	}
	if len(hello.SigAlgs) != 2 || hello.SigAlgs[0] != 0x0403 || hello.SigAlgs[1] != 0x0804 {
		t.Fatalf("sigalgs %v", hello.SigAlgs)
	}
	if len(hello.ALPN) != 1 || hello.ALPN[0] != "h2" {
		t.Fatalf("alpn %v", hello.ALPN)
	}
	if !hello.HasSNI {
		t.Fatal("sni presence lost")
	}
	if hello.Version != 0x0304 {
		t.Fatalf("supported_versions must win over legacy: %#04x", hello.Version)
	}
}

func TestJA4ReadableHalf(t *testing.T) {
	hello, err := ParseJA4ClientHello(ja4SyntheticHello(true))
	if err != nil {
		t.Fatal(err)
	}
	// TLS 1.3, has SNI, 2 ciphers, 4 non-GREASE extensions, ALPN h2.
	if got := hello.JA4A(); got != "t13d0204h2" {
		t.Fatalf("ja4_a = %q, want t13d0204h2", got)
	}
}

func TestJA4SNIDiffersOnlyInReadableHalf(t *testing.T) {
	with, err := ParseJA4ClientHello(ja4SyntheticHello(true))
	if err != nil {
		t.Fatal(err)
	}
	without, err := ParseJA4ClientHello(ja4SyntheticHello(false))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(with.JA4A(), "d") || !strings.Contains(without.JA4A(), "i") {
		t.Fatalf("sni flags wrong: %q vs %q", with.JA4A(), without.JA4A())
	}
	if with.JA4() == without.JA4() {
		t.Fatal("fingerprints must differ")
	}
	// SNI is excluded from the hash on purpose (varies per request).
	if with.JA4C() != without.JA4C() {
		t.Fatal("ja4_c must ignore SNI presence")
	}
}

func TestJA4CipherOrderInvariant(t *testing.T) {
	a := &JA4Hello{Ciphers: []uint16{0x1301, 0x1302, 0xc02b}}
	b := &JA4Hello{Ciphers: []uint16{0xc02b, 0x1301, 0x1302}}
	if a.JA4B() != b.JA4B() {
		t.Fatal("cipher order must not change ja4_b")
	}
}

func TestJA4SigAlgOrderMatters(t *testing.T) {
	a := &JA4Hello{SigAlgs: []uint16{0x0403, 0x0804}, Extensions: []uint16{0x000d}}
	b := &JA4Hello{SigAlgs: []uint16{0x0804, 0x0403}, Extensions: []uint16{0x000d}}
	if a.JA4C() == b.JA4C() {
		t.Fatal("sigalg wire order is implementation identity")
	}
}

func TestJA4TruncationNeverPanics(t *testing.T) {
	full := ja4SyntheticHello(true)
	for cut := 1; cut < len(full); cut++ {
		_, _ = ParseJA4ClientHello(full[:cut]) // may error, must not panic
	}
	if _, err := ParseJA4ClientHello(full[:10]); err == nil {
		t.Fatal("deep truncation must be an error")
	}
}

func TestJA4RefusesNonClientHello(t *testing.T) {
	if _, err := ParseJA4ClientHello([]byte{0x02, 0, 0, 0}); err == nil {
		t.Fatal("non-CH handshake must be refused")
	}
	if _, err := ParseJA4ClientHello(nil); err == nil {
		t.Fatal("empty input must be refused")
	}
	// Bare handshake (without the 5-byte record header) parses identically.
	full := ja4SyntheticHello(true)
	a, errA := ParseJA4ClientHello(full)
	b, errB := ParseJA4ClientHello(full[5:])
	if errA != nil || errB != nil || a.JA4() != b.JA4() {
		t.Fatal("bare handshake must parse to the same fingerprint")
	}
}
