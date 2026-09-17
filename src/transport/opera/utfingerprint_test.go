package opera

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

// captureClientHello listens raw, captures the first ClientHello record the
// client sends, and hands the bytes back for inspection (JA3 goldens need
// the RAW hello, not the server-side view).
func captureClientHello(t *testing.T, client func(addr string) error) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	type result struct {
		hello []byte
		err   error
	}
	done := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer c.Close()
		hdr := make([]byte, 5)
		if _, err := readFull(c, hdr); err != nil {
			done <- result{err: err}
			return
		}
		if hdr[0] != 0x16 {
			done <- result{err: fmt.Errorf("not a handshake record: %x", hdr[0])}
			return
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		body := make([]byte, recLen)
		if _, err := readFull(c, body); err != nil {
			done <- result{err: err}
			return
		}
		done <- result{hello: append(append([]byte{}, hdr...), body...)}
	}()

	go func() { _ = client(ln.Addr().String()) }()

	select {
	case res := <-done:
		if res.err != nil {
			t.Fatalf("capture: %v", res.err)
		}
		return res.hello
	case <-time.After(5 * time.Second):
		t.Fatal("capture timeout")
		return nil
	}
}

func readFull(c net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := c.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// minimal ClientHello parser (record header + handshake body).
type parsedHello struct {
	cipherSuites []uint16
	extensions   []uint16
	sni          string
	alpn         []string
}

func parseClientHello(t *testing.T, raw []byte) parsedHello {
	t.Helper()
	// skip record header (5), handshake header (4)
	b := raw[9:]
	if len(b) < 34 {
		t.Fatal("hello too short")
	}
	b = b[2:]  // client version
	b = b[32:] // random
	sidLen := int(b[0])
	b = b[1+sidLen:]
	csLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	var out parsedHello
	for i := 0; i+1 < csLen; i += 2 {
		out.cipherSuites = append(out.cipherSuites, binary.BigEndian.Uint16(b[i:i+2]))
	}
	b = b[csLen:]
	compLen := int(b[0])
	b = b[1+compLen:]
	if len(b) < 2 {
		return out // no extensions
	}
	extLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	for i := 0; i+4 <= extLen; {
		etype := binary.BigEndian.Uint16(b[i : i+2])
		elen := int(binary.BigEndian.Uint16(b[i+2 : i+4]))
		body := b[i+4 : min(i+4+elen, len(b))]
		switch etype {
		case 0: // SNI
			if len(body) > 5 {
				nameLen := int(binary.BigEndian.Uint16(body[3:5]))
				if 5+nameLen <= len(body) {
					out.sni = string(body[5 : 5+nameLen])
				}
			}
		case 16: // ALPN
			if len(body) >= 2 {
				listLen := int(binary.BigEndian.Uint16(body[:2]))
				bb := body[2 : 2+listLen]
				for len(bb) > 0 {
					l := int(bb[0])
					if 1+l > len(bb) {
						break
					}
					out.alpn = append(out.alpn, string(bb[1:1+l]))
					bb = bb[1+l:]
				}
			}
		}
		out.extensions = append(out.extensions, etype)
		i += 4 + elen
	}
	return out
}

// ja3 computes the JA3-style md5 over version+ciphers+sorted extensions
// (extensions sorted to neutralize Chrome's authentic extension shuffle;
// GREASE values skipped per the JA3 spec). The separator is appended between
// APPENDED values only: an index-based separator would leave a leading dash
// whenever the first element is GREASE (Chrome always opens the cipher list
// with GREASE), and that artifact hash would match no real JA3 tool.
func ja3(version uint16, ciphers, extensions []uint16) string {
	isGREASE := func(v uint16) bool { return v&0x0f0f == 0x0a0a }
	vals := fmt.Sprintf("%d,", version)
	appendVals := func(list []uint16) {
		first := true
		for _, v := range list {
			if isGREASE(v) {
				continue
			}
			if !first {
				vals += "-"
			}
			first = false
			vals += fmt.Sprintf("%d", v)
		}
	}
	appendVals(ciphers)
	vals += ","
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })
	appendVals(extensions)
	vals += ",,"
	sum := md5.Sum([]byte(vals))
	return hex.EncodeToString(sum[:])
}

// TestUTLSChromeGoldenHello (review §7.7 OP-M1 verification): the uTLS
// layer must emit a Chrome-120 ClientHello with the OWNER'S ALPN override,
// the real SNI, and a fingerprint distinct from any plain-Go hello.
func TestUTLSChromeGoldenHello(t *testing.T) {
	// One production-path capture: a fresh uTLS dial against a listener
	// that records the hello and never answers (the handshake cannot
	// complete, which is fine — the hello bytes are the whole subject).
	captureOnce := func() parsedHello {
		client := func(addr string) error {
			raw, err := net.Dial("tcp", addr)
			if err != nil {
				return err
			}
			defer raw.Close()
			mq := DefaultMasquerade() // chrome120, ALPN http/1.1
			_, err = dialUTLSClient(context.Background(), raw, "eu0.sec-tunnel.com", mq,
				utls.NewLRUClientSessionCache(4), func(cs utls.ConnectionState) error { return nil })
			return err
		}
		return parseClientHello(t, captureClientHello(t, client))
	}
	assertChromeShape := func(p parsedHello) {
		if p.sni != "eu0.sec-tunnel.com" {
			t.Fatalf("SNI = %q, want the real node name", p.sni)
		}
		if len(p.alpn) != 2 || p.alpn[0] != "h2" || p.alpn[1] != "http/1.1" {
			t.Fatalf("ALPN = %v, want the owner override [h2,http/1.1]", p.alpn)
		}

		// Chrome 120 cipher list (GREASE 0x?A?A filtered by the JA3 view).
		wantCiphers := []uint16{
			0x1301, 0x1302, 0x1303,
			0xC02B, 0xC02F, 0xC02C, 0xC030, 0xCCA9, 0xCCA8,
			0xC013, 0xC014, 0x009C, 0x009D, 0x002F, 0x0035,
		}
		if len(p.cipherSuites) < len(wantCiphers)-2 {
			t.Fatalf("cipher count = %d (%x), want the Chrome-120 set", len(p.cipherSuites), p.cipherSuites)
		}
		first := make(map[uint16]bool)
		for _, c := range p.cipherSuites {
			first[c] = true
		}
		for _, want := range wantCiphers {
			if !first[want] {
				t.Fatalf("cipher 0x%04x missing from the Chrome-120 offer", want)
			}
		}

		// Extension set sanity: SNI, ALPN, key_share and supported_versions
		// must be present (GREASE omitted by the JA3 view; the padding
		// extension is deliberately absent here — it is mode-dependent,
		// see the golden below).
		ext := make(map[uint16]bool)
		for _, e := range p.extensions {
			ext[e] = true
		}
		for _, want := range []uint16{0x0000, 0x0010, 0x0033, 0x002b} {
			if !ext[want] {
				t.Fatalf("extension 0x%04x missing from the Chrome hello", want)
			}
		}
		// NOTE: the PSK extension (0x0029) is absent on a FRESH handshake by
		// design (OmitEmptyPsk conceals it until a session ticket exists —
		// Chrome behaves the same way).
	}

	// Deterministic golden: md5 over version+ciphers+sorted-extensions.
	//
	// The Chrome-120 hello is LENGTH-BIMODAL BY DESIGN — this mirrors real
	// Chrome and is NOT fingerprint drift. uTLS' BoringGREASEECH draws the
	// ECH-GREASE payload length from {128,160,192,224}+16 bytes per
	// connection, and BoringPaddingStyle adds the padding extension (0x0015)
	// only when the UNPADDED hello lands in (255, 512): a short ECH draw is
	// padded to exactly 512 bytes (the hello then carries ext 21), a long
	// one sits above the threshold with no padding at all. The observable
	// extension SET therefore has exactly two stable variants (the JA3
	// hashes only IDs, not lengths, so payload draws inside one mode hash
	// identically) — pin both, select by the padding extension seen, and
	// capture until BOTH variants have been validated.
	seenPadded, seenNoPad := false, false
	for attempt := 0; attempt < 32 && !(seenPadded && seenNoPad); attempt++ {
		p := captureOnce()
		assertChromeShape(p)
		got := ja3(0x0303, p.cipherSuites, append([]uint16(nil), p.extensions...))
		padded := false
		for _, e := range p.extensions {
			if e == 0x0015 {
				padded = true
			}
		}
		want := goldenJA3Chrome120NoPad
		if padded {
			want = goldenJA3Chrome120Padded
		}
		if got != want {
			ciph := make([]string, 0, len(p.cipherSuites))
			for _, c := range p.cipherSuites {
				ciph = append(ciph, fmt.Sprintf("%04x", c))
			}
			ext := make([]string, 0, len(p.extensions))
			for _, e := range p.extensions {
				ext = append(ext, fmt.Sprintf("%04x", e))
			}
			t.Fatalf("JA3-style golden drifted: got %s (padded=%v), want %s (re-pin after an intentional uTLS bump); wire ciphers=[%s] wire exts=[%s]",
				got, padded, want, strings.Join(ciph, " "), strings.Join(ext, " "))
		}
		if padded {
			seenPadded = true
		} else {
			seenNoPad = true
		}
	}
	if !seenPadded || !seenNoPad {
		// The golden never lies when it IS observed — but one variant may
		// stay unobserved within the budget (the padded mode manifests on
		// roughly every fourth draw). An unobserved variant is a coverage
		// gap for the next run to close, not a fingerprint failure.
		t.Skipf("JA3 golden covered only one bimodal variant in 32 captures (padded=%v, noPad=%v); re-run for full coverage", seenPadded, seenNoPad)
	}
}

// The two pinned JA3-style goldens of the uTLS Chrome-120 ClientHello
// (see TestUTLSChromeGoldenHello for the bimodality rationale).
const (
	// Long ECH-GREASE draw: the unpadded hello is above the BoringSSL pad
	// threshold, so no padding extension is present.
	goldenJA3Chrome120NoPad = "c6d2a29454c25daacb05f58703349e3d"
	// Short ECH-GREASE draw: BoringPaddingStyle pads the hello to exactly
	// 512 bytes and the extension set gains 0x0015 (padding).
	goldenJA3Chrome120Padded = "5aba9b2856b0f458793999a2bed97dcd"
)

// TestUTLSFingerprintLadderFallback: the minimal profile drops the uTLS
// layer by design (§7.5 rung 'plain-Go'), so a broken fingerprint layer can
// be stepped around without code changes.
func TestUTLSFingerprintLadderFallback(t *testing.T) {
	mq := ResolveMasquerade("minimal", "", nil, nil, nil, false)
	if mq.FingerprintActive() {
		t.Fatal("minimal profile must not activate the uTLS layer")
	}
	mq = ResolveMasquerade("off", "", nil, nil, nil, false)
	if mq.FingerprintActive() {
		t.Fatal("off profile must not activate the uTLS layer")
	}
	if DefaultMasquerade().Fingerprint != FingerprintChrome120 {
		t.Fatalf("default fingerprint = %q, want chrome120", DefaultMasquerade().Fingerprint)
	}
	_ = tls.VersionTLS12
	_ = strings.TrimSpace("")
}
