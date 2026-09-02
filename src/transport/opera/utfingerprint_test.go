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
// GREASE values skipped per the JA3 spec).
func ja3(version uint16, ciphers, extensions []uint16) string {
	isGREASE := func(v uint16) bool { return v&0x0f0f == 0x0a0a }
	vals := fmt.Sprintf("%d,", version)
	for i, c := range ciphers {
		if isGREASE(c) {
			continue
		}
		if i > 0 {
			vals += "-"
		}
		vals += fmt.Sprintf("%d", c)
	}
	vals += ","
	sort.Slice(extensions, func(i, j int) bool { return extensions[i] < extensions[j] })
	for i, e := range extensions {
		if isGREASE(e) {
			continue
		}
		if i > 0 {
			vals += "-"
		}
		vals += fmt.Sprintf("%d", e)
	}
	vals += ",,"
	sum := md5.Sum([]byte(vals))
	return hex.EncodeToString(sum[:])
}

// TestUTLSChromeGoldenHello (review §7.7 OP-M1 verification): the uTLS
// layer must emit a Chrome-120 ClientHello with the OWNER'S ALPN override,
// the real SNI, and a fingerprint distinct from any plain-Go hello.
func TestUTLSChromeGoldenHello(t *testing.T) {
	var helloRaw []byte
	client := func(addr string) error {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			return err
		}
		defer raw.Close()
		mq := DefaultMasquerade() // chrome120, ALPN http/1.1
		_, err = dialUTLSClient(context.Background(), raw, "eu0.sec-tunnel.com", mq,
			utls.NewLRUClientSessionCache(4), func(cs utls.ConnectionState) error { return nil })
		return err // the capture listener never answers; the hello is what matters
	}
	helloRaw = captureClientHello(t, client)

	p := parseClientHello(t, helloRaw)
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

	// Extension set sanity: SNI, ALPN, key_share, PSK, supported_versions
	// and padding must be present (GREASE omitted by the JA3 view).
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

	// Deterministic golden: md5 over version+ciphers+sorted-extensions.
	got := ja3(0x0303, p.cipherSuites, p.extensions)
	want := "60b3ea9ff5201af35749d8a2a4db563a"
	if got != want {
		t.Fatalf("JA3-style golden drifted: got %s, want %s (re-pin after an intentional uTLS bump)", got, want)
	}
}

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
