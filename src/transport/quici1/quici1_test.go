// Golden tests of the enriched QUIC Initial (review §4.4 + §6): decrypt
// the packet per RFC 9000/9001 with an INDEPENDENT code path, parse the
// ClientHello back out and pin the Chrome-class shape — extension order,
// session_id, cipher order, supported_versions, key_share, alpn, the QUIC
// transport parameters with initial_source_connection_id == DCID, and the
// padding extension.
package quici1

import (
        "bytes"
        "crypto/aes"
        "crypto/cipher"
        "crypto/hmac"
        "crypto/sha256"
        "encoding/hex"
        "strings"
        "testing"

        "golang.org/x/crypto/hkdf"
)

// xorshift feeds deterministic randomness (reproducible golden vectors).
type xorshift struct{ state uint64 }

func newXorshift(seed uint64) *xorshift { return &xorshift{state: seed} }

func (r *xorshift) Read(p []byte) (int, error) {
        for i := range p {
                r.state ^= r.state << 13
                r.state ^= r.state >> 7
                r.state ^= r.state << 17
                p[i] = byte(r.state)
        }
        return len(p), nil
}

// decryptedInitial is the RFC-honest unpacking of one generated packet:
// key schedule -> header protection removal -> AES-GCM open -> CRYPTO
// frame -> ClientHello.
type decryptedInitial struct {
        dcid []byte
        ch   []byte // full ClientHello handshake message
}

func decryptInitial(t *testing.T, packet []byte) decryptedInitial {
        t.Helper()

        mac := hmac.New(sha256.New, InitialSalt)
        mac.Write(packet[6:14])
        initialSecret := mac.Sum(nil)
        label := func(secret []byte, l string, n int) []byte {
                full := []byte("tls13 " + l)
                info := make([]byte, 0, 2+1+len(full)+1)
                info = append(info, byte(n>>8), byte(n), byte(len(full)))
                info = append(info, full...)
                info = append(info, 0)
                out := make([]byte, n)
                r := hkdf.Expand(sha256.New, secret, info)
                _, _ = r.Read(out)
                return out
        }
        clientSecret := label(initialSecret, "client in", 32)
        key := label(clientSecret, "quic key", 16)
        iv := label(clientSecret, "quic iv", 12)
        hp := label(clientSecret, "quic hp", 16)

        if packet[5]>>4 != 8 {
                t.Fatalf("DCIL = %d, want 8", packet[5]>>4)
        }
        dcid := append([]byte{}, packet[6:14]...)
        dcEnd := 14
        if packet[dcEnd] != 0x00 {
                t.Fatalf("token length = %02x, want empty", packet[dcEnd])
        }
        // Length varInt.
        lenFirst := packet[dcEnd+1]
        viLen := 1 << (lenFirst >> 6)
        length := uint64(lenFirst & 0x3F)
        for i := 1; i < viLen; i++ {
                length = length<<8 | uint64(packet[dcEnd+1+i])
        }
        pnOffset := dcEnd + 1 + viLen
        headerLen := pnOffset + 1

        hpBlock, err := aes.NewCipher(hp)
        if err != nil {
                t.Fatal(err)
        }
        sample := packet[pnOffset+4:][:16]
        mask := make([]byte, 16)
        hpBlock.Encrypt(mask, sample)

        plainHeader := append([]byte{}, packet[:headerLen]...)
        plainHeader[0] ^= mask[0] & 0x0F
        plainHeader[headerLen-1] ^= mask[1]
        if plainHeader[0] != 0xC0 || plainHeader[headerLen-1] != 0x00 {
                t.Fatalf("unprotected header % x", plainHeader[:2])
        }
        nonce := append([]byte{}, iv...)
        nonce[len(nonce)-1] ^= plainHeader[headerLen-1]
        block, _ := aes.NewCipher(key)
        gcm, _ := cipher.NewGCM(block)
        payload, err := gcm.Open(nil, nonce, packet[headerLen:], plainHeader[:headerLen])
        if err != nil {
                t.Fatalf("GCM open failed: %v", err)
        }
        if int(length)-1-16 != len(payload) {
                t.Fatalf("payload len %d != Length-PKN-tag %d", len(payload), int(length)-1-16)
        }
        if payload[0] != 0x06 {
                t.Fatalf("frame type %02x, want CRYPTO", payload[0])
        }
        if payload[1] != 0x00 {
                t.Fatalf("crypto offset %02x, want 0", payload[1])
        }
        readVarInt := func(b []byte) (uint64, int) {
                first := b[0]
                n := 1 << (first >> 6)
                v := uint64(first & 0x3F)
                for i := 1; i < n; i++ {
                        v = v<<8 | uint64(b[i])
                }
                return v, n
        }
        chLen, vn := readVarInt(payload[2:])
        if int(chLen) > len(payload)-2-vn {
                t.Fatalf("crypto length %d exceeds payload %d", chLen, len(payload))
        }
        ch := payload[2+vn : 2+vn+int(chLen)]
        if ch[0] != 0x01 {
                t.Fatalf("handshake type %02x, want ClientHello", ch[0])
        }
        return decryptedInitial{dcid: dcid, ch: ch}
}

// tlsExtension is one parsed TLS extension.
type tlsExtension struct {
        typ  uint16
        body []byte
}

func parseClientHello(t *testing.T, ch []byte) (random, sessionID []byte, suites []uint16, exts []tlsExtension) {
        t.Helper()
        if len(ch) < 4+2+32+1 {
                t.Fatalf("CH too short: %d", len(ch))
        }
        body := ch[4:]
        if !bytes.Equal(body[0:2], []byte{0x03, 0x03}) {
                t.Fatalf("legacy_version = %x, want 0303", body[0:2])
        }
        random = append([]byte{}, body[2:34]...)
        sidLen := int(body[34])
        sessionID = append([]byte{}, body[35:35+sidLen]...)
        pos := 35 + sidLen
        csLen := int(body[pos])<<8 | int(body[pos+1])
        pos += 2
        for i := 0; i < csLen; i += 2 {
                suites = append(suites, uint16(body[pos+i])<<8|uint16(body[pos+i+1]))
        }
        pos += csLen
        compLen := int(body[pos])
        pos++
        if compLen != 1 || body[pos] != 0x00 {
                t.Fatalf("compression = % x, want [0]", body[pos:pos+compLen])
        }
        pos += compLen
        extLen := int(body[pos])<<8 | int(body[pos+1])
        pos += 2
        blob := body[pos : pos+extLen]
        for len(blob) > 0 {
                if len(blob) < 4 {
                        t.Fatalf("truncated extension % x", blob)
                }
                typ := uint16(blob[0])<<8 | uint16(blob[1])
                ln := int(blob[2])<<8 | int(blob[3])
                if 4+ln > len(blob) {
                        t.Fatalf("extension %04x overruns blob", typ)
                }
                exts = append(exts, tlsExtension{typ: typ, body: append([]byte{}, blob[4:4+ln]...)})
                blob = blob[4+ln:]
        }
        return random, sessionID, suites, exts
}

func readQUICVarInt(b []byte) (uint64, int) {
        first := b[0]
        n := 1 << (first >> 6)
        v := uint64(first & 0x3F)
        for i := 1; i < n; i++ {
                v = v<<8 | uint64(b[i])
        }
        return v, n
}

// TestEnrichedInitialGoldenShape is the review §6 golden test: decrypt,
// parse, and pin every chrome-class element of the ClientHello.
func TestEnrichedInitialGoldenShape(t *testing.T) {
        const sni = "www.gosuslugi.ru"
        i1 := Build(sni, newXorshift(0xBEEF))
        if i1 == "" {
                t.Fatal("Build returned empty")
        }
        raw, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(i1, "<b 0x"), ">"))
        if err != nil {
                t.Fatal(err)
        }
        if len(raw) != PadTo {
                t.Fatalf("packet size %d, want %d", len(raw), PadTo)
        }

        dec := decryptInitial(t, raw)
        random, sessionID, suites, exts := parseClientHello(t, dec.ch)

        if len(sessionID) != 32 {
                t.Fatalf("session_id %d bytes, want 32 (browsers never send empty)", len(sessionID))
        }
        if len(random) != 32 {
                t.Fatalf("random %d bytes, want 32", len(random))
        }
        wantSuites := []uint16{0x1301, 0x1303, 0x1302} // Chrome order
        if len(suites) != len(wantSuites) {
                t.Fatalf("cipher_suites % x, want % x", suites, wantSuites)
        }
        for i := range wantSuites {
                if suites[i] != wantSuites[i] {
                        t.Fatalf("cipher_suites[%d] = %04x, want %04x (Chrome order)", i, suites[i], wantSuites[i])
                }
        }

        // Extension order (review §4.4): GREASE, server_name,
        // supported_versions, key_share, alpn, quic_transport_parameters,
        // padding.
        wantOrder := []uint16{greaseSentinel, extServerName, extSupportedVersions, extKeyShare, extALPN, extQUICTransportParms, extPadding}
        if len(exts) != len(wantOrder) {
                t.Fatalf("got %d extensions, want %d: % x", len(exts), len(wantOrder), extTypesOf(exts))
        }
        for i, want := range wantOrder {
                got := exts[i].typ
                switch want {
                case greaseSentinel: // GREASE: 0x?a?a form
                        if got&0x0F0F != 0x0A0A {
                                t.Fatalf("ext[%d] = %04x, want GREASE", i, got)
                        }
                default:
                        if got != want {
                                t.Fatalf("ext[%d] = %04x, want %04x (browser order)", i, got, want)
                        }
                }
        }

        // GREASE consistency: the supported_versions head entry equals the
        // GREASE extension type (one pattern across the hello, the Chrome
        // behavior). Body = list_len(2) + head entry(2) + 0x0304.
        if exts[2].body[2] != byte(exts[0].typ>>8) || exts[2].body[3] != byte(exts[0].typ) {
                t.Fatalf("supported_versions head % x != GREASE type %04x", exts[2].body[2:4], exts[0].typ)
        }
        svTail := exts[2].body[4:]
        if len(svTail) != 2 || svTail[0] != 0x03 || svTail[1] != 0x04 {
                t.Fatalf("supported_versions tail = % x, want 0304", svTail)
        }

        // key_share: X25519 group with a 32-byte public half.
        // Body = client_shares list_len(2) + entry(group(2) len(2) key).
        if ksGroup := int(exts[3].body[2])<<8 | int(exts[3].body[3]); ksGroup != groupX25519 {
                t.Fatalf("key_share group %04x, want X25519", ksGroup)
        }
        if ksLen := int(exts[3].body[4])<<8 | int(exts[3].body[5]); ksLen != 32 {
                t.Fatalf("key_share len %d, want 32", ksLen)
        }

        // alpn: exactly "h3" — RFC 7301 wire: list_len(2) + entry_len(1) + name.
        if !bytes.Equal(exts[4].body, []byte{0x00, 0x03, 0x02, 'h', '3'}) {
                t.Fatalf("alpn = % x, want the RFC 7301 h3 entry", exts[4].body)
        }

        // quic_transport_parameters: walk the varint list; the red-line check
        // is initial_source_connection_id == the packet DCID.
        qtp := map[uint64][]byte{}
        blob := exts[5].body
        for len(blob) > 0 {
                id, n := readQUICVarInt(blob)
                blob = blob[n:]
                ln, n2 := readQUICVarInt(blob)
                blob = blob[n2:]
                if int(ln) > len(blob) {
                        t.Fatalf("qtp %d length %d overruns body", id, ln)
                }
                qtp[id] = blob[:ln]
                blob = blob[ln:]
        }
        if scid, ok := qtp[qtpInitialSourceConnectionID]; !ok {
                t.Fatal("initial_source_connection_id missing — the RFC 9368 spec violation the review flagged")
        } else if !bytes.Equal(scid, dec.dcid) {
                t.Fatalf("SCID = % x, want the packet DCID % x", scid, dec.dcid)
        }
        if v, _ := readQUICVarInt(qtp[qtpInitialMaxData]); v != 1572864 {
                t.Fatalf("initial_max_data = %d, want 1572864", v)
        }
        if v, _ := readQUICVarInt(qtp[qtpMaxIdleTimeout]); v < 30000 || v > 60000 {
                t.Fatalf("max_idle_timeout = %d, want 30–60 s", v)
        }
        if v, _ := readQUICVarInt(qtp[qtpActiveConnectionIDLimit]); v < 2 || v > 4 {
                t.Fatalf("active_connection_id_limit = %d, want 2–4", v)
        }

        // padding extension present and plausibly sized (the chrome-class CH
        // fill; the packet-level PADDING frames top the datagram to PadTo).
        if len(exts[6].body) < 512 {
                t.Fatalf("padding extension %d bytes, want the ~1200-byte CH fill", len(exts[6].body))
        }
        chTotal := 4 + 2 + 32 + 1 + 32 + 2 + 6 + 1 + 1 + 2
        for _, e := range exts {
                chTotal += 4 + len(e.body)
        }
        if chTotal != chPadTarget {
                t.Fatalf("ClientHello total %d, want chPadTarget %d", chTotal, chPadTarget)
        }
}

// TestEnrichedInitialTwoBuildsDiffer feeds the P3 invariant at the
// generator level: two generated Initials must never be byte-identical
// (fresh DCID + fresh randomness per build).
func TestEnrichedInitialTwoBuildsDiffer(t *testing.T) {
        a := Build("go.sber.ru", newXorshift(7))
        b := Build("go.sber.ru", newXorshift(8))
        if a == "" || b == "" {
                t.Fatal("empty build")
        }
        if a == b {
                t.Fatal("two builds produced identical packets — the static-DCID regression")
        }
        ra, _ := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(a, "<b 0x"), ">"))
        rb, _ := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(b, "<b 0x"), ">"))
        if bytes.Equal(ra[6:14], rb[6:14]) {
                t.Fatal("DCID repeated across builds")
        }
}

// TestEnrichedInitialLongSNIStillPads: a 250-byte SNI must keep the
// packet valid (1250) with the padded CH clamped, never overflowing.
func TestEnrichedInitialLongSNIStillPads(t *testing.T) {
        i1 := Build(strings.Repeat("a", 250), newXorshift(9))
        if i1 == "" {
                t.Fatal("long SNI must still produce a valid I1")
        }
        if InitialSize(i1) != PadTo {
                t.Fatalf("long-SNI packet size %d, want %d", InitialSize(i1), PadTo)
        }
        raw, _ := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(i1, "<b 0x"), ">"))
        decryptInitial(t, raw) // must decrypt cleanly
}

func extTypesOf(exts []tlsExtension) []uint16 {
        out := make([]uint16, 0, len(exts))
        for _, e := range exts {
                out = append(out, e.typ)
        }
        return out
}

// greaseSentinel marks the GREASE slot of wantOrder (0x?a?a family).
const greaseSentinel = 0x0a0a
