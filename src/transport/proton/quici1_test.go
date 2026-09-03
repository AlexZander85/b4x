package proton

import (
        "bytes"
        "crypto/aes"
        "crypto/cipher"
        "crypto/hmac"
        "crypto/sha256"
        "encoding/binary"
        "encoding/hex"
        "strings"
        "testing"

        "golang.org/x/crypto/hkdf"
)

// testReader feeds deterministic pseudo-randomness: an xorshift stream seeded
// once, so the golden vectors are reproducible.
type testReader struct{ state uint64 }

func newXorshift(seed uint64) *testReader { return &testReader{state: seed} }

func (r *testReader) Read(p []byte) (int, error) {
        for i := range p {
                r.state ^= r.state << 13
                r.state ^= r.state >> 7
                r.state ^= r.state << 17
                p[i] = byte(r.state)
        }
        return len(p), nil
}

// TestQuicInitialEmptySNI: no SNI = no obfuscation — the caller treats the
// empty string explicitly (never substitutes a stub).
func TestQuicInitialEmptySNI(t *testing.T) {
        if got := BuildQuicInitial("", newXorshift(1)); got != "" {
                t.Fatalf("empty SNI must yield empty I1, got %d bytes", QuicInitialSize(got))
        }
        if got := BuildQuicInitial("   ", newXorshift(1)); got != "" {
                t.Fatal("blank SNI must yield empty I1")
        }
        if got := BuildQuicInitial(strings.Repeat("a", 251), newXorshift(1)); got != "" {
                t.Fatal("oversized SNI must yield empty I1")
        }
}

// TestQuicInitialGoldenShape pins the deterministic blob: size 1250, long
// header 0xC0 (after protection mask & 0xF0), QUIC v1, DCIL=8/SCIL=0 in the
// single 0x80 byte (RFC 9000 §17.2 — the ProtonHandshakeVectorTest pattern:
// byte0 form, version bytes, DCID length byte).
func TestQuicInitialGoldenShape(t *testing.T) {
        i1 := BuildQuicInitial("www.gosuslugi.ru", newXorshift(0xDEADBEEF))
        if i1 == "" {
                t.Fatal("BuildQuicInitial returned empty")
        }
        if !strings.HasPrefix(i1, "<b 0x") || !strings.HasSuffix(i1, ">") {
                t.Fatalf("unexpected grammar: %s...", i1[:24])
        }
        raw, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(i1, "<b 0x"), ">"))
        if err != nil {
                t.Fatalf("hex body: %v", err)
        }
        if QuicInitialSize(i1) != QuicPadTo {
                t.Fatalf("packet size = %d, want %d (RFC 9000 §14.1)", QuicInitialSize(i1), QuicPadTo)
        }
        // Header protection only touches the low nibble of byte 0: the high
        // nibble must read 0xC (form 1, fixed bit, Initial).
        if raw[0]&0xF0 != 0xC0 {
                t.Fatalf("first byte %02x: high nibble must be 0xC0-masked", raw[0])
        }
        if !bytes.Equal(raw[1:5], []byte{0x00, 0x00, 0x00, 0x01}) {
                t.Fatalf("version = %x, want 00000001", raw[1:5])
        }
        // DCIL=8 (high nibble), SCIL=0 (low nibble) — RFC 9000 §17.2.
        if raw[5] != 0x80 {
                t.Fatalf("DCIL/SCIL byte = %02x, want 0x80", raw[5])
        }

        // Determinism: the same seed produces the same packet byte-for-byte.
        again := BuildQuicInitial("www.gosuslugi.ru", newXorshift(0xDEADBEEF))
        if again != i1 {
                t.Fatal("BuildQuicInitial not deterministic for a fixed rand")
        }
}

// TestQuicInitialDecryptsPerRFC9001 is the strongest golden check: the
// packet decrypts as a REAL QUIC v1 Initial. The test re-derives the keys
// per RFC 9001 (independent code path: hkdf.Expand + explicit label
// assembly), strips the header protection, recovers the packet number,
// verifies the AES-128-GCM tag over the CRYPTO frame, and parses the
// ClientHello back out to the SNI. Any DPI capable of Initial decryption
// reaches the same verdict.
func TestQuicInitialDecryptsPerRFC9001(t *testing.T) {
        const sni = "go.sber.ru"
        i1 := BuildQuicInitial(sni, newXorshift(0xC0FFEE))
        raw, err := hex.DecodeString(strings.TrimSuffix(strings.TrimPrefix(i1, "<b 0x"), ">"))
        if err != nil {
                t.Fatal(err)
        }

        // --- key schedule (RFC 9001 §5.2) -----------------------------------
        mac := hmac.New(sha256.New, quicInitialSalt)
        mac.Write(raw[6:14]) // DCID (8 bytes per DCIL=8)
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

        // --- header layout (RFC 9000 §17.2) ---------------------------------
        // flags(1) ver(4) DCILSCIL(1) DCID(8) token_len(1) Length(varInt) PKN.
        dcLen := int(raw[5] >> 4)
        if dcLen != 8 {
                t.Fatalf("DCIL = %d", dcLen)
        }
        dcEnd := 6 + dcLen
        if raw[dcEnd] != 0x00 {
                t.Fatalf("token length = %02x, want empty", raw[dcEnd])
        }
        // Length varInt (2-byte form expected at this size).
        lenFirst := raw[dcEnd+1]
        varIntLen := 0
        switch lenFirst & 0xC0 {
        case 0x00:
                varIntLen = 1
        case 0x40:
                varIntLen = 2
        case 0x80:
                varIntLen = 4
        case 0xC0:
                varIntLen = 8
        }
        length := 0
        for i := 0; i < varIntLen; i++ {
                b := raw[dcEnd+1+i]
                if i == 0 {
                        b &= 0xFF >> (2 * varIntLen) // strip the 2-bit length tag
                }
                length = length<<8 | int(b)
        }
        // pnOffset = where the packet number starts — structural: token_len(1)
        // then the Length varInt, all unprotected; the pn-length bits themselves
        // are masked, the construction constant is 1 byte.
        pnOffset := dcEnd + 1 + varIntLen
        headerLen := pnOffset + 1
        if headerLen > len(raw) {
                t.Fatalf("header %d exceeds packet %d", headerLen, len(raw))
        }

        // --- header protection removal (RFC 9001 §5.4.2) --------------------
        hpBlock, _ := aes.NewCipher(hp)
        sample := raw[pnOffset+4:][:16]
        if len(sample) != 16 {
                t.Fatalf("sample window short: %d", len(sample))
        }
        mask := make([]byte, 16)
        hpBlock.Encrypt(mask, sample)

        plainHeader := append([]byte{}, raw[:headerLen]...)
        plainHeader[0] ^= mask[0] & 0x0F
        plainHeader[headerLen-1] ^= mask[1]
        if plainHeader[0] != 0xC0 {
                t.Fatalf("unprotected first byte = %02x, want 0xC0", plainHeader[0])
        }
        if plainHeader[headerLen-1] != 0x00 {
                t.Fatalf("packet number = %02x, want 0", plainHeader[headerLen-1])
        }

        // --- payload decryption (AES-128-GCM, nonce = iv XOR pkn) -----------
        nonce := append([]byte{}, iv...)
        nonce[len(nonce)-1] ^= plainHeader[headerLen-1]
        block, _ := aes.NewCipher(key)
        gcm, _ := cipher.NewGCM(block)
        payload, err := gcm.Open(nil, nonce, raw[headerLen:], plainHeader[:headerLen])
        if err != nil {
                t.Fatalf("GCM open failed — the packet is not decryptable QUIC: %v", err)
        }
        // RFC 9000: the Length field counts PKN + payload WHERE payload includes
        // the 16-byte AEAD tag; the decrypted plaintext is Length-1-16.
        if len(payload) != length-1-16 {
                t.Fatalf("payload %d != Length-PKN-tag %d", len(payload), length-1-16)
        }

        // --- CRYPTO frame -> ClientHello -> SNI -----------------------------
        if payload[0] != 0x06 {
                t.Fatalf("frame type = %02x, want CRYPTO (0x06)", payload[0])
        }
        // offset varInt (0) then length varInt (RFC 9000 §16).
        if payload[1] != 0x00 {
                t.Fatalf("crypto offset = %02x, want 0", payload[1])
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
                t.Fatalf("crypto frame length %d exceeds payload %d", chLen, len(payload))
        }
        ch := payload[2+vn : 2+vn+int(chLen)]
        if ch[0] != 0x01 {
                t.Fatalf("handshake type = %02x, want ClientHello", ch[0])
        }
        if len(ch) < 84 {
                t.Fatalf("client hello too short: %d", len(ch))
        }
        // Walk to the extensions: legacy_version(2)+random(32)+sid_len(1)+
        // sid(32)+cs_len(2)+cs(6)+comp_len(1)+comp(1) = 77, ext_len(2) next.
        body := ch[4:]
        extLen := int(binary.BigEndian.Uint16(body[77:79]))
        extBlob := body[79 : 79+extLen]
        if len(extBlob) < 4 {
                t.Fatalf("extension blob too short: %d", len(extBlob))
        }
        // Chrome-class order (review §4.4): GREASE first, server_name second.
        extType := binary.BigEndian.Uint16(extBlob[0:2])
        if extType&0x0F0F != 0x0A0A || extType&0xF00F == 0 {
                t.Fatalf("first extension %04x, want the GREASE family", extType)
        }
        greasedLen := int(binary.BigEndian.Uint16(extBlob[2:4]))
        pos := 4 + greasedLen
        if pos+4 > len(extBlob) {
                t.Fatalf("extensions end after GREASE: pos %d of %d", pos, len(extBlob))
        }
        sniExt := extBlob[pos:]
        if !bytes.Equal(sniExt[0:2], []byte{0x00, 0x00}) {
                t.Fatalf("second extension type = %x, want server_name", sniExt[0:2])
        }
        sniExtLen := int(binary.BigEndian.Uint16(sniExt[2:4]))
        if sniExtLen < 5 {
                t.Fatalf("server_name ext too short: %d", sniExtLen)
        }
        // list_len(2) name_type(1)=0 host_len(2) host.
        hostLen := int(binary.BigEndian.Uint16(sniExt[7:9]))
        gotSNI := string(sniExt[9 : 9+hostLen])
        if gotSNI != sni {
                t.Fatalf("decrypted SNI = %q, want %q", gotSNI, sni)
        }
}
