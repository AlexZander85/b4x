// Package quici1: shared RFC-9001-accurate QUIC Initial generator — the
// AmneziaWG "I1" bait packet builder extracted from transport/proton so
// every transport can reuse it without cross-domain coupling (E-FXVPN
// masquerade chapter §7.4.1 / FX-M0).
//
// The packet is a REAL QUIC v1 Initial per RFC 9000/9001: version-1 salt,
// "client in" / "quic key" / "quic iv" / "quic hp" HKDF labels,
// AES-128-GCM over the CRYPTO frame and header protection. Inside: a
// minimal ClientHello whose only extension is server_name (Proton's
// Nova ProtonQuicInitial.kt clientHello shape, design §3.3 point 2).
//
// Use: send 1-2 of these to the target BEFORE the real handshake on a
// short-TTL socket (UDP only!) — the DPI's "first Initial of the flow"
// reads the white SNI while the datagram dies before reaching the server.
// It never replaces a real handshake (masquerade red line 1).
//
// Output grammar: `<b 0x…>` — the amneziawg-go chain parser format
// (transport/wg chain.go holds 4096-byte elements; PAD_TO 1250 fits).
package quici1

import (
        "crypto/aes"
        "crypto/cipher"
        "crypto/hmac"
        crand "crypto/rand"
        "crypto/sha256"
        "encoding/hex"
        "io"
        "strings"

        "golang.org/x/crypto/hkdf"
)

// QUIC v1 constants (RFC 9000/9001).
const (
        PadTo    = 1250
        DCIDSize = 8
        tagLen   = 16 // AES-GCM tag
        // sampleWindow is the minimum post-PN bytes the header-protection
        // sample needs (RFC 9001 §5.4.2: pn_offset+4 .. +20).
        sampleWindow = 20
)

// InitialSalt is the version-1 Initial salt (RFC 9001 §5.2) — exported for
// the delegating packages' test suites that re-derive the key schedule.
var InitialSalt = []byte{
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

// quicInitialSalt is the internal alias used by Build.
var quicInitialSalt = InitialSalt

// quicVarInt renders a QUIC variable-length integer (RFC 9000 §16). Values
// in this generator never exceed the 2-byte range, but the full table is
// implemented for completeness.
func quicVarInt(v uint64) []byte {
        switch {
        case v < 0x40:
                return []byte{byte(v)}
        case v < 0x4000:
                return []byte{byte(v>>8) | 0x40, byte(v)}
        case v < 0x40000000:
                return []byte{byte(v>>24) | 0x80, byte(v >> 16), byte(v >> 8), byte(v)}
        default:
                return []byte{byte(v>>56) | 0xC0, byte(v >> 48), byte(v >> 40), byte(v >> 32),
                        byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
        }
}

func quicVarIntLen(v uint64) int { return len(quicVarInt(v)) }

// quicExpandLabel is RFC 8446 §7.1 HKDF-Expand-Label over SHA-256:
// HkdfLabel = uint16(L) | opaque label | opaque context(empty).
func quicExpandLabel(secret []byte, length int, label string) ([]byte, error) {
        full := []byte("tls13 " + label)
        info := make([]byte, 0, 2+1+len(full)+1)
        info = append(info, byte(length>>8), byte(length))
        info = append(info, byte(len(full)))
        info = append(info, full...)
        info = append(info, 0x00) // empty context
        out := make([]byte, length)
        r := hkdf.Expand(sha256.New, secret, info)
        if _, err := io.ReadFull(r, out); err != nil {
                return nil, err
        }
        return out, nil
}

// quicClientHello builds the minimal ClientHello: legacy_version 0x0303,
// 32 random bytes, empty session_id/cipher_suites/compression, one
// server_name extension (ProtonQuicInitial.kt clientHello shape).
func quicClientHello(sni string, random []byte) []byte {
        name := []byte(sni)
        u16 := func(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

        serverNameList := append(u16(len(name)+3), 0x00)
        serverNameList = append(serverNameList, u16(len(name))...)
        serverNameList = append(serverNameList, name...)

        sniExt := u16(0x0000) // extension type: server_name
        sniExt = append(sniExt, u16(len(serverNameList))...)
        sniExt = append(sniExt, serverNameList...)

        extensions := u16(len(sniExt))
        extensions = append(extensions, sniExt...)

        // legacy_version(2) + random(32) + session_id_len(1) +
        // cipher_suites_len(2) + compression_len(1), all empty after random.
        body := []byte{0x03, 0x03}
        body = append(body, random...)
        body = append(body, 0x00, 0x00, 0x00, 0x00)
        body = append(body, extensions...)

        out := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
        return append(out, body...)
}

// Build assembles the fake QUIC Initial and returns it in the AmneziaWG
// `<b 0x…>` grammar. An empty/oversized SNI returns "" — the caller MUST
// treat that as "no bait" (an Initial with garbage inside is worse than
// none, ProtonQuicInitial.kt buildI1 contract).
func Build(sni string, r io.Reader) string {
        host := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(sni), "."))
        if host == "" || len(host) > 250 {
                return ""
        }
        if r == nil {
                r = cryptoRandReader{}
        }

        dcid := make([]byte, DCIDSize)
        if _, err := io.ReadFull(r, dcid); err != nil {
                return ""
        }
        chRandom := make([]byte, 32)
        if _, err := io.ReadFull(r, chRandom); err != nil {
                return ""
        }

        pkn := []byte{0x00} // packet number 0, 1 byte
        hello := quicClientHello(host, chRandom)
        // CRYPTO frame: type 0x06, offset 0, length, data.
        payload := []byte{0x06}
        payload = append(payload, quicVarInt(0)...)
        payload = append(payload, quicVarInt(uint64(len(hello)))...)
        payload = append(payload, hello...)

        // Padding fit: the Length varInt width depends on the padding it counts,
        // so the size converges iteratively (ProtonQuicInitial.kt overall()).
        // Long-header layout: flags(1) version(4) DCIL/SCIL(1) DCID(8)
        // token_len(1) Length(varInt) PKN(1).
        baseHeader := 1 + 4 + 1 + DCIDSize + 1 + len(pkn)
        overall := func(padding int) int {
                remainder := uint64(len(pkn) + len(payload) + padding + tagLen)
                return baseHeader + quicVarIntLen(remainder) + len(payload) + padding + tagLen
        }
        padding := 0
        if overall(0) < PadTo {
                padding = PadTo - overall(0)
                for padding > 0 && overall(padding) > PadTo {
                        padding--
                }
                if overall(padding) < PadTo {
                        padding++
                }
        }
        // The tail from the packet number must hold the 20-byte protection
        // sample (pn + payload-tail + padding + tag).
        if len(pkn)+len(payload)+padding+tagLen < sampleWindow {
                padding = sampleWindow - len(pkn) - len(payload) - tagLen
        }
        remainder := uint64(len(pkn) + len(payload) + padding + tagLen)

        // RFC 9000 long header: 0xC0 (form 1, fixed 1, Initial, reserved 0,
        // PKN len 1 byte), version 1, DCIL=8/SCIL=0 in ONE byte (0x80), DCID,
        // empty token, Length, PKN.
        header := []byte{0xC0, 0x00, 0x00, 0x00, 0x01, 0x80}
        header = append(header, dcid...)
        header = append(header, 0x00) // token length: empty
        header = append(header, quicVarInt(remainder)...)
        header = append(header, pkn...)

        // RFC 9001 §5.2 keys: initial secret = HKDF-Extract(salt, DCID).
        mac := hmac.New(sha256.New, quicInitialSalt)
        mac.Write(dcid)
        initialSecret := mac.Sum(nil)
        clientSecret, err := quicExpandLabel(initialSecret, 32, "client in")
        if err != nil {
                return ""
        }
        key, err := quicExpandLabel(clientSecret, 16, "quic key")
        if err != nil {
                return ""
        }
        iv, err := quicExpandLabel(clientSecret, 12, "quic iv")
        if err != nil {
                return ""
        }
        hp, err := quicExpandLabel(clientSecret, 16, "quic hp")
        if err != nil {
                return ""
        }
        for i := range pkn { // nonce = iv XOR pkn (tail)
                iv[len(iv)-len(pkn)+i] ^= pkn[i]
        }

        block, err := aes.NewCipher(key)
        if err != nil {
                return ""
        }
        gcm, err := cipher.NewGCM(block)
        if err != nil {
                return ""
        }
        plaintext := append(append([]byte{}, payload...), make([]byte, padding)...)
        sealed := gcm.Seal(nil, iv, plaintext, header)

        // Header protection: sample = 4 bytes past the PN start, 16 bytes long
        // (RFC 9001 §5.4.2); mask = AES-ECB(hp, sample).
        sampleOffset := 4 - len(pkn)
        if sampleOffset+16 > len(sealed) {
                return ""
        }
        hpBlock, err := aes.NewCipher(hp)
        if err != nil {
                return ""
        }
        mask := make([]byte, 16)
        hpBlock.Encrypt(mask, sealed[sampleOffset:sampleOffset+16])

        protected := append([]byte{}, header...)
        protected[0] ^= mask[0] & 0x0F
        for i := range pkn {
                protected[len(protected)-len(pkn)+i] ^= mask[1+i]
        }

        packet := append(protected, sealed...)
        return "<b 0x" + hex.EncodeToString(packet) + ">"
}

// cryptoRandReader adapts crypto/rand's Read to io.Reader (Build takes
// io.Reader so tests pin determinism with a fixed byte stream).
type cryptoRandReader struct{}

func (cryptoRandReader) Read(p []byte) (int, error) { return crand.Read(p) }

// InitialSize reports the wire size of an I1 value (0 when empty).
func InitialSize(i1 string) int {
        const prefix, suffix = "<b 0x", ">"
        if !strings.HasPrefix(i1, prefix) || !strings.HasSuffix(i1, suffix) {
                return 0
        }
        hexPart := strings.TrimSuffix(strings.TrimPrefix(i1, prefix), suffix)
        n := len(hexPart) / 2
        if len(hexPart)%2 != 0 {
                return 0
        }
        return n
}
