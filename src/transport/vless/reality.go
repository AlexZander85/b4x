package vless

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

// REALITY client handshake (design §8, phase V4b). The protocol facts below
// are implemented from the public REALITY client algorithm (XTLS/REALITY,
// MPL-2.0); no reference code is copied.
//
// Summary of the client side:
//   - uTLS builds the ClientHello for the node fingerprint.
//   - The 32-byte session_id carries the obfuscated auth block: version(3) +
//     reserved(1) + unix-time(4) + shortId(<=16), sealed in place with
//     AES-256-GCM using a key derived from X25519(ephemeral, serverPublicKey).
//   - The GCM nonce is ClientHello.random[20:32]; the AEAD is keyed with
//     HKDF-SHA256(shared, salt=random[:20], info="REALITY").
//   - The server proves itself by signing its temporary certificate's public
//     key with HMAC-SHA512(authKey); a real (borrowed site) certificate means
//     the server rejected us / MitM, which this client treats as FAIL (no
//     crawler mode in V4).

// realityClientVersion is the client version advertised in the REALITY auth
// block (major/minor/patch). Servers with minClientVer/maxClientVer bounds
// compare it; the values are the long-standing 1.8.0 shape.
var realityClientVersion = [3]byte{1, 8, 0}

// applyReality mutates the built ClientHello in place and returns the derived
// auth key used to verify the server's temporary certificate.
func applyReality(uconn *utls.UConn, n Node) ([]byte, error) {
	if err := uconn.BuildHandshakeState(); err != nil {
		return nil, fmt.Errorf("vless: reality build hello: %w", err)
	}
	hello := uconn.HandshakeState.Hello
	if hello == nil {
		return nil, errors.New("vless: reality: no client hello")
	}
	hello.SessionId = make([]byte, 32)
	// The session id sits at a fixed offset inside the marshaled hello
	// (handshake type(1) + length(3) + version(2) + random(32) + sidLen(1)).
	const sessionIDOffset = 39
	if len(hello.Raw) < sessionIDOffset+len(hello.SessionId) {
		return nil, fmt.Errorf("vless: reality: unexpected hello length %d", len(hello.Raw))
	}
	copy(hello.Raw[sessionIDOffset:], hello.SessionId)
	hello.SessionId[0] = realityClientVersion[0]
	hello.SessionId[1] = realityClientVersion[1]
	hello.SessionId[2] = realityClientVersion[2]
	hello.SessionId[3] = 0 // reserved
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	sid, err := decodeShortID(n.ShortID)
	if err != nil {
		return nil, err
	}
	copy(hello.SessionId[8:], sid)

	serverPub, err := parseRealityPublicKey(n.PublicKey)
	if err != nil {
		return nil, err
	}
	ks := uconn.HandshakeState.State13.KeyShareKeys
	if ks == nil {
		return nil, errors.New("vless: reality: no TLS1.3 key share state")
	}
	eph := ks.Ecdhe
	if eph == nil {
		eph = ks.MlkemEcdhe
	}
	if eph == nil {
		return nil, errors.New("vless: reality: fingerprint does not offer an X25519 key share")
	}
	shared, err := eph.ECDH(serverPub)
	if err != nil {
		return nil, fmt.Errorf("vless: reality: ecdh: %w", err)
	}
	authKey := make([]byte, 32)
	reader := hkdf.New(sha256.New, shared, hello.Random[:20], []byte("REALITY"))
	if _, err := reader.Read(authKey); err != nil {
		return nil, fmt.Errorf("vless: reality: hkdf: %w", err)
	}

	// Seal the auth block: plaintext is the first 16 bytes (version/time/
	// shortId), nonce is random[20:], AAD is the hello as marshaled above.
	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, fmt.Errorf("vless: reality: aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vless: reality: gcm: %w", err)
	}
	plain := make([]byte, 16)
	copy(plain, hello.SessionId[:16])
	sealed := aead.Seal(hello.SessionId[:0], hello.Random[20:], plain, hello.Raw)
	hello.SessionId = sealed
	copy(hello.Raw[sessionIDOffset:], hello.SessionId)
	return authKey, nil
}

// decodeShortID parses the REALITY short id (hex, 0..16 bytes; empty allowed).
func decodeShortID(s string) ([]byte, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return nil, nil
	}
	if len(v)%2 != 0 || len(v) > 16 {
		return nil, fmt.Errorf("vless: reality: shortId %q must be even-length hex, <=16 chars", s)
	}
	b, err := hex.DecodeString(v)
	if err != nil {
		return nil, fmt.Errorf("vless: reality: shortId %q: %w", s, err)
	}
	return b, nil
}

// parseRealityPublicKey decodes the node's REALITY public key. The public
// corpus (and Xray itself) encodes it as unpadded base64url of 32 bytes —
// reference: infra/conf/transport_security.go decodes `publicKey` with
// base64.RawURLEncoding and requires len == 32. A 32-byte hex value is still
// accepted for our own fixtures and for older hand-written configs.
func parseRealityPublicKey(s string) (*ecdh.PublicKey, error) {
	v := strings.TrimSpace(s)
	if v == "" {
		return nil, errors.New("vless: reality: empty public key")
	}
	var raw []byte
	if b, err := base64.RawURLEncoding.DecodeString(v); err == nil && len(b) == 32 {
		raw = b
	} else if b, err := base64.StdEncoding.DecodeString(v); err == nil && len(b) == 32 {
		raw = b
	} else if b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(v), "0x")); err == nil && len(b) == 32 {
		raw = b
	} else {
		return nil, fmt.Errorf("vless: reality: public key must be base64url/base64 (32 bytes) or 64-char hex")
	}
	pub, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, fmt.Errorf("vless: reality: public key: %w", err)
	}
	return pub, nil
}

// verifyRealityCertificate implements utls.Config.VerifyPeerCertificate for
// REALITY: the temporary certificate carries an ed25519 public key whose
// signature is HMAC-SHA512(authKey, publicKey). A borrowed (real) certificate
// fails this check and the connection is refused (fail-closed; no crawler).
func verifyRealityCertificate(authKey []byte, rawCerts [][]byte) error {
	if len(authKey) == 0 {
		return errors.New("vless: reality: auth key unavailable")
	}
	if len(rawCerts) == 0 {
		return errors.New("vless: reality: server sent no certificate")
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("vless: reality: parse certificate: %w", err)
	}
	pub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return errors.New("vless: reality: certificate is not a REALITY temporary certificate")
	}
	h := hmac.New(sha512.New, authKey)
	h.Write(pub)
	if !hmac.Equal(h.Sum(nil), cert.Signature) {
		return errors.New("vless: reality: certificate signature mismatch (server rejected or MITM)")
	}
	return nil
}
