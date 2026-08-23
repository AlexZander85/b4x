// Identity key material and endpoint pinning (addendum v1.2 §8 secret model;
// protocol per pinned usque reference api/masque.go PrepareTlsConfig and
// internal/utils.go GenerateEcKeyPair/GenerateCert, cross-checked against
// warp-socks tls.rs and Aether consts.rs).
//
// Rules enforced here:
//   - client key is ECDSA P-256 (Cloudflare MASQUE enrollment type
//     "secp256r1"; other types are rejected by the API);
//   - the client certificate is a short-lived self-signed certificate
//     regenerated per connection attempt window (usque regenerates it every
//     process start; validity is 24h);
//   - server authentication is PUBLIC-KEY PINNING of the leaf certificate,
//     not CA-chain validation: Cloudflare endpoints present certificates whose
//     names never match the SNI, so InsecureSkipVerify=true is combined with a
//     mandatory VerifyPeerCertificate hook. Production forbids insecure mode
//     (addendum §C.6 / hard gate masque_insecure_tls_total).
package transportwarp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Key material errors.
var (
	ErrNoPin           = errors.New("transportwarp: endpoint public-key pin required (insecure mode forbidden)")
	ErrPinNotECDSA     = errors.New("transportwarp: pinned endpoint key is not ECDSA")
	ErrPinMismatch     = errors.New("transportwarp: remote endpoint has a different public key than the trusted pin")
	ErrBadClientKey    = errors.New("transportwarp: malformed client private key")
	ErrBadEndpointCert = errors.New("transportwarp: malformed endpoint peer certificate")
)

// GenerateClientKey creates a fresh ECDSA P-256 key pair for MASQUE
// enrollment. It returns base64(SEC1-DER) private form (the on-disk identity
// format shared with usque/warp-reg-gw state files) and PKIX-DER public form
// (what the PATCH enrollment request carries as `key`).
func GenerateClientKey() (privB64 string, pubPKIX []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("%w: %v", ErrBadClientKey, err)
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", nil, err
	}
	return base64.StdEncoding.EncodeToString(privDER), pubDER, nil
}

// ParseClientKeyB64 decodes a base64(SEC1-DER) ECDSA private key.
func ParseClientKeyB64(privB64 string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadClientKey, err)
	}
	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadClientKey, err)
	}
	if priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: curve %v", ErrBadClientKey, priv.Curve)
	}
	return priv, nil
}

// ParsePublicKeyPEM parses the PEM-encoded PKIX public key that Cloudflare
// returns as peers[0].public_key in the registration response (the endpoint
// trust anchor). The returned digest is its SHA-256 fingerprint (SPKI form),
// usable for diagnostics without exposing the key itself.
func ParsePublicKeyPEM(pemStr string) (*ecdsa.PublicKey, string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, "", errors.New("transportwarp: failed to decode endpoint public key PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrBadEndpointCert, err)
	}
	pub, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", ErrPinNotECDSA
	}
	return pub, PinDigest(pub), nil
}

// PinDigest returns the SHA-256 hex fingerprint of an ECDSA public key
// (SPKI DER), the redacted-safe identifier used in traces.
func PinDigest(pub *ecdsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ClientCertificate builds the TLS client certificate from the enrolled key.
// The self-signed cert mirrors usque internal.GenerateCert: serial 0,
// 24-hour validity; Cloudflare pins our enrollment key out-of-band and never
// validates the chain.
func ClientCertificate(priv *ecdsa.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		Subject:      pkix.Name{},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}

// PrepareTLSConfig builds the pinned client configuration for one endpoint
// class. ALPN selects h2 (production transport); insecure=false is mandatory.
//
// Verification follows usque api/masque.go exactly: parse the raw leaf,
// require ECDSA, require exact equality with the pinned endpoint key. The
// optional extraPins set (SHA-256 SPKI digests, Aether-style) accepts
// alternative known Cloudflare edge keys so a single backend key rotation
// does not strand every client; equality with the primary pin always wins.
func PrepareTLSConfig(client tls.Certificate, sni string, pin *ecdsa.PublicKey, extraPins map[string]bool) (*tls.Config, error) {
	if pin == nil {
		return nil, ErrNoPin
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{client},
		ServerName:   sni,
		NextProtos:   []string{"h2"},
		// The SNI is usually not the endpoint's own name; chain validation
		// cannot succeed by design. Trust is carried exclusively by the pin.
		InsecureSkipVerify: true, //nolint:gosec // pinned-peer scheme, see above
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return ErrBadEndpointCert
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrBadEndpointCert, err)
			}
			leafPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return ErrPinNotECDSA
			}
			if leafPub.Equal(pin) {
				return nil
			}
			if len(extraPins) > 0 && extraPins[PinDigest(leafPub)] {
				return nil
			}
			return ErrPinMismatch
		},
	}
	return cfg, nil
}
