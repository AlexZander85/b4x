// H3 TLS profile: identical pinning contract to the H2 branch (tlsconf.go),
// different transport parameters — ALPN h3, TLS 1.3 only, CurvePreferences
// P-256,P-384 without X25519 so no HelloRetryRequest round-trip is possible
// (warp-socks tls.rs pattern, E-H3 design §1).
package transportwarp

import (
	"crypto/ecdsa"
	"crypto/tls"
)

// PrepareH3TLSConfig builds the pinned client configuration for one QUIC/H3
// endpoint attempt by reusing PrepareTLSConfig wholesale (InsecureSkipVerify+
// VerifyPeerCertificate leaf-pubkey equality, extraPins set) and overriding
// only the transport-visible knobs.
func PrepareH3TLSConfig(clientCert tls.Certificate, sni string, pin *ecdsa.PublicKey, extraPins map[string]bool) (*tls.Config, error) {
	cfg, err := PrepareTLSConfig(clientCert, sni, pin, extraPins)
	if err != nil {
		return nil, err
	}
	cfg.NextProtos = []string{"h3"}
	cfg.MinVersion = tls.VersionTLS13 // 0-RTT stays off: no ExtraConfigs anywhere
	cfg.CurvePreferences = []tls.CurveID{tls.CurveP256, tls.CurveP384}
	return cfg, nil
}
