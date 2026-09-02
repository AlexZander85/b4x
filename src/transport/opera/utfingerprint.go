// uTLS fingerprint layer (review E-OPERA §7.4.2, stage OP-M1 — the
// OWNER-APPROVED dependency exception): Go's crypto/tls emits a JA3/JA4
// fingerprint no browser on earth produces, and the TSPU classifies on it
// by default. The Go-config tuning of OP-M0 (§7.4.2a) removes the crudest
// differences but keeps the Go extension layout; this layer swaps the
// ClientHello for a byte-accurate Chrome profile (uTLS), which the review
// lists as the ONLY practical full solution — a hand-rolled ClientHello
// writer (§7.4.2c) was explicitly rejected as 2-3k lines of permanent
// catch-up against browser evolution.
//
// WHY UTLS FOR OPERA WHILE PROTON MASKS WITHOUT IT: the Proton reserve is
// an AWG/WireGuard transport over UDP — its masquerade lives in the
// packet layer (amnezia obfuscation headers + a crafted QUIC-Initial I1
// with a white SNI; see transport/proton/quici1.go). The first flight is
// hand-built there, byte for byte — no TLS library ever produces a
// ClientHello. Opera's data plane, by contrast, IS a TLS-over-TCP
// transport: the ClientHello itself is the observable payload, produced
// byte-for-byte by crypto/tls. You cannot fake a hello you do not build;
// hence the fingerprint must live inside the TLS stack, and uTLS — with
// VerifyConnection preserved — is the community-maintained way to do that.
//
// Red lines (§7.8): the trust model is untouched — VerifyConnection
// against the real node name with the embedded Mozilla/NSS pool (data
// plane) and the TOFU SPKI pin (control channel) remain the only anchors;
// uTLS changes the OBSERVED BYTES, never the verification.
package opera

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"

	utls "github.com/refraction-networking/utls"
)

// Fingerprint identifiers for MasqueradeSettings.Fingerprint.
const (
	// FingerprintChrome120: the uTLS Chrome 120 profile — a widely
	// deployed, deterministic ClientHello. NOTE (review deviation, owner
	// visible): the review asked for "Chrome_128"; uTLS does not ship a
	// 128 spec (128 is byte-identical to 120 for the JA3 fields except the
	// optional post-quantum key share). "chrome131" selects the ML-KEM
	// variant for field experiments.
	FingerprintChrome120 = "chrome120"
	// FingerprintChrome131: Chrome with the ML-KEM curve.
	FingerprintChrome131 = "chrome131"
	// FingerprintNone: plain Go crypto/tls (OP-M0 tuning only).
	FingerprintNone = "none"
)

// ClientHelloID maps the fingerprint identifier onto the uTLS preset.
func (m MasqueradeSettings) ClientHelloID() (utls.ClientHelloID, bool) {
	switch m.Fingerprint {
	case FingerprintChrome120:
		return utls.HelloChrome_120, true
	case FingerprintChrome131:
		return utls.HelloChrome_131, true
	default:
		return utls.ClientHelloID{}, false
	}
}

// FingerprintActive reports whether the uTLS layer should produce the
// ClientHello (browser profile with a chrome fingerprint).
func (m MasqueradeSettings) FingerprintActive() bool {
	_, ok := m.ClientHelloID()
	return ok
}

// dialUTLSClient performs the fingerprinted TLS handshake: a uTLS UConn
// with the requested Chrome ClientHello, the browser ALPN from the
// masquerade settings, session resumption via the uTLS cache, and the
// SAME verification callback semantics as the plain-Go path (SNI-
// independent; resumption-safe).
func dialUTLSClient(ctx context.Context, raw net.Conn, sni string, m MasqueradeSettings, cache utls.ClientSessionCache, verify func(utls.ConnectionState) error) (*utls.UConn, error) {
	hello, ok := m.ClientHelloID()
	if !ok {
		return nil, fmt.Errorf("%w: fingerprint %q has no ClientHello profile", errSetup, m.Fingerprint)
	}
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // verification is delegated to the callback below
		VerifyConnection:   verify,
		// Conceal the PSK extension when no session ticket exists yet
		// (first connection: a full handshake follows, and an empty PSK
		// would be a fingerprint oddity of its own).
		OmitEmptyPsk: true,
	}
	if m.SessionResumption && cache != nil {
		cfg.ClientSessionCache = cache
	}

	// Static Chrome presets carry their own ALPN list ("h2","http/1.1");
	// the engine's ALPN policy (config masquerade.alpn) is authoritative —
	// materialize the spec, swap the ALPN extension, and apply it to a
	// HelloCustom UConn (the documented utls pattern).
	spec, err := utls.UTLSIdToSpec(hello)
	if err != nil {
		return nil, fmt.Errorf("opera: utls spec %q: %w", m.Fingerprint, err)
	}
	if len(m.ALPN) > 0 {
		replaced := false
		for i, ext := range spec.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = append([]string(nil), m.ALPN...)
				spec.Extensions[i] = alpn
				replaced = true
				break
			}
		}
		if !replaced {
			spec.Extensions = append(spec.Extensions,
				&utls.ALPNExtension{AlpnProtocols: append([]string(nil), m.ALPN...)})
		}
	}
	// Session resumption needs the PSK extension present in the spec; the
	// Chrome 120 generated spec does not carry one. utls aborts the
	// handshake without it (its own error message prescribes exactly this
	// remedy) — keep resumption usable, keep the extension last as Chrome
	// does.
	if m.SessionResumption {
		hasPSK := false
		for _, ext := range spec.Extensions {
			if _, ok := ext.(utls.ISessionTicketExtension); ok {
				continue
			}
			if _, ok := ext.(*utls.UtlsPreSharedKeyExtension); ok {
				hasPSK = true
				break
			}
		}
		if !hasPSK {
			spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
		}
	}

	uconn := utls.UClient(raw, cfg, utls.HelloCustom)
	if err := uconn.ApplyPreset(&spec); err != nil {
		return nil, fmt.Errorf("opera: utls preset %q: %w", m.Fingerprint, err)
	}
	if err := uconn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	return uconn, nil
}

// verifyNodeChainUTLS builds the data-plane verification closure for uTLS
// connections: identical trust semantics to the plain-Go VerifyConnection
// (real node name against the merged Mozilla/NSS pool, SNI-independent,
// resumption-safe).
func verifyNodeChainUTLS(nodeName string, pool *x509.CertPool) func(utls.ConnectionState) error {
	return func(cs utls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			// Resumed session: see the plain-Go comment (§7.4.4) — a
			// ticket exists only after a verified full handshake.
			return nil
		}
		opts := x509.VerifyOptions{
			DNSName:       nodeName,
			Intermediates: x509.NewCertPool(),
			Roots:         pool,
		}
		for _, cert := range cs.PeerCertificates[1:] {
			opts.Intermediates.AddCert(cert)
		}
		_, err := cs.PeerCertificates[0].Verify(opts)
		return err
	}
}
