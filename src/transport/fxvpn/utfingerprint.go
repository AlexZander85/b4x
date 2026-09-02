// uTLS fingerprint layer for the fxvpn H2 carrier (review chapter 7
// §7.4.3, stage FX-M1 — the owner-approved dependency exception, the
// opera/utfingerprint.go pattern): Go's crypto/tls emits a JA3/JA4 no
// browser produces and the TSPU classifies on it; the FX-M0 cheap layer
// (cipher/curve order, padding) removes the crudest differences but keeps
// the Go extension layout. This layer swaps the ClientHello for the
// byte-accurate Firefox profile (uTLS HelloFirefox_Auto) with ALPN h2 —
// the review lists it as the ONLY practical full solution for the TLS path.
//
// QUIC path (honest scope, review FX-M1): quic-go builds the ClientHello
// internally through crypto/tls and exposes no hook for uTLS — the full
// QUIC mimicry needs the community fork shim (owner decision, precedent
// amneziawg-go v3). The QUIC carrier therefore rides the FX-M0 cheap layer
// (Firefox suites/curves, 1250 padding, preflight bait) and is documented
// as a fork-shim TODO; the H3 rung of the masquerade ladder compensates
// with the bait-first ordering.
//
// Red lines (§7.8): the trust model is untouched — the uTLS connection
// verifies the REAL node name against the SYSTEM WebPKI pool through the
// VerifyConnection callback (identical semantics to the plain-Go path);
// uTLS changes the OBSERVED BYTES, never the verification. And the bait
// (preflight fake) never rides this connection: fakes precede handshakes,
// they do not replace them.
package fxvpn

import (
        "context"
        "crypto/x509"
        "fmt"
        "net"

        utls "github.com/refraction-networking/utls"
)

// Fingerprint identifiers for MasqueradeSettings.Fingerprint.
const (
        // FingerprintFirefox: the uTLS Firefox auto profile (HelloFirefox_Auto
        // = Firefox 120 in uTLS v1.8) — the shipping default of the firefox
        // masquerade profile.
        FingerprintFirefox = "firefox"
        // FingerprintNone: plain Go crypto/tls with the FX-M0 tuning only (the
        // ladder fallback rung).
        FingerprintNone = "none"
)

// fingerprintActive reports whether the uTLS layer produces the ClientHello.
func (m MasqueradeSettings) fingerprintActive() bool {
        return m.Fingerprint == FingerprintFirefox
}

// dialUTLSClient performs the fingerprinted TLS handshake: a uTLS UConn
// with the Firefox ClientHello, ALPN h2, and WebPKI verification through
// the callback (InsecureSkipVerify only delegates the chain check to that
// callback — the opera pattern).
func dialUTLSClient(ctx context.Context, raw net.Conn, sni string, m MasqueradeSettings, verify func(utls.ConnectionState) error) (*utls.UConn, error) {
        if m.Fingerprint != FingerprintFirefox {
                return nil, fmt.Errorf("fxvpn: fingerprint %q has no ClientHello profile", m.Fingerprint)
        }
        cfg := &utls.Config{
                ServerName:         sni,
                InsecureSkipVerify: true, // verification is delegated to `verify` below
                VerifyConnection:   verify,
                // A Firefox first-contact hello carries no PSK; an empty PSK
                // extension would be a fingerprint oddity of its own.
                OmitEmptyPsk: true,
        }

        // Materialize the Firefox spec and swap the ALPN extension for the H2
        // carrier offer (the documented utls pattern: spec + HelloCustom).
        spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_Auto)
        if err != nil {
                return nil, fmt.Errorf("fxvpn: utls firefox spec: %w", err)
        }
        replaced := false
        for i, ext := range spec.Extensions {
                if alpn, ok := ext.(*utls.ALPNExtension); ok {
                        alpn.AlpnProtocols = []string{"h2"}
                        spec.Extensions[i] = alpn
                        replaced = true
                        break
                }
        }
        if !replaced {
                spec.Extensions = append(spec.Extensions, &utls.ALPNExtension{AlpnProtocols: []string{"h2"}})
        }

        uconn := utls.UClient(raw, cfg, utls.HelloCustom)
        if err := uconn.ApplyPreset(&spec); err != nil {
                return nil, fmt.Errorf("fxvpn: utls firefox preset: %w", err)
        }
        if err := uconn.HandshakeContext(ctx); err != nil {
                return nil, err
        }
        return uconn, nil
}

// verifyWebPKIUTLS builds the verification closure for uTLS connections:
// identical trust semantics to the plain-Go DialH2 path — the real node
// name against the ROOT POOL of the base TLS config (nil = system WebPKI
// pool; the fake-stand seam passes InsecureSkipVerify which skips exactly
// like the plain path would). SNI-independent, resumption-safe.
func verifyWebPKIUTLS(host string, roots *x509.CertPool, insecure bool) func(utls.ConnectionState) error {
        return func(cs utls.ConnectionState) error {
                if insecure {
                        return nil // the documented test/bootstrap seam, same as the plain path
                }
                if len(cs.PeerCertificates) == 0 {
                        // Resumed session: a ticket can only exist after a verified
                        // full handshake (opera §7.4.4 comment).
                        return nil
                }
                opts := x509.VerifyOptions{
                        DNSName:       host,
                        Roots:         roots,
                        Intermediates: x509.NewCertPool(),
                }
                for _, cert := range cs.PeerCertificates[1:] {
                        opts.Intermediates.AddCert(cert)
                }
                _, err := cs.PeerCertificates[0].Verify(opts)
                return err
        }
}
