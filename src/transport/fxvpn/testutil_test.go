package fxvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"path/filepath"
	"testing"
	"time"
)

// newSelfSignedCert mints a UNIQUE certificate for fake edges. httptest's
// shared static cert would make SPKI/pin scenarios untestable (FX1 gotcha).
func newSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "edge.fxvpn.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost", "edge.fxvpn.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// testTLSBase is the documented TEST-ONLY seam value: skip verification
// against our self-signed stands (production never sets this).
func testTLSBase() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test stand
}

func testTunnelConfig(host string, port int, token string) TunnelConfig {
	return TunnelConfig{
		Host:            host,
		Port:            port,
		Token:           token,
		TLS:             testTLSBase(),
		HandshakeBudget: 10 * time.Second,
		OpenBudget:      3 * time.Second,
	}
}

// halfClose finishes the send side of a relay (EOF for the far peer) while
// keeping the receive side open - the echo-test contract.
func halfClose(conn net.Conn) error {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return nil
}

// echoChunkLen is how many bytes the teardown stands echo back before
// killing the stream/stream-reset (both carriers' tests read this much).
const echoChunkLen = 16

// storeSeedPath returns a fresh temp path for an accounts.json fixture.
func storeSeedPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "accounts.json")
}
