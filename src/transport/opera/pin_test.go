package opera

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TLS stand for the TOFU pin: one listener, certificate swapped mid-flight
// via GetCertificate (no port rebinding flakiness).
type tlsStand struct {
	t        *testing.T
	srv      *http.Server
	ln       net.Listener
	base     string
	certA    tls.Certificate
	certB    tls.Certificate
	current  atomic.Pointer[tls.Certificate]
	se       *seStand
}

func newTLSStand(t *testing.T) *tlsStand {
	s := &tlsStand{
		t:     t,
		certA: mustSelfSigned(t, "api2.sec-tunnel.com"),
		certB: mustSelfSigned(t, "api2.sec-tunnel.com"),
	}
	s.current.Store(&s.certA)
	s.se = newSEStand(t)

	cfg := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := s.current.Load()
			return c, nil
		},
		MinVersion: tls.VersionTLS12,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.ln = tls.NewListener(ln, cfg)
	s.base = fmt.Sprintf("https://%s", s.ln.Addr().String())
	s.srv = &http.Server{Handler: s.se.handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.srv.Serve(s.ln) }()
	t.Cleanup(func() {
		_ = s.srv.Close()
	})
	return s
}

func (s *tlsStand) swapCertificate() { s.current.Store(&s.certB) }

func mustSelfSigned(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestTofuPinLifecycle walks the full TOFU story over a real TLS channel:
// bootstrap records the pin only after a genuine API exchange, the slot
// persists it, and a server key change fails closed with ClassAPIPinMismatch.
func TestTofuPinLifecycle(t *testing.T) {
	ctx := context.Background()
	stand := newTLSStand(t)
	slot := &IdentityStore{Path: filepath.Join(t.TempDir(), "identity.json")}

	c := newTestClient(t, stand.se.endpointsBase(stand.base), slot, "pin-client")
	if err := c.EnsureSession(ctx); err != nil {
		t.Fatalf("bootstrap over self-signed channel: %v", err)
	}

	// Pin committed and persisted (design §3: TOFU at first successful RPC).
	id, err := slot.Load()
	if err != nil {
		t.Fatalf("slot load: %v", err)
	}
	host := stand.ln.Addr().(*net.TCPAddr).IP.String()
	fp, ok := id.Pins[host]
	if !ok || len(fp) != 64 {
		t.Fatalf("pin missing in slot for %q: %+v", host, id.Redacted().Pins)
	}

	// Same key still works.
	if _, err := c.GeoList(ctx); err != nil {
		t.Fatalf("geo_list with valid pin: %v", err)
	}

	// Server key rotation => fail closed.
	stand.swapCertificate()
	c.Close() // drop pooled conns so the next call re-handshakes
	_, err = c.GeoList(ctx)
	if !IsClass(err, ClassAPIPinMismatch) {
		t.Fatalf("err after key change = %v (%T), want ClassAPIPinMismatch", err, err)
	}
}
