package fxvpn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- account store ------------------------------------------------------------

func TestAccountStoreRoundtripAndAbsent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	st := NewAccountStore(path)

	if _, err := st.Load(); !errors.Is(err, ErrStoreAbsent) {
		t.Fatalf("absent store: %v", err)
	}

	want := &AccountsFile{Accounts: []Account{
		{Email: "a@example.com", Label: "primary", RefreshToken: "rt-1"},
		{Email: "b@example.com", Password: "pw-2"},
	}}
	if err := st.Save(want); err != nil {
		t.Fatalf("save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Logf("note: perms %s wider than 0600 (platform-dependent)", info.Mode())
	}

	got, err := st.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Accounts) != 2 || got.Version != accountsFormatVersion {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
	if got.Accounts[0] != want.Accounts[0] || got.Accounts[1] != want.Accounts[1] {
		t.Fatalf("account mismatch: %+v vs %+v", got.Accounts, want.Accounts)
	}
}

func TestAccountStoreCorruptQuarantined(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewAccountStore(path).Load()
	if !errors.Is(err, ErrStoreCorrupt) || Classify(err) != ClassAccountStoreCorrupt {
		t.Fatalf("corrupt load = %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("quarantine missing: %v", err)
	}

	// Structurally valid JSON but invalid account also quarantines.
	if err := os.WriteFile(path, []byte(`{"version":1,"accounts":[{"refresh_token":"no-email"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = NewAccountStore(path).Load()
	if !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("invalid account must quarantine: %v", err)
	}
}

func TestAccountRedactionNeverLeaksSecrets(t *testing.T) {
	a := Account{Email: "user@example.com", Password: "hunter2-super-secret", RefreshToken: "rt-super-secret-987", Label: "lab"}
	rendered := a.Redacted() + " " + a.String()
	for _, secret := range []string{"hunter2", "rt-super-secret"} {
		if strings.Contains(rendered, secret) {
			t.Fatalf("secret %q leaked in redaction: %s", secret, rendered)
		}
	}
	if !strings.Contains(rendered, "u***@example.com") || !strings.Contains(rendered, "pw") || !strings.Contains(rendered, "rt") {
		t.Fatalf("redaction lost shape flags: %s", rendered)
	}
}

// ---- TOFU pin store -------------------------------------------------------------

// tlsStand starts an HTTPS server with a UNIQUE self-signed certificate
// (httptest.NewTLSServer shares one static cert across all servers, which
// would make SPKI mismatch untestable).
func tlsStand(t *testing.T) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"subscribed":true,"uid":1}`))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, pool
}

func TestPinTOFURecordVerifyMismatchPersist(t *testing.T) {
	dir := t.TempDir()
	pinPath := filepath.Join(dir, "pins.json")

	cp := newTestCP(t, pinPath)
	srvA, poolA := tlsStand(t)
	cp.SetRootCAs(poolA)
	hostKey, _, err := net.SplitHostPort(strings.TrimPrefix(srvA.URL, "https://"))
	if err != nil {
		t.Fatalf("split host: %v", err)
	}
	cp.EP.Guardian = srvA.URL

	g := &Guardian{CP: cp}
	if _, err := g.FetchUserInfo(t.Context(), "tok"); err != nil {
		t.Fatalf("first contact through TLS+pin: %v", err)
	}

	pins, err := LoadPinStore(pinPath)
	if err != nil {
		t.Fatalf("reload pins: %v", err)
	}
	if _, ok := pins.Snapshot()[hostKey]; !ok {
		t.Fatalf("pin for %s not recorded: %+v", hostKey, pins.Snapshot())
	}

	// Same cert passes again (pinned path).
	if _, err := g.FetchUserInfo(t.Context(), "tok"); err != nil {
		t.Fatalf("second contact: %v", err)
	}

	// Different certificate on the same host => fail-closed mismatch.
	srvB, _ := tlsStand(t) // httptest mints a fresh unique cert per server
	cpB := newTestCP(t, pinPath)
	poolB := x509.NewCertPool()
	poolB.AddCert(srvB.Certificate())
	cpB.SetRootCAs(poolB)
	cpB.EP.Guardian = srvB.URL

	_, err = (&Guardian{CP: cpB}).FetchUserInfo(t.Context(), "tok")
	if !errors.Is(err, ErrPinMismatch) || Classify(err) != ClassAPIPinMismatch {
		t.Fatalf("want pin mismatch, got %v", err)
	}
}

func TestPinVerifyEmptyChainErrors(t *testing.T) {
	ps, err := LoadPinStore(filepath.Join(t.TempDir(), "p.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.Verify("h.example", nil); err == nil {
		t.Fatal("empty chain must error")
	}
}

// ---- control-plane basics ---------------------------------------------------------

func TestControlPlaneAppliesMozillaHeadersAndTimeout(t *testing.T) {
	ua := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua = r.UserAgent()
		w.WriteHeader(200)
	}))
	defer srv.Close()

	cp := newTestCP(t, "")
	cp.EP.Guardian = srv.URL
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, guardianURL(cp, "/api/v1/fpn/status"), nil)
	applyMozillaHeaders(req)
	resp, err := cp.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if ua != mozillaVPNUserAgent {
		t.Fatalf("UA = %q", ua)
	}
	if cp.HTTP.Timeout != 30*time.Second {
		t.Fatalf("timeout = %v", cp.HTTP.Timeout)
	}
	if tlsMin := cp.tlsCfg.MinVersion; tlsMin != tls.VersionTLS12 {
		t.Fatalf("TLS min version = %#x", tlsMin)
	}
}
