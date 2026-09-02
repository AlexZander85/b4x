package opera

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Test PKI: root -> (optional intermediate) -> leaf, so the VerifyConnection
// intermediates path is exercised for real chains.
// ---------------------------------------------------------------------------

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, cert := makeCertPair(t, cn, nil, true)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

func makeCertPair(t *testing.T, cn string, parent *testCA, isCA bool) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key %s: %v", cn, err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	signerCert, signerKey := tmpl, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}
	if isCA {
		tmpl.IsCA = true
		tmpl.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, key.Public(), signerKey)
	if err != nil {
		t.Fatalf("cert %s: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse %s: %v", cn, err)
	}
	return key, cert
}

// issueLeaf returns a leaf certificate signed directly by this CA.
func (ca *testCA) issueLeaf(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, cert := makeCertPair(t, cn, ca, false)
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key}
}

// issueChained returns leaf+intermediate presented as a two-cert chain.
func (ca *testCA) issueChained(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	iKey, iCert := makeCertPair(t, "intermediate."+cn, ca, true)
	lKey, lCert := makeCertPair(t, cn, &testCA{cert: iCert, key: iKey}, false)
	return tls.Certificate{Certificate: [][]byte{lCert.Raw, iCert.Raw}, PrivateKey: lKey}
}

// ---------------------------------------------------------------------------
// Fake SurfEasy edge: TLS front (SNI capture) + CONNECT handler + optional
// banner + echo tunnel.
// ---------------------------------------------------------------------------

type nodeEdge struct {
	t       *testing.T
	addr    string
	srv     *http.Server
	sni     atomic.Value // string
	authOK  atomic.Bool
	target  atomic.Value // string
	ca      *testCA
	cn      string
	status  string // non-empty => reply with this status line instead of 200
	banner  []byte // pushed right after a 200
	prelude []byte // written in the SAME burst as the 200 line (prefixConn test)
}

func newNodeEdge(t *testing.T, ca *testCA, cn string, cert tls.Certificate) *nodeEdge {
	e := &nodeEdge{t: t, ca: ca, cn: cn}
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"h2", "http/1.1"}, // CDN-like offer; clients opt in
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			e.sni.Store(chi.ServerName)
			c := cert
			return &c, nil
		},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	e.addr = ln.Addr().String()
	e.srv = &http.Server{
		Handler:           http.HandlerFunc(e.handle),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         cfg,
	}
	go func() { _ = e.srv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = e.srv.Close() })
	return e
}

func (e *nodeEdge) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "connect only", http.StatusMethodNotAllowed)
		return
	}
	e.target.Store(r.Host)
	wantAuth := BasicAuthHeader(capitalHexSHA1(deviceIDFix), jwtInitial)
	e.authOK.Store(r.Header.Get("Proxy-Authorization") == wantAuth)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	rwc, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer rwc.Close()

	status := "HTTP/1.1 200 Connection established\r\n\r\n"
	if e.status != "" {
		status = e.status
	}
	burst := append([]byte(status), e.prelude...)
	if _, err := rwc.Write(burst); err != nil {
		return
	}
	_ = brw.Flush()
	if e.status != "" || e.prelude != nil {
		return // nothing else to do for these scenarios
	}
	if len(e.banner) > 0 {
		if _, err := rwc.Write(e.banner); err != nil {
			return
		}
	}
	// Echo tunnel: read through the bufio wrapper so any server-side
	// buffering is honored, write straight to the raw conn.
	_, _ = io.Copy(rwc, brw)
}

func (e *nodeEdge) sawSNI() string    { s, _ := e.sni.Load().(string); return s }
func (e *nodeEdge) sawTarget() string { s, _ := e.target.Load().(string); return s }

func fixedAuth() func() (string, error) {
	h := BasicAuthHeader(capitalHexSHA1(deviceIDFix), jwtInitial)
	return func() (string, error) { return h, nil }
}

func randomBlob(t *testing.T, n int, seed byte) []byte {
	t.Helper()
	b := make([]byte, n)
	for i := range b {
		b[i] = seed ^ byte(i*2654435761>>24)
	}
	sum := sha256.Sum256(b)
	t.Logf("blob seed=%d len=%d sha=%s", seed, n, hex.EncodeToString(sum[:8]))
	return b
}

// ---------------------------------------------------------------------------
// Scenarios.
// ---------------------------------------------------------------------------

func TestNodeDialerHappyBannerAndEcho(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA(t, "test-root")
	edge := newNodeEdge(t, ca, "eu0.sec-tunnel.com", ca.issueChained(t, "eu0.sec-tunnel.com"))
	edge.banner = randomBlob(t, 16*1024, 0x42)

	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		FakeSNI:       "", // suppressed SNI — upstream default
		Auth:          fixedAuth(),
		RootPool:      ca.pool,
	}
	conn, err := d.DialContext(ctx, "tcp", "93.184.216.34:80")
	if err != nil {
		t.Fatalf("dial through node: %v", err)
	}
	defer conn.Close()

	if got := edge.sawSNI(); got != "" {
		t.Fatalf("edge saw SNI %q, want none", got)
	}
	if !edge.authOK.Load() {
		t.Fatal("Proxy-Authorization mismatch at edge")
	}
	if got := edge.sawTarget(); got != "93.184.216.34:80" {
		t.Fatalf("CONNECT target = %q", got)
	}

	// Banner arrives unsolicited right after CONNECT (reverse direction).
	banner := make([]byte, len(edge.banner))
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if string(banner) != string(edge.banner) {
		t.Fatal("banner corrupted in transit")
	}

	// Forward direction: 64KB payload echoed back intact.
	payload := randomBlob(t, 64*1024, 0x7e)
	go func() {
		_, _ = conn.Write(payload)
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	sumWant := sha256.Sum256(payload)
	sumGot := sha256.Sum256(got)
	if sumWant != sumGot {
		t.Fatal("echo payload corrupted")
	}
}

func TestNodeDialerFakeSNIVisibleRealNameVerified(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA(t, "test-root")
	edge := newNodeEdge(t, ca, "eu0.sec-tunnel.com", ca.issueLeaf(t, "eu0.sec-tunnel.com"))

	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		FakeSNI:       "www.opera.com",
		Auth:          fixedAuth(),
		RootPool:      ca.pool,
	}
	conn, err := d.DialContext(ctx, "tcp", "1.2.3.4:443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if got := edge.sawSNI(); got != "www.opera.com" {
		t.Fatalf("edge saw SNI %q, want fake value", got)
	}
	// The connection verified against the REAL name despite fake SNI — the
	// core design §1.3 semantics.
}

func TestNodeDialerWrongNameFailsClosed(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA(t, "test-root")
	edge := newNodeEdge(t, ca, "eu0.sec-tunnel.com", ca.issueLeaf(t, "other.example.com"))

	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		Auth:          fixedAuth(),
		RootPool:      ca.pool,
	}
	_, err := d.DialContext(ctx, "tcp", "1.2.3.4:443")
	if !IsClass(err, ClassDataPlaneTLS) {
		t.Fatalf("err = %v (%T), want ClassDataPlaneTLS", err, err)
	}
}

func TestNodeDialerUntrustedRootFailsClosed(t *testing.T) {
	ctx := context.Background()
	goodCA := newTestCA(t, "good-root")
	evilCA := newTestCA(t, "evil-root")
	edge := newNodeEdge(t, goodCA, "eu0.sec-tunnel.com", evilCA.issueLeaf(t, "eu0.sec-tunnel.com"))

	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		Auth:          fixedAuth(),
		RootPool:      goodCA.pool, // evil root not trusted
	}
	_, err := d.DialContext(ctx, "tcp", "1.2.3.4:443")
	if !IsClass(err, ClassDataPlaneTLS) {
		t.Fatalf("err = %v, want ClassDataPlaneTLS", err)
	}
}

func TestNodeDialerConnectRefusedClassified(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA(t, "test-root")
	for _, st := range []string{"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", "HTTP/1.1 403 Forbidden\r\n\r\n"} {
		edge := newNodeEdge(t, ca, "eu0.sec-tunnel.com", ca.issueLeaf(t, "eu0.sec-tunnel.com"))
		edge.status = st
		d := &NodeDialer{
			Address:       edge.addr,
			TLSServerName: "eu0.sec-tunnel.com",
			Auth:          fixedAuth(),
			RootPool:      ca.pool,
		}
		_, err := d.DialContext(ctx, "tcp", "1.2.3.4:443")
		if !IsClass(err, ClassDataPlaneConnectRefused) {
			t.Fatalf("status %q: err = %v, want ClassDataPlaneConnectRefused", strings.TrimSpace(st), err)
		}
		// resp.Status carries no "HTTP/1.1" prefix; match the code token.
		wantCode := strings.Split(strings.TrimSpace(st), " ")[1]
		if !strings.Contains(err.Error(), wantCode) {
			t.Fatalf("error should carry upstream status %s, got: %v", wantCode, err)
		}
	}
}

func TestConnectReplyLeftoversReplayed(t *testing.T) {
	ctx := context.Background()
	ca := newTestCA(t, "test-root")
	edge := newNodeEdge(t, ca, "eu0.sec-tunnel.com", ca.issueLeaf(t, "eu0.sec-tunnel.com"))
	edge.prelude = []byte("TUNNEL-PRELUDE") // same-segment tunnel bytes after the 200

	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		Auth:          fixedAuth(),
		RootPool:      ca.pool,
	}
	conn, err := d.DialContext(ctx, "tcp", "5.6.7.8:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	got := make([]byte, len(edge.prelude))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read prelude: %v", err)
	}
	if string(got) != string(edge.prelude) {
		t.Fatalf("prelude = %q, want %q (prefixConn replay broken)", got, edge.prelude)
	}
}

func TestNodeDialerValidationGuards(t *testing.T) {
	d := &NodeDialer{TLSServerName: "x", Auth: fixedAuth()}
	if _, err := d.DialContext(context.Background(), "udp", "a:1"); err == nil {
		t.Fatal("udp network accepted")
	}
	d2 := &NodeDialer{Address: "a:1", TLSServerName: "", Auth: fixedAuth()}
	if _, err := d2.DialContext(context.Background(), "tcp", "b:2"); err == nil ||
		!strings.Contains(err.Error(), "empty TLS server name") {
		t.Fatalf("empty name guard: %v", err)
	}
	d3 := &NodeDialer{Address: "a:1", TLSServerName: "x"}
	if _, err := d3.DialContext(context.Background(), "tcp", "b:2"); err == nil ||
		!strings.Contains(err.Error(), "auth provider required") {
		t.Fatalf("auth guard: %v", err)
	}
}

func TestRelayBidirectionalIntegrity(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type end struct {
		c net.Conn
		r *bufio.Reader
	}
	var ends [2]*end
	acceptDone := make(chan *end, 2)
	go func() {
		for i := 0; i < 2; i++ {
			c, err := ln.Accept()
			if err != nil {
				close(acceptDone)
				return
			}
			acceptDone <- &end{c: c, r: bufio.NewReader(c)}
		}
	}()

	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	ends[0] = <-acceptDone
	ends[1] = <-acceptDone

	relayErr := make(chan error, 1)
	go func() { relayErr <- Relay(ends[0].c, ends[1].c) }()

	payloadA := randomBlob(t, 192*1024, 0xa1)
	payloadB := randomBlob(t, 96*1024, 0xb2)

	done := make(chan error, 2)
	transfer := func(from, to *end, payload []byte) {
		if _, err := from.c.Write(payload); err != nil {
			done <- err
			return
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(to.r, got); err != nil {
			done <- err
			return
		}
		if sha256.Sum256(payload) != (sha256.Sum256(got)) {
			done <- fmt.Errorf("checksum mismatch")
			return
		}
		done <- nil
	}
	ea := &end{c: a, r: bufio.NewReader(a)}
	eb := &end{c: b, r: bufio.NewReader(b)}
	go transfer(ea, eb, payloadA) // A -> B through relay
	go transfer(eb, ea, payloadB) // B -> A through relay

	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("transfer %d: %v", i, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("relay transfer timeout")
		}
	}

	// Clean shutdown: EOF on one side finishes Relay without error.
	_ = a.Close()
	select {
	case err := <-relayErr:
		if err != nil {
			t.Fatalf("relay returned error on clean EOF: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not finish after close")
	}
}

func TestClientNodeDialerWiringAndJWTRotation(t *testing.T) {
	ctx := context.Background()
	stand := newSEStand(t)
	c := newTestClient(t, stand.endpoints(), nil, "wire")
	if err := c.EnsureSession(ctx); err != nil {
		t.Fatalf("EnsureSession: %v", err)
	}

	entry := SEIPEntry{Geo: SEGeoEntry{CountryCode: "NL"}, IP: "77.111.244.3", Ports: []uint16{443}}
	nd, err := c.NodeDialer(entry, "")
	if err != nil {
		t.Fatalf("NodeDialer: %v", err)
	}
	if nd.Address != "77.111.244.3:443" || nd.TLSServerName != "nl0.sec-tunnel.com" {
		t.Fatalf("dialer wiring: addr=%q name=%q", nd.Address, nd.TLSServerName)
	}
	auth1, err := c.ProxyAuthHeader()
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	want1 := BasicAuthHeader(capitalHexSHA1(deviceIDFix), jwtInitial)
	if auth1 != want1 {
		t.Fatalf("auth1 = %q, want %q", auth1, want1)
	}

	// JWT rotation must be visible to subsequent dials (per-dial resolution).
	if err := c.RefreshCredentials(ctx); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	auth2, _ := c.ProxyAuthHeader()
	want2 := BasicAuthHeader(capitalHexSHA1(deviceIDFix), jwtRotated)
	if auth2 != want2 || auth2 == auth1 {
		t.Fatalf("auth2 = %q, want rotated %q", auth2, want2)
	}
}

// ---------------------------------------------------------------------------
// Review E-OPERA H1: embedded Mozilla/NSS root pool.
// ---------------------------------------------------------------------------

// TestEmbeddedRootsParse: the built-in pool must carry the design-named
// anchors (USERTrust ECC first among them) — a router without
// ca-certificates depends on every single one parsing.
func TestEmbeddedRootsParse(t *testing.T) {
	certs, err := embeddedRootCerts()
	if err != nil {
		t.Fatalf("embedded roots: %v", err)
	}
	if len(certs) < 3 {
		t.Fatalf("embedded anchors = %d, want the USERTrust/Sectigo set", len(certs))
	}
	foundECC := false
	for _, c := range certs {
		if strings.Contains(c.Subject.CommonName, "USERTrust ECC") {
			foundECC = true
		}
	}
	if !foundECC {
		t.Fatal("USERTrust ECC Certification Authority missing from embedded pool")
	}
}

// TestResolveRootSurvivesEmptySystemStore: with the OS store unavailable
// (OpenWrt/Entware without ca-certificates), the merged pool still carries
// the embedded anchors — node verification proceeds instead of the old
// silent fail-closed.
func TestResolveRootSurvivesEmptySystemStore(t *testing.T) {
	orig := systemCertPool
	systemCertPool = func() (*x509.CertPool, error) { return nil, errors.New("no certs installed") }
	defer func() { systemCertPool = orig }()

	d := &NodeDialer{Address: "1.2.3.4:443", TLSServerName: "eu0.sec-tunnel.com"}
	pool, err := d.resolveRoot()
	if err != nil {
		t.Fatalf("resolveRoot: %v", err)
	}
	if pool == nil {
		t.Fatal("pool nil")
	}
}

// TestResolveRootStructuralNoRoots: if the embedded asset itself cannot be
// parsed, the dialer must fail closed with the dedicated
// opera-dataplane-no-roots class (review §6 second test).
func TestResolveRootStructuralNoRoots(t *testing.T) {
	origPool := systemCertPool
	origRoots := embeddedRoots
	systemCertPool = func() (*x509.CertPool, error) { return nil, errors.New("no certs installed") }
	embeddedRoots = embed.FS{} // unreadable asset
	defer func() {
		systemCertPool = origPool
		embeddedRoots = origRoots
	}()

	d := &NodeDialer{Address: "1.2.3.4:443", TLSServerName: "eu0.sec-tunnel.com"}
	_, err := d.resolveRoot()
	if err == nil {
		t.Fatal("expected structural failure")
	}
	if !IsClass(err, ClassDataPlaneNoRoots) {
		t.Fatalf("class = %v, want opera-dataplane-no-roots", err)
	}
}

// ---------------------------------------------------------------------------
// Review E-OPERA §7 / OP-M0: masquerade golden tests.
// ---------------------------------------------------------------------------

// TestMasqueradeNodeSNIIsRealName: the shipping default (sni_mode=node)
// must put the REAL node name into the ClientHello — no-SNI is a first-
// class DPI signature (§7.4.1), suppression is only an explicit rung.
func TestMasqueradeNodeSNIIsRealName(t *testing.T) {
	ca := newTestCA(t, "opera-test-ca")
	edge := newNodeEdge(t, ca, "eu0.sec-tunnel.com", ca.issueLeaf(t, "eu0.sec-tunnel.com"))

	mq := DefaultMasquerade()
	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		Auth:          func() (string, error) { return BasicAuthHeader("l", "p"), nil },
		RootPool:      ca.pool,
		Masquerade:    mq,
		// Client.NodeDialer resolves the SNI via the masquerade settings;
		// mirror that contract here.
		FakeSNI: mq.EffectiveNodeSNI("eu0.sec-tunnel.com", edge.addr),
	}
	conn, err := d.DialContext(context.Background(), "tcp", "www.gstatic.com:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if got := edge.sni.Load(); got != "eu0.sec-tunnel.com" {
		t.Fatalf("ClientHello SNI = %v, want the real node name", got)
	}
}

// TestMasqueradeSuppressionIsExplicit: MasqueradeOff (the historical
// behavior) suppresses the SNI — reachable only by explicit config.
func TestMasqueradeSuppressionIsExplicit(t *testing.T) {
	ca := newTestCA(t, "opera-test-ca")
	edge := newNodeEdge(t, ca, "eu0.sec-tunnel.com", ca.issueLeaf(t, "eu0.sec-tunnel.com"))

	mq := ResolveMasquerade("off", "", nil, nil, nil, false)
	if mq.SNIMode != SNIModeNone {
		t.Fatalf("off profile SNI mode = %q, want none", mq.SNIMode)
	}
	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		Auth:          func() (string, error) { return BasicAuthHeader("l", "p"), nil },
		RootPool:      ca.pool,
		Masquerade:    mq,
	}
	conn, err := d.DialContext(context.Background(), "tcp", "www.gstatic.com:80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if got := edge.sni.Load(); got != "" {
		t.Fatalf("ClientHello SNI = %q, want suppressed", got)
	}
}

// TestMasqueradePoolStickyPerNode: pool picks are deterministic per node
// (resumption coherence) and come from the configured pool.
func TestMasqueradePoolStickyPerNode(t *testing.T) {
	pool := []string{"www.gosuslugi.ru", "go.sber.ru", "m.vk.com"}
	mq := ResolveMasquerade("browser", "pool", pool, nil, nil, false)

	a1 := mq.EffectiveNodeSNI("eu0.sec-tunnel.com", "77.111.244.3:443")
	a2 := mq.EffectiveNodeSNI("eu0.sec-tunnel.com", "77.111.244.3:443")
	if a1 != a2 {
		t.Fatalf("pool pick not sticky: %q vs %q", a1, a2)
	}
	found := false
	for _, p := range pool {
		if a1 == p {
			found = true
		}
	}
	if !found {
		t.Fatalf("pick %q outside the pool", a1)
	}
	// API SNI honors the same discipline (a pool name — the pin is
	// SNI-independent, review §7.4.5).
	api := mq.EffectiveAPISNI("api2.sec-tunnel.com")
	found = false
	for _, p := range pool {
		if api == p {
			found = true
		}
	}
	if !found {
		t.Fatalf("api pick %q outside the pool", api)
	}
}

// TestMasqueradeResumptionDidResume (§7.4.4): with the session cache wired,
// the SECOND handshake to the same node resumes instead of issuing a full
// handshake — the browser pattern that kills the handshake-burst
// signature.
func TestMasqueradeResumptionDidResume(t *testing.T) {
	ca := newTestCA(t, "opera-test-ca")
	edge := newNodeEdge(t, ca, "eu0.sec-tunnel.com", ca.issueLeaf(t, "eu0.sec-tunnel.com"))

	cache := NewSessionCache()
	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		Auth:          func() (string, error) { return BasicAuthHeader("l", "p"), nil },
		RootPool:      ca.pool,
		Masquerade:    DefaultMasquerade(),
		SessionCache:  cache,
	}

	// First dial: full handshake (verification passes -> ticket stored).
	conn1, err := d.DialNodeTLS(context.Background())
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}
	if conn1.(*tls.Conn).ConnectionState().DidResume {
		t.Fatal("first handshake resumed??")
	}
	// TLS 1.3 session tickets arrive post-handshake and the client caches
	// them while READING; drain briefly so the ticket is processed before
	// the close (an application read does this naturally in production).
	_ = conn1.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	buf := make([]byte, 64)
	_, _ = conn1.Read(buf)
	_ = conn1.Close()

	// Second dial: resumption expected.
	conn2, err := d.DialNodeTLS(context.Background())
	if err != nil {
		t.Fatalf("second dial: %v", err)
	}
	if !conn2.(*tls.Conn).ConnectionState().DidResume {
		t.Fatal("second handshake did not resume — session cache broken")
	}
	_ = conn2.Close()
}

// TestMasqueradeBrowserTLSParams: the browser profile applies the Chrome
// cipher order, curve order and ALPN (OP-M0 golden of §7.4.2a).
func TestMasqueradeBrowserTLSParams(t *testing.T) {
	ca := newTestCA(t, "opera-test-ca")
	edge := newNodeEdge(t, ca, "eu0.sec-tunnel.com", ca.issueLeaf(t, "eu0.sec-tunnel.com"))

	d := &NodeDialer{
		Address:       edge.addr,
		TLSServerName: "eu0.sec-tunnel.com",
		Auth:          func() (string, error) { return BasicAuthHeader("l", "p"), nil },
		RootPool:      ca.pool,
		Masquerade:    DefaultMasquerade(),
	}
	tlsConn, err := d.DialNodeTLS(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer tlsConn.Close()
	cs := tlsConn.(*tls.Conn).ConnectionState()
	if !cs.NegotiatedProtocolIsMutual || cs.NegotiatedProtocol != "http/1.1" {
		t.Fatalf("negotiated ALPN = %q, want http/1.1", cs.NegotiatedProtocol)
	}
	if cs.Version < tls.VersionTLS12 {
		t.Fatalf("version = %x", cs.Version)
	}
}
