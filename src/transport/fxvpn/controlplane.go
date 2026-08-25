// Control-plane HTTP plumbing shared by FxA, Guardian and Remote Settings
// (reference: firefox-vpn-client http_client.go/http_headers.go, protocol
// facts verified against its sources). One client, one cookie jar: the
// Fastly anti-bot cookie is issued with Domain=firefox.com and bound to the
// EXIT IP that solved the challenge, so challenge solving and subsequent API
// calls MUST share both the transport (same exit) and the jar (fastly.go).
package fxvpn

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"time"
)

const (
	mozillaVPNUserAgent = "MozillaVPN/2.35.0 (sys:linux; iap:true)"

	// controlPlaneTimeout bounds every API call; the Fastly solver extends
	// its own window internally via minBudgetContext (reference
	// contextWithMinDeadline semantics).
	controlPlaneTimeout = 30 * time.Second

	// errorBodyLimit caps how much of an error response body we keep for
	// diagnostics. API error bodies are not known to carry credentials;
	// the cap exists so a hostile/misbehaving edge cannot flood logs.
	errorBodyLimit = 16 * 1024
)

// Endpoints carries every control-plane base URL. Defaults mirror the
// production hosts; tests and bootstrap-through-carrier overrides replace
// them wholesale. FxAAPI includes the /v1 prefix.
type Endpoints struct {
	FxAAPI         string // https://api.accounts.firefox.com/v1
	FxASite        string // https://accounts.firefox.com (challenge page host)
	Guardian       string // https://vpn.mozilla.org
	RemoteSettings string // full records URL of the vpn-serverlist collection
}

// DefaultEndpoints returns the production endpoint set.
func DefaultEndpoints() Endpoints {
	return Endpoints{
		FxAAPI:         "https://api.accounts.firefox.com/v1",
		FxASite:        "https://accounts.firefox.com",
		Guardian:       "https://vpn.mozilla.org",
		RemoteSettings: "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records",
	}
}

// ControlPlane is the isolated HTTP client for all Mozilla control-plane
// traffic. It is deliberately separate from http.DefaultClient.
type ControlPlane struct {
	HTTP *http.Client
	EP   Endpoints
	Pins *PinStore // nil disables SPKI pinning (tests only)

	tlsCfg   *tls.Config
	chMu     chan struct{} // serializes Fastly challenge solving per client
	rootCAs  *x509.CertPool
	baseDial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewControlPlane builds the client. pinPath empty = no TOFU persistence
// (tests); otherwise the PinStore loads from/commits to pinPath.
func NewControlPlane(pinPath string) (*ControlPlane, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, fmt.Errorf("fxvpn: cookie jar: %w", err)
	}
	cp := &ControlPlane{
		EP:   DefaultEndpoints(),
		chMu: make(chan struct{}, 1),
	}
	base := &tls.Config{MinVersion: tls.VersionTLS12}
	cp.tlsCfg = base
	if pinPath != "" {
		pins, err := LoadPinStore(pinPath)
		if err != nil {
			return nil, err
		}
		cp.Pins = pins
	}
	tr := &http.Transport{
		TLSClientConfig:   base,
		ForceAttemptHTTP2: true,
		DialTLSContext:    cp.dialTLS,
	}
	cp.HTTP = &http.Client{
		Timeout:   controlPlaneTimeout,
		Jar:       jar,
		Transport: tr,
	}
	return cp, nil
}

// SetBaseDial overrides the TCP leg UNDER the pinned TLS handshake
// (bootstrap-through-carrier seam: control-plane requests ride the active
// base tunnel while SPKI pinning keeps verifying the far end). Must be set
// before the first request.
func (c *ControlPlane) SetBaseDial(dial func(ctx context.Context, network, addr string) (net.Conn, error)) {
	c.baseDial = dial
}

// dialTCP performs the TCP leg honoring the optional base-dial override.
func (c *ControlPlane) dialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	if c.baseDial != nil {
		return c.baseDial(ctx, network, addr)
	}
	d := &net.Dialer{}
	return d.DialContext(ctx, network, addr)
}

// dialTLS dials TCP then handshakes with our TLS config, verifying the
// TOFU SPKI pin for the target host afterwards (fail-closed on mismatch:
// the connection is closed before it can carry a request).
func (c *ControlPlane) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("fxvpn: bad addr %q: %w", addr, err)
	}
	raw, err := c.dialTCP(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	cfg := c.tlsCfg.Clone()
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	tc := tls.Client(raw, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	if c.Pins != nil {
		state := tc.ConnectionState()
		if perr := c.Pins.Verify(host, state.PeerCertificates); perr != nil {
			_ = tc.Close()
			return nil, perr
		}
	}
	return tc, nil
}

// SetTransport replaces the RoundTripper wholesale: the
// bootstrap-through-carrier path routes control-plane requests through the
// active base tunnel this way, and fake-stand tests inject plain transports.
// Must be called before the first request (documented seam).
func (c *ControlPlane) SetTransport(rt http.RoundTripper) {
	c.HTTP.Transport = rt
}

// SetRootCAs pins the trust pool for self-signed fake stands (tests) and
// any future corporate CA need. Must be called before the first request.
func (c *ControlPlane) SetRootCAs(pool *x509.CertPool) {
	c.rootCAs = pool
	c.tlsCfg.RootCAs = pool
}

// Jar exposes the shared cookie jar (Fastly solver installs earned cookies
// here; nothing else may touch it).
func (c *ControlPlane) Jar() http.CookieJar { return c.HTTP.Jar }

// Do issues req with the shared client. It exists so call sites stay on one
// path (timeout, jar, transport) — thin by design.
func (c *ControlPlane) Do(req *http.Request) (*http.Response, error) {
	return c.HTTP.Do(req)
}

// applyMozillaHeaders stamps the masquerade headers used by the official
// client on all control-plane calls (http_headers.go:3-9).
func applyMozillaHeaders(req *http.Request) {
	req.Header.Set("User-Agent", mozillaVPNUserAgent)
	req.Header.Set("Accept", "application/json")
}

// spkiPin computes the SHA-256 over the leaf certificate's DER
// SubjectPublicKeyInfo — the pin material for TOFU.
func spkiPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return fmt.Sprintf("%x", sum[:])
}

// readErrBody drains up to errorBodyLimit of an error response body and
// CLOSES it; call sites must treat the response body as consumed afterwards.
func readErrBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
	if err != nil {
		return "reading error body failed: " + err.Error()
	}
	return string(b)
}
