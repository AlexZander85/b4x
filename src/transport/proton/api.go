// Proton API client (design §1/§2, patch-plan §3.1): the four registration
// steps of the credentialless flow + session refresh + logicals (v2/v1
// ladder) + keep-alive. The account Proton path never touches email/password
// — /auth/v4/credentialless is the official client's "connect without
// account" route; the WireGuard key is registered through /vpn/v1/certificate.
//
// Bootstrap ladder (design §2) — every REQUEST walks it:
//
//  1. direct hosts   vpn-api.proton.me -> api.protonvpn.ch
//  2. DoH mirrors    TXT d<base32(host)>.protonpro.xyz candidates; a bare
//     IP dials with no SNI and the pin as the only anchor
//  3. carrier        the base-tunnel dial is spliced UNDER the direct dial
//     (fxvpn failoverDial canon: direct first, carrier on a
//     dead TCP leg — one logical rung, two physical paths)
//
// Only a TRANSPORT failure (dial/TLS/pin) escalates to the next rung — an
// HTTP error answer repeats verbatim on the fallback route and must stop the
// ladder (Nova ProtonApi.kt:95-100). Authenticity is SPKI pinning, never the
// chain (mirrors are self-signed by design).
//
// Timeouts mirror the Nova OkHttp profile: connect 12 s, response header
// 20 s, overall 30 s. Zero global HTTP clients: everything is injectable;
// tests always point HTTP at the local stand (consent rule: zero live calls
// from unit tests).
package proton

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DialFunc is the base-tunnel dial shape shared with the warp/opera/fxvpn
// engines (bootstrap-through-carrier).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Nova default header constants (design §1.1). Version overrides live in the
// config so a spoof-version bump never needs a release.
const (
	DefaultAppVersion  = "android-vpn@5.4.44.0"
	DefaultAPIVersion  = "3"
	DefaultUserAgent   = "ProtonVPN/5.4.44.0 (Android 13; Pixel 7)"
	DefaultDeviceName  = "Nova"
	ProtonSuccessCode  = 1000
	CodeCaptcha        = 9001
	CodeCaptchaInvalid = 12087
)

// Timeout profile (Nova OkHttp: connect 12 / read 20 / call 30).
const (
	dialTimeout        = 12 * time.Second
	tlsTimeout         = 12 * time.Second
	responseHdrTimeout = 20 * time.Second
	callTimeout        = 30 * time.Second
)

// DefaultDirectHosts are the two live control hosts (Nova ProtonApi.kt:26).
var DefaultDirectHosts = []string{
	"https://vpn-api.proton.me",
	"https://api.protonvpn.ch",
}

// Session is one Proton session (carrier or credentialless).
type Session struct {
	UID          string
	AccessToken  string
	RefreshToken string
	Scopes       []string
}

// HasScope reports scope membership (the mandatory "vpn" check).
func (s *Session) HasScope(scope string) bool {
	for _, sc := range s.Scopes {
		if sc == scope {
			return true
		}
	}
	return false
}

// Endpoints is the host ladder configuration.
type Endpoints struct {
	Direct      []string // default DefaultDirectHosts
	MirrorHosts []string // dynamic DoH output (cached for the process when set)
}

// Client is the Proton control-plane client. All inputs are injectable.
type Client struct {
	// HTTP injects the whole client (tests). nil => built-in pinned client.
	HTTP *http.Client
	// Pins verifies the TLS channel (SPKI, not the chain). Required when
	// HTTP == nil.
	Pins *PinStore
	// DoH resolves the alternative-routing mirrors. nil disables the mirror
	// rung.
	DoH *DoHResolver
	// Carrier is the base-tunnel dial spliced under the direct dial (rung 3).
	Carrier DialFunc

	// Header defaults; config overrides for release-free version bumps.
	UserAgent  string
	AppVersion string
	APIVersion string
	DeviceName string
	// Netzone is the X-PM-netzone value (public IP/24), set ONCE at start —
	// not per request (design §1.7).
	Netzone string

	Endpoints Endpoints

	// OnPinCommit fires after a successful response commits a TOFU pin (the
	// service persists the store).
	OnPinCommit func(host string)
}

// NewPinnedClient builds the default TLS-pinning HTTP client. carrier (when
// non-nil) backs the TCP leg after the direct dial fails.
func (c *Client) NewPinnedClient(carrier DialFunc) *http.Client {
	dialer := &net.Dialer{Timeout: dialTimeout}
	dialTLS := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		sni := host
		if net.ParseIP(host) != nil {
			sni = "" // bare-IP mirrors: no SNI on the wire (SNI-block bypass)
		}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil && carrier != nil {
			conn, err = carrier(ctx, network, addr)
		}
		if err != nil {
			return nil, err
		}
		cfg := &tls.Config{
			ServerName: sni,
			// Chain validation is REPLACED by SPKI pinning (design §2): the
			// mirrors are self-signed for a foreign CN by design, so the
			// chain would reject the honest mirror; the pin rejects the
			// hostile one. InsecureSkipVerify is REQUIRED with
			// VerifyConnection (Go runs the x509 chain+hostname check first
			// otherwise); the pin callback is the only trust anchor here and
			// it fails closed.
			InsecureSkipVerify: true,
			VerifyConnection:   c.Pins.VerifyConnection(sniIf(sni, host)),
		}
		tlsConn := tls.Client(conn, cfg)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	return &http.Client{
		Timeout: callTimeout,
		Transport: &http.Transport{
			DialTLSContext:        dialTLS,
			TLSHandshakeTimeout:   tlsTimeout,
			ResponseHeaderTimeout: responseHdrTimeout,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          4,
			IdleConnTimeout:       90 * time.Second,
		},
	}
}

// sniIf keeps the verification key honest: a bare-IP channel is pinned under
// its literal address, a named channel under its name.
func sniIf(sni, host string) string {
	if sni != "" {
		return sni
	}
	return host
}

// httpClient returns the active HTTP client (injected stand or built-in
// pinned client).
func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return c.NewPinnedClient(c.Carrier)
}

// ---- envelope --------------------------------------------------------------------

// envelope is the common Proton response head. Code == 1000 is success.
type envelope struct {
	Code  int    `json:"Code"`
	Error string `json:"Error"`
}

// apiError builds the classified failure for a non-success answer
// (patch-plan §3.1 Classify table): 401/403/410 refused; 429/5xx throttled
// (Retry-After honored, cap 30 s — the enrollment canon); 9001/12087
// captcha; anything else a plain APIError.
func apiError(status int, code int, body, retryAfter string) error {
	short := body
	if len(short) > 200 {
		short = short[:200]
	}
	switch {
	case status == 401 || status == 403 || status == 410:
		return &APIError{Code: code, Status: status, Body: short, Wrapped: ErrAPIRefused}
	case status == 429 || status >= 500:
		te := &ThrottledError{Status: status, Body: short}
		if ra := retryAfterOf(retryAfter); ra > 0 {
			te.RetryAfter, te.HasRetryAfter = minDuration(ra, 30*time.Second), true
		}
		return te
	case code == CodeCaptcha || code == CodeCaptchaInvalid:
		return &APIError{Code: code, Status: status, Body: short, Wrapped: ErrCaptchaRequired}
	default:
		return &APIError{Code: code, Status: status, Body: short}
	}
}

// retryAfterOf parses the Retry-After header value (seconds form; Proton
// sends seconds). Zero for absent/unparseable values.
func retryAfterOf(seconds string) time.Duration {
	if seconds == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(seconds))
	if err != nil || n < 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// ---- request ladder ---------------------------------------------------------------

// target is one concrete rung of the request ladder.
type target struct {
	// urlHost goes into the URL (and is the dial target when an IP literal
	// or host:port pair).
	urlHost string
	// sni is the TLS ServerName ("" for bare-IP mirrors).
	sni string
	// pinHost keys the SPKI verification/TOFU.
	pinHost string
	// hostHeader overrides the HTTP Host header ("" = URL host).
	hostHeader string
}

// call walks the ladder until one rung returns an HTTP-level answer.
// Transport-level failures (dial/TLS/pin-mismatch — anything that never
// produced an HTTP response) escalate; an HTTP error answer is FINAL.
// Returns the raw success body or the last error. A 304 answer surfaces as
// (nil, 304, nil) — only the logicals ladder treats it as success (cache
// still valid); every other endpoint classifies it as an error.
func (c *Client) call(ctx context.Context, method, path string, body any, sess *Session, extra map[string]string) ([]byte, error) {
	raw, status, err := c.callStatus(ctx, method, path, body, sess, extra)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotModified {
		return nil, nil
	}
	return raw, nil
}

// callStatus is the raw ladder: it returns the last HTTP status alongside
// the body so the 304-able endpoints can branch before classification.
func (c *Client) callStatus(ctx context.Context, method, path string, body any, sess *Session, extra map[string]string) ([]byte, int, error) {
	client := c.httpClient()

	var (
		result  []byte
		status  int
		done    bool
		lastErr error
	)
	tryRung := func(t target) bool {
		req, err := c.buildRequest(ctx, method, path, body, sess, extra, t)
		if err != nil {
			lastErr = fmt.Errorf("proton: build request: %w", err)
			return true
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("proton: %s%s: %w", t.urlHost, path, err)
			return true // transport-level -> next rung
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		if err != nil {
			lastErr = fmt.Errorf("proton: read response from %s: %w", t.urlHost, err)
			return true
		}
		if resp.StatusCode == http.StatusNotModified {
			// 304 is not an error: the logicals ladder treats it as "cache
			// still valid"; every other endpoint must reject it upstream.
			result, status, done = nil, resp.StatusCode, true
			return false
		}
		var head envelope
		_ = json.Unmarshal(raw, &head) // non-JSON body leaves head zeroed; status decides
		if err := parseEnvelope(resp, head, raw); err != nil {
			lastErr = err
			status = resp.StatusCode
			return false // HTTP-level answer is final for the ladder
		}
		// Success through this channel: promote a pending TOFU pin.
		if c.Pins != nil && c.Pins.Commit(t.pinHost) {
			_ = c.Pins.Save()
			if c.OnPinCommit != nil {
				c.OnPinCommit(t.pinHost)
			}
		}
		result = raw
		status = resp.StatusCode
		lastErr = nil // a later rung won: earlier rung failures are history
		done = true
		return false
	}

	c.forEachRung(tryRung)
	if !done && lastErr == nil {
		lastErr = errors.New("proton: no ladder rung produced a response")
	}
	return result, status, lastErr
}

// forEachRung walks direct -> mirrors -> (carrier-backed direct retry).
// `try` returns false to stop the walk.
func (c *Client) forEachRung(try func(target) bool) {
	direct := c.Endpoints.Direct
	if len(direct) == 0 {
		direct = DefaultDirectHosts
	}
	for _, host := range direct {
		name := strings.TrimPrefix(strings.TrimPrefix(host, "https://"), "http://")
		if !try(target{urlHost: name, sni: name, pinHost: name}) {
			return
		}
	}
	// Mirror rung: only reached when every direct rung failed at the
	// transport layer.
	if c.DoH != nil {
		if mirrors, err := c.mirrorCandidates(); err == nil {
			for _, m := range mirrors {
				t, terr := mirrorTarget(m)
				if terr != nil {
					continue
				}
				if !try(t) {
					return
				}
			}
		}
	}
}

// mirrorCandidates resolves (or reuses) the alternative-routing hosts for
// the primary direct host.
func (c *Client) mirrorCandidates() ([]string, error) {
	if len(c.Endpoints.MirrorHosts) > 0 {
		return c.Endpoints.MirrorHosts, nil
	}
	direct := c.Endpoints.Direct
	if len(direct) == 0 {
		direct = DefaultDirectHosts
	}
	primary := strings.TrimPrefix(strings.TrimPrefix(direct[0], "https://"), "http://")
	hosts, err := c.DoH.ResolveMirrors(context.Background(), primary)
	if err != nil {
		return nil, err
	}
	c.Endpoints.MirrorHosts = hosts
	return hosts, nil
}

// mirrorTarget maps a DoH candidate onto a request target: names keep their
// TLS identity, bare IPs dial SNI-less with the pin as the only anchor.
// host:port candidates (field/test material) keep their port; everything
// else defaults to 443.
func mirrorTarget(cand string) (target, error) {
	host, port := cand, "443"
	if i := strings.LastIndex(cand, ":"); i > 0 {
		host, port = cand[:i], cand[i+1:]
		if _, err := strconv.Atoi(port); err != nil {
			return target{}, fmt.Errorf("proton: mirror candidate %q: bad port", cand)
		}
	}
	if net.ParseIP(host) != nil {
		addrPort := net.JoinHostPort(host, port)
		return target{urlHost: addrPort, sni: "", pinHost: addrPort}, nil
	}
	return target{urlHost: net.JoinHostPort(host, port), sni: host, pinHost: host}, nil
}

// buildRequest assembles one request: Nova header set + session auth + the
// target-specific URL/Host overrides.
func (c *Client) buildRequest(ctx context.Context, method, path string, body any, sess *Session, extra map[string]string, t target) (*http.Request, error) {
	url := "https://" + t.urlHost + path
	var reader io.Reader
	if body != nil {
		blob, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(blob)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	if t.hostHeader != "" {
		req.Host = t.hostHeader
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("x-pm-appversion", c.appVersion())
	req.Header.Set("x-pm-apiversion", c.apiVersion())
	req.Header.Set("Accept", "application/vnd.protonmail.v1+json")
	req.Header.Set("User-Agent", c.userAgent())
	if sess != nil {
		req.Header.Set("x-pm-uid", sess.UID)
		req.Header.Set("Authorization", "Bearer "+sess.AccessToken)
	}
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	return req, nil
}

func (c *Client) appVersion() string {
	if c.AppVersion != "" {
		return c.AppVersion
	}
	return DefaultAppVersion
}

func (c *Client) apiVersion() string {
	if c.APIVersion != "" {
		return c.APIVersion
	}
	return DefaultAPIVersion
}

func (c *Client) userAgent() string {
	if c.UserAgent != "" {
		return c.UserAgent
	}
	return DefaultUserAgent
}

func (c *Client) deviceName() string {
	if c.DeviceName != "" {
		return c.DeviceName
	}
	return DefaultDeviceName
}

// ---- registration steps -----------------------------------------------------------

type sessionResponse struct {
	envelope
	UID          string   `json:"UID"`
	AccessToken  string   `json:"AccessToken"`
	RefreshToken string   `json:"RefreshToken"`
	Scopes       []string `json:"Scopes"`
}

func sessionOf(out *sessionResponse) (*Session, error) {
	if out.UID == "" || out.AccessToken == "" {
		return nil, &APIError{Code: out.Code, Body: "session without UID/AccessToken", Wrapped: ErrAPIInvalid}
	}
	return &Session{UID: out.UID, AccessToken: out.AccessToken, RefreshToken: out.RefreshToken, Scopes: out.Scopes}, nil
}

// CreateSession performs step 1: the unauthenticated carrier session
// (POST /auth/v4/sessions {}). Tokens of this step are ONLY the bearer for
// step 2 — the /vpn endpoints answer 9106 MissingScopes to it.
func (c *Client) CreateSession(ctx context.Context) (*Session, error) {
	raw, err := c.call(ctx, http.MethodPost, "/auth/v4/sessions", struct{}{}, nil, nil)
	if err != nil {
		return nil, err
	}
	var out sessionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("proton: sessions response: %w", err)
	}
	if err := parseEnvelopeOK(out.Code, raw); err != nil {
		return nil, err
	}
	return sessionOf(&out)
}

// parseEnvelopeOK refuses a non-1000 code on an otherwise-200 answer.
func parseEnvelopeOK(code int, raw []byte) error {
	if code != ProtonSuccessCode {
		return apiError(http.StatusOK, code, string(raw), "")
	}
	return nil
}

// parseEnvelope classifies a received HTTP response: any non-200 status or
// non-1000 code is a FINAL (HTTP-level) failure; Retry-After is honored on
// the throttled branch.
func parseEnvelope(resp *http.Response, head envelope, body []byte) error {
	if resp.StatusCode != http.StatusOK || head.Code != ProtonSuccessCode {
		return apiError(resp.StatusCode, head.Code, string(body), resp.Header.Get("Retry-After"))
	}
	return nil
}

// Credentialless performs step 2 (POST /auth/v4/credentialless): binds the
// challenge frame to a fresh carrier session and returns the vpn-scoped
// session. NOT idempotent — if the request landed but the answer was lost,
// the retry answers 400 "Session already tied to a user"; the Nova treatment
// is exactly ONE retry on a NEW carrier session (ProtonApi.kt:201-226).
func (c *Client) Credentialless(ctx context.Context, frame map[string]any) (*Session, error) {
	sess, err := c.credentiallessOnce(ctx, frame)
	if err == nil {
		return sess, nil
	}
	if !errors.Is(err, ErrAlreadyTied) {
		return nil, err
	}
	// The previous carrier is burned; take a new one and repeat exactly once.
	return c.credentiallessOnce(ctx, frame)
}

func (c *Client) credentiallessOnce(ctx context.Context, frame map[string]any) (*Session, error) {
	carrier, err := c.CreateSession(ctx)
	if err != nil {
		return nil, err
	}
	// frame is the FULL body already: {"Payload": {"<key>": {...}}} —
	// ChallengeBody() wraps once; do not double-wrap.
	raw, err := c.call(ctx, http.MethodPost, "/auth/v4/credentialless", frame, carrier, nil)
	if err != nil {
		if isAlreadyTied(err) {
			return nil, ErrAlreadyTied
		}
		return nil, err
	}
	var out sessionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("proton: credentialless response: %w", err)
	}
	if err := parseEnvelopeOK(out.Code, raw); err != nil {
		if isAlreadyTiedCode(out) {
			return nil, ErrAlreadyTied
		}
		return nil, err
	}
	sess, err := sessionOf(&out)
	if err != nil {
		return nil, err
	}
	if !sess.HasScope("vpn") {
		return nil, fmt.Errorf("%w: scopes=%v", ErrScopeMissing, sess.Scopes)
	}
	return sess, nil
}

// isAlreadyTied detects the 400 "Session already tied to a user" family both
// in the classified error body and the raw text (Nova checks the message).
func isAlreadyTied(err error) bool {
	var ae *APIError
	if errors.As(err, &ae) {
		return strings.Contains(strings.ToLower(ae.Body), "already tied")
	}
	return false
}

func isAlreadyTiedCode(out sessionResponse) bool {
	return strings.Contains(strings.ToLower(out.Error), "already tied")
}

// Refresh performs POST /auth/v4/refresh WITHOUT Authorization (Next
// ProtonAuthApi.kt:145-152). Success = Code 1000 && AccessToken != ""; the
// refresh token is replaced only when the server rotated it. 400/401/422
// classify as session-refresh-failed upstream (the service re-registers,
// gated once per boot).
func (c *Client) Refresh(ctx context.Context, uid, refreshToken string) (*Session, error) {
	body := map[string]any{
		"UID":          uid,
		"RefreshToken": refreshToken,
		"ResponseType": "token",
		"GrantType":    "refresh_token",
		"RedirectURI":  "http://protonmail.ch",
	}
	raw, err := c.call(ctx, http.MethodPost, "/auth/v4/refresh", body, nil, nil)
	if err != nil {
		return nil, err
	}
	var out sessionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("proton: refresh response: %w", err)
	}
	if err := parseEnvelopeOK(out.Code, raw); err != nil {
		return nil, err
	}
	if out.AccessToken == "" {
		return nil, &APIError{Code: out.Code, Body: "refresh without AccessToken", Wrapped: ErrAPIInvalid}
	}
	newUID := out.UID
	if newUID == "" {
		newUID = uid
	}
	return &Session{UID: newUID, AccessToken: out.AccessToken, RefreshToken: out.RefreshToken, Scopes: out.Scopes}, nil
}

// ---- logicals ---------------------------------------------------------------------

// LogicalServer is one Proton logical server entry (the fields the free
// filter and the location model need).
type LogicalServer struct {
	Name        string           `json:"Name"`
	ExitCountry string           `json:"ExitCountry"`
	City        string           `json:"City"`
	Tier        int              `json:"Tier"`
	Status      int              `json:"Status"`
	Load        int              `json:"Load"`
	Score       float64          `json:"Score"`
	Servers     []PhysicalServer `json:"Servers"`
}

// PhysicalServer is one WG endpoint behind a logical.
type PhysicalServer struct {
	EntryIP         string `json:"EntryIP"`
	X25519PublicKey string `json:"X25519PublicKey"`
	Status          int    `json:"Status"`
	Domain          string `json:"Domain"`
	Label           string `json:"Label"`
}

// LogicalsResponse is the parsed logicals payload.
type LogicalsResponse struct {
	LogicalServers []LogicalServer `json:"LogicalServers"`
}

// FetchLogicals walks the v2 -> v1 ladder (design §1.7): v2 carries
// If-Modified-Since + X-PM-netzone and answers 304 when the stored cache is
// fresh (=> nil, nil); a v2 TRANSPORT failure steps down to the simpler
// v1 Tier=0 endpoint (which historically hangs on alternative routes — so it
// is the SECOND rung, never the first).
func (c *Client) FetchLogicals(ctx context.Context, sess *Session, cacheHint string) (*LogicalsResponse, error) {
	extra := map[string]string{}
	if cacheHint != "" {
		extra["If-Modified-Since"] = cacheHint
	}
	if c.Netzone != "" {
		extra["X-PM-netzone"] = c.Netzone
	}

	raw, status, err := c.callStatus(ctx, http.MethodGet,
		"/vpn/v2/logicals?WithEntriesForProtocols=wireguard&WithState=true", nil, sess, extra)
	if err != nil {
		// Transport-level failure -> step down to v1; an HTTP-level answer
		// is final (a bad session fails identically on v1).
		var httpErr *APIError
		if !errors.As(err, &httpErr) {
			return c.fetchLogicalsV1(ctx, sess)
		}
		return nil, err
	}
	if status == http.StatusNotModified {
		return nil, nil // cache still valid
	}
	var head envelope
	_ = json.Unmarshal(raw, &head)
	if head.Code != ProtonSuccessCode {
		return nil, apiError(http.StatusOK, head.Code, string(raw), "")
	}
	var out LogicalsResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("proton: logicals v2 response: %w", err)
	}
	return &out, nil
}

func (c *Client) fetchLogicalsV1(ctx context.Context, sess *Session) (*LogicalsResponse, error) {
	raw, err := c.call(ctx, http.MethodGet, "/vpn/logicals?Tier=0", nil, sess, nil)
	if err != nil {
		return nil, err
	}
	var head envelope
	_ = json.Unmarshal(raw, &head)
	if head.Code != ProtonSuccessCode {
		return nil, apiError(http.StatusOK, head.Code, string(raw), "")
	}
	var out LogicalsResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("proton: logicals v1 response: %w", err)
	}
	return &out, nil
}

// ---- certificate + keep-alive ------------------------------------------------------

// CertResponse is the /vpn/v1/certificate answer. The certificate itself is
// not needed by the tunnel — the FACT that Proton knows our public key is
// (the server derives the X25519 half itself).
type CertResponse struct {
	ExpirationTime int64    `json:"ExpirationTime"` // unix seconds
	RefreshTime    int64    `json:"RefreshTime"`    // unix seconds (optional)
	Certificate    string   `json:"Certificate"`
	IPv4           string   `json:"IPv4"`
	IPv6           string   `json:"IPv6"`
	DNS            []string `json:"DNS"`
}

// RegisterClientKey performs step 4 (POST /vpn/v1/certificate): Mode
// persistent gives ~1 year; in-place re-issue of the same key is free and
// consequence-free (ProtonProfileManager.kt:193-198). A response without
// ExpirationTime is a structural invalid answer (scenario 15).
func (c *Client) RegisterClientKey(ctx context.Context, sess *Session, pubPEM string) (*CertResponse, error) {
	body := map[string]any{
		"ClientPublicKey": pubPEM,
		"Mode":            "persistent",
		"DeviceName":      c.deviceName(),
	}
	raw, err := c.call(ctx, http.MethodPost, "/vpn/v1/certificate", body, sess, nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		envelope
		CertResponse
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("proton: certificate response: %w", err)
	}
	if err := parseEnvelopeOK(out.Code, raw); err != nil {
		return nil, err
	}
	if out.ExpirationTime <= 0 {
		return nil, &APIError{Code: out.Code, Body: "certificate without ExpirationTime", Wrapped: ErrAPIInvalid}
	}
	return &out.CertResponse, nil
}

// UserKeepAlive refreshes the session liveness (GET /core/v4/users, Next
// SessionRefreshWorker cadence: 12 h) without touching tokens.
func (c *Client) UserKeepAlive(ctx context.Context, sess *Session) error {
	raw, err := c.call(ctx, http.MethodGet, "/core/v4/users", nil, sess, nil)
	if err != nil {
		return err
	}
	var head envelope
	if err := json.Unmarshal(raw, &head); err != nil {
		return fmt.Errorf("proton: users response: %w", err)
	}
	if head.Code != ProtonSuccessCode {
		return apiError(http.StatusOK, head.Code, string(raw), "")
	}
	return nil
}
