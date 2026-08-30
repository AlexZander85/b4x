package proton

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- fake Proton API stand ----------------------------------------------------------

// recordedCall is one request the stand saw.
type recordedCall struct {
	Method        string
	Path          string
	Host          string // URL host (where the client intended to go)
	HeaderHost    string // req.Host override
	Authorization string
	UID           string
	Body          string
	Header        http.Header
}

// apiStand is the fake Proton API: a httptest server with a scripted
// responder plus a request journal. Zero external calls (consent rule).
type apiStand struct {
	srv *httptest.Server
	URL string

	mu    sync.Mutex
	calls []recordedCall

	// respond decides the (status, body) per request; nil => generic success.
	respond func(rc recordedCall) (int, string)
}

func newAPIStand(t *testing.T, respond func(rc recordedCall) (int, string)) *apiStand {
	t.Helper()
	st := &apiStand{respond: respond}
	st.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		st.mu.Lock()
		st.calls = append(st.calls, recordedCall{
			Method:        r.Method,
			Path:          r.URL.RequestURI(),
			Host:          r.Host,
			HeaderHost:    r.Host,
			Authorization: r.Header.Get("Authorization"),
			UID:           r.Header.Get("x-pm-uid"),
			Body:          string(body),
			Header:        r.Header.Clone(),
		})
		responder := st.respond
		st.mu.Unlock()
		if responder == nil {
			responder = func(rc recordedCall) (int, string) { return http.StatusOK, `{"Code":1000}` }
		}
		status, payload := responder(st.last())
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(st.srv.Close)
	st.URL = st.srv.URL
	return st
}

// last returns the most recent recorded call (stand handler context).
func (s *apiStand) last() recordedCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.calls) == 0 {
		return recordedCall{}
	}
	return s.calls[len(s.calls)-1]
}

func (s *apiStand) journal() []recordedCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedCall(nil), s.calls...)
}

func (s *apiStand) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// client returns a Client whose HTTP points at the stand; the URL host is
// forced to the stand's listener for every request (the ladder still walks
// real host names — vpn-api.proton.me etc. — but everything lands here).
func (s *apiStand) client() *Client {
	return &Client{HTTP: &http.Client{
		Transport: s.transport(s.srv.URL, ""),
	}}
}

// transport rewrites every request to base (or rejects the direct hosts when
// base is ""), simulating a transport-dead direct channel.
func (s *apiStand) transport(base, deadErr string) http.RoundTripper {
	return roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if base == "" {
			return nil, errors.New(deadErr)
		}
		u, err := url.Parse(base)
		if err != nil {
			return nil, err
		}
		r.URL.Scheme = u.Scheme
		r.URL.Host = u.Host
		return http.DefaultTransport.RoundTrip(r)
	})
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// ---- helpers -----------------------------------------------------------------------

func sessionJSON(uid, access, refresh string, scopes ...string) string {
	sc, _ := json.Marshal(scopes)
	return fmt.Sprintf(`{"Code":1000,"UID":%q,"AccessToken":%q,"RefreshToken":%q,"Scopes":%s}`,
		uid, access, refresh, string(sc))
}

const testPubPEM = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAtesttesttesttesttesttesttesttesttesttesttes=\n-----END PUBLIC KEY-----\n"

// ---- scenarios ---------------------------------------------------------------------

// Scenario 1: happy path — full cycle, header discipline, exactly one
// registration (one createSession + one credentialless).
func TestHappyPathFullCycle(t *testing.T) {
	certCalls := 0
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		switch {
		case rc.Path == "/auth/v4/sessions":
			return http.StatusOK, sessionJSON("uid-carrier", "tok-carrier", "rf-carrier", "user")
		case rc.Path == "/auth/v4/credentialless":
			return http.StatusOK, sessionJSON("uid-vpn", "tok-vpn", "rf-vpn", "vpn", "user")
		case strings.HasPrefix(rc.Path, "/vpn/v2/logicals"):
			return http.StatusOK, `{"Code":1000,"LogicalServers":[{"Name":"NL-FREE#1","Tier":0,"Status":1,"ExitCountry":"NL","Load":10,"Score":1.5,"Servers":[{"EntryIP":"1.2.3.4","X25519PublicKey":"pubkey","Status":1}]}]}`
		case rc.Path == "/vpn/v1/certificate":
			certCalls++
			return http.StatusOK, `{"Code":1000,"ExpirationTime":1800000000,"RefreshTime":1799000000}`
		default:
			return http.StatusOK, `{"Code":1000}`
		}
	})
	c := st.client()
	c.UserAgent = "ProtonVPN/5.4.44.0 (Android 13; Pixel 7)"

	ctx := context.Background()
	sess, err := c.Credentialless(ctx, DeviceProfile{}.ChallengeBody())
	if err != nil {
		t.Fatalf("Credentialless: %v", err)
	}
	if !sess.HasScope("vpn") {
		t.Fatal("vpn scope missing in the credentialless session")
	}
	logicals, err := c.FetchLogicals(ctx, sess, "")
	if err != nil {
		t.Fatalf("FetchLogicals: %v", err)
	}
	if len(logicals.LogicalServers) != 1 || logicals.LogicalServers[0].Name != "NL-FREE#1" {
		t.Fatalf("logicals parse: %+v", logicals)
	}
	cert, err := c.RegisterClientKey(ctx, sess, testPubPEM)
	if err != nil {
		t.Fatalf("RegisterClientKey: %v", err)
	}
	if cert.ExpirationTime != 1800000000 {
		t.Fatalf("ExpirationTime = %d", cert.ExpirationTime)
	}

	calls := st.journal()
	if len(calls) != 4 {
		t.Fatalf("expected exactly 4 calls, got %d: %+v", len(calls), calls)
	}
	// Header discipline (design §1.1).
	for _, rc := range calls {
		if got := rc.Header.Get("x-pm-appversion"); got != DefaultAppVersion {
			t.Fatalf("x-pm-appversion = %q", got)
		}
		if got := rc.Header.Get("x-pm-apiversion"); got != "3" {
			t.Fatalf("x-pm-apiversion = %q", got)
		}
		if got := rc.Header.Get("Accept"); got != "application/vnd.protonmail.v1+json" {
			t.Fatalf("Accept = %q", got)
		}
		if got := rc.Header.Get("User-Agent"); got != c.UserAgent {
			t.Fatalf("User-Agent = %q", got)
		}
	}
	// Bearer of step 1 rides step 2 (carrier discipline).
	if calls[1].Authorization != "Bearer tok-carrier" || calls[1].UID != "uid-carrier" {
		t.Fatalf("credentialless auth: %q / %q", calls[1].Authorization, calls[1].UID)
	}
	// Steps 3-4 authenticate as the VPN session.
	if calls[2].Authorization != "Bearer tok-vpn" || calls[3].Authorization != "Bearer tok-vpn" {
		t.Fatal("logicals/certificate must carry the vpn session bearer")
	}
	// Persistent mode + device name (design §1.6).
	if !strings.Contains(calls[3].Body, `"Mode":"persistent"`) || !strings.Contains(calls[3].Body, `"DeviceName":"Nova"`) {
		t.Fatalf("certificate body: %s", calls[3].Body)
	}
	// Registration invariants: exactly one carrier + one credentialless.
	creates, credless := 0, 0
	for _, rc := range calls {
		switch rc.Path {
		case "/auth/v4/sessions":
			creates++
		case "/auth/v4/credentialless":
			credless++
		}
	}
	if creates != 1 || credless != 1 {
		t.Fatalf("registration noise: creates=%d credentialless=%d", creates, credless)
	}
}

// Scenario 2: credentialless "already tied" 400 -> retry-1 on a NEW carrier,
// success; the caller never sees the sentinel.
func TestCredentiallessAlreadyTiedRetryOnce(t *testing.T) {
	credlessCalls := 0
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		switch rc.Path {
		case "/auth/v4/sessions":
			return http.StatusOK, sessionJSON("uid-c", "tok-c", "rf-c")
		case "/auth/v4/credentialless":
			credlessCalls++
			if credlessCalls == 1 {
				return http.StatusBadRequest, `{"Code":12000,"Error":"Session already tied to a user"}`
			}
			return http.StatusOK, sessionJSON("uid-vpn", "tok-vpn", "rf-vpn", "vpn")
		default:
			return http.StatusOK, `{"Code":1000}`
		}
	})
	c := st.client()
	sess, err := c.Credentialless(context.Background(), DeviceProfile{}.ChallengeBody())
	if err != nil {
		t.Fatalf("Credentialless: %v", err)
	}
	if sess.UID != "uid-vpn" {
		t.Fatalf("session uid = %q", sess.UID)
	}
	if credlessCalls != 2 {
		t.Fatalf("credentialless attempts = %d, want exactly 2 (one retry)", credlessCalls)
	}
	calls := st.journal()
	if len(calls) != 4 { // 2x carrier + 2x credentialless
		t.Fatalf("calls = %d, want 4", len(calls))
	}
}

// Scenario 3: scopes without vpn -> proton-scope-missing; NO second attempt.
func TestCredentiallessScopeMissing(t *testing.T) {
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		switch rc.Path {
		case "/auth/v4/sessions":
			return http.StatusOK, sessionJSON("uid-c", "tok-c", "rf-c")
		case "/auth/v4/credentialless":
			return http.StatusOK, sessionJSON("uid-nope", "tok-nope", "rf-nope", "user")
		default:
			return http.StatusOK, `{"Code":1000}`
		}
	})
	c := st.client()
	_, err := c.Credentialless(context.Background(), DeviceProfile{}.ChallengeBody())
	if !errors.Is(err, ErrScopeMissing) {
		t.Fatalf("err = %v, want ErrScopeMissing", err)
	}
	if Classify(err) != ClassScopeMissing {
		t.Fatalf("class = %q", Classify(err))
	}
	if st.count() != 2 {
		t.Fatalf("calls = %d, want 2 (no retry on scope-missing)", st.count())
	}
}

// Scenario 4: 401 on any step -> proton-api-refused; no auto re-registration.
func TestRefused401(t *testing.T) {
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		if rc.Path == "/auth/v4/sessions" {
			return http.StatusUnauthorized, `{"Code":8002,"Error":"Unauthorized"}`
		}
		return http.StatusOK, `{"Code":1000}`
	})
	c := st.client()
	_, err := c.CreateSession(context.Background())
	if !errors.Is(err, ErrAPIRefused) {
		t.Fatalf("err = %v, want ErrAPIRefused", err)
	}
	if Classify(err) != ClassAPIRefused {
		t.Fatalf("class = %q", Classify(err))
	}
	if st.count() != 1 {
		// The ladder stops at the FIRST HTTP-level answer: no other rung is
		// tried after an HTTP error (only transport failures escalate).
		t.Fatalf("calls = %d, want 1 (ladder must not escalate on HTTP errors)", st.count())
	}
}

// Scenario 5: 429 + Retry-After -> throttled with capped Retry-After.
func TestThrottled429RetryAfterCap(t *testing.T) {
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		if rc.Path == "/auth/v4/sessions" {
			return http.StatusTooManyRequests, `{"Code":4391,"Error":"Too many requests"}`
		}
		return http.StatusOK, `{"Code":1000}`
	})
	c := st.client()
	_, err := c.CreateSession(context.Background())
	var te *ThrottledError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v (%T), want ThrottledError", err, err)
	}
	if Classify(err) != ClassAPIThrottled {
		t.Fatalf("class = %q", Classify(err))
	}
}

// The stand middleware cannot set response headers per-call through the
// simple responder; this test uses a raw httptest server to verify the
// Retry-After parsing + 30s cap directly.
func TestRetryAfterParsingCap(t *testing.T) {
	if got := retryAfterOf("90"); got != 90*time.Second {
		t.Fatalf("parse 90 = %v", got)
	}
	if got := retryAfterOf(""); got != 0 {
		t.Fatalf("parse empty = %v", got)
	}
	err := apiError(429, 0, "body", "90")
	te := err.(*ThrottledError)
	if te.RetryAfter != 30*time.Second || !te.HasRetryAfter {
		t.Fatalf("cap: %+v", te)
	}
	err = apiError(429, 0, "body", "10")
	if te := err.(*ThrottledError); te.RetryAfter != 10*time.Second {
		t.Fatalf("no-cap: %+v", te)
	}
}

// Scenario 6: code 9001 -> captcha-required structural refusal.
func TestCaptcha9001(t *testing.T) {
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		if rc.Path == "/auth/v4/credentialless" {
			return http.StatusOK, `{"Code":9001,"Error":"Human verification required"}`
		}
		return http.StatusOK, sessionJSON("uid-c", "tok-c", "rf-c")
	})
	c := st.client()
	_, err := c.Credentialless(context.Background(), DeviceProfile{}.ChallengeBody())
	if !errors.Is(err, ErrCaptchaRequired) {
		t.Fatalf("err = %v, want ErrCaptchaRequired", err)
	}
	if Classify(err) != ClassCaptchaRequired {
		t.Fatalf("class = %q", Classify(err))
	}
}

// Scenarios 7/8/9: refresh success with rotation; refresh 400 classifies for
// re-registration; force semantics belong to the service (PT5).
func TestRefreshSuccessAndRotation(t *testing.T) {
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		if rc.Path == "/auth/v4/refresh" {
			return http.StatusOK, `{"Code":1000,"UID":"uid-new","AccessToken":"at-new","RefreshToken":"rf-new"}`
		}
		return http.StatusOK, `{"Code":1000}`
	})
	c := st.client()
	sess, err := c.Refresh(context.Background(), "uid-old", "rf-old")
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if sess.AccessToken != "at-new" || sess.RefreshToken != "rf-new" || sess.UID != "uid-new" {
		t.Fatalf("refresh: %+v", sess)
	}
	rc := st.last()
	if rc.Authorization != "" {
		t.Fatalf("refresh must NOT carry Authorization, got %q", rc.Authorization)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(rc.Body), &body); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]string{
		"UID": "uid-old", "RefreshToken": "rf-old",
		"ResponseType": "token", "GrantType": "refresh_token", "RedirectURI": "http://protonmail.ch",
	} {
		if body[k] != want {
			t.Fatalf("refresh body[%s] = %v, want %v", k, body[k], want)
		}
	}
}

func TestRefresh400Classified(t *testing.T) {
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		if rc.Path == "/auth/v4/refresh" {
			return http.StatusBadRequest, `{"Code":10013,"Error":"Invalid refresh token"}`
		}
		return http.StatusOK, `{"Code":1000}`
	})
	c := st.client()
	_, err := c.Refresh(context.Background(), "uid", "rf")
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusBadRequest {
		t.Fatalf("err = %v, want APIError(400)", err)
	}
}

// Scenario 10: logicals 304 -> nil, nil (cache valid).
func TestLogicals304(t *testing.T) {
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		return http.StatusNotModified, ""
	})
	c := st.client()
	c.Netzone = "1.2.3.0/24"
	sess := &Session{UID: "u", AccessToken: "a"}
	out, err := c.FetchLogicals(context.Background(), sess, "Mon, 01 Jan 2026 00:00:00 GMT")
	if err != nil {
		t.Fatalf("FetchLogicals: %v", err)
	}
	if out != nil {
		t.Fatalf("304 must yield nil response, got %+v", out)
	}
	rc := st.last()
	if rc.Header.Get("If-Modified-Since") == "" {
		t.Fatal("If-Modified-Since header missing")
	}
	if rc.Header.Get("X-PM-netzone") != "1.2.3.0/24" {
		t.Fatalf("X-PM-netzone = %q", rc.Header.Get("X-PM-netzone"))
	}
}

// Scenario 15: certificate without ExpirationTime -> ErrAPIInvalid; the
// caller must NOT treat the key as registered.
func TestCertificateWithoutExpiration(t *testing.T) {
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		return http.StatusOK, `{"Code":1000}`
	})
	c := st.client()
	sess := &Session{UID: "u", AccessToken: "a"}
	_, err := c.RegisterClientKey(context.Background(), sess, testPubPEM)
	if !errors.Is(err, ErrAPIInvalid) {
		t.Fatalf("err = %v, want ErrAPIInvalid", err)
	}
	if Classify(err) != ClassAPIInvalid {
		t.Fatalf("class = %q", Classify(err))
	}
}

// Scenario 16: v2 transport-dead, v1 alive -> the second rung answers.
func TestLogicalsV1Fallback(t *testing.T) {
	st := newAPIStand(t, func(rc recordedCall) (int, string) {
		switch {
		case strings.HasPrefix(rc.Path, "/vpn/v2/logicals"):
			return http.StatusOK, `{"Code":1000,"LogicalServers":[]}`
		case strings.HasPrefix(rc.Path, "/vpn/logicals"):
			return http.StatusOK, `{"Code":1000,"LogicalServers":[{"Name":"US-FREE#9","Tier":0,"Status":1,"Servers":[{"EntryIP":"5.6.7.8","X25519PublicKey":"pk","Status":1}]}]}`
		default:
			return http.StatusOK, `{"Code":1000}`
		}
	})
	// Inject a transport that kills v2 by path but lets v1 through.
	c := st.client()
	c.HTTP.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasPrefix(r.URL.RequestURI(), "/vpn/v2/logicals") {
			return nil, errors.New("v2 transport dead")
		}
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(st.srv.URL, "http://")
		return http.DefaultTransport.RoundTrip(r)
	})
	sess := &Session{UID: "u", AccessToken: "a"}
	out, err := c.FetchLogicals(context.Background(), sess, "")
	if err != nil {
		t.Fatalf("FetchLogicals: %v", err)
	}
	if len(out.LogicalServers) != 1 || out.LogicalServers[0].Name != "US-FREE#9" {
		t.Fatalf("v1 fallback content: %+v", out)
	}
}

// ---- DoH ---------------------------------------------------------------------------

func TestMirrorNameGolden(t *testing.T) {
	// Golden against RFC 4648 base32 without padding (computed independently
	// in Python: base64.b32encode(host).rstrip('=')).
	cases := map[string]string{
		"vpn-api.proton.me": "dOZYG4LLBOBUS44DSN52G63RONVSQ.protonpro.xyz",
		"api.protonvpn.ch":  "dMFYGSLTQOJXXI33OOZYG4LTDNA.protonpro.xyz",
	}
	for host, want := range cases {
		if got := MirrorName(host); got != want {
			t.Fatalf("MirrorName(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestParseTXTAnswer(t *testing.T) {
	body := []byte(`{"Status":0,"Answer":[
		{"name":"dX.protonpro.xyz","data":"\"vpn.protonpro.xyz.\"","type":16},
		{"name":"dX.protonpro.xyz","data":"\"203.0.113.10\"","type":16}]}`)
	ans, err := parseTXTAnswer(body)
	if err != nil {
		t.Fatal(err)
	}
	got := sortCandidates(ans)
	if len(got) != 2 || got[0] != "vpn.protonpro.xyz" || got[1] != "203.0.113.10" {
		t.Fatalf("candidates = %+v (names must precede addresses)", got)
	}
}

// Scenario 13: direct hosts transport-dead, DoH mirrors resolve -> the
// mirror candidate serves the request; the mirror pin is TOFU-committed.
func TestMirrorRouteAndTOFUCommit(t *testing.T) {
	// The mirror is a TLS server (chain ignored, pin decides).
	mirror := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Code":1000,"UID":"u","AccessToken":"a","Scopes":["vpn"]}`))
	}))
	defer mirror.Close()

	// Fake DoH: TXT answer names the mirror host with the test listener port.
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(mirror.URL, "https://"))
	_ = host
	doh := newAPIStand(t, func(rc recordedCall) (int, string) {
		return http.StatusOK, fmt.Sprintf(`{"Status":0,"Answer":[{"data":"\"mirror.test:%s\"","type":16}]}`, port)
	})
	pins, err := NewPinStore("")
	if err != nil {
		t.Fatal(err)
	}
	committed := ""

	c := &Client{Pins: pins, OnPinCommit: func(h string) { committed = h }}
	c.HTTP = c.NewPinnedClient(nil)
	// The mirror candidate must dial the test listener: replace the pinned
	// client's dial through a custom transport that keeps the pin check.
	c.HTTP.Transport = &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := net.Dial(network, net.JoinHostPort("127.0.0.1", port))
			if err != nil {
				return nil, err
			}
			pinHost := addr[:strings.LastIndex(addr, ":")]
			tc := tls.Client(raw, &tls.Config{
				ServerName:         "mirror.test",
				InsecureSkipVerify: true,
				VerifyConnection:   pins.VerifyConnection(pinHost),
			})
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tc, nil
		},
	}
	// Direct hosts are transport-dead: reject everything aimed at the real
	// Proton names before the mirror rung gets its chance.
	directDead := c.HTTP.Transport
	c.HTTP.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Host, "proton.me") || strings.HasSuffix(r.URL.Host, "protonvpn.ch") {
			return nil, errors.New("transport dead (blocked network)")
		}
		return directDead.RoundTrip(r)
	})
	// DoH points at the fake resolver.
	c.DoH = &DoHResolver{HTTP: doh.srv.Client(), Resolvers: []string{doh.URL}}

	sess, err := c.CreateSession(context.Background())
	if err != nil {
		t.Fatalf("CreateSession via mirror: %v", err)
	}
	if sess.UID != "u" {
		t.Fatalf("session = %+v", sess)
	}
	if committed != "mirror.test" {
		t.Fatalf("TOFU commit missing for mirror.test (got %q)", committed)
	}
}

// Scenario 14: certificate substitution -> pin mismatch fail-closed.
func TestPinMismatchFailClosed(t *testing.T) {
	// Server A with cert A.
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"Code":1000}`))
	}))
	defer server.Close()

	// An unrelated cert B whose fingerprint is committed for the host.
	certB, err := selfSignedCert()
	if err != nil {
		t.Fatal(err)
	}
	pins, _ := NewPinStore("")
	pins.committed["vpn-api.proton.me"] = Fingerprint(certB)

	c := &Client{Pins: pins}
	c.HTTP = c.NewPinnedClient(nil)
	c.HTTP.Transport = &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, _ := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
			_ = host
			raw, err := net.Dial(network, net.JoinHostPort("127.0.0.1", port))
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{
				ServerName:         "vpn-api.proton.me",
				InsecureSkipVerify: true,
				VerifyConnection:   pins.VerifyConnection("vpn-api.proton.me"),
			})
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tc, nil
		},
	}
	_, err = c.CreateSession(context.Background())
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("err = %v, want ErrPinMismatch", err)
	}
	if Classify(err) != ClassAPIPinMismatch {
		t.Fatalf("class = %q", Classify(err))
	}
}

func selfSignedCert() (*x509.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "impostor.example.net"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// PinStore OnCommitHook is the test notification seam; production uses
// OnPinCommit on the Client.
func TestPinStoreCommitLifecycle(t *testing.T) {
	pins, _ := NewPinStore("")
	if pins.Commit("h1") {
		t.Fatal("commit without pending must be false")
	}
	// Seed pin match short-circuits (no pending, no commit).
	certA, _ := selfSignedCert()
	// A cert chain containing a seed pin can be simulated only with the real
	// pinned certs; here verify the TOFU pending path instead.
	pins.pending["h1"] = Fingerprint(certA)
	if !pins.Commit("h1") {
		t.Fatal("commit of pending failed")
	}
	if pins.Commit("h1") {
		t.Fatal("second commit must be false")
	}
	if err := pins.Verify("h1", []*x509.Certificate{certA}); err != nil {
		t.Fatalf("committed pin verify: %v", err)
	}
}
