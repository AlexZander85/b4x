package operaservice

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	opera "github.com/daniellavrushin/b4/transport/opera"
)
type DialFuncAlias = func(ctx context.Context, network, addr string) (net.Conn, error)

// liteDigestVerify recomputes the RFC 7616 KD chain server-side (self-contained
// mirror of the engine's golden formulas — no cross-package test imports).
func liteDigestVerify(header, password, uri string) bool {
	vals := map[string]string{}
	for _, pair := range strings.Split(strings.TrimPrefix(header, "Digest "), ", ") {
		if i := strings.Index(pair, "="); i > 0 {
			k, v := pair[:i], pair[i+1:]
			v = strings.Trim(v, `"`)
			vals[k] = v
		}
	}
	md5hex := func(s string) string {
		sum := md5.Sum([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	ha1 := md5hex(opera.DefaultAPILogin + ":" + opera.DefaultAPILogin + ":" + password)
	ha2 := md5hex("POST:" + uri)
	want := md5hex(ha1 + ":" + vals["nonce"] + ":" + vals["nc"] + ":" + vals["cnonce"] + ":auth:" + ha2)
	return want == vals["response"]
}

// Minimal fake SurfEasy API for THIS package (the engine package has its own
// richer stand; test fixtures are intentionally not shared across packages).

const (
	liteNonce   = "l1teN0nce0001"
	liteOpaque  = "l1te0p4qu3"
	liteDevice  = "LITEDEV1"
	liteJWT     = "eyJhbGciOiJub25lIn0.bGl0ZQ.sig"
	liteGeoJSON = `{"ips":[{"geo":{"country_code":"NL"},"ip":"77.111.244.3","ports":[443]},
	 {"geo":{"country_code":"DE"},"host":"host1.sec-tunnel.com","ip":"77.111.244.9","ports":[8443]}]}`
)

type seReqLite struct {
	Path string
	Form url.Values
}

type seStandLite struct {
	srv  *httptest.Server
	mu   sync.Mutex
	reqs []seReqLite
}

func newSEStandLite(t *testing.T) *seStandLite {
	s := &seStandLite{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form := url.Values{}
		for k, vs := range r.Form {
			form[k] = append([]string(nil), vs...)
		}
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Digest realm=%q, nonce=%q, qop="auth", algorithm=MD5, opaque=%q`,
					opera.DefaultAPILogin, liteNonce, liteOpaque))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if !liteDigestVerify(auth, opera.DefaultAPIPassword, r.URL.RequestURI()) {
			w.WriteHeader(http.StatusForbidden)
			return
		}

		s.mu.Lock()
		s.reqs = append(s.reqs, seReqLite{Path: r.URL.Path, Form: form})
		s.mu.Unlock()

		data, code := "null", "0"
		switch r.URL.Path {
		case "/v4/register_device":
			data = fmt.Sprintf(`{"client_type":"se0316","device_id":%q,"device_password":%q}`, liteDevice, liteJWT)
		case "/v4/device_generate_password":
			data = fmt.Sprintf(`{"device_password":%q}`, liteJWT)
		case "/v4/geo_list":
			data = `{"geos":[{"country_code":"EU"},{"country_code":"AS"},{"country_code":"AM"}]}`
		case "/v4/discover":
			data = liteGeoJSON
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"data":%s,"return_code":{"%s":"OK"}}`, data, code)
	})
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *seStandLite) snapshot() []seReqLite {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seReqLite(nil), s.reqs...)
}

// ---------------------------------------------------------------------------
// Engine-side test hooks (same package as production code would be cleaner,
// but engine tests own them; here we use exported test-only shims).
// ---------------------------------------------------------------------------

func newEngineClient(t *testing.T, apiBase, slotPath string) *opera.Client {
	t.Helper()
	c, err := opera.New(opera.Options{
		Endpoints:   liteEndpoints(apiBase),
		Slot:        &opera.IdentityStore{Path: slotPath},
		DialContext: localhostOnlyDial(),
	})
	if err != nil {
		t.Fatalf("engine client: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// localhostOnlyDial permits loopback egress (the fake API) and fails FAST on
// every other address — unit tests must never touch the real SurfEasy nodes.
func localhostOnlyDial() func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("egress blocked by test: %s", addr)
		}
		d := &net.Dialer{Timeout: 3 * time.Second}
		return d.DialContext(ctx, network, addr)
	}
}

func liteEndpoints(base string) opera.SEEndpoints {
	return opera.SEEndpoints{
		RegisterSubscriber:     base + "/v4/register_subscriber",
		SubscriberLogin:        base + "/v4/subscriber_login",
		RegisterDevice:         base + "/v4/register_device",
		DeviceGeneratePassword: base + "/v4/device_generate_password",
		GeoList:                base + "/v4/geo_list",
		Discover:               base + "/v4/discover",
	}
}

func countPath(stand *seStandLite, path string) int {
	n := 0
	for _, r := range stand.snapshot() {
		if r.Path == path {
			n++
		}
	}
	return n
}

func countGeoRequestsLite(stand *seStandLite, region string) int {
	want := fmt.Sprintf("%q,,", region)
	n := 0
	for _, r := range stand.snapshot() {
		if r.Path == "/v4/discover" && r.Form.Get("requested_geo") == want {
			n++
		}
	}
	return n
}
