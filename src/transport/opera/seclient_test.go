package opera

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Fake SurfEase API stand (design §6 OP1 verification vehicle).
// ---------------------------------------------------------------------------

const (
	standNonce  = "st4ndN0nce0001"
	standOpaque = "st4nd0p4qu3"
	deviceIDFix = "DEV0001"
	jwtInitial  = "eyJhbGciOiJub25lIn0.aW5pdGlhbA.sig"
	jwtRotated  = "eyJhbGciOiJub25lIn0.cm90YXRlZA.sig2"

	discoverIPsFixture = `[
	 {"geo":{"country":"Netherlands","country_code":"NL"},"ip":"77.111.244.3","ports":[443]},
	 {"geo":{"country_code":"DE"},"host":"host1.sec-tunnel.com","ip":"77.111.244.9","ports":[8443]}]`

	geosFixture = `[
	 {"country":"Europe","country_code":"EU"},
	 {"country":"Asia","country_code":"AS"},
	 {"country":"Americas","country_code":"AM"}]`
)

type seReq struct {
	Path       string
	Form       url.Values
	HasAuth    bool
	AuthOK     bool
	Challenged bool
}

type seStand struct {
	srv *httptest.Server

	mu                sync.Mutex
	reqs              []seReq
	genCalls          int
	refuse            bool
	throttle          bool
	malformed         bool
	regionUnavailable bool
}

func newSEStand(t *testing.T) *seStand {
	s := &seStand{}
	s.srv = httptest.NewServer(s.handler())
	t.Cleanup(s.srv.Close)
	return s
}

func (s *seStand) handler() http.Handler {
	return http.HandlerFunc(s.handle)
}

func (s *seStand) endpointsBase(base string) SEEndpoints {
	return SEEndpoints{
		RegisterSubscriber:     base + "/v4/register_subscriber",
		SubscriberLogin:        base + "/v4/subscriber_login",
		RegisterDevice:         base + "/v4/register_device",
		DeviceGeneratePassword: base + "/v4/device_generate_password",
		GeoList:                base + "/v4/geo_list",
		Discover:               base + "/v4/discover",
	}
}

func (s *seStand) endpoints() SEEndpoints { return s.endpointsBase(s.srv.URL) }

func (s *seStand) setKnobs(refuse, throttle, malformed, region801 bool) {
	s.mu.Lock()
	s.refuse, s.throttle, s.malformed, s.regionUnavailable = refuse, throttle, malformed, region801
	s.mu.Unlock()
}

func (s *seStand) snapshot() []seReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]seReq(nil), s.reqs...)
}

func (s *seStand) generateCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.genCalls
}

func (s *seStand) handle(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	form := url.Values{}
	for k, vs := range r.Form {
		form[k] = append([]string(nil), vs...)
	}
	auth := r.Header.Get("Authorization")
	hasAuth := auth != ""
	authOK := hasAuth && verifyDigestRequest(r, auth,
		DefaultAPILogin, DefaultAPIPassword, goldRealm, standNonce, standOpaque)

	s.mu.Lock()
	refuse, throttle := s.refuse, s.throttle
	s.reqs = append(s.reqs, seReq{
		Path: r.URL.Path, Form: form,
		HasAuth: hasAuth, AuthOK: authOK,
		Challenged: !hasAuth || refuse || !authOK,
	})
	malformed, region801 := s.malformed, s.regionUnavailable
	s.mu.Unlock()

	if throttle {
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	if !hasAuth || refuse || !authOK {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Digest realm=%q, nonce=%q, qop="auth", algorithm=MD5, opaque=%q`,
				goldRealm, standNonce, standOpaque))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	data := "null"
	code, msg := "0", "OK"
	switch r.URL.Path {
	case "/v4/register_subscriber":
	case "/v4/subscriber_login":
	case "/v4/register_device":
		data = fmt.Sprintf(`{"client_type":"se0316","device_id":%q,"device_password":%q}`,
			deviceIDFix, jwtInitial)
	case "/v4/device_generate_password":
		s.mu.Lock()
		s.genCalls++
		s.mu.Unlock()
		data = fmt.Sprintf(`{"device_password":%q}`, jwtRotated)
	case "/v4/geo_list":
		data = fmt.Sprintf(`{"geos":%s}`, geosFixture)
	case "/v4/discover":
		if region801 {
			code, msg = "801", "no nodes for region"
			break
		}
		data = fmt.Sprintf(`{"ips":%s}`, discoverIPsFixture)
	default:
		http.NotFound(w, r)
		return
	}
	if malformed {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":null,"return_code":{"0":"OK","1":"duplicate"}}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"data":%s,"return_code":{"%s":%q}}`, data, code, msg)
}

// verifyDigestRequest recomputes the KD chain from the stand's own challenge
// parameters — the same discipline a real Digest server applies.
func verifyDigestRequest(r *http.Request, header, user, pass, realm, nonce, opaque string) bool {
	vals := parseAuthPairs(strings.TrimPrefix(header, "Digest "))
	resp := digestResponse(
		digestHA1(user, realm, pass),
		vals["nonce"], vals["nc"], vals["cnonce"], vals["qop"],
		digestHA2(r.Method, r.URL.RequestURI()))
	return resp == vals["response"] &&
		vals["username"] == user &&
		vals["realm"] == realm &&
		vals["opaque"] == opaque &&
		len(vals["nc"]) == 8
}

// ---------------------------------------------------------------------------
// Scenario helpers.
// ---------------------------------------------------------------------------

func slotPath(t *testing.T) string {
	return filepath.Join(t.TempDir(), "opera", "identity.json")
}

func newTestClient(t *testing.T, eps SEEndpoints, slot *IdentityStore, deviceName string) *Client {
	t.Helper()
	c, err := New(Options{
		Endpoints: eps,
		Slot:      slot,
		Settings:  SESettings{DeviceName: deviceName},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(c.Close)
	return c
}

// ---------------------------------------------------------------------------
// Scenarios.
// ---------------------------------------------------------------------------

func TestRegisterDiscoverHappyFlow(t *testing.T) {
	ctx := context.Background()
	stand := newSEStand(t)
	slot := &IdentityStore{Path: slotPath(t)}
	c := newTestClient(t, stand.endpoints(), slot, "client-A")

	if err := c.EnsureSession(ctx); err != nil {
		t.Fatalf("EnsureSession: %v", err)
	}

	// Registration wire shape (reference parity). Each Digest attempt is a
	// separate HTTP request: register_subscriber appears twice (unauth
	// probe + authorized retry), register_device rides the cached session.
	reqs := stand.snapshot()
	if len(reqs) != 3 {
		t.Fatalf("requests = %d (%v), want [register_subscriber x2, register_device]", len(reqs), paths(reqs))
	}
	reg := reqs[0]
	if reg.Path != "/v4/register_subscriber" || reg.HasAuth || reg.AuthOK || !reg.Challenged {
		t.Fatalf("register_subscriber record %+v — want unauthenticated first hit", reg)
	}
	email := reg.Form.Get("email")
	pass := reg.Form.Get("password")
	if !strings.HasSuffix(email, "@"+DefaultSESettings.ClientType+".best.vpn") {
		t.Fatalf("email = %q, want localpart@se0316.best.vpn", email)
	}
	if pass != capitalHexSHA1(email) {
		t.Fatalf("subscriber password derivation mismatch")
	}
	regRetry := reqs[1]
	if regRetry.Path != "/v4/register_subscriber" || !regRetry.HasAuth || !regRetry.AuthOK || regRetry.Challenged {
		t.Fatalf("register_subscriber retry %+v — want authorized", regRetry)
	}
	dev := reqs[2]
	if dev.Path != "/v4/register_device" || !dev.HasAuth || !dev.AuthOK || dev.Challenged {
		t.Fatalf("register_device record %+v — want cached-digest authorized hit", dev)
	}
	if got := dev.Form.Get("device_hash"); got != c.deviceRaw || len(got) != 40 {
		t.Fatalf("device_hash = %q, want per-boot 40-hex %q", got, c.deviceRaw)
	}
	if dev.Form.Get("device_name") != "client-A" || dev.Form.Get("client_type") != "se0316" {
		t.Fatalf("register_device form = %v", dev.Form)
	}

	login, jwt := c.ProxyCredentials()
	if login != capitalHexSHA1(deviceIDFix) || jwt != jwtInitial {
		t.Fatalf("proxy credentials = %q/%q", login, jwt)
	}

	// Slot persisted, validates, hash derivable.
	id, err := slot.Load()
	if err != nil {
		t.Fatalf("slot load: %v", err)
	}
	if id.DeviceID != deviceIDFix || id.DeviceIDHash != login || id.DevicePassword != jwtInitial {
		t.Fatalf("stored identity mismatch: %+v", id.Redacted())
	}
	if id.UpdatedAt.Before(id.CreatedAt) {
		t.Fatal("updated_at before created_at")
	}

	// Cached auth rides subsequent RPCs without a new challenge.
	geos, err := c.GeoList(ctx)
	if err != nil {
		t.Fatalf("GeoList: %v", err)
	}
	if len(geos) != 3 || geos[0].CountryCode != "EU" || geos[2].CountryCode != "AM" {
		t.Fatalf("geos = %+v", geos)
	}
	last := stand.snapshot()[3]
	if last.Path != "/v4/geo_list" || last.Challenged || !last.AuthOK {
		t.Fatalf("geo_list record %+v — want direct authorized hit", last)
	}
	if got := last.Form.Get("device_id"); got != capitalHexSHA1(deviceIDFix) {
		t.Fatalf("geo_list serial = %q", got)
	}

	// Discover: region normalization + CVS artifact + entry semantics.
	ips, err := c.Discover(ctx, " eu ")
	if err != nil {
		t.Fatalf("Discover(eu): %v", err)
	}
	if got := stand.snapshot()[4].Form.Get("requested_geo"); got != `"EU",,` {
		t.Fatalf("requested_geo = %q, want %q", got, `"EU",,`)
	}
	if len(ips) != 2 {
		t.Fatalf("ips = %+v", ips)
	}
	if ips[0].NetAddr() != "77.111.244.3:443" {
		t.Fatalf("NetAddr fallback = %q", ips[0].NetAddr())
	}
	if ips[1].NetAddr() != "77.111.244.9:8443" {
		t.Fatalf("NetAddr ports[0] = %q", ips[1].NetAddr())
	}
	if ips[0].TLSServerName() != "nl0.sec-tunnel.com" {
		t.Fatalf("TLSServerName fallback = %q", ips[0].TLSServerName())
	}
	if ips[1].TLSServerName() != "host1.sec-tunnel.com" {
		t.Fatalf("TLSServerName explicit host = %q", ips[1].TLSServerName())
	}
}

func TestAPIThrottleClassified(t *testing.T) {
	stand := newSEStand(t)
	stand.setKnobs(false, true, false, false)
	c := newTestClient(t, stand.endpoints(), nil, "t")
	err := c.EnsureSession(context.Background())
	if !IsClass(err, ClassAPIThrottled) {
		t.Fatalf("err = %v, want ClassAPIThrottled", err)
	}
}

func TestAPIRefusedClassified(t *testing.T) {
	stand := newSEStand(t)
	stand.setKnobs(true, false, false, false)
	c := newTestClient(t, stand.endpoints(), nil, "r")
	err := c.EnsureSession(context.Background())
	if !IsClass(err, ClassAPIAuthRefused) {
		t.Fatalf("err = %v, want ClassAPIAuthRefused", err)
	}
}

func TestDiscoverRegionUnavailableClassified(t *testing.T) {
	ctx := context.Background()
	stand := newSEStand(t)
	stand.setKnobs(false, false, false, true)
	c := newTestClient(t, stand.endpoints(), nil, "u")
	if err := c.EnsureSession(ctx); err != nil {
		t.Fatalf("EnsureSession: %v", err)
	}
	_, err := c.Discover(ctx, "AS")
	if !IsClass(err, ClassDiscoverRegionUnavailable) {
		t.Fatalf("err = %v, want ClassDiscoverRegionUnavailable", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 801 {
		t.Fatalf("wrapped apiErr = %+v, want code 801", apiErr)
	}
}

func TestMalformedStatusRejected(t *testing.T) {
	stand := newSEStand(t)
	stand.setKnobs(false, false, true, false)
	c := newTestClient(t, stand.endpoints(), nil, "m")
	err := c.EnsureSession(context.Background())
	if err == nil || !strings.Contains(err.Error(), "ambiguous status") {
		t.Fatalf("err = %v, want ambiguous-status decode failure", err)
	}
}

func TestIdentityReusedAcrossClientsAndJWTRefreshed(t *testing.T) {
	ctx := context.Background()
	stand := newSEStand(t)
	slot := &IdentityStore{Path: slotPath(t)}

	a := newTestClient(t, stand.endpoints(), slot, "client-A")
	if err := a.EnsureSession(ctx); err != nil {
		t.Fatalf("A register: %v", err)
	}
	before := len(stand.snapshot())

	// Second process/boot over the same slot must NOT register again.
	b := newTestClient(t, stand.endpoints(), slot, "client-B")
	if err := b.EnsureSession(ctx); err != nil {
		t.Fatalf("B adopt: %v", err)
	}
	if got := len(stand.snapshot()) - before; got != 0 {
		t.Fatalf("adopt produced %d extra requests, want 0", got)
	}
	if _, jwt := b.ProxyCredentials(); jwt != jwtInitial {
		t.Fatalf("adopted jwt = %q", jwt)
	}

	// Refresh: subscriber_login + device_generate_password, authorized hits.
	if err := b.RefreshCredentials(ctx); err != nil {
		t.Fatalf("RefreshCredentials: %v", err)
	}
	reqs := stand.snapshot()
	n := len(reqs)
	if n < 2 || reqs[n-2].Path != "/v4/subscriber_login" || reqs[n-1].Path != "/v4/device_generate_password" {
		t.Fatalf("refresh tail = %v", paths(reqs[max(0, n-2):]))
	}
	for _, rec := range reqs[n-2:] {
		if !rec.HasAuth || !rec.AuthOK || rec.Challenged {
			t.Fatalf("refresh record %+v — want authorized", rec)
		}
	}
	if got := reqs[n-1].Form.Get("device_id"); got != deviceIDFix {
		t.Fatalf("generate_password device_id = %q, want RAW %q", got, deviceIDFix)
	}
	if _, jwt := b.ProxyCredentials(); jwt != jwtRotated {
		t.Fatalf("jwt after refresh = %q, want rotated", jwt)
	}
	id, err := slot.Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if id.DevicePassword != jwtRotated {
		t.Fatal("rotated jwt not persisted")
	}
	if stand.generateCalls() != 1 {
		t.Fatalf("generate_calls = %d, want 1", stand.generateCalls())
	}
}

func TestCorruptSlotQuarantinedAndRecovered(t *testing.T) {
	ctx := context.Background()
	stand := newSEStand(t)
	path := slotPath(t)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{\"format\":1,\"broken\""), 0o600); err != nil {
		t.Fatal(err)
	}
	c := newTestClient(t, stand.endpoints(), &IdentityStore{Path: path}, "recovery")
	if err := c.EnsureSession(ctx); err != nil {
		t.Fatalf("recovery registration: %v", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatalf("corrupt slot not quarantined: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("fresh identity not saved: %v", err)
	}
}

func TestNoSessionGuards(t *testing.T) {
	stand := newSEStand(t)
	c := newTestClient(t, stand.endpoints(), nil, "guard")
	ctx := context.Background()
	if _, err := c.GeoList(ctx); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("GeoList guard = %v", err)
	}
	if _, err := c.Snapshot(); err == nil {
		t.Fatal("Snapshot must fail without session")
	}
	if err := c.RefreshCredentials(ctx); !errors.Is(err, ErrIdentityInvalid) {
		t.Fatalf("Refresh guard = %v", err)
	}
}

func paths(reqs []seReq) []string {
	out := make([]string, len(reqs))
	for i, r := range reqs {
		out[i] = strings.TrimPrefix(r.Path, "/v4/")
	}
	return out
}
