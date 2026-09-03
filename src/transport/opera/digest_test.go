package opera

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// Golden vectors computed OUTSIDE Go (python hashlib) from the reference
// dac formulas (Alexey71/go-http-digest-auth-client v1.1.3 authorization.go,
// read and pinned during E-OPERA OP1): KD(HA1 : nonce : nc : cnonce : qop :
// HA2), md5 lower-hex. Inputs are fixed so the byte-exact Authorization
// header can be locked, including the reference field order.
const (
	goldUser    = "se0316"
	goldRealm   = "se0316"
	goldPass    = DefaultAPIPassword
	goldNonce   = "a1b2c3d4e5f60718"
	goldCnonce  = "cafebabe00c0ffee"
	goldOpaque  = "0p4qu3v4lu3"
	goldMethod  = "POST"
	goldURI     = "/v4/register_subscriber"
	goldHA1     = "e96895904a68f722d54e8bddf10121ac"
	goldHA2     = "09e892c923ba66f225ef007bf892566a"
	goldRespNC1 = "6ca4f9fac4898719531b3e809e22eacf"
	goldRespNC2 = "bf6126f921cc7f4d53b3aa13485a97c0"
)

func fixedCnonce(gold string) cnonceFunc {
	return func() (string, error) { return gold, nil }
}

func goldenSession(t *testing.T) *digestSession {
	t.Helper()
	s := newDigestSession(goldUser, goldPass)
	s.cnonceGen = fixedCnonce(goldCnonce)
	if err := s.reset(&digestChallenge{
		realm: goldRealm, nonce: goldNonce, opaque: goldOpaque,
		qop: "auth", algorithm: "MD5",
	}); err != nil {
		t.Fatalf("reset: %v", err)
	}
	return s
}

func TestDigestGoldenVector(t *testing.T) {
	s := goldenSession(t)

	hdr1, err := s.authorize(goldMethod, goldURI)
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	want1 := fmt.Sprintf(
		`Digest username=%q, realm=%q, nonce=%q, uri=%q, response=%q, algorithm=MD5, cnonce=%q, opaque=%q, qop=auth, nc=00000001`,
		goldUser, goldRealm, goldNonce, goldURI, goldRespNC1, goldCnonce, goldOpaque)
	if hdr1 != want1 {
		t.Fatalf("golden header nc=1:\n got %s\nwant %s", hdr1, want1)
	}

	hdr2, err := s.authorize(goldMethod, goldURI)
	if err != nil {
		t.Fatalf("authorize #2: %v", err)
	}
	want2 := fmt.Sprintf(
		`Digest username=%q, realm=%q, nonce=%q, uri=%q, response=%q, algorithm=MD5, cnonce=%q, opaque=%q, qop=auth, nc=00000002`,
		goldUser, goldRealm, goldNonce, goldURI, goldRespNC2, goldCnonce, goldOpaque)
	if hdr2 != want2 {
		t.Fatalf("golden header nc=2:\n got %s\nwant %s", hdr2, want2)
	}
}

func TestDigestHashPrimitivesMatchReference(t *testing.T) {
	// dac's own unit suite pins md5("example") — cross-check our primitive.
	if got := md5hex("example"); got != "1a79a4d60de6718e8e5b326e338ae533" {
		t.Fatalf("md5hex(example) = %s", got)
	}
	if got := digestHA1(goldUser, goldRealm, goldPass); got != goldHA1 {
		t.Fatalf("HA1 = %s, want %s", got, goldHA1)
	}
	if got := digestHA2(goldMethod, goldURI); got != goldHA2 {
		t.Fatalf("HA2 = %s, want %s", got, goldHA2)
	}
	if got := digestResponse(goldHA1, goldNonce, "00000001", goldCnonce, "auth", goldHA2); got != goldRespNC1 {
		t.Fatalf("response(nc=1) = %s, want %s", got, goldRespNC1)
	}
}

func TestParseDigestChallenge(t *testing.T) {
	ch, err := parseDigestChallenge(
		`Digest realm="se0316", nonce="abc123", qop="auth", algorithm=MD5, opaque="op", stale=false`)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ch.realm != "se0316" || ch.nonce != "abc123" || ch.qop != "auth" ||
		ch.algorithm != "MD5" || ch.opaque != "op" || ch.stale {
		t.Fatalf("parsed %+v", ch)
	}

	// Quoted-string escapes survive (gorilla-parser lineage).
	ch, err = parseDigestChallenge(`Digest realm="we\"ird", nonce="n"`)
	if err != nil {
		t.Fatalf("parse escaped: %v", err)
	}
	if ch.realm != `we"ird` {
		t.Fatalf("escaped realm = %q", ch.realm)
	}

	// Case-insensitive stale.
	ch, err = parseDigestChallenge(`Digest nonce="n", STALE=True`)
	if err != nil {
		t.Fatalf("parse stale: %v", err)
	}
	if !ch.stale {
		t.Fatal("stale=True not detected")
	}

	// Missing nonce is a hard parse error.
	if _, err := parseDigestChallenge(`Digest realm="r"`); err == nil {
		t.Fatal("expected error for missing nonce")
	}
	// Non-Digest scheme rejected (transport falls through untouched).
	if _, err := parseDigestChallenge(`Basic realm="r"`); err == nil {
		t.Fatal("expected error for Basic scheme")
	}
}

func TestNormalizeAlgorithmProfile(t *testing.T) {
	for _, ok := range []string{"", "MD5", "md5"} {
		alg, err := normalizeAlgorithm(ok)
		if err != nil || alg != "MD5" {
			t.Fatalf("normalize(%q) = %q, %v", ok, alg, err)
		}
	}
	for _, bad := range []string{"SHA-256", "MD5-sess", "unknown"} {
		_, err := normalizeAlgorithm(bad)
		if !IsClass(err, ClassAPIAlgorithm) {
			t.Fatalf("normalize(%q) err = %v, want ClassAPIAlgorithm", bad, err)
		}
	}
}

func TestResolveQopProfile(t *testing.T) {
	for _, offer := range []string{"auth", "auth, auth-int", " auth "} {
		qop, err := resolveQop(offer)
		if err != nil || qop != "auth" {
			t.Fatalf("resolveQop(%q) = %q, %v", offer, qop, err)
		}
	}
	if _, err := resolveQop("auth-int"); err == nil {
		t.Fatal("auth-int must be unsupported")
	}
	if _, err := resolveQop(""); err == nil {
		t.Fatal("empty qop must be rejected")
	}
}

// ---------------------------------------------------------------------------
// Transport flows against a real HTTP loop.
// ---------------------------------------------------------------------------

// digestStand verifies presented Authorization headers server-side by
// recomputing the KD chain from its own nonce.
type digestStand struct {
	t         *testing.T
	srv       *httptest.Server
	user      string
	pass      string
	realm     string
	nonce     string
	opaque    string
	staleOnce chan string // when non-empty: reject next authorized req with this new nonce + stale=true

	mu       sync.Mutex
	seen     []string // "plain" | "ok" | "bad"
	challeng int
}

func newDigestStand(t *testing.T) *digestStand {
	s := &digestStand{
		t:      t,
		user:   goldUser,
		pass:   goldPass,
		realm:  goldRealm,
		nonce:  goldNonce,
		opaque: goldOpaque,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v4/register_subscriber", s.handle)
	s.srv = httptest.NewServer(mux)
	t.Cleanup(s.srv.Close)
	return s
}

func (s *digestStand) handle(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	switch {
	case auth == "":
		s.record("plain")
		s.challenge(w, s.nonce, false)
	case s.verify(r, auth):
		s.mu.Lock()
		select {
		case nn := <-s.staleOnce:
			s.mu.Unlock()
			s.record("bad") // counts as rejected-with-stale
			s.challenge(w, nn, true)
			return
		default:
			s.mu.Unlock()
		}
		s.record("ok")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"data":null,"return_code":{"0":"OK"}}`))
	default:
		s.record("bad")
		http.Error(w, "bad digest", http.StatusForbidden)
	}
}

func (s *digestStand) challenge(w http.ResponseWriter, nonce string, stale bool) {
	s.mu.Lock()
	s.challeng++
	s.mu.Unlock()
	st := ""
	if stale {
		st = ", stale=true"
	}
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Digest realm=%q, nonce=%q, qop="auth", algorithm=MD5, opaque=%q%s`,
			s.realm, nonce, s.opaque, st))
	w.WriteHeader(http.StatusUnauthorized)
}

func (s *digestStand) verify(r *http.Request, header string) bool {
	vals := parseAuthPairs(strings.TrimPrefix(header, "Digest "))
	nc := vals["nc"]
	resp := digestResponse(
		digestHA1(s.user, s.realm, s.pass),
		vals["nonce"], nc, vals["cnonce"], vals["qop"],
		digestHA2(r.Method, r.URL.RequestURI()))
	return resp == vals["response"] &&
		vals["realm"] == s.realm &&
		vals["opaque"] == s.opaque &&
		vals["username"] == s.user &&
		len(nc) == 8
}

func (s *digestStand) record(kind string) {
	s.mu.Lock()
	s.seen = append(s.seen, kind)
	s.mu.Unlock()
}

func (s *digestStand) seenKinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

func doStandCall(ctx context.Context, url string, tr http.RoundTripper) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader("email=x@y"))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return tr.RoundTrip(req)
}

func TestDigestTransportHappyChallenge(t *testing.T) {
	stand := newDigestStand(t)
	tr := newDigestTransport(DefaultAPILogin, DefaultAPIPassword, nil)

	resp, err := doStandCall(context.Background(), stand.srv.URL+"/v4/register_subscriber", tr)
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	kinds := stand.seenKinds()
	if len(kinds) != 2 || kinds[0] != "plain" || kinds[1] != "ok" {
		t.Fatalf("flow = %v, want [plain ok]", kinds)
	}
}

func TestDigestTransportStaleTransparentRechallenge(t *testing.T) {
	stand := newDigestStand(t)
	tr := newDigestTransport(DefaultAPILogin, DefaultAPIPassword, nil)

	ctx := context.Background()
	url := stand.srv.URL + "/v4/register_subscriber"
	// Warm the session (plain -> challenge -> ok).
	if resp, err := doStandCall(ctx, url, tr); err != nil || resp.StatusCode != 200 {
		t.Fatalf("warmup: %v status=%v", err, resp)
	}
	// Arm AFTER warmup: next authorized request gets ONE stale=true
	// rejection carrying a fresh nonce; the transport must recover inside
	// the same RoundTrip.
	newNonce := "fresh-nonce-42"
	stand.staleOnce = make(chan string, 1)
	stand.staleOnce <- newNonce

	resp, err := doStandCall(ctx, url, tr)
	if err != nil {
		t.Fatalf("stale flow: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stale recovery status = %d, want 200", resp.StatusCode)
	}
	kinds := stand.seenKinds()
	// warmup(2) + ok(rejected stale) + retry-ok
	if len(kinds) != 4 || kinds[2] != "bad" || kinds[3] != "ok" {
		t.Fatalf("flow = %v, want [..., bad, ok]", kinds)
	}
}

func TestDigestTransportRefusalPassesThrough(t *testing.T) {
	// Server that always answers 401 with stale=false regardless of auth.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Digest realm=%q, nonce=%q, qop="auth", algorithm=MD5`, goldRealm, goldNonce))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	tr := newDigestTransport(DefaultAPILogin, DefaultAPIPassword, nil)
	ctx := context.Background()
	url := srv.URL + "/v4/register_subscriber"

	// Attempt 1: challenge adopted. Attempt 2: presented -> still 401
	// stale=false => transport hands the raw 401 back (rpc classifies).
	resp, err := doStandCall(ctx, url, tr)
	if err != nil {
		t.Fatalf("refusal round trip: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 passthrough", resp.StatusCode)
	}
}

func TestDigestTransportUnknownAlgorithmFailsStructured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Digest realm=%q, nonce=%q, qop="auth", algorithm=SHA-256`, goldRealm, goldNonce))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	tr := newDigestTransport(DefaultAPILogin, DefaultAPIPassword, nil)
	_, err := doStandCall(context.Background(), srv.URL+"/v4/x", tr)
	if !IsClass(err, ClassAPIAlgorithm) {
		t.Fatalf("err = %v, want ClassAPIAlgorithm", err)
	}
}
