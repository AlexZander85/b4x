package fxvpn

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// The fake FxA edge with a full Fastly anti-bot scenario:
//
//	login POST  -> 406 (empty body) until a valid challenge cookie rides
//	               the request; then the login JSON.
//	GET /       -> challenge page (must contain "/_fs-ch-" and "Client
//	               Challenge") while unsolved; normal page once solved.
//	script.js   -> init([...pow...], "tok1", prefix) with a solvable PoW.
//	post-back   -> validates the answer, sets the cookie on success.
type fxaChallengeStand struct {
	srv *httptest.Server

	mu          sync.Mutex
	solved      bool
	probeAlways bool // simulate exit-IP rotation: probe never accepts
	logins      int
	solves      int
}

const (
	chPrefix     = "/_fs-ch-x7"
	powBase      = "deadbeefcafe"
	powSuffix    = "aZ" // golden suffix; hash computed below
	fstCookieVal = "solved-cookie-value"
)

func newFxAChallengeStand(t *testing.T) *fxaChallengeStand {
	t.Helper()
	st := &fxaChallengeStand{}
	target := sha256.Sum256([]byte(powBase + powSuffix))
	targetHex := hexSum(target[:])

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/account/login", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		st.logins++
		if !st.solved {
			w.WriteHeader(http.StatusNotAcceptable) // empty body per contract
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"sessionToken":"sess-ok","uid":"uid-7","verified":true}`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		st.mu.Lock()
		defer st.mu.Unlock()
		if st.probeAlways || !st.solved {
			_, _ = io.WriteString(w, `<html>`+chPrefix+` Client Challenge</html>`)
			return
		}
		_, _ = io.WriteString(w, `<html>ordinary site</html>`)
	})

	mux.HandleFunc(chPrefix+"/script.js", func(w http.ResponseWriter, r *http.Request) {
		script := `var cfg = init([{"ty":"pow","data":{"base":"` + powBase + `","expires":"soon","hmac":"hm","hash":"` + targetHex + `"}}],"tok1","` + chPrefix + `");`
		_, _ = io.WriteString(w, script)
	})

	mux.HandleFunc(chPrefix+"/fst-post-back", func(w http.ResponseWriter, r *http.Request) {
		var pb fastlyPostBack
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &pb); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		ok := false
		answer := ""
		for _, d := range pb.Data {
			m, _ := d.(map[string]interface{})
			if m["ty"] == "pow" {
				answer, _ = m["answer"].(string)
				ok = answer == powSuffix
			}
		}
		st.mu.Lock()
		st.solves++
		st.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"status":"failed"}`)
			return
		}
		st.mu.Lock()
		st.solved = true
		st.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "fst", Value: fstCookieVal, Path: "/"})
		_, _ = io.WriteString(w, `{"status":"success","ch":[],"tok":""}`)
	})

	st.srv = httptest.NewServer(mux)
	t.Cleanup(st.srv.Close)
	return st
}

func TestFastlyChallengeFullFlowUnlocksLogin(t *testing.T) {
	st := newFxAChallengeStand(t)

	cp := newTestCP(t, "")
	cp.EP.FxAAPI = st.srv.URL + "/v1"
	cp.EP.FxASite = st.srv.URL
	fxa := &FXA{CP: cp}

	resp, err := fxa.Login(context.Background(), "user@example.com", "pw")
	if err != nil {
		t.Fatalf("login through challenge: %v", err)
	}
	if resp.SessionToken != "sess-ok" {
		t.Fatalf("unexpected session %q", resp.SessionToken)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.solves == 0 {
		t.Fatal("solver never ran")
	}
	if st.logins < 2 {
		t.Fatalf("logins = %d, want >=2 (406 then success)", st.logins)
	}
	// Earned cookie must live in the SHARED control-plane jar.
	if len(cp.Jar().Cookies(mustParseURL(st.srv.URL))) == 0 {
		t.Fatal("challenge cookies not installed into control-plane jar")
	}
}

func TestFastlyChallengeNotAcceptedSurfacesErrChallenge(t *testing.T) {
	st := newFxAChallengeStand(t)
	st.mu.Lock()
	st.probeAlways = true // exit IP rotated: probe keeps challenging
	st.mu.Unlock()

	cp := newTestCP(t, "")
	cp.EP.FxAAPI = st.srv.URL + "/v1"
	cp.EP.FxASite = st.srv.URL
	fxa := &FXA{CP: cp}

	_, err := fxa.Login(context.Background(), "user@example.com", "pw")
	if !errors.Is(err, ErrChallenge) {
		t.Fatalf("want ErrChallenge, got %v", err)
	}
	if Classify(err) != ClassChallengeFailed {
		t.Fatalf("class = %q", Classify(err))
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.solves == 0 {
		t.Fatal("solver did not attempt post-back")
	}
	if st.logins > maxChallengeAttempts+1 {
		t.Fatalf("too many direct logins: %d", st.logins)
	}
}

func TestSolveFastlyChallengeNoChallengePageAnywhere(t *testing.T) {
	// Both bases serve ordinary content: solver must report
	// errNoChallengePage-derived failure, not hang or panic.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/account/login", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "<html>hello</html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cp := newTestCP(t, "")
	cp.EP.FxAAPI = srv.URL + "/v1"
	cp.EP.FxASite = srv.URL

	err := cp.SolveFastlyChallenge(context.Background())
	if err == nil || !strings.Contains(err.Error(), "challenge page") {
		t.Fatalf("want no-challenge-page error, got %v", err)
	}
}

func TestInstallChallengeCookiesRejectsEmptyAndNilJar(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	jar := mustJar(t)
	if err := installChallengeCookies(jar, srv.URL+"/", nil, srv.URL+"/", srv.URL+"/"); err == nil {
		t.Fatal("nil target jar must error")
	}
	empty := mustJar(t)
	if err := installChallengeCookies(empty, srv.URL+"/", jar, srv.URL+"/", srv.URL+"/"); err == nil {
		t.Fatal("solver jar without cookies must error")
	}
}

// ---- small helpers ------------------------------------------------------------

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func mustJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("jar: %v", err)
	}
	return jar
}
