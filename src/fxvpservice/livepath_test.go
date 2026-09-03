// livepath_test.go: supervisor live-path tests (review F3). A fake FxA
// stand, a fake Guardian stand (both plain httptest over the exported
// ControlPlane endpoint seams) and a fake TunnelOpener session let the tick
// be exercised END TO END without any wire contact: bootstrap two accounts,
// run a live session, drop the active account's quota below the rotation
// threshold, tick, and verify the pre-emptive rotation applies as a SOFT
// swap — new bearer in place, session never torn down, streams untouched.
package fxvpservice

import (
        "context"
        "encoding/base64"
        "encoding/json"
        "fmt"
        "net"
        "net/http"
        "net/http/httptest"
        "os"
        "strings"
        "sync"
        "testing"
        "time"

        "github.com/daniellavrushin/b4/config"
        "github.com/daniellavrushin/b4/observability"
        fxvpn "github.com/daniellavrushin/b4/transport/fxvpn"
)

// ---- fake stands ---------------------------------------------------------------

type fxaStand struct {
        srv      *httptest.Server
        mu       sync.Mutex
        refreshN int
}

func newFxAStand() *fxaStand {
        f := &fxaStand{}
        mux := http.NewServeMux()
        mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
                f.mu.Lock()
                f.refreshN++
                f.mu.Unlock()
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusOK)
                _ = json.NewEncoder(w).Encode(fxvpn.TokenResponse{
                        AccessToken:  fmt.Sprintf("at-%d", time.Now().UnixNano()),
                        RefreshToken: "rt-rotated",
                        ExpiresIn:    3600,
                        Scope:        "profile",
                        TokenType:    "Bearer",
                })
        })
        f.srv = httptest.NewServer(mux)
        return f
}

type guardianStand struct {
        srv       *httptest.Server
        mu        sync.Mutex
        quotaLeft string
        quotaMax  string
}

func newGuardianStand() *guardianStand {
        g := &guardianStand{quotaLeft: "500", quotaMax: "1000"}
        mux := http.NewServeMux()
        mux.HandleFunc("/api/v1/fpn/token", func(w http.ResponseWriter, r *http.Request) {
                g.mu.Lock()
                left, max := g.quotaLeft, g.quotaMax
                g.mu.Unlock()
                if left != "" {
                        w.Header().Set("X-Quota-Remaining", left)
                }
                if max != "" {
                        w.Header().Set("X-Quota-Limit", max)
                }
                w.WriteHeader(http.StatusOK)
                _ = json.NewEncoder(w).Encode(map[string]string{"token": testJWT()})
        })
        mux.HandleFunc("/api/v1/fpn/activate", func(w http.ResponseWriter, r *http.Request) {
                w.WriteHeader(http.StatusOK)
                _, _ = w.Write([]byte(`{"subscribed":true,"uid":1}`))
        })
        g.srv = httptest.NewServer(mux)
        return g
}

func (g *guardianStand) setQuota(left, max string) {
        g.mu.Lock()
        defer g.mu.Unlock()
        g.quotaLeft, g.quotaMax = left, max
}

// testJWT mints an unsigned 3-part JWT (ParseJWTClaims reads the payload
// only — the pin layer owns authenticity).
func testJWT() string {
        payload := fmt.Sprintf(`{"sub":"test-sub","aud":"fpn","iss":"guardian","iat":%d,"nbf":%d,"exp":%d}`,
                time.Now().Unix(), time.Now().Unix()-1, time.Now().Unix()+3600)
        return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"
}

// fakeSession is the injectable live session (fxvpn.TunnelOpener).
type fakeSession struct {
        mu     sync.Mutex
        alive  bool
        tokens []string
        closed int
}

func newFakeSession() *fakeSession { return &fakeSession{alive: true} }

func (s *fakeSession) OpenTunnel(ctx context.Context, authority string) (net.Conn, error) {
        return nil, fmt.Errorf("not used in this test")
}

func (s *fakeSession) IsAlive() bool {
        s.mu.Lock()
        defer s.mu.Unlock()
        return s.alive
}

func (s *fakeSession) UpdateToken(token string) error {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.tokens = append(s.tokens, token)
        return nil
}

func (s *fakeSession) Close() error {
        s.mu.Lock()
        defer s.mu.Unlock()
        s.closed++
        s.alive = false
        return nil
}

func (s *fakeSession) lastToken() string {
        s.mu.Lock()
        defer s.mu.Unlock()
        if len(s.tokens) == 0 {
                return ""
        }
        return s.tokens[len(s.tokens)-1]
}

// ---- runtime fixture -------------------------------------------------------------

type liveFixture struct {
        rt       *Runtime
        fxa      *fxaStand
        guardian *guardianStand
}

func newLiveFixture(t *testing.T, rotatePct int) *liveFixture {
        t.Helper()
        // The observability registry is a process-wide singleton: reset around
        // the fixture so the metric exports here do not leak into other tests.
        observability.Default().Metrics.Reset()
        t.Cleanup(func() { observability.Default().Metrics.Reset() })
        fx := &liveFixture{fxa: newFxAStand(), guardian: newGuardianStand()}
        t.Cleanup(fx.fxa.srv.Close)
        t.Cleanup(fx.guardian.srv.Close)

        storePath := t.TempDir() + "/accounts.json"
        accs := fxvpn.AccountsFile{Version: 1, Accounts: []fxvpn.Account{
                {Email: "a@example.com", Label: "a", RefreshToken: "rt-a"},
                {Email: "b@example.com", Label: "b", RefreshToken: "rt-b"},
        }}
        blob, err := json.Marshal(accs)
        if err != nil {
                t.Fatalf("marshal accounts: %v", err)
        }
        if err := os.WriteFile(storePath, blob, 0600); err != nil {
                t.Fatalf("seed store: %v", err)
        }

        cfg := &config.Config{}
        cfg.System.FxVPN = config.FxVPNConfig{
                Enabled:            true,
                AccountsPath:       storePath,
                RotateThresholdPct: rotatePct,
        }
        rt, err := Build(cfg, Options{Now: time.Now})
        if err != nil {
                t.Fatalf("Build: %v", err)
        }
        // Redirect the shared control plane onto the fake stands (exported
        // endpoint seams; http:// URLs ride DialContext, no TLS).
        rt.cp.EP.FxAAPI = fx.fxa.srv.URL
        rt.cp.EP.Guardian = fx.guardian.srv.URL
        if err := rt.pool.Bootstrap(context.Background()); err != nil {
                t.Fatalf("bootstrap: %v", err)
        }
        fx.rt = rt
        return fx
}

// ---- scenarios -------------------------------------------------------------------

// TestTickRotatesLiveSessionSoftly pins review F3: with the session ALIVE,
// a quota drop below the rotation threshold must still trigger the pool
// rotation inside tick, apply the new bearer IN PLACE (no "Bearer " scheme
// duplication — ActiveBearer returns the raw token), and never close the
// serving session (open streams survive; the object rebuilds later).
func TestTickRotatesLiveSessionSoftly(t *testing.T) {
        fx := newLiveFixture(t, 15)
        ctx := context.Background()

        // Live serving session on account "a".
        sess := newFakeSession()
        fx.rt.session = sess
        fx.rt.sessionHost = "atn1.m1.fastly-masque.net:2499"

        // Drop the ACTIVE account below the threshold: 10% < 15%.
        fx.guardian.setQuota("100", "1000")
        fx.rt.tick(ctx)

        if sess.closed != 0 {
                t.Fatalf("soft swap must not close the live session (closes=%d)", sess.closed)
        }
        if !sess.IsAlive() {
                t.Fatal("live session must stay alive across a pre-emptive rotation")
        }
        tok := sess.lastToken()
        if tok == "" {
                t.Fatal("bearer not rotated in place")
        }
        if strings.HasPrefix(tok, "Bearer ") {
                t.Fatalf("ActiveBearer must return the RAW token (carriers add the scheme): %q", tok)
        }
        st := fx.rt.Status()
        if st.Pool.Views[1].Label != "b" || !st.Pool.Views[1].Active {
                t.Fatalf("pool must have rotated to account b: %+v", st.Pool.Views)
        }
        var rotated bool
        for _, ev := range st.Events {
                if ev.Type == "fxvpn_session_bearer_rotated" {
                        rotated = true
                }
        }
        if !rotated {
                t.Fatal("fxvpn_session_bearer_rotated event missing")
        }
}

// TestDialStreamCarriesRawBearer pins the double-prefix regression found
// during F3: the CONNECT relay must stamp exactly one "Bearer " scheme, so
// ActiveBearer hands out the RAW token only.
func TestDialStreamCarriesRawBearer(t *testing.T) {
        fx := newLiveFixture(t, 15)
        bearer, ok := fx.rt.pool.ActiveBearer()
        if !ok {
                t.Fatal("no active bearer after bootstrap")
        }
        if strings.HasPrefix(bearer, "Bearer ") {
                t.Fatalf("ActiveBearer leaked the scheme: %q", bearer)
        }
}
