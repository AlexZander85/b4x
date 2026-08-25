package fxvpn

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// poolGuardian is a MUTABLE Guardian stand: tests flip quota headers,
// statuses and reset stamps between pool operations.
type poolGuardian struct {
	srv *httptest.Server

	mu           sync.Mutex
	tokenStatus  int
	quotaLeft    string
	quotaMax     string
	quotaReset   string
	retryAfter   string
	tokenCount   int
	activateUsed int
}

func newPoolGuardian(t *testing.T) *poolGuardian {
	t.Helper()
	g := &poolGuardian{tokenStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/fpn/token", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		st, left, max, reset, ra := g.tokenStatus, g.quotaLeft, g.quotaMax, g.quotaReset, g.retryAfter
		g.tokenCount++
		g.mu.Unlock()

		if st == http.StatusTooManyRequests {
			if ra != "" {
				w.Header().Set(retryAfterHeader, ra)
			}
			w.WriteHeader(st)
			return
		}
		if left != "" {
			w.Header().Set(quotaHeaderLeft, left)
		}
		if max != "" {
			w.Header().Set(quotaHeaderMax, max)
		}
		if reset != "" {
			w.Header().Set(quotaHeaderReset, reset)
		}
		w.WriteHeader(st)
		_, _ = io.WriteString(w, `{"token":"`+makeJWT(t, ProxyPassClaims{
			Sub: "pool-sub", Aud: "fpn",
			Iat: timeNowUnix(), Nbf: timeNowUnix() - 1, Exp: timeNowUnix() + 3600, Iss: "guardian",
		})+`"}`)
	})
	mux.HandleFunc("/api/v1/fpn/activate", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.activateUsed++
		g.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"subscribed":true,"uid":1}`)
	})

	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *poolGuardian) setQuota(left, max, reset string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.quotaLeft, g.quotaMax, g.quotaReset = left, max, reset
}

func (g *poolGuardian) setTokenFailure(status int, retryAfter string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tokenStatus = status
	g.retryAfter = retryAfter
}

func (g *poolGuardian) counts() (tokens, activates int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.tokenCount, g.activateUsed
}

// refreshAlwaysFailFxA is an FxA stand whose /oauth/token rejects every
// refresh with errno 105 (invalid token): drives the ban ladder.
func refreshAlwaysFailFxA(t *testing.T) *FXA {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"errno":105,"message":"Invalid authentication token in request"}`)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cp := newTestCP(t, "")
	cp.EP.FxAAPI = srv.URL + "/v1"
	return &FXA{CP: cp}
}

func timeNowUnix() int64 { return 1_800_000_000 }
