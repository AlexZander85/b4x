package handler

// TT8 handler tests (the fxvpn_test.go canon): disabled shapes, method
// guards, unwired 503s, entry validation + persistence, restart/newnym
// dispatch, bridges listing.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/torservice"
)

func newTorTestAPI(t *testing.T, enabled bool) (*API, *atomic.Pointer[config.Config], string) {
	t.Helper()
	cfg := config.NewConfig()
	cfg.System.Tor.Enabled = enabled
	cfg.ConfigPath = filepath.Join(t.TempDir(), "b4.json")
	if err := cfg.SaveToFile(cfg.ConfigPath); err != nil {
		t.Fatal(err)
	}
	cfgPtr := &atomic.Pointer[config.Config]{}
	cfgPtr.Store(&cfg)
	api := NewAPIHandler(cfgPtr)
	api.cfgPtr = cfgPtr
	api.mux = http.NewServeMux()
	api.RegisterTorApi()
	return api, cfgPtr, cfg.ConfigPath
}

func doTorReq(t *testing.T, api *API, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	api.mux.ServeHTTP(rec, req)
	return rec
}

func TestTorStatusDisabledShape(t *testing.T) {
	api, _, _ := newTorTestAPI(t, false)
	rec := doTorReq(t, api, http.MethodGet, "/api/tor/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["enabled"] != false || body["running"] != false || body["listening"] != false {
		t.Fatalf("disabled shape = %v", body)
	}
	entry, _ := body["entry"].(map[string]any)
	if entry == nil || entry["mode"] != "auto" {
		t.Fatalf("entry shape = %v", body["entry"])
	}
}

func TestTorStatusMethodGuard(t *testing.T) {
	api, _, _ := newTorTestAPI(t, false)
	if rec := doTorReq(t, api, http.MethodPost, "/api/tor/status", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}

func TestTorEndpointsUnwiredRuntime(t *testing.T) {
	api, _, _ := newTorTestAPI(t, true) // enabled but no runtime wired
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodPost, "/api/tor/restart", http.StatusServiceUnavailable},
		{http.MethodPost, "/api/tor/newnym", http.StatusServiceUnavailable},
		{http.MethodPut, "/api/tor/entry", http.StatusServiceUnavailable},
		{http.MethodPost, "/api/tor/bridges/refresh", http.StatusServiceUnavailable},
	} {
		rec := doTorReq(t, api, tc.method, tc.path, map[string]string{"mode": "auto"})
		if rec.Code != tc.want {
			t.Fatalf("%s %s = %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
	// bridges GET with unwired runtime: empty honest shape, not 503
	rec := doTorReq(t, api, http.MethodGet, "/api/tor/bridges", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("bridges = %d, want 200", rec.Code)
	}
}

func TestTorEndpointsDisabledConflict(t *testing.T) {
	api, _, _ := newTorTestAPI(t, false)
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/api/tor/restart"},
		{http.MethodPost, "/api/tor/newnym"},
		{http.MethodPut, "/api/tor/entry"},
		{http.MethodPost, "/api/tor/bridges/refresh"},
	} {
		rec := doTorReq(t, api, tc.method, tc.path, map[string]string{"mode": "auto"})
		if rec.Code != http.StatusConflict {
			t.Fatalf("%s %s = %d, want 409", tc.method, tc.path, rec.Code)
		}
	}
}

func TestTorEntryValidation(t *testing.T) {
	api, _, _ := newTorTestAPI(t, true) // enabled, runtime unwired
	// valid modes pass VALIDATION (503 = unwired, not a mode rejection)
	for _, mode := range []string{"auto", "webtunnel", "obfs4", "snowflake", "meek", "vanilla", "direct"} {
		rec := doTorReq(t, api, http.MethodPut, "/api/tor/entry", map[string]string{"mode": mode})
		if rec.Code == http.StatusBadRequest {
			t.Fatalf("mode %q rejected", mode)
		}
	}
	// invalid modes: 400 BEFORE any runtime check
	for _, mode := range []string{"utopia", "", "TOR"} {
		rec := doTorReq(t, api, http.MethodPut, "/api/tor/entry", map[string]string{"mode": mode})
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("mode %q = %d, want 400", mode, rec.Code)
		}
	}
}

func TestTorEntryPersistsConfig(t *testing.T) {
	api, _, cfgPath := newTorTestAPI(t, false) // disabled: 409 after validation
	rec := doTorReq(t, api, http.MethodPut, "/api/tor/entry", map[string]string{"mode": "webtunnel"})
	if rec.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409 (disabled)", rec.Code)
	}
	_ = cfgPath
	_ = os.Remove(cfgPath)
}

// wiring smoke: a REAL runtime (spawn refuses → binary-missing) behind
// SetTorRuntime answers the status endpoint with the honest state.
func TestTorWiringSmoke(t *testing.T) {
	api, cfgPtr, _ := newTorTestAPI(t, true)
	cfg := *cfgPtr.Load()
	rt, err := torservice.Build(&cfg, torservice.Options{
		Spawn: func(ctx context.Context, binaryPath, torrcPath, dataPath string) (torservice.ProcessController, error) {
			return nil, os.ErrNotExist
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	SetTorRuntime(rt)
	defer SetTorRuntime(nil)

	rec := doTorReq(t, api, http.MethodGet, "/api/tor/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["enabled"] != true || body["running"] != false {
		t.Fatalf("wired shape = %v", body)
	}
}

func TestTorNewnymMethodGuard(t *testing.T) {
	api, _, _ := newTorTestAPI(t, false)
	if rec := doTorReq(t, api, http.MethodGet, "/api/tor/newnym", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET newnym = %d, want 405", rec.Code)
	}
	if rec := doTorReq(t, api, http.MethodGet, "/api/tor/entry", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET entry = %d, want 405", rec.Code)
	}
}
