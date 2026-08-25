package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

// newFxvpnTestAPI builds an API with fxvpn routes and a disabled config.
func newFxvpnTestAPI(t *testing.T, enabled bool) (*API, *http.ServeMux, *atomic.Pointer[config.Config]) {
	t.Helper()
	cfg := config.NewConfig() // value type; store a copy
	cfg.System.FxVPN.Enabled = enabled
	var ptr atomic.Pointer[config.Config]
	cfgCopy := cfg
	ptr.Store(&cfgCopy)

	api := NewAPIHandler(&ptr)
	mux := http.NewServeMux()
	api.cfgPtr = &ptr
	api.mux = mux
	api.RegisterFxvpnApi()
	return api, mux, &ptr
}

func doReq(t *testing.T, mux *http.ServeMux, method, path string, body string) (*httptest.ResponseRecorder, map[string]interface{}) {
	t.Helper()
	var rd *strings.Reader
	if body == "" {
		rd = strings.NewReader("")
	} else {
		rd = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rd)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	out := map[string]interface{}{}
	if w.Code == http.StatusOK {
		_ = json.Unmarshal(w.Body.Bytes(), &out)
	}
	return w, out
}

func TestFxvpnStatusDisabledShape(t *testing.T) {
	SetFxvpnRuntime(nil)
	_, mux, _ := newFxvpnTestAPI(t, false)
	w, out := doReq(t, mux, http.MethodGet, "/api/fxvpn/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if out["enabled"] != false || out["running"] != false || out["listening"] != false || out["transport"] != "tcp-only" {
		t.Fatalf("disabled shape wrong: %v", out)
	}
	if _, ok := out["location"]; !ok {
		t.Fatal("location must always be present")
	}
}

func TestFxvpnLocationsWithoutRuntimeIs503(t *testing.T) {
	SetFxvpnRuntime(nil)
	_, mux, _ := newFxvpnTestAPI(t, true)
	w, _ := doReq(t, mux, http.MethodGet, "/api/fxvpn/locations", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", w.Code)
	}
}

func TestFxvpnPutLocationDisabledConflicts(t *testing.T) {
	SetFxvpnRuntime(nil)
	_, mux, _ := newFxvpnTestAPI(t, false)
	w, _ := doReq(t, mux, http.MethodPut, "/api/fxvpn/location", `{"mode":"auto"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409", w.Code)
	}
}

func TestFxvpnRestartMethodGuard(t *testing.T) {
	SetFxvpnRuntime(nil)
	_, mux, _ := newFxvpnTestAPI(t, false)
	w, _ := doReq(t, mux, http.MethodGet, "/api/fxvpn/restart", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code = %d, want 405", w.Code)
	}
}

func TestFxvpnAccountTestBadBody400(t *testing.T) {
	SetFxvpnRuntime(nil)
	_, mux, _ := newFxvpnTestAPI(t, true)
	w, _ := doReq(t, mux, http.MethodPost, "/api/fxvpn/accounts/test", `{not-json`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", w.Code)
	}

	// Empty credentials: runtime missing => 503 before validation.
	w2, _ := doReq(t, mux, http.MethodPost, "/api/fxvpn/accounts/test", `{}`)
	if w2.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503 (no runtime)", w2.Code)
	}
}

// Example response shapes pinned for the GUI (Дополнение 3 contract).
func TestFxvpnStatusExampleKeysWhenEnabledNoRuntime(t *testing.T) {
	SetFxvpnRuntime(nil)
	_, mux, ptr := newFxvpnTestAPI(t, true)
	cfg := config.NewConfig()
	cfg.System.FxVPN.Enabled = true // enabled but runtime not wired: minimal honest shape
	ptr.Store(&cfg)
	w, out := doReq(t, mux, http.MethodGet, "/api/fxvpn/status", "")
	loaded := ptr.Load()
	t.Logf("DEBUG stored-enabled=%v body=%s", loaded.System.FxVPN.Enabled, w.Body.String())
	if w.Code != http.StatusOK || out["enabled"] != true {
		t.Fatalf("enabled-no-runtime shape broken: %d %v", w.Code, out)
	}
}
