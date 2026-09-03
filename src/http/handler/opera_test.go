package handler

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

// newOperaTestAPI builds an API with opera routes and the given enabled
// flag (proton_test.go canon).
func newOperaTestAPI(t *testing.T, enabled bool) (*API, *http.ServeMux, *atomic.Pointer[config.Config]) {
	t.Helper()
	cfg := config.NewConfig()
	cfg.System.Opera.Enabled = enabled
	var ptr atomic.Pointer[config.Config]
	cfgCopy := cfg
	ptr.Store(&cfgCopy)

	api := NewAPIHandler(&ptr)
	mux := http.NewServeMux()
	api.cfgPtr = &ptr
	api.mux = mux
	api.RegisterOperaApi()
	return api, mux, &ptr
}

// TestOperaStatusDisabledShape: with opera disabled and no runtime wired,
// the status answers the truthful minimal shape (config facts + zeros).
func TestOperaStatusDisabledShape(t *testing.T) {
	SetOperaRuntime(nil)
	_, mux, _ := newOperaTestAPI(t, false)
	w, out := doReq(t, mux, http.MethodGet, "/api/opera/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if out["enabled"] != false || out["running"] != false || out["listening"] != false {
		t.Fatalf("disabled shape wrong: %v", out)
	}
	if out["transport"] != "tcp-only" {
		t.Fatalf("transport = %v, want tcp-only", out["transport"])
	}
	if _, ok := out["region"]; !ok {
		t.Fatal("region must always be present")
	}
	// The zero-goroutine invariant rides the same gate: no runtime wired.
	if operaRuntime.Load() != nil {
		t.Fatal("runtime must not be wired for the disabled shape test")
	}
}

// TestOperaRegionDisabledConflict: PUT region without a runtime/disabled
// config answers 409, never silently accepts.
func TestOperaRegionDisabledConflict(t *testing.T) {
	SetOperaRuntime(nil)
	_, mux, _ := newOperaTestAPI(t, false)
	w, _ := doReq(t, mux, http.MethodPut, "/api/opera/region", `{"region":"EU"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409", w.Code)
	}
}

// TestOperaRegionDisabledConflictRuntimeNil: enabled=true but no runtime
// wired — the handler answers 409, never silently accepts.
func TestOperaRegionDisabledConflictRuntimeNil(t *testing.T) {
	SetOperaRuntime(nil)
	_, mux, _ := newOperaTestAPI(t, true)
	w, _ := doReq(t, mux, http.MethodPut, "/api/opera/region", `{"region":"EU"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409", w.Code)
	}
}

// TestOperaRestartDisabledConflict: POST restart without a runtime is 409.
func TestOperaRestartDisabledConflict(t *testing.T) {
	SetOperaRuntime(nil)
	_, mux, _ := newOperaTestAPI(t, true)
	w, _ := doReq(t, mux, http.MethodPost, "/api/opera/restart", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409", w.Code)
	}
}

// TestOperaRoutesRegistered: every /api/opera/* surface answers something
// other than 404 once RegisterOperaApi ran (wiring smoke — review C1).
func TestOperaRoutesRegistered(t *testing.T) {
	SetOperaRuntime(nil)
	_, mux, _ := newOperaTestAPI(t, false)
	for _, path := range []string{"/api/opera/status", "/api/opera/region", "/api/opera/restart"} {
		w, _ := doReq(t, mux, http.MethodGet, path, "")
		if w.Code == http.StatusNotFound {
			t.Fatalf("%s answered 404 — route not registered", path)
		}
	}
}
