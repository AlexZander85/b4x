package handler

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

// newProtonTestAPI builds an API with proton routes and the given enabled
// flag (fxvpn_test.go canon).
func newProtonTestAPI(t *testing.T, enabled bool) (*API, *http.ServeMux, *atomic.Pointer[config.Config]) {
	t.Helper()
	cfg := config.NewConfig()
	cfg.System.Proton.Enabled = enabled
	var ptr atomic.Pointer[config.Config]
	cfgCopy := cfg
	ptr.Store(&cfgCopy)

	api := NewAPIHandler(&ptr)
	mux := http.NewServeMux()
	api.cfgPtr = &ptr
	api.mux = mux
	api.RegisterProtonApi()
	return api, mux, &ptr
}

// TestProtonStatusDisabledShape: with proton disabled and no runtime wired,
// the status answers the truthful minimal shape (config facts + zeros).
func TestProtonStatusDisabledShape(t *testing.T) {
	SetProtonRuntime(nil)
	_, mux, _ := newProtonTestAPI(t, false)
	w, out := doReq(t, mux, http.MethodGet, "/api/proton/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if out["enabled"] != false || out["running"] != false || out["listening"] != false {
		t.Fatalf("disabled shape wrong: %v", out)
	}
	if out["transport"] != "udp-full-scope" {
		t.Fatalf("transport = %v, want udp-full-scope", out["transport"])
	}
	if _, ok := out["location"]; !ok {
		t.Fatal("location must always be present")
	}
	// The zero-goroutine invariant rides the same gate: no runtime wired.
	if protonRuntime.Load() != nil {
		t.Fatal("runtime must not be wired for the disabled shape test")
	}
}

// TestProtonLocationsWithoutRuntimeIs503: no runtime -> 503, never a lie.
func TestProtonLocationsWithoutRuntimeIs503(t *testing.T) {
	SetProtonRuntime(nil)
	_, mux, _ := newProtonTestAPI(t, true)
	w, _ := doReq(t, mux, http.MethodGet, "/api/proton/locations", "")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", w.Code)
	}
}

// TestProtonPutLocationDisabledConflicts: the mutating surface refuses the
// disabled transport with 409 (fxvpn parity).
func TestProtonPutLocationDisabledConflicts(t *testing.T) {
	SetProtonRuntime(nil)
	_, mux, _ := newProtonTestAPI(t, false)
	w, _ := doReq(t, mux, http.MethodPut, "/api/proton/location", `{"mode":"auto"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409", w.Code)
	}
}

// TestProtonRestartMethodGuard: GET on the POST endpoint -> 405.
func TestProtonRestartMethodGuard(t *testing.T) {
	SetProtonRuntime(nil)
	_, mux, _ := newProtonTestAPI(t, false)
	w, _ := doReq(t, mux, http.MethodGet, "/api/proton/restart", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code = %d, want 405", w.Code)
	}
	// The reissue endpoint carries the same guard.
	w2, _ := doReq(t, mux, http.MethodGet, "/api/proton/reissue", "")
	if w2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code = %d, want 405", w2.Code)
	}
}

// TestProtonReissueDisabledConflicts: re-issue on a disabled transport is a
// conflict, not a silent success.
func TestProtonReissueDisabledConflicts(t *testing.T) {
	SetProtonRuntime(nil)
	_, mux, _ := newProtonTestAPI(t, false)
	w, _ := doReq(t, mux, http.MethodPost, "/api/proton/reissue", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("code = %d, want 409", w.Code)
	}
}
