package handler

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func newVlessTestAPI(t *testing.T, enabled bool) (*API, *http.ServeMux, *atomic.Pointer[config.Config]) {
	t.Helper()
	cfg := config.NewConfig()
	cfg.System.Vless.Enabled = enabled
	var ptr atomic.Pointer[config.Config]
	cfgCopy := cfg
	ptr.Store(&cfgCopy)

	api := NewAPIHandler(&ptr)
	mux := http.NewServeMux()
	api.cfgPtr = &ptr
	api.mux = mux
	api.RegisterVlessApi()
	return api, mux, &ptr
}

// TestVlessStatusDisabledShape: with vless disabled and no runtime wired, the
// status answers the truthful minimal shape (config facts + zeros).
func TestVlessStatusDisabledShape(t *testing.T) {
	SetVlessRuntime(nil)
	_, mux, _ := newVlessTestAPI(t, false)
	w, out := doReq(t, mux, http.MethodGet, "/api/vless/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if out["enabled"] != false || out["running"] != false {
		t.Fatalf("disabled shape wrong: %v", out)
	}
	if out["transport"] != "tcp-only" {
		t.Fatalf("transport = %v, want tcp-only", out["transport"])
	}
	if vlessRuntime.Load() != nil {
		t.Fatal("runtime must not be wired for the disabled shape test")
	}
}

// TestVlessRoutesRegistered: the /api/vless/status surface answers something
// other than 404 once RegisterVlessApi ran (wiring smoke).
func TestVlessRoutesRegistered(t *testing.T) {
	SetVlessRuntime(nil)
	_, mux, _ := newVlessTestAPI(t, false)
	w, _ := doReq(t, mux, http.MethodGet, "/api/vless/status", "")
	if w.Code == http.StatusNotFound {
		t.Fatal("/api/vless/status answered 404 — route not registered")
	}
}
