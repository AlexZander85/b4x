package handler

import (
	"net/http"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

// newTunnelsTestAPI builds an API with the tunnels routes mounted and the
// given config behind the pointer (opera_test.go canon; no runtimes wired —
// the overview must answer the honest config-only shapes).
func newTunnelsTestAPI(t *testing.T, cfg *config.Config) (*API, *http.ServeMux, *atomic.Pointer[config.Config]) {
	t.Helper()
	if cfg == nil {
		c := config.NewConfig()
		cfg = &c
	}
	var ptr atomic.Pointer[config.Config]
	stored := *cfg
	ptr.Store(&stored)

	api := NewAPIHandler(&ptr)
	mux := http.NewServeMux()
	api.cfgPtr = &ptr
	api.mux = mux
	api.RegisterTunnelsApi()
	return api, mux, &ptr
}

func tunnelChainPreset(t *testing.T, out map[string]interface{}, kind string) map[string]interface{} {
	t.Helper()
	chains, ok := out["chains"].([]interface{})
	if !ok {
		t.Fatalf("overview has no chains array: %v", out)
	}
	for _, c := range chains {
		m, ok := c.(map[string]interface{})
		if !ok {
			t.Fatalf("chain preset is not an object: %v", c)
		}
		if m["kind"] == kind {
			return m
		}
	}
	t.Fatalf("chain preset %q missing from the overview: %v", kind, out)
	return nil
}

// TestTunnelsOverviewChainPresets: the four shipped compositions report
// availability; the nonru geo-gate preset stays honestly-unavailable and
// never picks up config state.
func TestTunnelsOverviewChainPresets(t *testing.T) {
	base := config.NewConfig()
	cfg := &base
	// A configured chain entry must reflect on its shipped preset (the
	// masque+masque entry here is shape-only; kind validity is the config
	// validator's job, exercised in config tests).
	cfg.System.Warp.Chains = []config.WarpChainConfig{{
		Kind:    config.ChainKindMasqueMasque,
		Enabled: true,
	}}
	_, mux, _ := newTunnelsTestAPI(t, cfg)
	w, out := doReq(t, mux, http.MethodGet, "/api/tunnels", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}

	shipped := []string{"masque+awg", "awg+masque", "awg+awg", "masque+masque"}
	for _, kind := range shipped {
		p := tunnelChainPreset(t, out, kind)
		if p["available"] != true {
			t.Fatalf("%s must be available (ships with the daemon assembly): %v", kind, p)
		}
	}
	// masque+masque reflects its config entry (stage-4 semantics).
	mm := tunnelChainPreset(t, out, "masque+masque")
	if mm["configured"] != true || mm["enabled"] != true {
		t.Fatalf("masque+masque must reflect the config entry: %v", mm)
	}

	// nonru: the honest-unavailable preset — availability off, the geo-gate
	// note set, the ADR-WARP-6 topology (nested WARP through the base warp:
	// both layers masque-h2), and NO config-state pickup of any kind.
	nr := tunnelChainPreset(t, out, "nonru")
	if nr["available"] != false {
		t.Fatalf("nonru must be honestly-unavailable (daemon assembly pending): %v", nr)
	}
	if nr["note"] != "nonru_geo_gated" {
		t.Fatalf("nonru note = %v, want nonru_geo_gated", nr["note"])
	}
	if nr["outer"] != "masque-h2" || nr["inner"] != "masque-h2" {
		t.Fatalf("nonru topology = %v -> %v, want masque-h2 -> masque-h2 (nested WARP through the base warp)", nr["outer"], nr["inner"])
	}
	if nr["configured"] != false || nr["enabled"] != false || nr["running"] != false {
		t.Fatalf("unavailable preset must carry no config/runtime state: %v", nr)
	}
}

// TestTunnelsOverviewNonruNoFacade: the unavailable preset must not leak a
// tunnel card either — the overview lists cards only for transports with a
// config section/runtime contract.
func TestTunnelsOverviewNonruNoFacade(t *testing.T) {
	_, mux, _ := newTunnelsTestAPI(t, nil)
	w, out := doReq(t, mux, http.MethodGet, "/api/tunnels", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	cards, ok := out["tunnels"].([]interface{})
	if !ok {
		t.Fatalf("overview has no tunnels array: %v", out)
	}
	for _, c := range cards {
		m, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		if m["kind"] == "nonru" {
			t.Fatalf("nonru must not render a tunnel card (no facade): %v", m)
		}
	}
}

// TestTunnelsRestartKindPosture: nonru is refused as an unknown kind (no
// runtime facade exists for it); masque+masque is a KNOWN chain kind and is
// refused with an honest 409 when no runtime is wired (not a 400 — the
// stage-4 gap fixed with the dispatcher case); the shipped chains share the
// same 409 posture without a runtime.
func TestTunnelsRestartKindPosture(t *testing.T) {
	SetAWGWarpRuntime(nil)
	_, mux, _ := newTunnelsTestAPI(t, nil)

	// nonru: honest 400 — there is no such restartable kind.
	w, _ := doReq(t, mux, http.MethodPost, "/api/tunnels/restart?kind=nonru", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("nonru restart code = %d, want 400 (unknown kind — no facade)", w.Code)
	}

	// Unknown kinds keep the 400 posture.
	w, _ = doReq(t, mux, http.MethodPost, "/api/tunnels/restart?kind=does-not-exist", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unknown kind restart code = %d, want 400", w.Code)
	}

	// The four shipped chain kinds are known: without a runtime they refuse
	// with 409 (dispatched, honestly not running) — never 400. The kind is
	// %-encoded the way the panel does it (chain kinds carry '+', which a
	// raw query would decode into a space).
	for _, kind := range []string{"masque+awg", "awg+masque", "awg+awg", "masque+masque"} {
		w, _ := doReq(t, mux, http.MethodPost, "/api/tunnels/restart?kind="+url.QueryEscape(kind), "")
		if w.Code != http.StatusConflict {
			t.Fatalf("chain %s restart code = %d, want 409 (known kind, no runtime)", kind, w.Code)
		}
	}
}
