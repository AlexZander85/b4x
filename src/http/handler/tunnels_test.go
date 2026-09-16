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

	// nonru (stage 6 — the daemon assembly shipped): available, the ADR-WARP-6
	// topology (nested WARP through the base warp: both layers masque-h2),
	// the config section reflected (system.warp.nonru), and no runtime wired
	// in this test → the honest assembly-pending note.
	nr := tunnelChainPreset(t, out, "nonru")
	if nr["available"] != true {
		t.Fatalf("nonru must be available (the stage-6 daemon assembly): %v", nr)
	}
	if nr["outer"] != "masque-h2" || nr["inner"] != "masque-h2" {
		t.Fatalf("nonru topology = %v -> %v, want masque-h2 -> masque-h2 (nested WARP through the base warp)", nr["outer"], nr["inner"])
	}
	if nr["configured"] != true {
		t.Fatalf("nonru must reflect the config schema section: %v", nr)
	}
	if nr["enabled"] != false {
		t.Fatalf("nonru disabled in config must surface enabled=false: %v", nr)
	}
	if nr["running"] != false {
		t.Fatalf("no runtime wired must surface running=false: %v", nr)
	}
	if nr["note"] != "chain_not_configured" {
		t.Fatalf("disabled nonru note = %v, want chain_not_configured", nr["note"])
	}

	// An ENABLED nonru section with no runtime wired: the honest pending note.
	enabled := config.NewConfig()
	enabled.System.Warp.NonRU.Enabled = true
	_, mux2, _ := newTunnelsTestAPI(t, &enabled)
	_, out2 := doReq(t, mux2, http.MethodGet, "/api/tunnels", "")
	nr2 := tunnelChainPreset(t, out2, "nonru")
	if nr2["enabled"] != true || nr2["running"] != false || nr2["note"] != "nonru_assembly_pending" {
		t.Fatalf("enabled-not-running nonru = %v", nr2)
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

// TestTunnelsRestartKindPosture: nonru is a KNOWN kind — without a runtime
// (or disabled in config) it refuses with an honest 409, never a 400; the
// shipped chains share the same posture. Unknown kinds keep the 400.
func TestTunnelsRestartKindPosture(t *testing.T) {
	SetAWGWarpRuntime(nil)
	_, mux, _ := newTunnelsTestAPI(t, nil)

	// nonru: known kind — disabled in config and no runtime → honest 409.
	w, _ := doReq(t, mux, http.MethodPost, "/api/tunnels/restart?kind=nonru", "")
	if w.Code != http.StatusConflict {
		t.Fatalf("nonru restart code = %d, want 409 (known kind, disabled/no runtime)", w.Code)
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

// TestNonRUStatusDisabledShape: without an engine the status answers the
// truthful minimal shape (config facts + the zero gate view).
func TestNonRUStatusDisabledShape(t *testing.T) {
	SetNonRURuntime(nil)
	enabled := config.NewConfig()
	enabled.System.Warp.NonRU.Enabled = true
	_, mux, _ := newTunnelsTestAPI(t, &enabled)
	w, out := doReq(t, mux, http.MethodGet, "/api/nonru/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("code = %d", w.Code)
	}
	if out["enabled"] != true || out["running"] != false || out["listening"] != false {
		t.Fatalf("disabled shape wrong: %v", out)
	}
	if out["transport"] != "nonru" {
		t.Fatalf("transport = %v, want nonru", out["transport"])
	}
	gate, ok := out["gate"].(map[string]interface{})
	if !ok || gate["open"] != false || gate["verdict"] != "" {
		t.Fatalf("gate view must be the honest zero shape: %v", out["gate"])
	}
}
