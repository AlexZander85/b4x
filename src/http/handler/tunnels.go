package handler

// Tunnels control plane (design TUNNELS_PANEL_DESIGN.md): one overview
// endpoint for the Tunnels page, one restart dispatcher over the existing
// per-service runtimes, and the missing /api/warp/status projection for
// the MASQUE-WARP engine (warpservice). The per-tunnel detail APIs stay
// where they are (/api/{tor,opera,fxvpn,proton}/*); this surface is the
// pane-level aggregation, not a replacement.
//
//      GET  /api/tunnels                    — catalog + runtime cards + assignments
//      POST /api/tunnels/{kind}/restart     — dispatch one supervision cycle
//      GET  /api/warp/status                — MASQUE-WARP engine status (nil-safe)

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/awgwarpservice"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/nonruservice"
	"github.com/daniellavrushin/b4/reserve"
	"github.com/daniellavrushin/b4/transport/health"
	"github.com/daniellavrushin/b4/warpchainservice"
	"github.com/daniellavrushin/b4/warpservice"
)

// warpServiceRuntime is the warpservice seam (the fxvpn canon): main wires
// the assembled MASQUE-WARP engine; the status projection stays nil-safe.
var warpServiceRuntime atomic.Pointer[warpservice.Runtime]

// SetWarpServiceRuntime binds (or unbinds, nil) the warpservice engine.
func SetWarpServiceRuntime(rt *warpservice.Runtime) { warpServiceRuntime.Store(rt) }

// awgWarpRuntime is the AWG-WARP seam (tunnels panel stage 2).
var awgWarpRuntime atomic.Pointer[awgwarpservice.Runtime]

// SetAWGWarpRuntime binds (or unbinds, nil) the AWG-WARP engine.
func SetAWGWarpRuntime(rt *awgwarpservice.Runtime) { awgWarpRuntime.Store(rt) }

// chainRuntimes holds the per-kind chain engines (masque+awg, awg+masque,
// awg+awg, masque+masque).
var chainRuntimes sync.Map // string(kind) -> *warpchainservice.Runtime

// SetChainRuntime binds (or unbinds, nil) one chain engine by kind.
func SetChainRuntime(kind string, rt *warpchainservice.Runtime) {
	if rt == nil {
		chainRuntimes.Delete(kind)
		return
	}
	chainRuntimes.Store(kind, rt)
}

// chainRuntime snapshots one chain engine (nil when absent).
func chainRuntime(kind string) *warpchainservice.Runtime {
	v, ok := chainRuntimes.Load(kind)
	if !ok {
		return nil
	}
	rt, _ := v.(*warpchainservice.Runtime)
	return rt
}

// nonruRuntime is the НЕ РФ engine seam (tunnels panel stage 6; the E6/E7
// daemon assembly in src/nonruservice).
var nonruRuntime atomic.Pointer[nonruservice.Runtime]

// SetNonRURuntime binds (or unbinds, nil) the nonru engine.
func SetNonRURuntime(rt *nonruservice.Runtime) { nonruRuntime.Store(rt) }

// nonruRuntimeLoad snapshots the engine (nil when absent).
func nonruRuntimeLoad() *nonruservice.Runtime { return nonruRuntime.Load() }

// RegisterTunnelsApi mounts the tunnels control plane.
func (api *API) RegisterTunnelsApi() {
	api.mux.HandleFunc("/api/tunnels", api.handleTunnelsOverview)
	api.mux.HandleFunc("/api/tunnels/restart", api.handleTunnelsRestart)
	api.mux.HandleFunc("/api/tunnels/measure", api.handleTunnelsMeasure)
	api.mux.HandleFunc("/api/tunnels/start", api.handleTunnelsStart)
	api.mux.HandleFunc("/api/warp/status", api.handleWarpStatus)
	api.mux.HandleFunc("/api/awgwarp/status", api.handleAWGWarpStatus)
	api.mux.HandleFunc("/api/nonru/status", api.handleNonRUStatus)
}

// tunnelsChainPreset describes one nested-chain preset (transport/nested
// matrix). The masque+awg, awg+masque, awg+awg and masque+masque
// compositions ship with the daemon assembly (warpchainservice); the rest
// stay engine-pending and the card reports that honestly instead of
// pretending availability.
type tunnelsChainPreset struct {
	Kind      string `json:"kind"`
	Outer     string `json:"outer"`
	Inner     string `json:"inner"`
	Available bool   `json:"available"`
	// Configured: the chain entry exists in system.warp.chains (any state).
	Configured bool `json:"configured"`
	// Enabled mirrors the config entry's enabled flag.
	Enabled bool `json:"enabled"`
	// Running: the chain engine reports a live composition.
	Running bool   `json:"running"`
	State   string `json:"state,omitempty"`
	Note    string `json:"note,omitempty"`
}

// tunnelsCard is one tunnel row of the overview.
type tunnelsCard struct {
	Kind              string `json:"kind"`
	Priority          int    `json:"priority"`
	Transport         string `json:"transport"`
	SupportsUDP       bool   `json:"supports_udp"`
	HasConfigSection  bool   `json:"has_config_section"`
	ConfigEnabled     bool   `json:"config_enabled"`
	CarrierRegistered bool   `json:"carrier_registered"`
	Running           bool   `json:"running"`
	Listening         bool   `json:"listening"`
	State             string `json:"state,omitempty"`
	Region            string `json:"region,omitempty"`
	LocationMode      string `json:"location_mode,omitempty"`
	LocationValue     string `json:"location_value,omitempty"`
	Restartable       bool   `json:"restartable"`
	Note              string `json:"note,omitempty"`
	// Health is the last measurement for this kind (design §8), if any.
	// RECOMMENDATION only: it never changes which tunnel routes traffic.
	Health *health.Metrics `json:"health,omitempty"`
}

// tunnelHealthCache stores the last manual measurement per tunnel kind.
// Phase A triggers measurements explicitly (POST /api/tunnels/measure);
// Phase B adds the automatic cadence.
var tunnelHealthCache = health.NewCache()

// tunnelsAssignment is one set routed through a tunnel.
type tunnelsAssignment struct {
	SetID           string `json:"set_id"`
	SetName         string `json:"set_name"`
	Enabled         bool   `json:"set_enabled"`
	Tunnel          string `json:"tunnel"`
	TunnelRunning   bool   `json:"tunnel_running"`
	Domains         int    `json:"domains"`
	GeositeCategory int    `json:"geosite_categories"`
	UDP             bool   `json:"udp"`
	FailOpen        bool   `json:"fail_open"`
}

// tunnelsOverview is the GET /api/tunnels response.
type tunnelsOverview struct {
	Tunnels     []tunnelsCard        `json:"tunnels"`
	Chains      []tunnelsChainPreset `json:"chains"`
	Assignments []tunnelsAssignment  `json:"assignments"`
	Registered  []string             `json:"registered_carriers"`
}

func tunnelsErr(status int, code, msg string) error {
	return &APIError{Status: status, Code: code, Message: msg}
}

// @Summary Tunnels overview for the management pane
// @Description Catalog of the reserve tunnel kinds merged with runtime
// @Description truth: config-enabled, carrier-registered, running/listening,
// @Description region/location; the nested-chain presets with honest
// @Description availability; the sets routed through tunnels.
// @Tags tunnels
// @Produce json
// @Success 200 {object} tunnelsOverview
// @Security BearerAuth
// @Router /tunnels [get]
func (api *API) handleTunnelsOverview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, tunnelsErr(http.StatusMethodNotAllowed, "method", "GET only"))
		return
	}
	cfg := api.cfgPtr.Load()
	api.sendTunnelsOverview(w, cfg)
}

func (api *API) sendTunnelsOverview(w http.ResponseWriter, cfg *config.Config) {
	registered := map[reserve.Kind]bool{}
	for _, e := range reserve.List() {
		registered[e.Kind] = true
	}

	cards := make([]tunnelsCard, 0, 7)

	// warp — AWG-WARP (tunnels panel stage 2: system.warp.awg +
	// awgwarpservice, kind=warp UDP full-scope through the session
	// netstack). Honest card: config section present, runtime optional.
	// In kernel mode the data plane is /dev/net/tun + PBR (the field
	// layer): Running reflects the session, the carrier is honestly absent.
	awgCfg := cfg.System.Warp.AWG
	wp := tunnelsCard{
		Kind:             string(reserve.KindWarp),
		Priority:         reserve.PriorityWarp,
		Transport:        "udp-full-scope",
		SupportsUDP:      true,
		HasConfigSection: true,
		ConfigEnabled:    awgCfg.Enabled,
		Restartable:      true, // RestartNow: retire + one supervision cycle
	}
	if awgCfg.KernelMode() {
		wp.Transport = "kernel-pbr"
		wp.SupportsUDP = false
	}
	if rt := awgWarpRuntime.Load(); rt != nil {
		st := rt.Status()
		if awgCfg.KernelMode() {
			// The engine owns the kernel session; the carrier registration
			// is deliberately absent (no userspace dial legs).
			wp.Running = st.Running
			wp.State = st.State
			wp.Note = "awg_warp_kernel_pbr"
		} else {
			wp.CarrierRegistered = true
			wp.Running = st.Running
			wp.Listening = st.Listening
			wp.State = st.State
			if !st.IdentityPresent {
				wp.Note = "awg_warp_provisioning"
			}
		}
	} else if awgCfg.Enabled {
		wp.Note = "engine_enabled_not_running"
	}
	cards = append(cards, wp)

	// masque — MASQUE-WARP (warpservice, system.warp).
	mq := tunnelsCard{
		Kind:             string(reserve.KindMasque),
		Priority:         reserve.PriorityMasque,
		Transport:        "udp-full-scope",
		SupportsUDP:      false, // netstack v1 carries IPv4 TCP only
		HasConfigSection: true,
		ConfigEnabled:    cfg.System.Warp.Enabled,
		Restartable:      false, // supervisor-owned lifecycle
	}
	if rt := warpServiceRuntime.Load(); rt != nil {
		snap := rt.Status()
		mq.CarrierRegistered = true
		mq.Running = true
		mq.State = string(snap.Status.State)
		mq.Listening = snap.Status.RouteHeld
	} else if cfg.System.Warp.Enabled {
		mq.Note = "engine_enabled_not_running"
	}
	cards = append(cards, mq)

	// h3 — the H3-first MASQUE-WARP transport. It is the SAME carrier as
	// kind=masque (the warpservice ladder negotiates H3 first, H2 fallback), so
	// this card mirrors the masque engine state and reports the alias carrier
	// that main registers under kind=h3. It is routable via routing.tunnel=h3.
	h3 := tunnelsCard{
		Kind:             string(reserve.KindH3),
		Priority:         reserve.PriorityH3,
		Transport:        "udp-full-scope",
		SupportsUDP:      true,
		HasConfigSection: false,
		ConfigEnabled:    cfg.System.Warp.Enabled,
		Restartable:      false, // supervisor-owned lifecycle (same as masque)
	}
	if rt := warpServiceRuntime.Load(); rt != nil {
		snap := rt.Status()
		h3.CarrierRegistered = true
		h3.Running = true
		h3.State = string(snap.Status.State)
		h3.Listening = snap.Status.RouteHeld
	} else if cfg.System.Warp.Enabled {
		h3.Note = "engine_enabled_not_running"
	}
	cards = append(cards, h3)

	// opera — Opera VPN (TCP-only).
	op := tunnelsCard{
		Kind:             string(reserve.KindOpera),
		Priority:         reserve.PriorityOpera,
		Transport:        "tcp-only",
		SupportsUDP:      false,
		HasConfigSection: true,
		ConfigEnabled:    cfg.System.Opera.Enabled,
		Region:           cfg.System.Opera.Region,
		Restartable:      true,
	}
	if rt := operaRuntime.Load(); rt != nil {
		st := rt.Status()
		op.CarrierRegistered = true
		op.Running = st.Running
		op.Listening = st.Listening
		if st.Degraded != "" {
			op.State = st.Degraded
		} else {
			op.State = "healthy"
		}
		if st.DesiredRegion != "" && st.Region != "" {
			op.Region = st.Region
		}
	}
	cards = append(cards, op)

	// vless — VLESS(+REALITY) via an external helper's local SOCKS5
	// (TCP-only; V1 carries config/nodes/status, the helper lifecycle is V2).
	vl := tunnelsCard{
		Kind:             string(reserve.KindVless),
		Priority:         reserve.PriorityVless,
		Transport:        "tcp-only",
		SupportsUDP:      false,
		HasConfigSection: true,
		ConfigEnabled:    cfg.System.Vless.Enabled,
		Restartable:      false, // helper supervisor/restart is V2
	}
	if rt := vlessRuntime.Load(); rt != nil {
		st := rt.Status()
		vl.CarrierRegistered = true
		vl.Running = st.Running
		vl.Listening = false // honest: V1 does not probe the helper's SOCKS port
		if st.Running {
			vl.State = "armed"
		}
	}
	cards = append(cards, vl)

	// fxvpn — Firefox VPN (TCP-only).
	fx := tunnelsCard{
		Kind:             string(reserve.KindFxvpn),
		Priority:         reserve.PriorityFxvpn,
		Transport:        "tcp-only",
		SupportsUDP:      false,
		HasConfigSection: true,
		ConfigEnabled:    cfg.System.FxVPN.Enabled,
		LocationMode:     cfg.System.FxVPN.Location.Mode,
		LocationValue:    fxvpnLocationValue(cfg),
		Restartable:      true,
	}
	if rt := fxvpnRuntime.Load(); rt != nil {
		st := rt.Status()
		fx.CarrierRegistered = true
		fx.Running = st.Running
		fx.Listening = st.Listening
		if st.LastFailure != "" {
			fx.State = st.LastFailure
		} else {
			fx.State = "healthy"
		}
	}
	cards = append(cards, fx)

	// proton — Proton VPN AWG (the only UDP full-scope reserve).
	pr := tunnelsCard{
		Kind:             string(reserve.KindProton),
		Priority:         reserve.PriorityProton,
		Transport:        "udp-full-scope",
		SupportsUDP:      true,
		HasConfigSection: true,
		ConfigEnabled:    cfg.System.Proton.Enabled,
		LocationMode:     cfg.System.Proton.Location.Mode,
		LocationValue:    protonLocationValue(cfg),
		Restartable:      true,
	}
	if rt := protonRuntime.Load(); rt != nil {
		st := rt.Status()
		pr.CarrierRegistered = true
		pr.Running = st.Running
		pr.Listening = st.Listening
		pr.State = st.State
	}
	cards = append(cards, pr)

	// tor — Tor reserve (TCP-only, carrier of last resort).
	tr := tunnelsCard{
		Kind:             string(reserve.KindTor),
		Priority:         reserve.PriorityTor,
		Transport:        "tcp-only",
		SupportsUDP:      false,
		HasConfigSection: true,
		ConfigEnabled:    cfg.System.Tor.Enabled,
		LocationMode:     cfg.System.Tor.EffectiveEntryMode(),
		Restartable:      true,
	}
	if rt := torRuntimeLoad(); rt != nil {
		st := rt.Status()
		tr.CarrierRegistered = true
		tr.Running = st.Running
		tr.Listening = st.Listening
		tr.State = st.State
	}
	cards = append(cards, tr)

	// Nested-chain presets: the masque+awg, awg+masque, awg+awg and
	// masque+masque compositions ship with the daemon assembly
	// (warpchainservice over transport/nested and transport/wg); each
	// preset reflects the config entry and the live engine. The
	// engine-pending compositions stay honest-unavailable.
	chainConfigured := map[string]config.WarpChainConfig{}
	for _, ch := range cfg.System.Warp.Chains {
		chainConfigured[ch.Kind] = ch
	}
	// nonru (НЕ РФ, addendum §3.2 / ADR-WARP-6): a SECOND isolated WARP
	// session whose control path is forced through the verified BASE
	// WARP — both layers are WARP/MASQUE sessions (outer = the base warp
	// transport, inner = the nested warp), gated by multi-provider geo
	// attestation before any route is promoted. Stage 6 ships the daemon
	// assembly (src/nonruservice: nested M+M over the base plane + the
	// NonRUGate route hooks). The preset reflects system.warp.nonru and
	// the live engine; Running means the COMPOSITION is up (the gate may
	// still be honestly closed — see /api/nonru/status for the gate view).
	nrCfg := cfg.System.Warp.NonRU
	nr := tunnelsChainPreset{
		Kind:       "nonru",
		Outer:      "masque-h2",
		Inner:      "masque-h2",
		Available:  true,
		Configured: true, // the section exists in the config schema
		Enabled:    nrCfg.Enabled,
	}
	if rt := nonruRuntimeLoad(); rt != nil {
		st := rt.Status()
		nr.Running = st.Running
		nr.State = st.State
		if st.Listening {
			nr.Note = "nonru_gate_open"
		} else {
			nr.Note = "nonru_gate_closed"
		}
	} else if nrCfg.Enabled {
		nr.Note = "nonru_assembly_pending"
	} else {
		nr.Note = "chain_not_configured"
	}
	chains := []tunnelsChainPreset{
		{Kind: "awg+awg", Outer: "awg", Inner: "awg", Available: true},
		{Kind: "masque+masque", Outer: "masque-h2", Inner: "masque-h2", Available: true},
		{Kind: "awg+masque", Outer: "awg", Inner: "masque-h2", Available: true},
		{Kind: "masque+awg", Outer: "masque-h2", Inner: "awg", Available: true},
		nr,
	}
	for i := range chains {
		ch := chains[i]
		if !ch.Available {
			continue
		}
		if ch.Kind == "nonru" {
			// nonru carries its own preset state above (system.warp.nonru +
			// the live engine); it has no system.warp.chains entry.
			continue
		}
		cfgEntry, configured := chainConfigured[ch.Kind]
		ch.Configured = configured
		if configured {
			ch.Enabled = cfgEntry.Enabled
		}
		if rt := chainRuntime(ch.Kind); rt != nil {
			st := rt.Status()
			ch.Running = st.Running
			ch.State = st.State
		}
		if configured && !cfgEntry.Enabled {
			ch.Note = "chain_disabled"
		} else if !configured {
			ch.Note = "chain_not_configured"
		}
		chains[i] = ch
	}

	// Assignments: sets whose routing.mode=tunnel.
	assignments := make([]tunnelsAssignment, 0)
	kindRunning := map[string]bool{}
	for _, c := range cards {
		kindRunning[c.Kind] = c.Running
	}
	for _, c := range chains {
		kindRunning[c.Kind] = c.Running
	}
	for _, set := range cfg.Sets {
		if set == nil || set.Routing.Mode != config.RoutingModeTunnel {
			continue
		}
		assignments = append(assignments, tunnelsAssignment{
			SetID:           set.Id,
			SetName:         set.Name,
			Enabled:         set.Enabled,
			Tunnel:          set.Routing.Tunnel,
			TunnelRunning:   kindRunning[set.Routing.Tunnel],
			Domains:         len(set.Targets.SNIDomains),
			GeositeCategory: len(set.Targets.GeoSiteCategories),
			UDP:             set.Routing.Upstream.UDP,
			FailOpen:        set.Routing.Upstream.FailOpen,
		})
	}

	// Phase A: attach the last manual health measurement (if any) to each
	// card. Recommendation only — this never changes routing (design §8).
	for i := range cards {
		if m, ok := tunnelHealthCache.Get(cards[i].Kind); ok {
			mm := m
			cards[i].Health = &mm
		}
	}

	registeredKinds := make([]string, 0, len(registered))
	for _, e := range reserve.List() {
		registeredKinds = append(registeredKinds, string(e.Kind))
	}

	sendResponse(w, tunnelsOverview{
		Tunnels:     cards,
		Chains:      chains,
		Assignments: assignments,
		Registered:  registeredKinds,
	})
}

func fxvpnLocationValue(cfg *config.Config) string {
	loc := cfg.System.FxVPN.Location
	switch loc.Mode {
	case "country":
		return loc.Country
	case "host":
		return loc.Host
	default:
		return "auto"
	}
}

func protonLocationValue(cfg *config.Config) string {
	loc := cfg.System.Proton.Location
	switch loc.Mode {
	case "country":
		return loc.Country
	case "host":
		return loc.Host
	default:
		return "auto"
	}
}

// @Summary Restart one tunnel (one supervision cycle)
// @Description Dispatches to the engine's own restart path (restart caps
// @Description still apply inside each service). warp/masque lifecycle is
// @Description supervisor-owned: the daemon restart is the honest answer;
// @Description the AWG-WARP engine retires the session and rebuilds it
// @Description under its own caps; chains tear the composition down and
// @Description rebuild once.
// @Tags tunnels
// @Produce json
// @Param kind query string true "tunnel kind (warp|opera|fxvpn|proton|tor|masque+awg|awg+masque|awg+awg)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} APIError
// @Failure 409 {object} APIError
// @Security BearerAuth
// @Router /tunnels/restart [post]
func (api *API) handleTunnelsRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, tunnelsErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	kind := r.URL.Query().Get("kind")
	cfg := api.cfgPtr.Load()
	switch kind {
	case "warp":
		rt := awgWarpRuntime.Load()
		if rt == nil || !cfg.System.Warp.AWG.Enabled {
			writeAPIError(w, tunnelsErr(http.StatusConflict, "disabled", "awg-warp disabled"))
			return
		}
		go rt.RestartNow(r.Context())
	case config.ChainKindMasqueAwg, config.ChainKindAwgMasque, config.ChainKindAwgAwg, config.ChainKindMasqueMasque:
		rt := chainRuntime(kind)
		if rt == nil {
			writeAPIError(w, tunnelsErr(http.StatusConflict, "disabled", "chain "+kind+" not running"))
			return
		}
		go rt.RestartNow(r.Context())
	case "nonru":
		rt := nonruRuntimeLoad()
		if rt == nil || !cfg.System.Warp.NonRU.Enabled {
			writeAPIError(w, tunnelsErr(http.StatusConflict, "disabled", "nonru disabled"))
			return
		}
		go rt.RestartNow(r.Context())
	case "opera":
		rt := operaRuntime.Load()
		if rt == nil || !cfg.System.Opera.Enabled {
			writeAPIError(w, tunnelsErr(http.StatusConflict, "disabled", "opera disabled"))
			return
		}
		rt.Kick(r.Context())
	case "fxvpn":
		rt := fxvpnRuntime.Load()
		if rt == nil || !cfg.System.FxVPN.Enabled {
			writeAPIError(w, tunnelsErr(http.StatusConflict, "disabled", "fxvpn disabled"))
			return
		}
		rt.RestartNow(r.Context())
	case "proton":
		rt := protonRuntime.Load()
		if rt == nil || !cfg.System.Proton.Enabled {
			writeAPIError(w, tunnelsErr(http.StatusConflict, "disabled", "proton disabled"))
			return
		}
		rt.RestartNow(r.Context())
	case "tor":
		rt := torRuntimeLoad()
		if rt == nil || !cfg.System.Tor.Enabled {
			writeAPIError(w, tunnelsErr(http.StatusConflict, "disabled", "tor disabled"))
			return
		}
		go rt.RestartNow(r.Context())
	default:
		writeAPIError(w, tunnelsErr(http.StatusBadRequest, "unknown_kind", "unknown or non-restartable tunnel kind "+kind))
		return
	}
	log.Infof("[tunnels] restart dispatched kind=%s", kind)
	sendResponse(w, map[string]interface{}{"success": true, "kind": kind})
}

// @Summary Measure tunnel health (availability / latency / throughput)
// @Description Runs one bounded probe THROUGH each requested reserve carrier
// @Description (all registered kinds, or ?kind=<k>) and returns the metrics;
// @Description results are cached and surface in GET /api/tunnels. This is a
// @Description RECOMMENDATION/score surface — it never changes routing
// @Description (design §8); promotion stays an explicit action.
// @Tags tunnels
// @Produce json
// @Param kind query string false "one tunnel kind (default: all registered)"
// @Success 200 {object} map[string]interface{}
// @Failure 405 {object} APIError
// @Security BearerAuth
// @Router /tunnels/measure [post]
func (api *API) handleTunnelsMeasure(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, tunnelsErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	p := health.New(health.DefaultConfig())
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()

	results := map[string]health.Metrics{}
	for _, e := range reserve.List() {
		if e.Carrier == nil {
			continue
		}
		if kind != "" && string(e.Kind) != kind {
			continue
		}
		m := p.Measure(ctx, e.Carrier)
		tunnelHealthCache.Put(m)
		results[string(e.Kind)] = m
		log.Infof("[tunnels] health kind=%s available=%t score=%.1f verdict=%s ttfb_ms=%d thr_mbps=%.2f",
			m.Kind, m.Available, m.Score, m.Verdict, m.TTFBms, m.ThroughputMbps)
	}
	sendResponse(w, map[string]interface{}{"results": results})
}

// @Summary Bring up every tunnel
// @Description Enables every tunnel config section (masque, warp/awg, opera,
// @Description fxvpn, proton, tor, nonru and the configured chains) and
// @Description persists the config. Engine startup happens on the next daemon
// @Description restart, which the UI triggers via POST /api/system/restart.
// @Description High blast radius: an explicit operator action.
// @Tags tunnels
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} APIError
// @Security BearerAuth
// @Router /tunnels/start [post]
func (api *API) handleTunnelsStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, tunnelsErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	cur := api.cfgPtr.Load()
	if cur == nil {
		writeAPIError(w, tunnelsErr(http.StatusInternalServerError, "config", "config unavailable"))
		return
	}
	next := cur.Clone()

	enabled := make([]string, 0, 8)
	next.System.Warp.Enabled = true
	enabled = append(enabled, string(reserve.KindMasque))
	next.System.Warp.AWG.Enabled = true
	enabled = append(enabled, string(reserve.KindWarp))
	next.System.Opera.Enabled = true
	enabled = append(enabled, string(reserve.KindOpera))
	next.System.FxVPN.Enabled = true
	enabled = append(enabled, string(reserve.KindFxvpn))
	next.System.Proton.Enabled = true
	enabled = append(enabled, string(reserve.KindProton))
	next.System.Tor.Enabled = true
	enabled = append(enabled, string(reserve.KindTor))
	for i := range next.System.Warp.Chains {
		next.System.Warp.Chains[i].Enabled = true
		enabled = append(enabled, "chain:"+next.System.Warp.Chains[i].Kind)
	}
	next.System.Warp.NonRU.Enabled = true
	enabled = append(enabled, "nonru")

	if err := api.saveAndPushConfig(next); err != nil {
		writeAPIError(w, err)
		return
	}
	log.Infof("[tunnels] start-all enabled=%v restart_required=true", enabled)
	sendResponse(w, map[string]interface{}{
		"success":          true,
		"enabled":          enabled,
		"restart_required": true,
	})
}

// @Summary MASQUE-WARP engine status
// @Description The warpservice projection (supervisor state, route held,
// @Description recent events). Nil-safe disabled shape like the other
// @Description reserve handlers.
// @Tags tunnels
// @Produce json
// @Success 200 {object} warpservice.StatusSnapshot
// @Security BearerAuth
// @Router /warp/status [get]
func (api *API) handleWarpStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, tunnelsErr(http.StatusMethodNotAllowed, "method", "GET only"))
		return
	}
	cfg := api.cfgPtr.Load().System.Warp
	rt := warpServiceRuntime.Load()
	if !cfg.Enabled || rt == nil {
		sendResponse(w, map[string]interface{}{
			"enabled":   cfg.Enabled,
			"running":   false,
			"listening": false,
			"transport": "masque-h2",
		})
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	sendResponse(w, rt.Status())
}

// @Summary AWG-WARP engine status
// @Description The awgwarpservice projection (state, identity presence,
// @Description restarts, recent events). Nil-safe disabled shape.
// @Tags tunnels
// @Produce json
// @Success 200 {object} awgwarpservice.StatusView
// @Security BearerAuth
// @Router /awgwarp/status [get]
func (api *API) handleAWGWarpStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, tunnelsErr(http.StatusMethodNotAllowed, "method", "GET only"))
		return
	}
	cfg := api.cfgPtr.Load().System.Warp.AWG
	rt := awgWarpRuntime.Load()
	if !cfg.Enabled || rt == nil {
		sendResponse(w, map[string]interface{}{
			"enabled":   cfg.Enabled,
			"running":   false,
			"listening": false,
			"transport": "awg",
		})
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	sendResponse(w, rt.Status())
}

// @Summary НЕ РФ (nonru) engine status
// @Description The nonruservice projection: the nested composition state,
// @Description the geo-gate view (verdict, attestation freshness, revocations)
// @Description and the classify-oracle posture. Nil-safe disabled shape.
// @Tags tunnels
// @Produce json
// @Success 200 {object} nonruservice.StatusView
// @Security BearerAuth
// @Router /nonru/status [get]
func (api *API) handleNonRUStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, tunnelsErr(http.StatusMethodNotAllowed, "method", "GET only"))
		return
	}
	cfg := api.cfgPtr.Load().System.Warp.NonRU
	rt := nonruRuntimeLoad()
	if !cfg.Enabled || rt == nil {
		sendResponse(w, map[string]interface{}{
			"enabled":   cfg.Enabled,
			"running":   false,
			"listening": false,
			"transport": "nonru",
			"gate": map[string]interface{}{
				"open":      false,
				"verdict":   "",
				"country":   "",
				"providers": 3,
			},
		})
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	sendResponse(w, rt.Status())
}
