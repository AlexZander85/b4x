package handler

// E-TOR HTTP API (design §9.5): the fxvpn handler canon — atomic runtime
// pointer, nil-safe disabled shapes, 4 KB body limit, swagger annotations.
// Endpoints:
//
//      GET  /api/tor/status          — the full status projection
//      POST /api/tor/restart         — teardown + restart from the winner
//      POST /api/tor/newnym          — rotate circuits
//      PUT  /api/tor/entry           — switch entry mode (validated, persisted)
//      GET  /api/tor/bridges         — stored bridge list + freshness
//      POST /api/tor/bridges/refresh — one conveyor pass (bounded)

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/torservice"
	"github.com/daniellavrushin/b4/transport/tor"
)

// torRuntime is the package-level injection seam (the fxvpn canon):
// main wires the assembled runtime; handlers stay thin and nil-safe.
var torRuntime atomic.Pointer[torservice.Runtime]

// SetTorRuntime wires the engine (nil = disabled shape).
func SetTorRuntime(rt *torservice.Runtime) { torRuntime.Store(rt) }

// torRuntimeLoad is the nil-safe load.
func torRuntimeLoad() *torservice.Runtime { return torRuntime.Load() }

// RegisterTorApi mounts the endpoints.
func (api *API) RegisterTorApi() {
	api.mux.HandleFunc("/api/tor/status", api.handleTorStatus)
	api.mux.HandleFunc("/api/tor/restart", api.handleTorRestart)
	api.mux.HandleFunc("/api/tor/newnym", api.handleTorNewnym)
	api.mux.HandleFunc("/api/tor/entry", api.handleTorEntry)
	api.mux.HandleFunc("/api/tor/bridges", api.handleTorBridges)
	api.mux.HandleFunc("/api/tor/bridges/refresh", api.handleTorBridgesRefresh)
	api.mux.HandleFunc("/api/tor/scan", api.handleTorScan)
}

// torDisabledStatus is the truthful minimal shape (nil runtime / config off).
func torDisabledStatus(cfg config.TorConfig) map[string]any {
	return map[string]any{
		"enabled":   cfg.Enabled,
		"running":   false,
		"listening": false,
		"state":     "idle",
		"entry":     map[string]any{"mode": cfg.EffectiveEntryMode()},
		"egress": map[string]any{
			"through":      cfg.EffectiveEgressThrough(),
			"bait_profile": cfg.EffectiveBaitProfile(),
		},
	}
}

// torErr builds an APIError.
func torErr(status int, code, msg string) error {
	return &APIError{Status: status, Code: code, Message: msg}
}

// @Summary Tor reserve tunnel status
// @Description Full E-TOR status: state machine, entry ladder, bridges, bootstrap progress, egress policy, exit probe, events ring
// @Tags tor
// @Produce json
// @Success 200 {object} torservice.Status
// @Failure 503 {object} ErrorResponse
// @Security BearerAuth
// @Router /tor/status [get]
func (api *API) handleTorStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		writeAPIError(w, torErr(http.StatusMethodNotAllowed, "method", "GET only"))
		return
	}
	cfg := api.cfgPtr.Load().System.Tor
	rt := torRuntimeLoad()
	if !cfg.Enabled || rt == nil {
		sendResponse(w, torDisabledStatus(cfg))
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	sendResponse(w, rt.Status())
}

// @Summary Restart the tor engine
// @Description Teardown + restart from the last working entry (the restart guard applies)
// @Tags tor
// @Produce json
// @Success 200 {object} torservice.Status
// @Failure 409 {object} ErrorResponse
// @Security BearerAuth
// @Router /tor/restart [post]
func (api *API) handleTorRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, torErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	cfg := api.cfgPtr.Load().System.Tor
	rt := torRuntimeLoad()
	if !cfg.Enabled {
		writeAPIError(w, torErr(http.StatusConflict, "disabled", "tor disabled"))
		return
	}
	if rt == nil {
		writeAPIError(w, torErr(http.StatusServiceUnavailable, "unavailable", "tor runtime not wired"))
		return
	}
	go rt.RestartNow(r.Context())
	sendResponse(w, rt.Status())
}

// @Summary Rotate tor circuits
// @Description SIGNAL NEWNYM (circuit rotation without teardown)
// @Tags tor
// @Produce json
// @Success 200 {object} torservice.Status
// @Failure 409 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Security BearerAuth
// @Router /tor/newnym [post]
func (api *API) handleTorNewnym(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, torErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	cfg := api.cfgPtr.Load().System.Tor
	rt := torRuntimeLoad()
	if !cfg.Enabled {
		writeAPIError(w, torErr(http.StatusConflict, "disabled", "tor disabled"))
		return
	}
	if rt == nil {
		writeAPIError(w, torErr(http.StatusServiceUnavailable, "unavailable", "tor runtime not wired"))
		return
	}
	if err := rt.Newnym(); err != nil {
		writeAPIError(w, torErr(http.StatusConflict, "not_listening", err.Error()))
		return
	}
	sendResponse(w, rt.Status())
}

type torEntryRequest struct {
	Mode string `json:"mode"`
}

// @Summary Switch the tor entry mode
// @Description Validate + persist to b4.json + restart the ladder from the new mode
// @Tags tor
// @Accept json
// @Produce json
// @Param body body torEntryRequest true "entry mode"
// @Success 200 {object} torservice.Status
// @Failure 400 {object} ErrorResponse
// @Failure 409 {object} ErrorResponse
// @Security BearerAuth
// @Router /tor/entry [put]
func (api *API) handleTorEntry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeAPIError(w, torErr(http.StatusMethodNotAllowed, "method", "PUT only"))
		return
	}
	var req torEntryRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeAPIError(w, ErrBadRequest("bad json: "+err.Error()))
		return
	}
	if !torservice.IsValidEntryMode(req.Mode) {
		// validation BEFORE the runtime checks: a bad mode is a client
		// error whatever the wiring state (a typo cannot hide behind a 503)
		writeAPIError(w, ErrBadRequest("mode must be one of: auto|webtunnel|obfs4|snowflake|meek|vanilla|direct"))
		return
	}
	cfg := api.cfgPtr.Load().System.Tor
	if !cfg.Enabled {
		writeAPIError(w, torErr(http.StatusConflict, "disabled", "tor disabled"))
		return
	}
	rt := torRuntimeLoad()
	if rt == nil {
		writeAPIError(w, torErr(http.StatusServiceUnavailable, "unavailable", "tor runtime not wired"))
		return
	}
	// persist b4.json (the owner's config survives the reboot)
	cur := api.cfgPtr.Load()
	cur.System.Tor.Entry.Mode = req.Mode
	if err := cur.SaveToFile(cur.ConfigPath); err != nil {
		writeAPIError(w, ErrInternal("persist config: "+err.Error()))
		return
	}
	rt.SetEntry(req.Mode)
	go rt.RestartNow(r.Context())
	sendResponse(w, rt.Status())
}

// @Summary Stored tor bridges
// @Description The bridges.json projection: lines, freshness, source, last collection error
// @Tags tor
// @Produce json
// @Success 200 {object} tor.BridgesFile
// @Security BearerAuth
// @Router /tor/bridges [get]
func (api *API) handleTorBridges(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeAPIError(w, torErr(http.StatusMethodNotAllowed, "method", "GET only"))
		return
	}
	cfg := api.cfgPtr.Load().System.Tor
	rt := torRuntimeLoad()
	if !cfg.Enabled || rt == nil {
		sendResponse(w, tor.BridgesFile{Schema: tor.BridgesFileSchema})
		return
	}
	sendResponse(w, rt.BridgesList())
}

// @Summary Force one bridge collection pass
// @Description Run the conveyor (mirror race + Moat + probes, bounded by the collector budgets)
// @Tags tor
// @Produce json
// @Success 200 {object} tor.BridgesFile
// @Failure 409 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Security BearerAuth
// @Router /tor/bridges/refresh [post]
func (api *API) handleTorBridgesRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, torErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	cfg := api.cfgPtr.Load().System.Tor
	if !cfg.Enabled {
		writeAPIError(w, torErr(http.StatusConflict, "disabled", "tor disabled"))
		return
	}
	rt := torRuntimeLoad()
	if rt == nil {
		writeAPIError(w, torErr(http.StatusServiceUnavailable, "unavailable", "tor runtime not wired"))
		return
	}
	f, err := rt.RefreshBridges(r.Context())
	if err != nil {
		writeAPIError(w, ErrInternal("collect: "+err.Error()))
		return
	}
	sendResponse(w, f)
}

// @Summary Run the vanilla relay scanner
// @Description One bounded scan run: onionoo fallback chain + deep probes + bandwidth ranking; vanilla lines persisted
// @Tags tor
// @Produce json
// @Success 200 {object} torscan.Result
// @Failure 409 {object} ErrorResponse
// @Failure 503 {object} ErrorResponse
// @Security BearerAuth
// @Router /tor/scan [post]
func (api *API) handleTorScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, torErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	cfg := api.cfgPtr.Load().System.Tor
	if !cfg.Enabled {
		writeAPIError(w, torErr(http.StatusConflict, "disabled", "tor disabled"))
		return
	}
	rt := torRuntimeLoad()
	if rt == nil {
		writeAPIError(w, torErr(http.StatusServiceUnavailable, "unavailable", "tor runtime not wired"))
		return
	}
	res, err := rt.ScanNow(r.Context())
	if err != nil {
		writeAPIError(w, ErrInternal("scan: "+err.Error()))
		return
	}
	sendResponse(w, res)
}
