package handler

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/protonservice"
)

// protonRuntime is the package-level injection seam (SetFxvpnRuntime
// pattern): main wires the assembled runtime; handlers stay thin.
var protonRuntime atomic.Pointer[protonservice.Runtime]

// SetProtonRuntime binds (or unbinds, nil) the proton runtime for handlers.
func SetProtonRuntime(rt *protonservice.Runtime) { protonRuntime.Store(rt) }

// RegisterProtonApi mounts the /api/proton/* surface (E-PROTON design §7,
// patch-plan §7.2).
func (api *API) RegisterProtonApi() {
	api.mux.HandleFunc("/api/proton/status", api.handleProtonStatus)
	api.mux.HandleFunc("/api/proton/locations", api.handleProtonLocations)
	api.mux.HandleFunc("/api/proton/location", api.handleProtonLocation)
	api.mux.HandleFunc("/api/proton/restart", api.handleProtonRestart)
	api.mux.HandleFunc("/api/proton/reissue", api.handleProtonReissue)
}

func protonDisabledStatus(cfg config.ProtonConfig) map[string]interface{} {
	// Truthful shape when the runtime cannot serve requests (disabled by
	// config OR not wired): config facts only, honest zeros elsewhere.
	return map[string]interface{}{
		"enabled":   cfg.Enabled,
		"running":   false,
		"listening": false,
		"state":     "idle",
		"transport": "udp-full-scope",
		"location":  cfg.Location,
	}
}

// handleProtonStatus answers GET /api/proton/status.
//
//	@Summary Proton VPN reserve transport status
//	@Description Runtime state: running/listening split, lifecycle state,
//	@Description active profile/node/port, certificate timing, redacted
//	@Description identity projection, event tail. Disabled transport answers
//	@Description a minimal shape.
//	@Tags proton
//	@Produce json
//	@Success 200 {object} protonservice.Status
//	@Router /proton/status [get]
func (api *API) handleProtonStatus(w http.ResponseWriter, r *http.Request) {
	cfg := api.cfgPtr.Load().System.Proton
	rt := protonRuntime.Load()
	if !cfg.Enabled || rt == nil {
		sendResponse(w, protonDisabledStatus(cfg))
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	sendResponse(w, rt.Status())
}

// handleProtonLocations answers GET /api/proton/locations.
//
//	@Summary Cached free-node catalog for the location dropdown
//	@Description Countries -> cities -> nodes from the cached list with load
//	@Description marks and the snapshot source (live-v2|live-v1|asset).
//	@Tags proton
//	@Produce json
//	@Success 200 {object} proton.LocationsView
//	@Failure 503 {string} string "node catalog unavailable"
//	@Router /proton/locations [get]
func (api *API) handleProtonLocations(w http.ResponseWriter, r *http.Request) {
	rt := protonRuntime.Load()
	if rt == nil {
		writeAPIError(w, protonErr(http.StatusServiceUnavailable, "unavailable", "proton runtime not wired"))
		return
	}
	view, err := rt.Locations(r.Context())
	if err != nil {
		writeAPIError(w, protonErr(http.StatusServiceUnavailable, "serverlist", err.Error()))
		return
	}
	sendResponse(w, view)
}

type protonLocationRequest struct {
	Mode    string `json:"mode"`
	Country string `json:"country"`
	Host    string `json:"host"`
}

// handleProtonLocation answers PUT /api/proton/location: validate against
// the cached catalog, apply in-memory, kick one supervision cycle, answer
// with the fresh status. Persistence of b4.json belongs to the generic
// config API.
//
//	@Summary Switch serving location
//	@Tags proton
//	@Accept json
//	@Produce json
//	@Param body body protonLocationRequest true "desired location"
//	@Success 200 {object} protonservice.Status
//	@Failure 400 {string} string "validation error"
//	@Failure 503 {string} string "node catalog unavailable"
//	@Router /proton/location [put]
func (api *API) handleProtonLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeAPIError(w, protonErr(http.StatusMethodNotAllowed, "method", "PUT only"))
		return
	}
	rt := protonRuntime.Load()
	if rt == nil || !api.cfgPtr.Load().System.Proton.Enabled {
		writeAPIError(w, protonErr(http.StatusConflict, "disabled", "proton disabled"))
		return
	}
	var req protonLocationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeAPIError(w, ErrBadRequest("bad json: "+err.Error()))
		return
	}
	loc := config.ProtonLocation{Mode: req.Mode, Country: req.Country, Host: req.Host}
	if err := rt.ValidateLocation(r.Context(), loc); err != nil {
		writeAPIError(w, ErrBadRequest(err.Error()))
		return
	}
	rt.SetLocation(loc)
	go rt.RestartNow(r.Context())
	sendResponse(w, rt.Status())
}

// handleProtonRestart answers POST /api/proton/restart.
//
//	@Summary Force one supervision cycle (restart caps still apply)
//	@Tags proton
//	@Produce json
//	@Success 200 {object} protonservice.Status
//	@Router /proton/restart [post]
func (api *API) handleProtonRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, protonErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	rt := protonRuntime.Load()
	if rt == nil || !api.cfgPtr.Load().System.Proton.Enabled {
		writeAPIError(w, protonErr(http.StatusConflict, "disabled", "proton disabled"))
		return
	}
	rt.RestartNow(r.Context())
	sendResponse(w, rt.Status())
}

// handleProtonReissue answers POST /api/proton/reissue: the owner-actioned
// re-registration (fresh key + fresh credentialless session; the explicit
// exception to the once-per-boot gate).
//
//	@Summary Manual key/certificate re-issue (explicit owner action)
//	@Description Draws a NEW seed, re-registers with Proton, retires the
//	@Description current session. Caps apply.
//	@Tags proton
//	@Produce json
//	@Success 200 {object} protonservice.Status
//	@Failure 503 {string} string "re-issue failed"
//	@Router /proton/reissue [post]
func (api *API) handleProtonReissue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, protonErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	rt := protonRuntime.Load()
	if rt == nil || !api.cfgPtr.Load().System.Proton.Enabled {
		writeAPIError(w, protonErr(http.StatusConflict, "disabled", "proton disabled"))
		return
	}
	if err := rt.Reissue(r.Context()); err != nil {
		writeAPIError(w, protonErr(http.StatusServiceUnavailable, "reissue", err.Error()))
		return
	}
	sendResponse(w, rt.Status())
}

func protonErr(status int, code, msg string) error {
	return &APIError{Status: status, Code: code, Message: msg}
}
