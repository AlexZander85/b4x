package handler

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/operaservice"
)

// operaRuntime is the package-level injection seam (SetProtonRuntime
// pattern): main wires the assembled runtime; handlers stay thin. Nil is a
// valid state — the disabled shape answers truthfully.
var operaRuntime atomic.Pointer[operaservice.Runtime]

// SetOperaRuntime binds (or unbinds, nil) the opera runtime for handlers.
func SetOperaRuntime(rt *operaservice.Runtime) { operaRuntime.Store(rt) }

// RegisterOperaApi mounts the /api/opera/* surface (E-OPERA review C1:
// parity with /api/fxvpn/* and /api/proton/*).
func (api *API) RegisterOperaApi() {
	api.mux.HandleFunc("/api/opera/status", api.handleOperaStatus)
	api.mux.HandleFunc("/api/opera/region", api.handleOperaRegion)
	api.mux.HandleFunc("/api/opera/restart", api.handleOperaRestart)
}

func operaDisabledStatus(cfg config.OperaConfig) map[string]interface{} {
	// Truthful shape when the runtime cannot serve requests (disabled by
	// config OR not wired): config facts only, honest zeros elsewhere.
	return map[string]interface{}{
		"enabled":   cfg.Enabled,
		"running":   false,
		"listening": false,
		"degraded":  "",
		"transport": "tcp-only",
		"region":    cfg.Region,
	}
}

// handleOperaStatus answers GET /api/opera/status.
//
//	@Summary Opera VPN reserve transport status
//	@Description Runtime state: running/listening split, effective vs desired
//	@Description megaregion, active node, probe verdicts, restart caps,
//	@Description masquerade ladder state. Disabled transport answers a
//	@Description minimal shape.
//	@Tags opera
//	@Produce json
//	@Success 200 {object} operaservice.Status
//	@Router /opera/status [get]
func (api *API) handleOperaStatus(w http.ResponseWriter, r *http.Request) {
	cfg := api.cfgPtr.Load().System.Opera
	rt := operaRuntime.Load()
	if !cfg.Enabled || rt == nil {
		sendResponse(w, operaDisabledStatus(cfg))
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	sendResponse(w, rt.Status())
}

type operaRegionRequest struct {
	Region string `json:"region"`
}

// handleOperaRegion answers PUT /api/opera/region: validate against the
// megaregion whitelist (EU/AS/AM — RU never participates), apply in-memory,
// answer with the fresh status. Persistence of b4.json belongs to the
// generic config API (proton/location parity).
//
//	@Summary Switch desired megaregion
//	@Tags opera
//	@Accept json
//	@Produce json
//	@Param body body operaRegionRequest true "desired region (EU|AS|AM)"
//	@Success 200 {object} operaservice.Status
//	@Failure 400 {string} string "validation error"
//	@Failure 405 {string} string "method not allowed"
//	@Failure 409 {string} string "opera disabled"
//	@Router /opera/region [put]
func (api *API) handleOperaRegion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeAPIError(w, operaErr(http.StatusMethodNotAllowed, "method", "PUT only"))
		return
	}
	rt := operaRuntime.Load()
	if rt == nil || !api.cfgPtr.Load().System.Opera.Enabled {
		writeAPIError(w, operaErr(http.StatusConflict, "disabled", "opera disabled"))
		return
	}
	var req operaRegionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		writeAPIError(w, ErrBadRequest("bad json: "+err.Error()))
		return
	}
	if err := rt.SetRegion(req.Region); err != nil {
		writeAPIError(w, ErrBadRequest(err.Error()))
		return
	}
	sendResponse(w, rt.Status())
}

// handleOperaRestart answers POST /api/opera/restart: kicks one supervision
// step immediately (restart caps + cooldown still apply inside the health
// layer).
//
//	@Summary Force one supervision cycle (restart caps still apply)
//	@Tags opera
//	@Produce json
//	@Success 200 {object} operaservice.Status
//	@Failure 405 {string} string "method not allowed"
//	@Failure 409 {string} string "opera disabled"
//	@Router /opera/restart [post]
func (api *API) handleOperaRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, operaErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	rt := operaRuntime.Load()
	if rt == nil || !api.cfgPtr.Load().System.Opera.Enabled {
		writeAPIError(w, operaErr(http.StatusConflict, "disabled", "opera disabled"))
		return
	}
	rt.Kick(r.Context())
	sendResponse(w, rt.Status())
}

func operaErr(status int, code, msg string) error {
	return &APIError{Status: status, Code: code, Message: msg}
}
