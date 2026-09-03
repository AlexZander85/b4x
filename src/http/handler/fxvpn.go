package handler

import (
	"encoding/json"
	"net/http"
	"sync/atomic"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/fxvpservice"
)

// fxvpnRuntime is the package-level injection seam (SetClientHelloSession-
// Controller pattern): main wires the assembled runtime; handlers stay thin.
var fxvpnRuntime atomic.Pointer[fxvpservice.Runtime]

// SetFxvpnRuntime binds (or unbinds, nil) the fxvpn runtime for handlers.
func SetFxvpnRuntime(rt *fxvpservice.Runtime) { fxvpnRuntime.Store(rt) }

// RegisterFxvpnApi mounts the /api/fxvpn/* surface (design Дополнение 3).
func (api *API) RegisterFxvpnApi() {
	api.mux.HandleFunc("/api/fxvpn/status", api.handleFxvpnStatus)
	api.mux.HandleFunc("/api/fxvpn/locations", api.handleFxvpnLocations)
	api.mux.HandleFunc("/api/fxvpn/location", api.handleFxvpnLocation)
	api.mux.HandleFunc("/api/fxvpn/restart", api.handleFxvpnRestart)
	api.mux.HandleFunc("/api/fxvpn/accounts/test", api.handleFxvpnAccountTest)
}

func fxvpnDisabledStatus(cfg config.FxVPNConfig) map[string]interface{} {
	// Truthful shape when the runtime cannot serve requests (disabled by
	// config OR not wired): config facts only, honest zeros elsewhere.
	return map[string]interface{}{
		"enabled":   cfg.Enabled,
		"running":   false,
		"listening": false,
		"transport": "tcp-only",
		"location":  cfg.Location,
	}
}

// handleFxvpnStatus answers GET /api/fxvpn/status.
//
//	@Summary Firefox VPN reserve transport status
//	@Description Runtime state: running/listening split, active account,
//	@Description quota, verified exit vs configured location, pool table,
//	@Description event tail. Disabled transport answers a minimal shape.
//	@Tags fxvpn
//	@Produce json
//	@Success 200 {object} fxvpservice.Status
//	@Router /fxvpn/status [get]
func (api *API) handleFxvpnStatus(w http.ResponseWriter, r *http.Request) {
	cfg := api.cfgPtr.Load().System.FxVPN
	rt := fxvpnRuntime.Load()
	if !cfg.Enabled || rt == nil {
		sendResponse(w, fxvpnDisabledStatus(cfg))
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	sendResponse(w, rt.Status())
}

// handleFxvpnLocations answers GET /api/fxvpn/locations.
//
//	@Summary Normalized server list for the location dropdown
//	@Tags fxvpn
//	@Produce json
//	@Success 200 {object} fxvpservice.LocationsView
//	@Failure 503 {string} string "server list unavailable"
//	@Router /fxvpn/locations [get]
func (api *API) handleFxvpnLocations(w http.ResponseWriter, r *http.Request) {
	rt := fxvpnRuntime.Load()
	if rt == nil {
		writeAPIError(w, fxErr(http.StatusServiceUnavailable, "unavailable", "fxvpn runtime not wired"))
		return
	}
	view, err := rt.Locations(r.Context())
	if err != nil {
		writeAPIError(w, fxErr(http.StatusServiceUnavailable, "serverlist", err.Error()))
		return
	}
	sendResponse(w, view)
}

type fxvpnLocationRequest struct {
	Mode    string `json:"mode"`
	Country string `json:"country"`
	City    string `json:"city"`
	Host    string `json:"host"`
}

// handleFxvpnLocation answers PUT /api/fxvpn/location: validate against the
// cached list, apply in-memory, kick one supervision cycle, answer with the
// fresh status. Persistence of b4.json belongs to the generic config API.
//
//	@Summary Switch serving location
//	@Tags fxvpn
//	@Accept json
//	@Produce json
//	@Param body body fxvpnLocationRequest true "desired location"
//	@Success 200 {object} fxvpservice.Status
//	@Failure 400 {string} string "validation error"
//	@Failure 503 {string} string "server list unavailable"
//	@Router /fxvpn/location [put]
func (api *API) handleFxvpnLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeAPIError(w, fxErr(http.StatusMethodNotAllowed, "method", "PUT only"))
		return
	}
	rt := fxvpnRuntime.Load()
	if rt == nil || !api.cfgPtr.Load().System.FxVPN.Enabled {
		writeAPIError(w, fxErr(http.StatusConflict, "disabled", "fxvpn disabled"))
		return
	}
	var req fxvpnLocationRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeAPIError(w, ErrBadRequest("bad json: "+err.Error()))
		return
	}
	loc := config.FxVPNLocation{Mode: req.Mode, Country: req.Country, City: req.City, Host: req.Host}
	if err := rt.ValidateLocation(r.Context(), loc); err != nil {
		writeAPIError(w, ErrBadRequest(err.Error()))
		return
	}
	rt.SetLocation(loc)
	go rt.RestartNow(r.Context())
	sendResponse(w, rt.Status())
}

// handleFxvpnRestart answers POST /api/fxvpn/restart.
//
//	@Summary Force one supervision cycle (restart caps still apply)
//	@Tags fxvpn
//	@Produce json
//	@Success 200 {object} fxvpservice.Status
//	@Router /fxvpn/restart [post]
func (api *API) handleFxvpnRestart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, fxErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	rt := fxvpnRuntime.Load()
	if rt == nil || !api.cfgPtr.Load().System.FxVPN.Enabled {
		writeAPIError(w, fxErr(http.StatusConflict, "disabled", "fxvpn disabled"))
		return
	}
	rt.RestartNow(r.Context())
	sendResponse(w, rt.Status())
}

// handleFxvpnAccountTest answers POST /api/fxvpn/accounts/test.
//
//	@Summary Check account credentials without enabling the tunnel
//	@Description Refresh-token path or interactive login (needs_code=true
//	@Description when FxA demands the emailed confirmation code).
//	@Tags fxvpn
//	@Accept json
//	@Produce json
//	@Param body body fxvpservice.TestAccountInput true "credentials"
//	@Success 200 {object} fxvpservice.TestAccountResult
//	@Router /fxvpn/accounts/test [post]
func (api *API) handleFxvpnAccountTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeAPIError(w, fxErr(http.StatusMethodNotAllowed, "method", "POST only"))
		return
	}
	var in fxvpservice.TestAccountInput
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
		writeAPIError(w, ErrBadRequest("bad json: "+err.Error()))
		return
	}
	rt := fxvpnRuntime.Load()
	if rt == nil {
		writeAPIError(w, fxErr(http.StatusServiceUnavailable, "unavailable", "fxvpn runtime not wired"))
		return
	}
	sendResponse(w, rt.TestAccount(r.Context(), in))
}

func fxErr(status int, code, msg string) error {
	return &APIError{Status: status, Code: code, Message: msg}
}
