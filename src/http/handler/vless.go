package handler

import (
	"net/http"
	"sync/atomic"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/vlessservice"
)

// vlessRuntime is the package-level injection seam (SetOperaRuntime pattern):
// main wires the assembled runtime; handlers stay thin. Nil is a valid state —
// the disabled shape answers truthfully.
var vlessRuntime atomic.Pointer[vlessservice.Runtime]

// SetVlessRuntime binds (or unbinds, nil) the vless runtime for handlers.
func SetVlessRuntime(rt *vlessservice.Runtime) { vlessRuntime.Store(rt) }

// RegisterVlessApi mounts the /api/vless/* surface (parity with /api/opera/*).
func (api *API) RegisterVlessApi() {
	api.mux.HandleFunc("/api/vless/status", api.handleVlessStatus)
}

func vlessDisabledStatus(cfg config.VLESSConfig) map[string]interface{} {
	// Truthful shape when the runtime cannot serve requests (disabled by
	// config OR not wired): config facts only, honest zeros elsewhere.
	return map[string]interface{}{
		"enabled":     cfg.Enabled,
		"running":     false,
		"helper":      cfg.Helper,
		"socks_addr":  cfg.SocksAddr,
		"transport":   "tcp-only",
		"node_count":  0,
		"active_node": "",
	}
}

// handleVlessStatus answers GET /api/vless/status.
//
//	@Summary VLESS(+REALITY) reserve transport status
//	@Description Runtime state: helper kind, local SOCKS5 inbound, node count,
//	@Description redacted subscriptions and the event tail. TCP-only in V1.
//	@Description Disabled transport answers a minimal shape.
//	@Tags vless
//	@Produce json
//	@Success 200 {object} vlessservice.Status
//	@Router /vless/status [get]
func (api *API) handleVlessStatus(w http.ResponseWriter, r *http.Request) {
	cfg := api.cfgPtr.Load().System.Vless
	rt := vlessRuntime.Load()
	if !cfg.Enabled || rt == nil {
		sendResponse(w, vlessDisabledStatus(cfg))
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	sendResponse(w, rt.Status())
}
