package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
)

type PPECapabilityProvider interface {
	Detect(context.Context) ppe.CapabilityReport
}

func (api *API) RegisterCaptureOffloadAPI() {
	api.mux.HandleFunc("/api/v1/capture/offload/capabilities", api.handleCaptureOffloadCapabilities)
}

func (api *API) handleCaptureOffloadCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	provider := api.ppeCapabilities
	if provider == nil {
		provider = ppe.NewDetector(nil)
	}
	sendResponse(w, provider.Detect(ctx))
}
