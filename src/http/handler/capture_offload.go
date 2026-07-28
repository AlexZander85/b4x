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

type PPEStatusProvider interface {
	Status(context.Context) ppe.DiagnosticsReport
}

func (api *API) RegisterCaptureOffloadAPI() {
	api.mux.HandleFunc("/api/v1/capture/offload/capabilities", api.handleCaptureOffloadCapabilities)
	api.mux.HandleFunc("/api/v1/capture/offload/status", api.handleCaptureOffloadStatus)
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

func (api *API) handleCaptureOffloadStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	provider := api.ppeStatus
	if provider == nil {
		provider = ppe.NewDiagnosticsService(api.getCfg, ppe.NewDetector(nil), ppe.NewRuleCounterCollector(nil), nil, "b4_managed")
	}
	sendResponse(w, provider.Status(ctx))
}
