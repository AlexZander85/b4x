package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

// RegisterObservabilityAPI exposes the bounded classifier/action diagnostics
// surface. The issue bundle is intentionally separate from raw capture
// download endpoints and never enables raw packet export implicitly.
func (api *API) RegisterObservabilityAPI() {
	api.mux.HandleFunc("/api/diagnostics/issue-bundle", api.handleIssueBundle)
	api.mux.HandleFunc("/api/observability/metrics", api.handleObservabilityMetrics)
	api.RegisterFailureInboxAPI()
	api.RegisterClientHelloLabAPI()
}

// @Summary Export a privacy-safe issue bundle
// @Tags Diagnostics
// @Produce json
// @Success 200 {object} observability.IssueBundle
// @Security BearerAuth
// @Router /diagnostics/issue-bundle [get]
func (api *API) handleIssueBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	now := time.Now()
	cfg := api.getCfg()
	queue := observability.QueueSummary{Status: "invalid_config"}
	configHash := ""
	if cfg != nil {
		captureInfo := collectCaptureEnvelopeInfo(cfg)
		queue = observability.QueueSummary{
			Ready:                 captureInfo.QueueReady,
			ProcessedMarkVerified: captureInfo.ProcessedMarkVerified,
			OffloadSuspected:      captureInfo.FlowOffloadBypassSuspected,
			QueueDrops:            captureInfo.QueueDrops,
			UserDrops:             captureInfo.UserDrops,
			Status:                captureInfo.Status,
		}
		if encoded, err := json.Marshal(cfg.System.Classifier); err == nil {
			configHash = observability.RedactIdentifier(string(encoded))
		}
	}

	bundle := observability.Default().Bundle(observability.BundleMeta{
		Version:     Version,
		Commit:      Commit,
		ConfigHash:  configHash,
		GeneratedAt: now,
		Queue:       queue,
	})
	if api.ppeProduct != nil {
		sendResponse(w, struct {
			observability.IssueBundle
			PPE any `json:"ppe"`
		}{IssueBundle: bundle, PPE: api.ppeProduct.IssueBundle(r.Context())})
		return
	}
	sendResponse(w, bundle)
}

// @Summary Get bounded classifier/action metrics
// @Tags Diagnostics
// @Produce json
// @Success 200 {object} observability.MetricsSnapshot
// @Security BearerAuth
// @Router /observability/metrics [get]
func (api *API) handleObservabilityMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sendResponse(w, observability.Default().Metrics.Snapshot(time.Now()))
}
