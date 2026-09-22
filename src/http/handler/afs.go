package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/discovery"
	"github.com/daniellavrushin/b4/monitor"
)

// synthesisStatusResponse is the read-only payload of
// GET /api/synthesis/v1/status. It extends the existing Monitoring surface
// (AFS §77) rather than adding a second status owner: Enabled reflects the
// canonical config opt-in, Statuses are the same per-scope lifecycle metadata
// already projected by the Monitor API. It carries no apply authority.
type synthesisStatusResponse struct {
	Enabled        bool                              `json:"enabled"`
	GrammarVersion string                            `json:"grammar_version"`
	Statuses       []monitor.AdaptiveSynthesisStatus `json:"statuses"`
	GeneratedAt    time.Time                         `json:"generated_at"`
}

// synthesisRevertRequest is the operator revert-to-catalog request (AFS §73):
// it targets one exact Monitor scope and carries a human reason.
type synthesisRevertRequest struct {
	Scope  monitor.MonitorScopeKey `json:"scope"`
	Reason string                  `json:"reason,omitempty"`
}

func (api *API) RegisterSynthesisAPI() {
	api.mux.HandleFunc("/api/synthesis/v1/status", api.handleSynthesisStatus)
	api.mux.HandleFunc("/api/synthesis/v1/revert", api.handleSynthesisRevert)
}

// @Summary Get adaptive strategy synthesis status
// @Description Read-only AFS status: the canonical config opt-in plus the per-scope synthesized lifecycle projection. Never mutates configuration.
// @Tags Synthesis
// @Produce json
// @Success 200 {object} synthesisStatusResponse
// @Failure 405 {string} string "Method not allowed"
// @Security BearerAuth
// @Router /synthesis/v1/status [get]
func (api *API) handleSynthesisStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	response := synthesisStatusResponse{
		GrammarVersion: discovery.AutomaticStrategyGrammarV1().Version,
		Statuses:       []monitor.AdaptiveSynthesisStatus{},
		GeneratedAt:    time.Now().UTC(),
	}
	if cfg := api.getCfg(); cfg != nil {
		response.Enabled = cfg.AdaptiveSynthesisAllowed("")
	}
	if globalMonitoring != nil {
		for _, status := range globalMonitoring.StatusList() {
			response.Statuses = append(response.Statuses, status.AdaptiveSynthesis)
		}
	}
	sendResponse(w, response)
}

// @Summary Revert synthesized winners for a scope
// @Description Revert-to-catalog (AFS §73): clears the synthesized lifecycle projection for the exact Monitor scope and permanently quarantines its persisted synthesized winners. Idempotent; never mutates production configuration.
// @Tags Synthesis
// @Accept json
// @Produce json
// @Param body body synthesisRevertRequest true "Revert request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {string} string "Invalid request"
// @Failure 409 {string} string "Lifecycle cannot be reverted in its current state"
// @Security BearerAuth
// @Router /synthesis/v1/revert [post]
func (api *API) handleSynthesisRevert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var request synthesisRevertRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := decoder.Decode(&request); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid revert request: "+err.Error())
		return
	}
	if !request.Scope.Valid() {
		writeJsonError(w, http.StatusBadRequest, "a valid monitoring scope is required")
		return
	}
	reason := strings.TrimSpace(request.Reason)
	if reason == "" {
		reason = "operator revert"
	}
	now := time.Now().UTC()

	// Quarantine first: an operator revert must not leave a reusable winner even
	// if the lifecycle reset below refuses an active state.
	quarantined := 0
	if cfg := api.getCfg(); cfg != nil && cfg.ConfigPath != "" {
		history := discovery.LoadDiscoveryHistory(cfg.ConfigPath)
		quarantined = history.QuarantineSynthesizedWinnersForScope(request.Scope, reason, now)
		if err := history.Save(cfg.ConfigPath); err != nil {
			writeJsonError(w, http.StatusInternalServerError, "failed to persist winner quarantine")
			return
		}
	}
	lifecycleReset := false
	if globalMonitoring != nil {
		if err := globalMonitoring.ResetAdaptiveSynthesis(request.Scope, now); err != nil {
			writeJsonError(w, http.StatusConflict, err.Error())
			return
		}
		lifecycleReset = true
	}
	sendResponse(w, map[string]any{
		"success":             true,
		"scope":               request.Scope,
		"reason":              reason,
		"quarantined_winners": quarantined,
		"lifecycle_reset":     lifecycleReset,
	})
}
