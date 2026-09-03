package handler

import (
	"encoding/json"
	"net/http"
	"time"
)

// MonitorV1Response is the read-only payload of GET /api/monitor/v1: the
// current monitor status projections (scope health, visibility, suppression)
// and the timestamp of the snapshot. Perfect monitoring is read-only by
// design — this endpoint never mutates configuration.
//
// CompatibilityProjection is always true: per MON addendum v1.0 §58 the v2
// API must expose compatibility_projection=true so clients can distinguish
// the projection surface from legacy sources of truth.
type MonitorV1Response struct {
	Statuses                []json.RawMessage `json:"statuses,omitempty"`
	GeneratedAt             time.Time         `json:"generated_at"`
	CompatibilityProjection bool              `json:"compatibility_projection"`
}

func (api *API) RegisterMonitorAPI() {
	api.mux.HandleFunc("/api/monitor/v1", api.handleMonitorV1)
}

// @Summary Get monitoring status projections
// @Description Returns the current MON -> ABD -> DDI monitoring projections (per-scope health, visibility, suppression state). Read-only: this endpoint never mutates configuration.
// @Tags Monitor
// @Produce json
// @Success 200 {object} MonitorV1Response
// @Failure 405 {string} string "Method not allowed"
// @Security BearerAuth
// @Router /monitor/v1 [get]
func (api *API) handleMonitorV1(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rt := globalMonitoring
	if rt == nil {
		http.Error(w, "monitoring runtime is not running", http.StatusServiceUnavailable)
		return
	}
	statuses := rt.StatusList()
	raw := make([]json.RawMessage, 0, len(statuses))
	for i := range statuses {
		b, err := json.Marshal(statuses[i])
		if err != nil {
			continue
		}
		raw = append(raw, b)
	}
	setJsonHeader(w)
	json.NewEncoder(w).Encode(MonitorV1Response{
		Statuses:                raw,
		GeneratedAt:             time.Now().UTC(),
		CompatibilityProjection: true, // MON addendum v1.0 §58: projection surface marker
	})
}
