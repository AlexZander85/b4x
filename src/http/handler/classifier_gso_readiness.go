package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/nfq"
)

// classifierGSOReadinessAPIPath is the production entry point for the static
// (operator-provided) part of the GSO readiness evidence. Wire observations
// are NFQ-owned and are never accepted through this API: they stay sticky on
// the packet path.
const classifierGSOReadinessAPIPath = "/api/v2/classifier/gso/readiness"

type classifierGSOReadinessRequest struct {
	Evidence nfq.GSOReadinessEvidence `json:"evidence"`
}

type classifierGSOReadinessResponse struct {
	APIVersion     string                   `json:"api_version"`
	AppliedWorkers int                      `json:"applied_workers"`
	Generation     uint64                   `json:"generation"`
	EvaluatedAt    time.Time                `json:"evaluated_at"`
	Snapshot       nfq.GSOReadinessSnapshot `json:"snapshot"`
}

func (api *API) handleClassifierGSOReadiness(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if err := api.runtimeControlOperationalGate(); err != nil {
		writeJsonError(w, http.StatusConflict, err.Error())
		return
	}
	if api.getCfg() == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "classifier configuration unavailable")
		return
	}
	if globalPool == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "NFQUEUE pool unavailable")
		return
	}
	var request classifierGSOReadinessRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid GSO readiness request: "+err.Error())
		return
	}
	// The operator never picks the generation: the evidence binds to the
	// active configuration generation of each worker. Accepting a foreign
	// generation here would produce a permanent STALE gate.
	request.Evidence.Generation = 0
	applied, snapshot := globalPool.SetGSOReadinessEvidence(request.Evidence)
	if applied == 0 {
		writeJsonError(w, http.StatusServiceUnavailable, "no GSO workers available")
		return
	}
	sendResponse(w, classifierGSOReadinessResponse{
		APIVersion: config.ClassifierHardeningAPIV1, AppliedWorkers: applied,
		Generation: snapshot.ConfigGeneration, EvaluatedAt: time.Now().UTC(), Snapshot: snapshot,
	})
}
