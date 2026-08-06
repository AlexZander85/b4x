package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/daniellavrushin/b4/serviceprofile"
)

const warpRecommendationAPIPath = "/api/v1/service-profiles/warp-recommendation"

// warpCompileRequest is the mutated payload of POST
// /api/v1/service-profiles/warp-recommendation/compile. It carries the raw
// candidate recommendation plus the live context flags the §28A.11 hard-gate
// checks evaluate (IP-path evidence, origin aliveness, control health,
// consuming service and FB-31 evidence authority).
type warpCompileRequest struct {
	Recommendation    serviceprofile.TransportRecommendation `json:"recommendation"`
	IPPathEvidence    bool                                   `json:"ip_path_evidence"`
	OriginAlive       bool                                   `json:"origin_alive"`
	ControlsHealthy   bool                                   `json:"controls_healthy"`
	ConsumerService   string                                 `json:"consumer_service"`
	EvidenceAuthority string                                 `json:"evidence_authority"`
}

// warpBeginTestRequest is the payload of POST
// /api/v1/service-profiles/warp-recommendation/begin-test: the full fresh
// eligible recommendation (the client persists the compiled recommendation
// and re-submits it — the endpoint never trusts a bare id).
type warpBeginTestRequest struct {
	Recommendation serviceprofile.TransportRecommendation `json:"recommendation"`
}

// warpValidateRequest commits a completed §28A.6 validation result to an open
// test transaction.
type warpValidateRequest struct {
	RecommendationID   string                                  `json:"recommendation_id"`
	Validation         serviceprofile.RecommendationValidation `json:"validation"`
	RegressionReported bool                                    `json:"regression_reported"`
}

// warpApplyRequest authorizes production for a validated recommendation.
type warpApplyRequest struct {
	RecommendationID      string `json:"recommendation_id"`
	ForwardedCanaryPassed bool   `json:"forwarded_canary_passed"`
}

// warpRecommendationStatusResponse is the read-only status projection of the
// WARP-recommendation control surface (§28A.5/§28A.8): the live capability
// projection (optionally rendered as the canonical warp_recommendation YAML)
// and the redacted recommendation inventory.
type warpRecommendationStatusResponse struct {
	RuntimeReady           bool                                    `json:"runtime_ready"`
	Projection             serviceprofile.WARPProjection           `json:"projection,omitempty"`
	WarpRecommendationYAML string                                  `json:"warp_recommendation_yaml,omitempty"`
	Recommendations        []serviceprofile.RecommendationSnapshot `json:"recommendations,omitempty"`
	GeneratedAt            time.Time                               `json:"generated_at"`
}

// RegisterServiceProfileAPI wires the WARP-recommendation control plane
// (SP-30/SP-31: status projection, bounded test transaction, validation and
// scoped production enablement) into the HTTP API. The endpoints are the
// production surface of the service-profile runtime created in main; they
// fail closed with 503 Service Unavailable when the runtime is not running.
func (api *API) RegisterServiceProfileAPI() {
	api.mux.HandleFunc(warpRecommendationAPIPath+"/status", api.handleWARPRecommendationStatus)
	api.mux.HandleFunc(warpRecommendationAPIPath+"/compile", api.handleWARPRecommendationCompile)
	api.mux.HandleFunc(warpRecommendationAPIPath+"/begin-test", api.handleWARPRecommendationBeginTest)
	api.mux.HandleFunc(warpRecommendationAPIPath+"/validate", api.handleWARPRecommendationValidate)
	api.mux.HandleFunc(warpRecommendationAPIPath+"/apply", api.handleWARPRecommendationApply)
}

func (api *API) serviceProfileRuntime() *serviceprofile.Runtime {
	return globalServiceProfile
}

func (api *API) handleWARPRecommendationStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rt := api.serviceProfileRuntime()
	if rt == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "service-profile runtime is not initialized")
		return
	}
	resp := warpRecommendationStatusResponse{
		RuntimeReady:    true,
		GeneratedAt:     time.Now().UTC(),
		Recommendations: rt.Recommendations(),
	}
	projection := rt.Projection()
	if projection.RuntimeState != "" {
		resp.Projection = projection
		if yaml, err := projection.MarshalWARPRecommendation(); err == nil {
			resp.WarpRecommendationYAML = string(yaml)
		}
	}
	sendResponse(w, resp)
}

func (api *API) handleWARPRecommendationCompile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rt := api.serviceProfileRuntime()
	if rt == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "service-profile runtime is not initialized")
		return
	}
	var req warpCompileRequest
	if err := decodeServiceProfileRequest(w, r, &req); err != nil {
		return
	}
	compiled, err := rt.Compile(time.Now(), req.Recommendation, serviceprofile.LifecycleEvent{
		IPPathEvidence:    req.IPPathEvidence,
		OriginAlive:       req.OriginAlive,
		ControlsHealthy:   req.ControlsHealthy,
		ConsumerService:   req.ConsumerService,
		EvidenceAuthority: req.EvidenceAuthority,
		// The causal-trace and path-proof gates run against the live
		// §28A.5 capability projection the daemon observed — never against
		// caller-supplied claims.
		Projection: rt.Projection(),
	})
	if err != nil {
		writeJsonError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	setJsonHeader(w)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(compiled)
}

func (api *API) handleWARPRecommendationBeginTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rt := api.serviceProfileRuntime()
	if rt == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "service-profile runtime is not initialized")
		return
	}
	var req warpBeginTestRequest
	if err := decodeServiceProfileRequest(w, r, &req); err != nil {
		return
	}
	tx, err := rt.BeginTest(time.Now(), req.Recommendation)
	if err != nil {
		writeJsonError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	snapshot, ok := rt.Snapshot(req.Recommendation.RecommendationID)
	if !ok {
		snapshot = serviceprofile.RecommendationSnapshot{
			RecommendationID: req.Recommendation.RecommendationID,
			State:            tx.Recommendation.State,
			TestTokenActive:  true,
		}
	}
	setJsonHeader(w)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(snapshot)
}

func (api *API) handleWARPRecommendationValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rt := api.serviceProfileRuntime()
	if rt == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "service-profile runtime is not initialized")
		return
	}
	var req warpValidateRequest
	if err := decodeServiceProfileRequest(w, r, &req); err != nil {
		return
	}
	state, err := rt.ValidateTransaction(req.RecommendationID, req.Validation, req.RegressionReported)
	if err != nil {
		writeJsonError(w, http.StatusConflict, err.Error())
		return
	}
	setJsonHeader(w)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"recommendation_id": req.RecommendationID,
		"state":             state,
	})
}

func (api *API) handleWARPRecommendationApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rt := api.serviceProfileRuntime()
	if rt == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "service-profile runtime is not initialized")
		return
	}
	var req warpApplyRequest
	if err := decodeServiceProfileRequest(w, r, &req); err != nil {
		return
	}
	if err := rt.Enable(req.RecommendationID, rt.Projection(), req.ForwardedCanaryPassed); err != nil {
		writeJsonError(w, http.StatusConflict, err.Error())
		return
	}
	snapshot, ok := rt.Snapshot(req.RecommendationID)
	if !ok {
		writeJsonError(w, http.StatusInternalServerError, "recommendation disappeared after enablement")
		return
	}
	sendResponse(w, snapshot)
}

func decodeServiceProfileRequest(w http.ResponseWriter, r *http.Request, dst any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid request: "+err.Error())
		return err
	}
	return nil
}
