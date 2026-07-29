package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/config"
)

type PPEProductController interface {
	Snapshot(context.Context) ppe.ProductStatus
	ApplyConfig(context.Context, *config.Config) (ppe.ProductStatus, error)
	Remove(context.Context) (ppe.ProductStatus, error)
	RunSelfTest(context.Context, ppe.SelfTestRequest) (ppe.CaptureVisibilityResult, error)
	SelfTestResult(string) (ppe.CaptureVisibilityResult, bool)
	IssueBundle(context.Context) ppe.ProductIssueBundle
	ExecuteIdempotent(string, func() (ppe.ProductStatus, error)) (ppe.ProductStatus, error)
}

type ppeMutationRequest struct {
	ExpectedGeneration string `json:"expected_generation"`
	IdempotencyKey     string `json:"idempotency_key,omitempty"`
}

type ppeSelfTestRequest struct {
	ExpectedGeneration string `json:"expected_generation"`
	IdempotencyKey     string `json:"idempotency_key,omitempty"`
	RunID              string `json:"run_id,omitempty"`
	ControlledEndpoint string `json:"controlled_endpoint,omitempty"`
	Family             string `json:"family,omitempty"`
	TCPFlowID          string `json:"tcp_flow_id,omitempty"`
	QUICFlowID         string `json:"quic_flow_id,omitempty"`
	TCPSourcePort      uint16 `json:"tcp_source_port"`
	QUICSourcePort     uint16 `json:"quic_source_port,omitempty"`
	RequireQUIC        bool   `json:"require_quic"`
	TimeoutMS          int    `json:"timeout_ms,omitempty"`
}

func (api *API) handleCaptureOffloadApply(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	request, err := decodePPEMutationRequest(w, r)
	if err != nil {
		writeJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	api.applyCaptureOffloadPolicy(w, r, request, config.OffloadPolicyExclude, "apply")
}

func (api *API) handleCaptureOffloadRollback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	request, err := decodePPEMutationRequest(w, r)
	if err != nil {
		writeJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	api.applyCaptureOffloadPolicy(w, r, request, config.OffloadPolicyDetect, "rollback")
}

func (api *API) applyCaptureOffloadPolicy(w http.ResponseWriter, r *http.Request, request ppeMutationRequest, policy, operation string) {
	controller := api.ppeProduct
	if controller == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "PPE product service is not initialized")
		return
	}
	key := mutationIdempotencyKey(r, request.IdempotencyKey)
	if key == "" {
		writeJsonError(w, http.StatusBadRequest, "Idempotency-Key header or idempotency_key is required")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	status, err := controller.ExecuteIdempotent("ppe:"+operation+":"+key, func() (ppe.ProductStatus, error) {
		current := api.getCfg()
		if current == nil {
			return ppe.ProductStatus{}, errors.New("active configuration is unavailable")
		}
		if err := checkPPEGeneration(controller.Snapshot(ctx), request.ExpectedGeneration); err != nil {
			return ppe.ProductStatus{}, err
		}
		candidate := current.CloneForRuntimeUpdate()
		candidate.ConfigPath = current.ConfigPath
		candidate.System.Classifier.Runtime.Capture.OffloadPolicy = policy
		if err := candidate.Validate(); err != nil {
			return ppe.ProductStatus{}, fmt.Errorf("PPE candidate validation failed: %w", err)
		}
		_, err := controller.ApplyConfig(ctx, candidate)
		if err != nil {
			return ppe.ProductStatus{}, err
		}
		if err := api.saveAndPushConfig(candidate); err != nil {
			_, rollbackErr := controller.ApplyConfig(context.Background(), current)
			if rollbackErr != nil {
				return ppe.ProductStatus{}, errors.Join(err, fmt.Errorf("restore previous PPE rules: %w", rollbackErr))
			}
			return ppe.ProductStatus{}, err
		}
		if classifierCaptureContractChanged(current.System.Classifier, candidate.System.Classifier) {
			api.PerformSoftRestart(candidate, current)
		}
		return controller.Snapshot(ctx), nil
	})
	if err != nil {
		writePPEProductError(w, err)
		return
	}
	sendResponse(w, status)
}

func (api *API) handleCaptureOffloadSelfTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	controller := api.ppeProduct
	if controller == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "PPE product service is not initialized")
		return
	}
	var request ppeSelfTestRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid PPE self-test request: "+err.Error())
		return
	}
	key := mutationIdempotencyKey(r, request.IdempotencyKey)
	if key == "" {
		writeJsonError(w, http.StatusBadRequest, "Idempotency-Key header or idempotency_key is required")
		return
	}
	status := controller.Snapshot(r.Context())
	if err := checkPPEGeneration(status, request.ExpectedGeneration); err != nil {
		writePPEProductError(w, err)
		return
	}
	if status.Desired == nil {
		writeJsonError(w, http.StatusConflict, "per-flow exclusion must be active before running the controlled self-test")
		return
	}
	cfg := api.getCfg()
	if cfg == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "active configuration is unavailable")
		return
	}
	request.RunID = strings.TrimSpace(request.RunID)
	if request.RunID == "" {
		request.RunID = ppeSelfTestRunID(key)
	}
	if existing, ok := controller.SelfTestResult(request.RunID); ok {
		sendResponse(w, existing)
		return
	}
	if request.Family == "" {
		request.Family = "ipv4"
	}
	if request.ControlledEndpoint == "" {
		request.ControlledEndpoint = cfg.System.Classifier.Runtime.Capture.PPE.SelfTest.ControlledEndpoint
	}
	if request.TimeoutMS <= 0 {
		request.TimeoutMS = cfg.System.Classifier.Runtime.Capture.PPE.SelfTest.TimeoutMS
	}
	if request.TCPFlowID == "" {
		request.TCPFlowID = request.RunID + "-tcp"
	}
	if request.RequireQUIC && request.QUICFlowID == "" {
		request.QUICFlowID = request.RunID + "-quic"
	}
	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(request.TimeoutMS+5000)*time.Millisecond)
	defer cancel()
	result, err := controller.RunSelfTest(ctx, ppe.SelfTestRequest{
		RunID: request.RunID, Generation: status.Desired.Generation,
		ControlledEndpoint: request.ControlledEndpoint, Family: strings.ToLower(strings.TrimSpace(request.Family)),
		TCPFlowID: request.TCPFlowID, QUICFlowID: request.QUICFlowID,
		TCPSourcePort: request.TCPSourcePort, QUICSourcePort: request.QUICSourcePort,
		RequireQUIC: request.RequireQUIC, Timeout: time.Duration(request.TimeoutMS) * time.Millisecond,
	})
	if err != nil {
		writePPEProductError(w, err)
		return
	}
	setJsonHeader(w)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(result)
}

func (api *API) handleCaptureOffloadSelfTestResult(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if api.ppeProduct == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "PPE product service is not initialized")
		return
	}
	runID := strings.TrimSpace(r.URL.Query().Get("run_id"))
	if runID == "" {
		writeJsonError(w, http.StatusBadRequest, "run_id is required")
		return
	}
	result, ok := api.ppeProduct.SelfTestResult(runID)
	if !ok {
		writeJsonError(w, http.StatusNotFound, "PPE self-test result not found")
		return
	}
	sendResponse(w, result)
}

func (api *API) handleCaptureOffloadIssueBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if api.ppeProduct == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "PPE product service is not initialized")
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="b4-ppe-issue-bundle.json"`)
	sendResponse(w, api.ppeProduct.IssueBundle(r.Context()))
}

func decodePPEMutationRequest(w http.ResponseWriter, r *http.Request) (ppeMutationRequest, error) {
	var request ppeMutationRequest
	if r.Body == nil {
		return request, nil
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		return request, fmt.Errorf("invalid PPE mutation request: %w", err)
	}
	return request, nil
}

func mutationIdempotencyKey(r *http.Request, fallback string) string {
	if r != nil {
		if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
			return key
		}
	}
	return strings.TrimSpace(fallback)
}

func checkPPEGeneration(status ppe.ProductStatus, expected string) error {
	actual := ""
	if status.Desired != nil {
		actual = status.Desired.Generation
	}
	expected = strings.TrimSpace(expected)
	if expected == "none" {
		expected = ""
	}
	if expected != actual {
		return fmt.Errorf("PPE generation changed: expected %q, active %q", expected, actual)
	}
	return nil
}

func ppeSelfTestRunID(key string) string {
	var b strings.Builder
	b.WriteString("api-")
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
		if b.Len() >= 60 {
			break
		}
	}
	if b.Len() < 7 {
		return fmt.Sprintf("api-%d", time.Now().UTC().UnixNano())
	}
	return b.String()
}

func writePPEProductError(w http.ResponseWriter, err error) {
	status := http.StatusConflict
	text := strings.ToLower(err.Error())
	switch {
	case strings.Contains(text, "validation"), strings.Contains(text, "required"), strings.Contains(text, "invalid"):
		status = http.StatusBadRequest
	case strings.Contains(text, "unsupported"):
		status = http.StatusUnprocessableEntity
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		status = http.StatusRequestTimeout
	}
	writeJsonError(w, status, err.Error())
}
