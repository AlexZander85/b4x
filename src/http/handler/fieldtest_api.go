package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/fieldtest"
	"github.com/google/uuid"
)

const (
	capabilitiesV1APIPath = "/api/v1/capabilities"
	testSessionsV1APIPath = "/api/v1/test-sessions"
	runtimeRollbackV1Path = "/api/v1/runtime/rollback"
)

var (
	fieldSessions     *fieldtest.Controller
	fieldSessionsOnce sync.Once
)

func fieldSessionController() *fieldtest.Controller {
	fieldSessionsOnce.Do(func() {
		dir := os.TempDir()
		c, err := fieldtest.NewController("local", dir)
		if err == nil {
			fieldSessions = c
		}
	})
	return fieldSessions
}

func (api *API) RegisterFieldTestAPI() {
	api.mux.HandleFunc(capabilitiesV1APIPath, api.handleCapabilitiesV1)
	api.mux.HandleFunc(testSessionsV1APIPath, api.handleTestSessionsCollection)
	api.mux.HandleFunc(testSessionsV1APIPath+"/{id}/markers", api.handleTestSessionMarkers)
	api.mux.HandleFunc(testSessionsV1APIPath+"/{id}/events", api.handleTestSessionEvents)
	api.mux.HandleFunc(testSessionsV1APIPath+"/{id}/stop", api.handleTestSessionStop)
	api.mux.HandleFunc(testSessionsV1APIPath+"/{id}/report", api.handleTestSessionReport)
	api.mux.HandleFunc(testSessionsV1APIPath+"/{id}/authorization-audit", api.handleTestSessionAudit)
	api.mux.HandleFunc(runtimeRollbackV1Path, api.handleRuntimeRollbackV1)
}

type capabilityDocument struct {
	fieldtest.Capabilities
	CheckedAt time.Time `json:"checked_at"`
}

func (api *API) handleCapabilitiesV1(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	sendResponse(w, api.liveCapabilities())
}

func (api *API) liveCapabilities() capabilityDocument {
	cfg := api.getCfg()
	doc := capabilityDocument{
		Capabilities: fieldtest.Capabilities{
			Commit:      Commit,
			APIVersions: []string{"/api/v1", "/api/v2", "/api/monitor/v1"},
			Features:    map[string]fieldtest.CapabilityValue{},
			Transports:  []string{},
		},
		CheckedAt: time.Now().UTC(),
	}
	if cfg != nil {
		doc.NFQueue = cfg.Queue.StartNum > 0 || globalPool != nil
		doc.CaptureEnvelope = cfg.System.Classifier.Flags.CaptureEnvelopeEnabled
		doc.OffloadVisibility = true
		doc.PCAP = true
	}
	doc.AndroidAPI = false // ADB is owned by the local controller, never the router.
	doc.SandboxCapacity = 1

	feature := func(name string, wired bool, reason string) {
		v := fieldtest.CapabilityValue{
			Supported:   wired,
			State:       "declared",
			Version:     Version,
			Hash:        Commit,
			TargetScope: "validation",
		}
		if !wired {
			v.State = "absent"
			v.DegradedReason = reason
		} else {
			v.DegradedReason = "no field validation_hash"
			v.State = "wired-unvalidated"
		}
		doc.Features[name] = v
	}
	feature("cross_service_isolation", true, "")
	feature("capture_candidate_action_authorization_split", true, "")
	feature("telegram_transparent_bridge", globalMTProtoBridge != nil, "mtproto bridge not bound")
	feature("continuous_monitoring", globalMonitoring != nil, "monitoring runtime not bound")
	feature("adaptive_blocking_detector", true, "")
	feature("detector_guided_discovery", discoveryRuntime != nil || api.discoveryRT != nil, "discovery runtime not bound")
	feature("warp_base_transport", globalWarp != nil, "warp runtime not bound")
	feature("service_profiles", globalServiceProfile != nil, "service profile runtime not bound")
	feature("silent_path_failure", true, "")
	feature("ppe_offload", api.ppeProduct != nil || api.ppeStatus != nil, "PPE product service not bound")
	if cfg != nil && cfg.System.Classifier.Flags.TransactionalApplyEnabled {
		feature("transactional_runtime", true, "")
	} else {
		feature("transactional_runtime", false, "transactional apply disabled")
	}
	return doc
}

type testSessionCreateRequest struct {
	ClientID         string   `json:"client_id"`
	ClientIP         string   `json:"client_ip,omitempty"`
	TargetAppID      string   `json:"target_app_id"`
	TargetVariant    string   `json:"target_variant,omitempty"`
	TargetPackage    string   `json:"target_package,omitempty"`
	ControlApps      []string `json:"control_apps,omitempty"`
	ConfigGeneration uint64   `json:"config_generation"`
	DurationLimitSec int      `json:"duration_limit_sec,omitempty"`
}

func requireMutatingHeaders(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Idempotency-Key") == "" || r.Header.Get("X-B4-Client") == "" || r.Header.Get("X-B4-Request-ID") == "" {
		writeJsonError(w, http.StatusBadRequest, "mutating request requires Idempotency-Key, X-B4-Client, X-B4-Request-ID")
		return false
	}
	return true
}

func (api *API) handleTestSessionsCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !requireMutatingHeaders(w, r) {
		return
	}
	ctrl := fieldSessionController()
	if ctrl == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "field-test controller unavailable")
		return
	}
	var req testSessionCreateRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid session request: "+err.Error())
		return
	}
	if req.ConfigGeneration == 0 {
		if mgr := api.getRuntimeControlManager(); mgr != nil {
			st := mgr.Status()
			if st.Active != nil {
				// Generation IDs are strings; keep a non-zero sentinel when live.
				req.ConfigGeneration = 1
			}
		}
		if req.ConfigGeneration == 0 {
			req.ConfigGeneration = 1
		}
	}
	id := fmt.Sprintf("s-%s", strings.ReplaceAll(uuid.NewString(), "-", "")[:16])
	sess, replayed, err := ctrl.Create(id, fieldtest.SessionRequest{
		ClientID: req.ClientID, ClientIP: req.ClientIP, TargetAppID: req.TargetAppID,
		TargetVariant: req.TargetVariant, TargetPackage: req.TargetPackage,
		ControlApps: req.ControlApps, ConfigGeneration: req.ConfigGeneration,
		DurationLimitSec: req.DurationLimitSec,
	}, req.ConfigGeneration, r.Header.Get("Idempotency-Key"))
	if err != nil {
		writeJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	setJsonHeader(w)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(sess)
}

func (api *API) handleTestSessionMarkers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !requireMutatingHeaders(w, r) {
		return
	}
	ctrl := fieldSessionController()
	if ctrl == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "field-test controller unavailable")
		return
	}
	var m fieldtest.Marker
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&m); err != nil {
		writeJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := ctrl.AddMarker(r.PathValue("id"), m); err != nil {
		writeJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	sendResponse(w, map[string]any{"ok": true})
}

func (api *API) handleTestSessionEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctrl := fieldSessionController()
	if ctrl == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "field-test controller unavailable")
		return
	}
	events, err := ctrl.Events(r.PathValue("id"))
	if err != nil {
		writeJsonError(w, http.StatusNotFound, err.Error())
		return
	}
	sendResponse(w, events)
}

func (api *API) handleTestSessionStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !requireMutatingHeaders(w, r) {
		return
	}
	ctrl := fieldSessionController()
	if ctrl == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "field-test controller unavailable")
		return
	}
	if err := ctrl.Stop(r.PathValue("id")); err != nil {
		writeJsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	sendResponse(w, map[string]any{"ok": true})
}

func (api *API) handleTestSessionReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctrl := fieldSessionController()
	if ctrl == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "field-test controller unavailable")
		return
	}
	rep, err := ctrl.Report(r.PathValue("id"))
	if err != nil {
		writeJsonError(w, http.StatusNotFound, err.Error())
		return
	}
	sendResponse(w, rep)
}

func (api *API) handleTestSessionAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ctrl := fieldSessionController()
	if ctrl == nil {
		writeJsonError(w, http.StatusServiceUnavailable, "field-test controller unavailable")
		return
	}
	if _, ok := ctrl.Get(r.PathValue("id")); !ok {
		writeJsonError(w, http.StatusNotFound, "unknown run")
		return
	}
	sendResponse(w, fieldtest.AuthorizationAudit{})
}

func (api *API) handleRuntimeRollbackV1(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !requireMutatingHeaders(w, r) {
		return
	}
	// Alias onto the production transactional rollback. Promotion is not
	// exposed on /api/v1.
	api.handleRuntimeControlRollback(w, r)
}
