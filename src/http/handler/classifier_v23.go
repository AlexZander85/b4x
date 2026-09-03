package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/runtimecontrol"
)

const classifierConfigAPIPath = "/api/v2/classifier/config"

type classifierConfigEnvelope struct {
	APIVersion           string                  `json:"api_version"`
	HardeningAPIVersion  string                  `json:"hardening_api_version"`
	SchemaVersion        int                     `json:"schema_version"`
	RuntimeGeneration    string                  `json:"runtime_generation,omitempty"`
	ExportedAt           time.Time               `json:"exported_at,omitempty"`
	Config               config.ClassifierConfig `json:"config"`
	RawArtifactsIncluded bool                    `json:"raw_artifacts_included"`
	Warnings             []string                `json:"warnings,omitempty"`
	RawArtifacts         json.RawMessage         `json:"raw_artifacts,omitempty"`
}

type classifierSchemaResponse struct {
	APIVersion          string               `json:"api_version"`
	HardeningAPIVersion string               `json:"hardening_api_version"`
	SchemaVersion       int                  `json:"schema_version"`
	DomainOnlyModes     []string             `json:"domain_only_modes"`
	ReassemblyModes     []string             `json:"reassembly_modes"`
	HoldReplayModes     []string             `json:"hold_replay_modes"`
	FallbackModes       []string             `json:"fallback_modes"`
	PrivacyModes        []string             `json:"privacy_modes"`
	GSOModes            []string             `json:"gso_modes"`
	GSOPolicies         []string             `json:"gso_policies"`
	GSOCapabilities     []string             `json:"gso_capabilities"`
	PassiveRSTModes     []string             `json:"passive_rst_modes"`
	Groups              []classifierAPIGroup `json:"groups"`
	Invariants          []string             `json:"invariants"`
}

type classifierAPIGroup struct {
	ID       string `json:"id"`
	Advanced bool   `json:"advanced"`
	Mutable  bool   `json:"mutable"`
}

func (api *API) RegisterClassifierV23API() {
	api.mux.HandleFunc(classifierConfigAPIPath, api.handleClassifierV23Config)
	api.mux.HandleFunc(classifierIsolationAPIPath, api.handleClassifierIsolation)
	api.mux.HandleFunc(classifierIsolationAPIPath+"/validate", api.handleClassifierIsolationValidation)
	api.mux.HandleFunc("/api/v2/classifier/schema", api.handleClassifierV23Schema)
	api.mux.HandleFunc("/api/v2/classifier/export", api.handleClassifierV23Export)
	api.mux.HandleFunc("/api/v2/classifier/import", api.handleClassifierV23Import)
	api.mux.HandleFunc(classifierHardeningAPIPath, api.handleClassifierHardeningStatus)
	api.mux.HandleFunc(classifierGSOReadinessAPIPath, api.handleClassifierGSOReadiness)
}

func (api *API) handleClassifierV23Config(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		api.writeClassifierEnvelope(w, api.getCfg().System.Classifier, nil)
	case http.MethodPut:
		cfg, err := decodeClassifierConfig(r)
		if err != nil {
			writeJsonError(w, http.StatusBadRequest, err.Error())
			return
		}
		api.applyClassifierV23Config(w, cfg)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (api *API) handleClassifierV23Schema(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	groups := []classifierAPIGroup{
		{ID: "feature_flags", Mutable: true},
		{ID: "client_identity", Advanced: true, Mutable: true},
		{ID: "confidence", Mutable: true},
		{ID: "hints", Advanced: true, Mutable: true},
		{ID: "capture", Advanced: true, Mutable: true},
		{ID: "execution", Advanced: true, Mutable: true},
		{ID: "reassembly", Advanced: true, Mutable: true},
		{ID: "hold_replay", Advanced: true, Mutable: true},
		{ID: "passive_rst", Advanced: true, Mutable: true},
		{ID: "hardening_status", Advanced: true, Mutable: false},
		{ID: "actions", Advanced: true, Mutable: true},
		{ID: "discovery", Mutable: true},
		{ID: "failure_inbox", Advanced: true, Mutable: true},
		{ID: "clienthello_lab", Advanced: true, Mutable: true},
		{ID: "rollout", Mutable: true},
		{ID: "strategies", Advanced: true, Mutable: true},
		{ID: "fallback", Advanced: true, Mutable: true},
		{ID: "privacy", Mutable: true},
	}
	sendResponse(w, classifierSchemaResponse{
		APIVersion: config.ClassifierAPIV23, HardeningAPIVersion: config.ClassifierHardeningAPIV1, SchemaVersion: config.ClassifierSchemaV23,
		DomainOnlyModes: []string{config.DomainStrict, config.DomainScopedHints, config.DomainLegacy, config.DomainDisabled},
		ReassemblyModes: []string{config.ReassemblyOff, config.ReassemblyObserve},
		HoldReplayModes: []string{config.HoldReplayOff, config.HoldReplayObserve, config.HoldReplayAuto, config.HoldReplayDebug},
		FallbackModes:   []string{config.FallbackDirect, config.FallbackGeneric, config.FallbackProxy},
		PrivacyModes:    []string{config.PrivacyTelemetryRedacted, config.PrivacyTelemetryLocal, config.PrivacyTelemetryOff},
		GSOModes:        []string{config.GSOModeOff, config.GSOModeObserve, config.GSOModeClassify, config.GSOModeFull},
		GSOPolicies:     []string{config.GSOPolicyFailOpen, config.GSOPolicyClassifyOnly, config.GSOPolicyNormalizeForAction},
		GSOCapabilities: []string{"unsupported", "supported-unvalidated", "observe-only", "classify-ready", "full-action-ready", "failed"},
		PassiveRSTModes: []string{config.PassiveRSTOff, config.PassiveRSTObserve, config.PassiveRSTConservative, config.PassiveRSTAggressive},
		Groups:          groups,
		Invariants: []string{
			"clean SYN without an explicit SYN technique is accepted",
			"generated packets carry a processed provenance mark and do not requeue",
			"all hold paths release unchanged packets on timeout, pressure, shutdown, or error",
			"raw captures are excluded from exports unless explicitly confirmed",
			"Discovery never applies a production candidate automatically",
			"full GSO actions and aggressive passive RST require explicit confirmation tokens",
			"topology-affecting changes are applied only through the runtime transaction",
		},
	})
}

func (api *API) handleClassifierV23Export(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	includeRaw := r.URL.Query().Get("include_raw") == "true"
	confirmed := r.URL.Query().Get("confirm_raw") == "true"
	if includeRaw && !confirmed {
		writeJsonError(w, http.StatusBadRequest, "raw export requires include_raw=true and confirm_raw=true")
		return
	}
	warnings := []string{"raw packets and ClientHello payloads are local artifacts and are not included in configuration exports"}
	if includeRaw {
		warnings = append(warnings, "raw export was explicitly requested, but this endpoint exports configuration only")
	}
	w.Header().Set("Content-Disposition", `attachment; filename="b4-classifier-v23.json"`)
	api.writeClassifierEnvelope(w, api.getCfg().System.Classifier, warnings)
}

func (api *API) handleClassifierV23Import(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var envelope classifierConfigEnvelope
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		writeJsonError(w, http.StatusBadRequest, "invalid classifier import: "+err.Error())
		return
	}
	if len(bytes.TrimSpace(envelope.RawArtifacts)) > 0 && string(bytes.TrimSpace(envelope.RawArtifacts)) != "null" {
		writeJsonError(w, http.StatusBadRequest, "raw artifacts cannot be imported through the configuration API")
		return
	}
	if envelope.APIVersion != "" && envelope.APIVersion != config.ClassifierAPIV23 {
		writeJsonError(w, http.StatusBadRequest, fmt.Sprintf("unsupported classifier API version %q", envelope.APIVersion))
		return
	}
	api.applyClassifierV23Config(w, envelope.Config)
}

func decodeClassifierConfig(r *http.Request) (config.ClassifierConfig, error) {
	body, err := readBoundedBody(r, 1<<20)
	if err != nil {
		return config.ClassifierConfig{}, err
	}
	var wrapper struct {
		Config json.RawMessage `json:"config"`
	}
	_ = json.Unmarshal(body, &wrapper)
	payload := body
	if len(bytes.TrimSpace(wrapper.Config)) > 0 {
		payload = wrapper.Config
	}
	out := config.DefaultClassifierConfig
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return config.ClassifierConfig{}, fmt.Errorf("invalid classifier config: %w", err)
	}
	return out, nil
}

func readBoundedBody(r *http.Request, limit int64) ([]byte, error) {
	if r == nil || r.Body == nil {
		return nil, fmt.Errorf("request body is required")
	}
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("request body is unreadable: %w", err)
	}
	if n > limit {
		return nil, fmt.Errorf("request body exceeds %d bytes", limit)
	}
	if len(bytes.TrimSpace(buf.Bytes())) == 0 {
		return nil, fmt.Errorf("request body is required")
	}
	return buf.Bytes(), nil
}

func (api *API) applyClassifierV23Config(w http.ResponseWriter, classifierCfg config.ClassifierConfig) {
	cur := api.getCfg()
	old := cur.Clone()
	candidate := cur.CloneForRuntimeUpdate()
	candidate.System.Classifier = classifierCfg
	if capture.GSOTopologyChanged(old, candidate) {
		meta := runtimecontrol.GenerationMeta{
			ID: candidate.RuntimeGeneration, SchemaVersion: config.ClassifierSchemaV23, CreatedAt: time.Now().UTC(),
			Validation: runtimecontrol.ValidationSummary{Valid: true},
		}
		if err := api.ApplyRuntimeControlTopology(context.Background(), old, candidate, meta); err != nil {
			writeAPIError(w, err)
			return
		}
		api.writeClassifierEnvelope(w, candidate.System.Classifier, nil)
		return
	}
	if err := api.saveAndPushConfig(candidate); err != nil {
		writeAPIError(w, err)
		return
	}
	if classifierCaptureContractChanged(old.System.Classifier, candidate.System.Classifier) {
		api.PerformSoftRestart(candidate, old)
	}
	api.writeClassifierEnvelope(w, candidate.System.Classifier, nil)
}

func classifierCaptureContractChanged(a, b config.ClassifierConfig) bool {
	return a.Flags.CaptureEnvelopeEnabled != b.Flags.CaptureEnvelopeEnabled ||
		a.Flags.TCPFSMEnabled != b.Flags.TCPFSMEnabled ||
		a.Flags.TCPReassemblyMode != b.Flags.TCPReassemblyMode ||
		a.Flags.TCPHoldReplayMode != b.Flags.TCPHoldReplayMode ||
		!reflect.DeepEqual(a.Runtime.Capture, b.Runtime.Capture)
}

func (api *API) writeClassifierEnvelope(w http.ResponseWriter, classifierCfg config.ClassifierConfig, warnings []string) {
	generation := ""
	if cfg := api.getCfg(); cfg != nil {
		generation = cfg.RuntimeGeneration
	}
	if warnings == nil && classifierCfg.Runtime.Privacy.IncludeRawInExport {
		warnings = []string{"raw export is enabled in configuration but still requires an explicit confirmed export request"}
	}
	setJsonHeader(w)
	_ = json.NewEncoder(w).Encode(classifierConfigEnvelope{
		APIVersion: config.ClassifierAPIV23, HardeningAPIVersion: config.ClassifierHardeningAPIV1, SchemaVersion: config.ClassifierSchemaV23,
		RuntimeGeneration: generation, ExportedAt: time.Now().UTC(), Config: classifierCfg,
		RawArtifactsIncluded: false, Warnings: compactStrings(warnings),
	})
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}
