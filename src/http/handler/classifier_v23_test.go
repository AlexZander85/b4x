package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/nfq"
)

func newClassifierV23TestAPI(t *testing.T) (*API, *http.ServeMux, *atomic.Pointer[config.Config]) {
	t.Helper()
	cfg := config.NewConfig()
	cfg.EnsureRuntimeGeneration()
	cfg.ConfigPath = ""
	var ptr atomic.Pointer[config.Config]
	ptr.Store(&cfg)
	mux := http.NewServeMux()
	api := &API{cfgPtr: &ptr, mux: mux}
	api.RegisterClassifierV23API()
	return api, mux, &ptr
}

func TestClassifierV23SchemaAndSafeExport(t *testing.T) {
	_, mux, _ := newClassifierV23TestAPI(t)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v2/classifier/schema", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("schema status=%d body=%s", rr.Code, rr.Body.String())
	}
	var schema classifierSchemaResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &schema); err != nil {
		t.Fatal(err)
	}
	if schema.APIVersion != config.ClassifierAPIV23 || schema.HardeningAPIVersion != config.ClassifierHardeningAPIV1 || len(schema.Groups) < 10 || len(schema.Invariants) == 0 {
		t.Fatalf("incomplete schema response: %+v", schema)
	}
	if len(schema.GSOModes) != 4 || len(schema.GSOPolicies) != 3 || len(schema.PassiveRSTModes) != 4 {
		t.Fatalf("hardening schema missing modes: %+v", schema)
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v2/classifier/export", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rr.Code, rr.Body.String())
	}
	var envelope classifierConfigEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.RawArtifactsIncluded || len(envelope.RawArtifacts) != 0 || envelope.Config.Runtime.Privacy.AutomaticRawUpload {
		t.Fatalf("unsafe export: %+v", envelope)
	}
	if envelope.HardeningAPIVersion != config.ClassifierHardeningAPIV1 {
		t.Fatalf("hardening API version missing: %+v", envelope)
	}
	if len(envelope.Warnings) == 0 {
		t.Fatal("safe export should explain raw artifact exclusion")
	}
}

func TestClassifierHardeningStatusIsReadOnlyAndRedacted(t *testing.T) {
	_, mux, ptr := newClassifierV23TestAPI(t)
	cfg := ptr.Load().Clone()
	cfg.System.Classifier.Runtime.PassiveRST.SetScopes = []string{"private-youtube"}
	cfg.System.Classifier.Runtime.PassiveRST.DeviceScopes = []string{"aa:bb:cc:dd:ee:99"}
	ptr.Store(cfg)
	previousPool, previousTopology := globalPool, globalGSOTopology
	pool := nfq.NewGSOPrimaryPool(cfg, 0)
	globalPool, globalGSOTopology = pool, nil
	t.Cleanup(func() {
		pool.Stop()
		globalPool, globalGSOTopology = previousPool, previousTopology
	})

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, classifierHardeningAPIPath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if bytes.Contains(rr.Body.Bytes(), []byte("private-youtube")) || bytes.Contains(rr.Body.Bytes(), []byte("aa:bb:cc:dd:ee:99")) {
		t.Fatalf("private scope leaked: %s", rr.Body.String())
	}
	var status classifierHardeningStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.APIVersion != config.ClassifierHardeningAPIV1 || status.GSO.RequestedMode != config.GSOModeOff || status.GSO.ExecutionPolicy != config.GSOPolicyFailOpen {
		t.Fatalf("incomplete hardening status: %+v", status)
	}
	if status.GSO.Readiness.State == "" {
		t.Fatalf("hardening status missing GSO readiness verdict: %+v", status.GSO)
	}
	if len(status.PassiveRST.SetScopes) != 1 || status.PassiveRST.SetScopes[0] == "private-youtube" {
		t.Fatalf("scope not redacted: %+v", status.PassiveRST.SetScopes)
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, classifierHardeningAPIPath, nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("hardening status accepted mutation: %d", rr.Code)
	}
}

func TestClassifierV23RawExportNeedsConfirmation(t *testing.T) {
	_, mux, _ := newClassifierV23TestAPI(t)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v2/classifier/export?include_raw=true", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestClassifierV23PutAndImportPrivacyGuard(t *testing.T) {
	_, mux, ptr := newClassifierV23TestAPI(t)
	candidate := config.DefaultClassifierConfig
	candidate.DomainOnlyMode = config.DomainScopedHints
	body, _ := json.Marshal(candidate)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPut, classifierConfigAPIPath, bytes.NewReader(body)))
	if rr.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", rr.Code, rr.Body.String())
	}
	if ptr.Load().System.Classifier.DomainOnlyMode != config.DomainScopedHints {
		t.Fatal("classifier config was not published")
	}
	if ptr.Load().RuntimeGeneration == "" {
		t.Fatal("runtime update must publish an immutable generation")
	}

	unsafe := classifierConfigEnvelope{
		APIVersion:   config.ClassifierAPIV23,
		Config:       candidate,
		RawArtifacts: json.RawMessage(`{"clienthello":"private"}`),
	}
	body, _ = json.Marshal(unsafe)
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v2/classifier/import", bytes.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unsafe import status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestDecodeClassifierConfigRejectsUnknownFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, classifierConfigAPIPath, bytes.NewBufferString(`{"schema_version":1,"unknown":true}`))
	if _, err := decodeClassifierConfig(req); err == nil {
		t.Fatal("expected unknown field error")
	}
}
