package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/nfq"
)

func TestClassifierGSOReadinessMutationEndpoint(t *testing.T) {
	_, mux, ptr := newClassifierV23TestAPI(t)
	cfg := ptr.Load().Clone()
	cfg.EnsureRuntimeGeneration()
	cfg.System.Classifier.Runtime.Capture.NFQueue.GSOMode = config.GSOModeClassify
	ptr.Store(cfg)
	previousPool, previousTopology := globalPool, globalGSOTopology
	pool := nfq.NewGSOPrimaryPool(cfg, 0)
	globalPool, globalGSOTopology = pool, nil
	t.Cleanup(func() {
		pool.Stop()
		globalPool, globalGSOTopology = previousPool, previousTopology
	})

	evidence := nfq.GSOReadinessEvidence{
		MetadataEnvelopeSeen:         true,
		RepresentationParityProven:   true,
		IPv4Ready:                    true,
		IPv6State:                    "proven",
		RetransmissionProven:         true,
		ResourceBudgetsProven:        true,
		QueueDropBudgetProven:        true,
		PPEVisibilityState:           "complete",
		ProductionEntryPointVerified: true,
	}
	payload, err := json.Marshal(classifierGSOReadinessRequest{Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, classifierGSOReadinessAPIPath, bytes.NewReader(payload)))
	if rr.Code != http.StatusOK {
		t.Fatalf("mutation status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out classifierGSOReadinessResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.AppliedWorkers == 0 {
		t.Fatalf("no workers applied: %+v", out)
	}
	if out.Generation == 0 {
		t.Fatalf("evidence not bound to active generation: %+v", out)
	}
	if out.Snapshot.State != nfq.GSOReadinessReady {
		t.Fatalf("expected READY snapshot, got %s (%+v)", out.Snapshot.State, out.Snapshot)
	}
	if out.Snapshot.ProcessInstanceID == "" || out.Snapshot.EvidenceHash == "" {
		t.Fatalf("snapshot missing instance/hash: %+v", out.Snapshot)
	}

	// The hardening status must now reflect the applied readiness verdict.
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, classifierHardeningAPIPath, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var status classifierHardeningStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if status.GSO.Readiness.State != nfq.GSOReadinessReady {
		t.Fatalf("hardening status did not reflect applied readiness: %+v", status.GSO.Readiness)
	}

	// Reject unknown fields and non-POST methods.
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, classifierGSOReadinessAPIPath, bytes.NewReader([]byte(`{"evidence":{"unknown_field":true}}`))))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, classifierGSOReadinessAPIPath, nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("read request accepted mutation endpoint: %d", rr.Code)
	}
}

func TestClassifierGSOReadinessRejectsOperatorGeneration(t *testing.T) {
	_, mux, ptr := newClassifierV23TestAPI(t)
	cfg := ptr.Load().Clone()
	cfg.EnsureRuntimeGeneration()
	ptr.Store(cfg)
	previousPool, previousTopology := globalPool, globalGSOTopology
	pool := nfq.NewGSOPrimaryPool(cfg, 0)
	globalPool, globalGSOTopology = pool, nil
	t.Cleanup(func() {
		pool.Stop()
		globalPool, globalGSOTopology = previousPool, previousTopology
	})

	evidence := nfq.GSOReadinessEvidence{
		Generation:                   999,
		MetadataEnvelopeSeen:         true,
		RepresentationParityProven:   true,
		IPv4Ready:                    true,
		RetransmissionProven:         true,
		ResourceBudgetsProven:        true,
		QueueDropBudgetProven:        true,
		PPEVisibilityState:           "not-required",
		ProductionEntryPointVerified: true,
	}
	payload, err := json.Marshal(classifierGSOReadinessRequest{Evidence: evidence})
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, classifierGSOReadinessAPIPath, bytes.NewReader(payload)))
	if rr.Code != http.StatusOK {
		t.Fatalf("mutation status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out classifierGSOReadinessResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Generation == 999 {
		t.Fatalf("operator-provided generation accepted: %+v", out)
	}
	if out.Snapshot.ConfigGeneration == 999 {
		t.Fatalf("snapshot bound to operator generation: %+v", out.Snapshot)
	}
	if out.Snapshot.ConfigGeneration == 0 {
		t.Fatalf("snapshot not bound to active generation: %+v", out.Snapshot)
	}
}
