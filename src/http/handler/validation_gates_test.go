package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/validation"
)

func newValidationGatesTestAPI(t *testing.T) (*API, *http.ServeMux) {
	t.Helper()
	cfg := config.NewConfig()
	cfg.System.Classifier.Flags.ClassifierV2Enabled = true
	var ptr atomic.Pointer[config.Config]
	ptr.Store(&cfg)
	mux := http.NewServeMux()
	api := &API{cfgPtr: &ptr, mux: mux}
	api.RegisterValidationAPI()
	return api, mux
}

func TestValidationGatesEndpointEvaluatesScopeAndExposesMeta(t *testing.T) {
	// Production-root: a real violation recorded through observability must
	// surface as FAIL in the validation API snapshot. The first call captures
	// the window baseline; a new violation after the baseline appears as the
	// window delta (FB-03 phase E2: one evaluation of the current
	// TestSession/ValidationRun, never process-lifetime totals).
	observability.Default().Metrics.Inc(observability.MetricUnrelatedControlAction, map[string]string{"service": "gmail"}, 1)
	t.Cleanup(func() {
		observability.Default().Metrics.Reset()
		validation.ResetProductionWindow()
	})

	_, mux := newValidationGatesTestAPI(t)

	// First call: captures the baseline of the current window.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, validationGatesAPIPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var first gateSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &first); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !first.Scope.WARPBase || !first.Scope.CSI || !first.Scope.RSTGSO {
		t.Fatalf("scope not projected from config: %+v", first.Scope)
	}
	if !first.Evaluation.WindowBaseline || !first.Window.Active {
		t.Fatalf("window must be active with baseline: %+v / %+v", first.Evaluation, first.Window)
	}
	if !first.Meta.RegistryComplete || !first.Meta.Reproducible {
		t.Fatalf("meta-suite must pass on canonical registry: %+v", first.Meta)
	}
	// Working-tree evidence is absent in tests => integrity must be false,
	// never silently PASS (missing evidence is not PASS).
	if first.Meta.EvidenceIntegrity {
		t.Fatalf("evidence integrity must be false without artifacts: %+v", first.Meta)
	}

	// New violation inside the same window: delta 1, verdict FAIL.
	observability.Default().Metrics.Inc(observability.MetricUnrelatedControlAction, map[string]string{"service": "gmail"}, 1)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, validationGatesAPIPath, nil))
	var second gateSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &second); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if second.Evaluation.Verdict != validation.GateFail {
		t.Fatalf("expected FAIL verdict for window-delta violation, got %v", second.Evaluation.Verdict)
	}
	if len(second.Evaluation.Violations) != 1 || second.Evaluation.Violations[0].Count != 1 {
		t.Fatalf("violations = %+v, want window delta 1 (baseline captured on first call)", second.Evaluation.Violations)
	}
}

func TestValidationGatesEndpointRejectsNonGet(t *testing.T) {
	_, mux := newValidationGatesTestAPI(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, validationGatesAPIPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}

func TestValidationIV18EndpointExecutesSuiteFailClosed(t *testing.T) {
	_, mux := newValidationGatesTestAPI(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, validationIV18APIPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var snapshot iv18Snapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &snapshot); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if snapshot.Suite != validation.IV18SuiteID {
		t.Fatalf("suite = %q, want IV-18", snapshot.Suite)
	}
	if len(snapshot.Requirements) != 22 || len(snapshot.Coverage) == 0 {
		t.Fatalf("requirements = %d coverage = %d, want 22 registered + coverage", len(snapshot.Requirements), len(snapshot.Coverage))
	}
	// Fail-closed: full coverage is in place and the legacy mutating path is
	// removed (cutover). With the production monitoring chain wired
	// (ObservationBus, DiagnosticScheduler, ABD->DDI, /api/monitor/v1) the
	// verdict must be PASS: the IV-18 suite executes as an ENDPOINT and
	// reports production readiness, never a false PASS while a dependency is
	// missing (owner decision 2026-08-02, updated when the production
	// integration landed).
	if snapshot.Result.Registered != 22 || snapshot.Result.Covered != 22 {
		t.Fatalf("suite registry must be complete: %+v", snapshot.Result)
	}
	if snapshot.Result.Verdict != validation.Pass {
		t.Fatalf("suite must be PASS with production wiring landed: %+v", snapshot.Result)
	}
	if len(snapshot.Result.LegacyMutatingHits) != 0 {
		t.Fatalf("legacy mutating path must be removed after cutover: %+v", snapshot.Result.LegacyMutatingHits)
	}
	if len(snapshot.Result.BlockedDependencies) != 0 {
		t.Fatalf("expected 0 blocked production dependencies with wiring landed: %+v", snapshot.Result)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, validationIV18APIPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rec.Code)
	}
}
