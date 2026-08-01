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
	// surface as FAIL in the validation API snapshot.
	observability.Default().Metrics.Inc(observability.MetricUnrelatedControlAction, map[string]string{"service": "gmail"}, 1)
	t.Cleanup(func() {
		observability.Default().Metrics.Reset()
	})

	_, mux := newValidationGatesTestAPI(t)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, validationGatesAPIPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var got gateSnapshot
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !got.Scope.WARPBase || !got.Scope.CSI {
		t.Fatalf("scope not projected from config: %+v", got.Scope)
	}
	if got.Evaluation.Verdict != validation.GateFail {
		t.Fatalf("expected FAIL verdict for unrelated-control violation, got %v", got.Evaluation.Verdict)
	}
	if !got.Meta.RegistryComplete || !got.Meta.Reproducible {
		t.Fatalf("meta-suite must pass on canonical registry: %+v", got.Meta)
	}
	// Working-tree evidence is absent in tests => integrity must be false,
	// never silently PASS (missing evidence is not PASS).
	if got.Meta.EvidenceIntegrity {
		t.Fatalf("evidence integrity must be false without artifacts: %+v", got.Meta)
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
