package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/config"
)

func TestHandleIssueBundleIsRedactedAndIncludesCaptureStatus(t *testing.T) {
	cfg := config.NewConfig()
	cfg.ConfigPath = "/tmp/private-b4-config.json"
	api := &API{cfgPtr: testCfgPtr(&cfg)}
	mux := http.NewServeMux()
	api.mux = mux
	api.RegisterObservabilityAPI()

	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics/issue-bundle", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var bundle struct {
		SchemaVersion string            `json:"schema_version"`
		Versions      map[string]string `json:"versions"`
		Queue         struct {
			Status string `json:"status"`
		} `json:"queue"`
		RawCapture bool `json:"raw_capture"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.SchemaVersion == "" || bundle.Versions["version"] == "" || bundle.Queue.Status == "" {
		t.Fatalf("issue bundle omitted required diagnostics: %+v", bundle)
	}
	if bundle.RawCapture {
		t.Fatal("raw capture must be disabled by default")
	}
	if strings.Contains(rec.Body.String(), cfg.ConfigPath) {
		t.Fatal("config path leaked from issue bundle")
	}
}

func TestHandleObservabilityMetricsMethod(t *testing.T) {
	api := &API{}
	mux := http.NewServeMux()
	api.mux = mux
	api.RegisterObservabilityAPI()

	req := httptest.NewRequest(http.MethodPost, "/api/observability/metrics", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
