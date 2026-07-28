package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
	"net/netip"
	"time"
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

func TestHandleFailureCandidatesReturnsBoundedPassiveInbox(t *testing.T) {
	inbox := diagnostics.NewFailureInbox(diagnostics.InboxConfig{}, nil)
	client := classifier.ClientKey{L3Family: 4, SourceIP: netip.MustParseAddr("192.0.2.81")}
	_, err := inbox.Observe(diagnostics.FailureObservation{
		Signal:          diagnostics.SignalClassifierAmbiguous,
		Client:          client,
		DestinationIP:   netip.MustParseAddr("203.0.113.81"),
		DestinationPort: 443,
		Protocol:        6,
		ObservedAt:      time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	old := failureInbox.Load()
	SetFailureInbox(inbox)
	defer SetFailureInbox(old)
	api := &API{}
	mux := http.NewServeMux()
	api.mux = mux
	api.RegisterObservabilityAPI()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/diagnostics/failures?limit=1", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "classifier_ambiguous") {
		t.Fatalf("failure inbox endpoint returned %d: %s", rec.Code, rec.Body.String())
	}
}
