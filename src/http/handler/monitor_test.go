package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/monitoring"
)

// TestMonitorV1EndpointServesLiveRuntime is the E2E smoke for the
// MON_PRODUCTION_READY wiring: a real monitoring runtime is started and
// registered through SetMonitoringRuntime, an observation is processed, and
// GET /api/monitor/v1 must serve the resulting projection (HTTP-level
// evidence that the production chain works outside the daemon itself).
func TestMonitorV1EndpointServesLiveRuntime(t *testing.T) {
	rt := monitoring.NewRuntime(monitoring.DefaultConfig())
	rt.Start()
	t.Cleanup(func() {
		rt.Stop()
		SetMonitoringRuntime(nil)
	})
	SetMonitoringRuntime(rt)

	// Feed one authoritative failure observation through the pipeline so the
	// projection becomes non-empty before the request.
	scope := monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{Role: "router-origin", ID: "monitor-v1-test"},
		TargetRole:       "control",
		NetworkContextID: "net-e2e",
		ConfigGeneration: 1,
		IPFamily:         "ipv4",
	}
	rt.ExecuteObservation(monitor.MonitorObservation{
		SchemaVersion:      monitor.SchemaVersion,
		ObservationID:      "e2e/watchdog-1",
		Scope:              scope,
		Source:             monitor.SourceControlFailure,
		OutcomeCode:        "transport-timeout",
		FailureAttribution: monitor.AttributionTransport,
		Authority:          monitor.AuthorityProvisionalFast,
		ObservedAt:         time.Now().UTC(),
		ExpiresAt:          time.Now().UTC().Add(time.Minute),
	})

	mux := http.NewServeMux()
	api := &API{mux: mux}
	api.RegisterMonitorAPI()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/monitor/v1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp MonitorV1Response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.GeneratedAt.IsZero() {
		t.Fatal("generated_at must be set")
	}
	if len(resp.Statuses) == 0 {
		t.Fatal("statuses must contain the processed observation projection")
	}
	var st monitor.MonitorStatus
	if err := json.Unmarshal(resp.Statuses[0], &st); err != nil {
		t.Fatalf("status entry unmarshal: %v", err)
	}
	if !st.Scope.Valid() || st.Health == monitor.HealthUnknown {
		t.Fatalf("projection must be valid and decided: %+v", st)
	}
}

// TestMonitorV1EndpointWithoutRuntime is the fail-closed counterpart: without
// SetMonitoringRuntime the endpoint must not serve empty data — it reports
// that the monitoring runtime is not running.
func TestMonitorV1EndpointWithoutRuntime(t *testing.T) {
	SetMonitoringRuntime(nil)
	t.Cleanup(func() { SetMonitoringRuntime(nil) })

	mux := http.NewServeMux()
	api := &API{mux: mux}
	api.RegisterMonitorAPI()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/monitor/v1", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 without runtime", rec.Code)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/monitor/v1", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}