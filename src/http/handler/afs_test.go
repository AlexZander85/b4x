package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/monitor"
)

func afsTestAPI(t *testing.T, enabled bool) *API {
	t.Helper()
	cfg := config.Config{}
	cfg.Automation.AdaptiveStrategySynthesis.Enabled = enabled
	ptr := &atomic.Pointer[config.Config]{}
	ptr.Store(&cfg)
	return &API{cfgPtr: ptr, mux: http.NewServeMux()}
}

func afsTestScope() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{ID: "client-a", Role: "forwarded"},
		ServiceProfileID: "service-a",
		ComponentID:      "tls",
		TargetRole:       "target",
		IPFamily:         "ipv4",
		NetworkContextID: "network-a",
		ConfigGeneration: 7,
	}
}

func TestSynthesisStatusReflectsConfigOptIn(t *testing.T) {
	SetMonitoringRuntime(nil)
	t.Cleanup(func() { SetMonitoringRuntime(nil) })
	for _, enabled := range []bool{false, true} {
		api := afsTestAPI(t, enabled)
		api.RegisterSynthesisAPI()
		rec := httptest.NewRecorder()
		api.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/synthesis/v1/status", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("enabled=%v status = %d, body = %s", enabled, rec.Code, rec.Body.String())
		}
		var resp synthesisStatusResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp.Enabled != enabled {
			t.Fatalf("enabled = %v, want %v", resp.Enabled, enabled)
		}
		if resp.GrammarVersion == "" {
			t.Fatal("grammar_version must be reported")
		}
		if resp.Statuses == nil {
			t.Fatal("statuses must be a non-nil list")
		}
	}

	api := afsTestAPI(t, false)
	api.RegisterSynthesisAPI()
	rec := httptest.NewRecorder()
	api.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/synthesis/v1/status", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", rec.Code)
	}
}

// TestDiscoveryStartDeniesAdaptiveSynthesisGate covers AFS §76: the run-request
// extension must deny allowed=true while the global opt-in is off, and once the
// opt-in is on it must fail closed on the canonical preflight (no fabricated
// profile/prior/behavioral evidence) rather than silently accept.
func TestDiscoveryStartDeniesAdaptiveSynthesisGate(t *testing.T) {
	SetMonitoringRuntime(nil)
	t.Cleanup(func() { SetMonitoringRuntime(nil) })
	body, err := json.Marshal(map[string]any{
		"check_url":          "https://example.com",
		"scope":              afsTestScope(),
		"adaptive_synthesis": map[string]any{"allowed": true, "max_candidates": 24},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, tc := range []struct {
		enabled bool
		want    int
	}{
		{enabled: false, want: http.StatusForbidden},
		{enabled: true, want: http.StatusConflict},
	} {
		api := afsTestAPI(t, tc.enabled)
		api.RegisterDiscoveryApi()
		rec := httptest.NewRecorder()
		api.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/discovery/start", bytes.NewReader(body)))
		if rec.Code != tc.want {
			t.Fatalf("enabled=%v status = %d, want %d (body %s)", tc.enabled, rec.Code, tc.want, rec.Body.String())
		}
	}

	// Enabled but scope missing: fail closed with 400 before the gate.
	noScope, _ := json.Marshal(map[string]any{
		"check_url":          "https://example.com",
		"adaptive_synthesis": map[string]any{"allowed": true},
	})
	api := afsTestAPI(t, true)
	api.RegisterDiscoveryApi()
	rec := httptest.NewRecorder()
	api.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/discovery/start", bytes.NewReader(noScope)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing scope status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestSynthesisRevertValidatesScopeAndIsIdempotent(t *testing.T) {
	SetMonitoringRuntime(nil)
	t.Cleanup(func() { SetMonitoringRuntime(nil) })
	api := afsTestAPI(t, true)
	api.RegisterSynthesisAPI()

	// Invalid scope fails closed.
	rec := httptest.NewRecorder()
	api.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/synthesis/v1/revert", bytes.NewReader([]byte(`{"scope":{}}`))))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid scope status = %d, want 400", rec.Code)
	}

	// Valid scope without a monitoring runtime: succeeds, quarantines nothing.
	scopeBody, _ := json.Marshal(map[string]any{"scope": afsTestScope(), "reason": "operator revert"})
	for i := 0; i < 2; i++ {
		rec = httptest.NewRecorder()
		api.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/synthesis/v1/revert", bytes.NewReader(scopeBody)))
		if rec.Code != http.StatusOK {
			t.Fatalf("revert #%d status = %d, body = %s", i, rec.Code, rec.Body.String())
		}
		var resp map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if resp["success"] != true {
			t.Fatalf("revert response = %v", resp)
		}
		if got := resp["lifecycle_reset"]; got != false {
			t.Fatalf("lifecycle_reset = %v, want false without runtime", got)
		}
	}
}
