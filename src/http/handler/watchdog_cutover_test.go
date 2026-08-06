package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/monitoring"
	"github.com/daniellavrushin/b4/watchdog"
)

// TestWatchdogCutoverMutatingEndpointsGone is the API migration evidence for
// MON addendum v1.0 §57.1: once legacy_watchdog_api=false (cutover active),
// every legacy mutating /api/watchdog/* endpoint MUST answer 410 Gone with
// the stable migration message and MUST NOT touch watchdog or config state.
func TestWatchdogCutoverMutatingEndpointsGone(t *testing.T) {
	cfg := config.NewConfig()
	cfg.System.Checker.Watchdog.LegacyWatchdogAPI = false

	mux := http.NewServeMux()
	api := &API{cfgPtr: testCfgPtr(&cfg), mux: mux}
	api.RegisterWatchdogApi()

	cases := []struct {
		name   string
		method string
		path   string
		body   string
	}{
		{name: "force check", method: http.MethodPost, path: "/api/watchdog/check", body: `{"domain":"example.com"}`},
		{name: "add domain", method: http.MethodPost, path: "/api/watchdog/domains", body: `{"domain":"example.com"}`},
		{name: "delete domain", method: http.MethodDelete, path: "/api/watchdog/domains/example.com"},
		{name: "enable", method: http.MethodPost, path: "/api/watchdog/enable"},
		{name: "disable", method: http.MethodPost, path: "/api/watchdog/disable"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body *strings.Reader
			if tc.body == "" {
				body = strings.NewReader("")
			} else {
				body = strings.NewReader(tc.body)
			}
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, body))
			if rec.Code != http.StatusGone {
				t.Fatalf("status = %d, want 410 Gone (%s)", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "cut over") {
				t.Fatalf("body must carry the stable migration message, got %q", rec.Body.String())
			}
		})
	}
}

// TestMonitorHealthToLegacyStatusMapping is the unit evidence for the §58
// projection vocabulary: escalating <- running_quick/running_deep,
// queued <- queued_quick/queued_deep, degraded <- degraded/failing/suppressed
// without in-flight diagnostics, healthy <- healthy/recovered, unknown ->
// no legacy entry.
func TestMonitorHealthToLegacyStatusMapping(t *testing.T) {
	cases := []struct {
		name                      string
		health                    monitor.HealthState
		queuedQuick, queuedDeep   int
		runningQuick, runningDeep int
		want                      string
		wantOK                    bool
	}{
		{name: "healthy", health: monitor.HealthHealthy, want: watchdog.StatusHealthy, wantOK: true},
		{name: "recovered", health: monitor.HealthRecovered, want: watchdog.StatusHealthy, wantOK: true},
		{name: "healthy ignores in-flight", health: monitor.HealthHealthy, runningQuick: 3, want: watchdog.StatusHealthy, wantOK: true},
		{name: "escalating quick", health: monitor.HealthFailing, runningQuick: 1, want: watchdog.StatusEscalating, wantOK: true},
		{name: "escalating deep", health: monitor.HealthDegraded, runningDeep: 2, want: watchdog.StatusEscalating, wantOK: true},
		{name: "queued quick", health: monitor.HealthFailing, queuedQuick: 1, want: watchdog.StatusQueued, wantOK: true},
		{name: "queued deep", health: monitor.HealthDegraded, queuedDeep: 1, want: watchdog.StatusQueued, wantOK: true},
		{name: "escalation wins over queued", health: monitor.HealthFailing, queuedQuick: 2, runningQuick: 1, want: watchdog.StatusEscalating, wantOK: true},
		{name: "degraded idle", health: monitor.HealthFailing, want: watchdog.StatusDegraded, wantOK: true},
		{name: "suppressed degrades", health: monitor.HealthDegraded, want: watchdog.StatusDegraded, wantOK: true},
		{name: "unknown no entry", health: monitor.HealthUnknown, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := monitorHealthToLegacyStatus(tc.health, tc.queuedQuick, tc.queuedDeep, tc.runningQuick, tc.runningDeep)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestWatchdogCutoverStatusServesMonitoringProjection is the read-only alias
// evidence (§57.1, §58): after cutover GET /api/watchdog/status serves the
// Monitoring projection (scope id + legacy status vocabulary), not the legacy
// watchdog's own state. The legacy watchdog is deliberately NOT registered
// here, so any legacy-state dependency would produce empty data.
func TestWatchdogCutoverStatusServesMonitoringProjection(t *testing.T) {
	cfg := config.NewConfig()
	cfg.System.Checker.Watchdog.LegacyWatchdogAPI = false
	cfg.System.Checker.Watchdog.Enabled = true
	cfg.System.Checker.Watchdog.IntervalSec = 120

	rt := monitoring.NewRuntime(monitoring.DefaultConfig())
	rt.Start()
	t.Cleanup(func() {
		rt.Stop()
		SetMonitoringRuntime(nil)
	})
	SetMonitoringRuntime(rt)

	rt.ExecuteObservation(monitor.MonitorObservation{
		SchemaVersion: monitor.SchemaVersion,
		ObservationID: "cutover/watchdog-status-1",
		Scope: monitor.MonitorScopeKey{
			ClientScope:      monitor.ClientScopeKey{Role: "router-origin", ID: "watchdog-cutover-test"},
			TargetRole:       "control",
			NetworkContextID: "net-cutover",
			ConfigGeneration: 1,
			IPFamily:         "ipv4",
		},
		Source:             monitor.SourceControlFailure,
		OutcomeCode:        "transport-timeout",
		FailureAttribution: monitor.AttributionTransport,
		Authority:          monitor.AuthorityProvisionalFast,
		ObservedAt:         time.Now().UTC(),
		ExpiresAt:          time.Now().UTC().Add(time.Minute),
	})

	mux := http.NewServeMux()
	api := &API{cfgPtr: testCfgPtr(&cfg), mux: mux}
	api.RegisterWatchdogApi()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/watchdog/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var state watchdog.WatchdogState
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !state.Enabled {
		t.Fatal("enabled must mirror the config after cutover")
	}
	if len(state.Domains) == 0 {
		t.Fatal("status must serve the monitoring projection entries after cutover")
	}
	found := false
	for _, d := range state.Domains {
		if d.Domain == "watchdog-cutover-test" {
			found = true
			// The failed run completes with a scheduled retry, so the scope
			// shows queued_quick=1 in the projection: legacy vocabulary is
			// "queued" (§58) until a lease is acquired (then "escalating").
			if d.Status != watchdog.StatusQueued {
				t.Fatalf("projected status = %q, want %q for a failing scope waiting for diagnostic retry", d.Status, watchdog.StatusQueued)
			}
			if d.MatchedSet != "monitoring-projection" {
				t.Fatalf("matched_set = %q, want monitoring-projection marker", d.MatchedSet)
			}
		}
	}
	if !found {
		t.Fatalf("monitoring projection entry not found in %+v", state.Domains)
	}
}

// TestWatchdogCutoverStatusWithoutRuntime is the fail-closed counterpart: with
// cutover active and no Monitoring runtime registered, the alias must still
// answer 200 with an empty projection (read-only, no own state) instead of
// failing or serving legacy state.
func TestWatchdogCutoverStatusWithoutRuntime(t *testing.T) {
	cfg := config.NewConfig()
	cfg.System.Checker.Watchdog.LegacyWatchdogAPI = false

	mux := http.NewServeMux()
	api := &API{cfgPtr: testCfgPtr(&cfg), mux: mux}
	api.RegisterWatchdogApi()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/watchdog/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with empty projection", rec.Code)
	}
	var state watchdog.WatchdogState
	if err := json.Unmarshal(rec.Body.Bytes(), &state); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(state.Domains) != 0 {
		t.Fatalf("empty projection expected, got %+v", state.Domains)
	}
}

// TestWatchdogPreCutoverMutatingNotGone is the compatibility-surface
// evidence: with the default legacy_watchdog_api=true (shadow surface, before
// the event-driven cutover) the legacy mutating endpoints must NOT answer 410.
func TestWatchdogPreCutoverMutatingNotGone(t *testing.T) {
	cfg := config.NewConfig() // default: LegacyWatchdogAPI == true

	mux := http.NewServeMux()
	api := &API{cfgPtr: testCfgPtr(&cfg), mux: mux}
	api.RegisterWatchdogApi()

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/watchdog/enable", nil))
	if rec.Code == http.StatusGone {
		t.Fatal("pre-cutover legacy mutating endpoint must not answer 410")
	}
}
