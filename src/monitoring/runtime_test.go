package monitoring

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

func validScope() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{Role: "router-origin", ID: "node-a"},
		TargetRole:       "control",
		NetworkContextID: "net-1",
		ConfigGeneration: 1,
		IPFamily:         "ipv4",
	}
}

func TestRuntimeETLFailureToProjection(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	scope := validScope()

	// An explicit failure observation must land in the bounded scheduler and
	// produce a non-unknown health projection (ETL wiring probe).
	ready := rt.Ingest(monitor.MonitorObservation{
		SchemaVersion:        monitor.SchemaVersion,
		ObservationID:        "watchdog/test-1",
		Scope:                scope,
		Source:               monitor.SourceControlFailure,
		OutcomeCode:          "transport-timeout",
		FailureAttribution:   monitor.AttributionTransport,
		Authority:            monitor.AuthorityProvisionalFast,
		ObservedAt:           time.Now().UTC(),
		ExpiresAt:            time.Now().UTC().Add(time.Minute),
		ResolutionSnapshotID: "watchdog",
	})
	if !ready {
		t.Fatal("observation must be ingested")
	}
	rt.ExecuteObservation(monitor.MonitorObservation{
		SchemaVersion:      monitor.SchemaVersion,
		ObservationID:      "watchdog/test-1",
		Scope:              scope,
		Source:             monitor.SourceControlFailure,
		OutcomeCode:        "transport-timeout",
		FailureAttribution: monitor.AttributionTransport,
		Authority:          monitor.AuthorityProvisionalFast,
		ObservedAt:         time.Now().UTC(),
		ExpiresAt:          time.Now().UTC().Add(time.Minute),
	})
	st, ok := rt.Status(scope)
	if !ok {
		t.Fatal("projection must exist for a processed scope")
	}
	if st.Health == monitor.HealthUnknown {
		t.Fatalf("projection health must be decided after processing, got %v", st.Health)
	}
	if st.SchemaVersion != monitor.SchemaVersion {
		t.Fatalf("projection schema version must match monitor schema, got %d", st.SchemaVersion)
	}
	list := rt.StatusList()
	if len(list) == 0 {
		t.Fatal("status list must contain the processed scope")
	}
}

func TestRuntimeRejectsInvalidObservation(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	// A scope without a network context must be rejected at ingest time.
	if rt.IngestFailure(monitor.MonitorScopeKey{}, "x", monitor.AttributionTransport, time.Time{}) {
		t.Fatal("an invalid scope must be rejected")
	}
}

func TestRuntimeStopSafe(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	rt.Stop() // never started: stopping must not panic
	rt.Stop() // double-stop must be idempotent
	rt.Start()
	rt.Stop()
}

func TestRuntimeShadowParityEvidenceOnWatchdogSignal(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	scope := validScope()
	now := time.Now().UTC()

	// A watchdog control-failure observation goes through the escalation
	// chain; the resulting projection must also be recorded as shadow parity
	// evidence (phase A: both pipelines count, evidence is collected).
	rt.Ingest(monitor.MonitorObservation{
		SchemaVersion:        monitor.SchemaVersion,
		ObservationID:        "watchdog/parity-1",
		Scope:                scope,
		Source:               monitor.SourceControlFailure,
		OutcomeCode:          "transport-timeout",
		FailureAttribution:   monitor.AttributionTransport,
		Authority:            monitor.AuthorityProvisionalFast,
		ObservedAt:           now,
		ExpiresAt:            now.Add(time.Minute),
		ResolutionSnapshotID: "watchdog",
	})
	rt.ExecuteObservation(monitor.MonitorObservation{
		SchemaVersion:      monitor.SchemaVersion,
		ObservationID:      "watchdog/parity-1",
		Scope:              scope,
		Source:             monitor.SourceControlFailure,
		OutcomeCode:        "transport-timeout",
		FailureAttribution: monitor.AttributionTransport,
		Authority:          monitor.AuthorityProvisionalFast,
		ObservedAt:         now,
		ExpiresAt:          now.Add(time.Minute),
	})

	ev, ok, total, contradictions := rt.ShadowParity(scope)
	if !ok {
		t.Fatal("shadow parity evidence must exist after a watchdog control-failure observation")
	}
	if ev.WatchdogState != "failing" {
		t.Fatalf("watchdog state must be failing for a control-failure signal, got %q", ev.WatchdogState)
	}
	if ev.AssessmentID == "" {
		t.Fatal("evidence must reference the canonical monitor assessment")
	}
	if total < 1 {
		t.Fatalf("tracker totals must include the observation, got %d", total)
	}
	if contradictions < 0 || contradictions > total {
		t.Fatalf("contradiction count %d outside [0,%d]", contradictions, total)
	}
}

