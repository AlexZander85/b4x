package monitoring

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/monitor"
)

func lifecycleTestScope() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{Role: "forwarded", ID: "client-afs"},
		ServiceProfileID: "youtube",
		ComponentID:      "video",
		TargetRole:       "target",
		NetworkContextID: "net-afs",
		ConfigGeneration: 4,
		IPFamily:         "ipv4",
	}
}

// TestMaybeOpenAdaptiveSynthesisTriggersOnPersistentRegression proves the
// autonomous trigger opens the AFS lifecycle only for a qualified persistent
// regression when the config opt-in allows it.
func TestMaybeOpenAdaptiveSynthesisTriggersOnPersistentRegression(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	scope := lifecycleTestScope()
	now := time.Now().UTC()
	assessment := monitor.MonitorAssessment{
		SchemaVersion: monitor.SchemaVersion,
		AssessmentID:  "assessment/afs",
		SubjectID:     "subject/afs",
		Scope:         scope,
		Health:        monitor.AxisFailing,
		AssessedAt:    now,
		ExpiresAt:     now.Add(time.Minute),
	}

	// Disabled opt-in: no lifecycle.
	cfg := config.NewConfig()
	cfg.Automation.AdaptiveStrategySynthesis.Enabled = false
	rt.SetConfigProvider(func() *config.Config { return &cfg })
	rt.projector.Correlator().EnsureScope(scope)
	for i := 0; i < 3; i++ {
		rt.projector.Correlator().ObserveHealth(scope, "", monitor.HealthFailing, now)
	}
	rt.maybeOpenAdaptiveSynthesis(scope, assessment, now)
	if status, ok := rt.AdaptiveSynthesisStatus(scope); ok && status.State != "" && status.State != monitor.SynthesisIdle {
		t.Fatalf("lifecycle opened while opt-in disabled: %s", status.State)
	}

	// Enabled opt-in: lifecycle opens.
	cfg.Automation.AdaptiveStrategySynthesis.Enabled = true
	rt.maybeOpenAdaptiveSynthesis(scope, assessment, now)
	status, ok := rt.AdaptiveSynthesisStatus(scope)
	if !ok {
		t.Fatal("adaptive synthesis status unavailable after trigger")
	}
	if status.State == "" || status.State == monitor.SynthesisIdle {
		t.Fatalf("lifecycle not opened on qualified regression: %q", status.State)
	}
}
