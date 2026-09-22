package monitoring

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

// TestSynthesisInputsRetainedPerScope proves the production monitoring runtime
// retains the decided ABD outcome per scope so a later AFS run can be gated from
// real evidence.
func TestSynthesisInputsRetainedPerScope(t *testing.T) {
	rt := NewRuntime(DefaultConfig())
	rt.Start()
	t.Cleanup(rt.Stop)

	scope := monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{Role: "router-origin", ID: "afs-inputs-test"},
		ServiceProfileID: "youtube",
		ComponentID:      "video",
		TargetRole:       "target",
		NetworkContextID: "net-afs",
		ConfigGeneration: 3,
		IPFamily:         "ipv4",
	}
	now := time.Now().UTC()
	rt.ExecuteObservation(monitor.MonitorObservation{
		SchemaVersion:      monitor.SchemaVersion,
		ObservationID:      "afs-inputs/1",
		Scope:              scope,
		Source:             monitor.SourceControlFailure,
		OutcomeCode:        "transport-timeout",
		FailureAttribution: monitor.AttributionTransport,
		Authority:          monitor.AuthorityProvisionalFast,
		ObservedAt:         now,
		ExpiresAt:          now.Add(time.Minute),
	})

	in, ok := rt.SynthesisInputs(scope)
	if !ok {
		t.Fatal("synthesis inputs not retained for the observed scope")
	}
	if in.Scope != scope {
		t.Fatalf("retained scope mismatch: %+v", in.Scope)
	}
	if in.Assessment.AssessmentID == "" || in.Assessment.Scope != scope {
		t.Fatalf("assessment not retained: %+v", in.Assessment)
	}
	if in.UpdatedAt.IsZero() {
		t.Fatal("updated_at not set")
	}

	other := monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{Role: "forwarded", ID: "other"},
		ServiceProfileID: "youtube",
		ComponentID:      "video",
		TargetRole:       "target",
		NetworkContextID: "net-afs",
		ConfigGeneration: 3,
		IPFamily:         "ipv4",
	}
	if _, ok := rt.SynthesisInputs(other); ok {
		t.Fatal("unexpected retention for an unobserved scope")
	}
}
