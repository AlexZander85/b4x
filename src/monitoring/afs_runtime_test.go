package monitoring

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

func afsRuntimeScope() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{ID: "android-a", Role: "forwarded"},
		ServiceProfileID: "youtube",
		ComponentID:      "video",
		TargetRole:       "target",
		NetworkContextID: "wan-a",
		ConfigGeneration: 11,
		IPFamily:         "ipv4",
	}
}

func afsRuntimeAssessment(scope monitor.MonitorScopeKey, now time.Time) monitor.MonitorAssessment {
	return monitor.MonitorAssessment{
		SchemaVersion:          monitor.SchemaVersion,
		AssessmentID:           "assessment-afs-runtime",
		SubjectID:              "youtube/video",
		Scope:                  scope,
		Health:                 monitor.AxisFailing,
		IndependentSourceCount: 2,
		EvidenceRefs:           []string{"monitor-a", "monitor-b"},
		AssessedAt:             now,
		ExpiresAt:              now.Add(time.Minute),
	}
}

func TestRuntimeRequiresRepeatedRegressionBeforeOpeningSynthesis(t *testing.T) {
	now := time.Now().UTC()
	scope := afsRuntimeScope()
	rt := NewRuntime(DefaultConfig())

	rt.projector.Update(monitor.MonitorStatus{SchemaVersion: monitor.SchemaVersion, Scope: scope, Health: monitor.HealthFailing, UpdatedAt: now})
	if rt.PersistentRegressionQualified(scope) {
		t.Fatal("single failure qualified persistent regression")
	}
	if err := rt.OpenAdaptiveSynthesis(afsRuntimeAssessment(scope, now), "run-1", true, now.Add(time.Minute), now); err == nil {
		t.Fatal("synthesis opened after one transient failure")
	}

	rt.projector.Update(monitor.MonitorStatus{SchemaVersion: monitor.SchemaVersion, Scope: scope, Health: monitor.HealthFailing, UpdatedAt: now.Add(time.Second)})
	rt.projector.Update(monitor.MonitorStatus{SchemaVersion: monitor.SchemaVersion, Scope: scope, Health: monitor.HealthFailing, UpdatedAt: now.Add(2 * time.Second)})
	if !rt.PersistentRegressionQualified(scope) {
		t.Fatal("repeated failing projections did not qualify persistent regression")
	}
	if err := rt.OpenAdaptiveSynthesis(afsRuntimeAssessment(scope, now), "run-1", true, now.Add(time.Minute), now.Add(3*time.Second)); err != nil {
		t.Fatalf("open after persistent regression: %v", err)
	}
	status, ok := rt.Status(scope)
	if !ok || status.AdaptiveSynthesis.State != monitor.SynthesisRegressionConfirmed {
		t.Fatalf("synthesis state not projected: %+v", status.AdaptiveSynthesis)
	}
}

func TestRuntimeDisableCancelsActiveSynthesisWithoutConfigMutation(t *testing.T) {
	now := time.Now().UTC()
	scope := afsRuntimeScope()
	rt := NewRuntime(DefaultConfig())
	for i := 0; i < 3; i++ {
		rt.projector.Update(monitor.MonitorStatus{SchemaVersion: monitor.SchemaVersion, Scope: scope, Health: monitor.HealthFailing, UpdatedAt: now.Add(time.Duration(i) * time.Second)})
	}
	if err := rt.OpenAdaptiveSynthesis(afsRuntimeAssessment(scope, now), "run-1", true, now.Add(time.Minute), now.Add(3*time.Second)); err != nil {
		t.Fatalf("open synthesis: %v", err)
	}
	if err := rt.SetAdaptiveSynthesisEnabled(scope, false, now.Add(4*time.Second)); err != nil {
		t.Fatalf("disable synthesis: %v", err)
	}
	status, ok := rt.Status(scope)
	if !ok {
		t.Fatal("missing projected status")
	}
	if status.AdaptiveSynthesis.Enabled || status.AdaptiveSynthesis.State != monitor.SynthesisCancelled {
		t.Fatalf("disable did not cancel lifecycle: %+v", status.AdaptiveSynthesis)
	}
}

func TestRuntimePublishesPrivacySafeBehavioralSummary(t *testing.T) {
	now := time.Now().UTC()
	scope := afsRuntimeScope()
	rt := NewRuntime(DefaultConfig())
	rt.projector.Update(monitor.MonitorStatus{SchemaVersion: monitor.SchemaVersion, Scope: scope, Health: monitor.HealthFailing, UpdatedAt: now})

	feature := detector.BehaviorFeature{
		FeatureID:    "tls-split-sensitive",
		Group:        "tls",
		State:        "supported",
		Confidence:   0.9,
		Supports:     []detector.StrategyOperatorFamily{detector.OperatorTCPSplit},
		EvidenceRefs: []string{"behavior-probe-1"},
	}
	attempt := detector.BehaviorAttemptSummary{
		ProbeID:           "probe-1",
		Attempt:           1,
		OperatorFamily:    detector.OperatorTCPSplit,
		ReferenceBaseline: detector.BehaviorOutcomeOK,
		TargetBaseline:    detector.BehaviorOutcomeFail,
		ReferenceMutated:  detector.BehaviorOutcomeOK,
		TargetMutated:     detector.BehaviorOutcomeOK,
		Interpretation:    "mutation-bypass-signal",
		Conclusive:        true,
		ObservedAt:        now,
		EvidenceRefs:      []string{"behavior-probe-1"},
	}
	evidence := detector.NewBehavioralFingerprintEvidence(scope, "panel-v1", []detector.BehaviorFeature{feature}, []detector.BehaviorAttemptSummary{attempt}, 0.9, 0.1, now.Add(time.Minute), now)
	if err := rt.PublishBehavioralFingerprint(evidence, now); err != nil {
		t.Fatalf("publish behavioral summary: %v", err)
	}
	status, ok := rt.Status(scope)
	if !ok || status.BehavioralFingerprint == nil {
		t.Fatal("behavioral summary missing from existing monitor status")
	}
	if status.BehavioralFingerprint.EvidenceID != evidence.EvidenceID || status.BehavioralFingerprint.FeatureVectorHash != evidence.FeatureVectorHash {
		t.Fatalf("behavioral summary mismatch: %+v", status.BehavioralFingerprint)
	}
}
