package discovery

import (
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

func validSynthesisGateInput(t *testing.T, now time.Time) SynthesisGateInput {
	t.Helper()
	scope := monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{ID: "client-a", Role: "forwarded"},
		ServiceProfileID: "service-a",
		ComponentID:      "tls",
		TargetRole:       "target",
		IPFamily:         "ipv4",
		NetworkContextID: "network-a",
		ConfigGeneration: 7,
	}

	graph := detector.NewEvidenceGraph()
	graph.AddNode(detector.EvidenceNode{
		ID:             "abd-e1",
		Kind:           detector.NodeObservation,
		Authority:      monitor.AuthorityAuthoritativeABD,
		Scope:          scope,
		Active:         true,
		IndependentKey: "transport",
		Supports:       true,
	})
	graph.AddEdge(detector.EvidenceEdge{From: "abd-e1", To: "dpi", Relation: "supports", Weight: 1})

	blocking, _, err := detector.CompileBlockingProfile(
		graph,
		detector.MonitorAssessmentRef{AssessmentID: "assessment-a", RequestID: "request-a", Scope: scope, ConfigGeneration: scope.ConfigGeneration},
		"dpi",
		true,
		true,
		[]string{"abd-e1"},
		now,
	)
	if err != nil {
		t.Fatalf("blocking profile: %v", err)
	}
	interpretation, conclusive := detector.ClassifyFourWayBehavior(
		detector.BehaviorOutcomeOK,
		detector.BehaviorOutcomeFail,
		detector.BehaviorOutcomeOK,
		detector.BehaviorOutcomeOK,
	)
	attempt := detector.BehaviorAttemptSummary{
		ProbeID:            "probe-a",
		Attempt:            1,
		OperatorFamily:     detector.OperatorTCPSplit,
		ReferenceBaseline:  detector.BehaviorOutcomeOK,
		TargetBaseline:     detector.BehaviorOutcomeFail,
		ReferenceMutated:   detector.BehaviorOutcomeOK,
		TargetMutated:      detector.BehaviorOutcomeOK,
		Interpretation:     interpretation,
		Conclusive:         conclusive,
		ObservedAt:         now,
		EvidenceRefs:       []string{"probe-a/r1", "probe-a/r2", "probe-a/r3", "probe-a/r4"},
	}
	feature := detector.BehaviorFeature{
		FeatureID:    "tcp-split-sensitive",
		Group:        "tcp_reassembly",
		State:        "mutation-bypass-signal",
		Confidence:   0.9,
		Supports:     []detector.StrategyOperatorFamily{detector.OperatorTCPSplit},
		EvidenceRefs: []string{"probe-a"},
	}
	behavioral := detector.NewBehavioralFingerprintEvidence(
		scope,
		"afs-panel-v1",
		[]detector.BehaviorFeature{feature},
		[]detector.BehaviorAttemptSummary{attempt},
		0.9,
		0.1,
		now.Add(time.Minute),
		now,
	)
	blocking, err = detector.AttachBehavioralEvidence(blocking, behavioral, graph, now)
	if err != nil {
		t.Fatalf("attach behavioral evidence: %v", err)
	}
	profile, err := NewNetworkDiagnosticProfile(blocking, now.Add(time.Minute), now)
	if err != nil {
		t.Fatalf("diagnostic profile: %v", err)
	}
	prior := detector.DiscoverySearchPrior{
		Scope:                scope,
		ProfileID:            blocking.ProfileID,
		BehavioralEvidenceID: behavioral.EvidenceID,
		SupportedOperators:   []detector.StrategyOperatorFamily{detector.OperatorTCPSplit},
		CoverageDenominator:  1,
		MandatoryBaselines:   []string{"baseline-none", "baseline-production"},
		Applied:              true,
	}
	assessment := monitor.MonitorAssessment{
		SchemaVersion: monitor.SchemaVersion,
		AssessmentID:  "assessment-a",
		SubjectID:     "service-a",
		Scope:         scope,
		Health:        monitor.AxisFailing,
		AssessedAt:    now,
		ExpiresAt:     now.Add(time.Minute),
		EvidenceRefs:  []string{"monitor-e1"},
	}
	return SynthesisGateInput{
		UserOptIn:                     true,
		PersistentRegressionQualified: true,
		Assessment:                    assessment,
		Profile:                       profile,
		Prior:                         prior,
		CurrentConfigGeneration:       scope.ConfigGeneration,
		RolloutIdle:                   true,
		NoConflictingRun:              true,
		VisibilityReady:               true,
		MandatoryControlsReady:        true,
		TargetPlanComplete:            true,
		ActiveTestAuthorized:          true,
		ResourceBudgetAvailable:       true,
		CleanupComplete:               true,
		CatalogEscalationSatisfied:    true,
		Now:                           now,
	}
}

func TestAutomaticSynthesisGateAcceptsCompletePreflight(t *testing.T) {
	now := time.Unix(22000, 0)
	if err := CheckAutomaticSynthesisGate(validSynthesisGateInput(t, now)); err != nil {
		t.Fatalf("valid synthesis gate rejected: %v", err)
	}
}

func TestAutomaticSynthesisGateSuppressors(t *testing.T) {
	now := time.Unix(23000, 0)
	tests := []struct {
		name string
		want string
		mut  func(*SynthesisGateInput)
	}{
		{"cleanup", "cleanup", func(in *SynthesisGateInput) { in.CleanupComplete = false }},
		{"conflicting-run", "active Discovery or synthesis run", func(in *SynthesisGateInput) { in.NoConflictingRun = false }},
		{"cooldown", "cooldown", func(in *SynthesisGateInput) { in.NextEligibleAt = now.Add(time.Minute) }},
		{"resource-budget", "resource budget", func(in *SynthesisGateInput) { in.ResourceBudgetAvailable = false }},
		{"catalog-escalation", "catalog strategy escalation", func(in *SynthesisGateInput) { in.CatalogEscalationSatisfied = false }},
		{"target-plan", "target plan", func(in *SynthesisGateInput) { in.TargetPlanComplete = false }},
		{"active-test-authorization", "not authorized", func(in *SynthesisGateInput) { in.ActiveTestAuthorized = false }},
		{"controls", "control", func(in *SynthesisGateInput) { in.MandatoryControlsReady = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := validSynthesisGateInput(t, now)
			tc.mut(&in)
			err := CheckAutomaticSynthesisGate(in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("gate error = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestAutomaticSynthesisGateRequiresExactServiceComponentScope(t *testing.T) {
	now := time.Unix(24000, 0)
	in := validSynthesisGateInput(t, now)
	in.Profile.Scope.ServiceProfileID = ""
	if err := CheckAutomaticSynthesisGate(in); err == nil || !strings.Contains(err.Error(), "service profile") {
		t.Fatalf("service-profile escape accepted: %v", err)
	}

	in = validSynthesisGateInput(t, now)
	in.Profile.Scope.ComponentID = ""
	if err := CheckAutomaticSynthesisGate(in); err == nil || !strings.Contains(err.Error(), "component") {
		t.Fatalf("component escape accepted: %v", err)
	}
}
