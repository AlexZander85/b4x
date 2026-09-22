package discovery

import (
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

func gateTestAssessment(scope monitor.MonitorScopeKey, now time.Time) monitor.MonitorAssessment {
	return monitor.MonitorAssessment{
		SchemaVersion:          monitor.SchemaVersion,
		AssessmentID:           "assessment/afs",
		SubjectID:              "subject/afs",
		Scope:                  scope,
		Health:                 monitor.AxisFailing,
		IndependentSourceCount: 1,
		TemporalBucket:         now.UTC().Format("2006-01-02T15:04"),
		EvidenceRefs:           []string{"watch/afs"},
		AssessedAt:             now,
		ExpiresAt:              now.Add(time.Minute),
	}
}

func gateTestScope() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{ID: "client-afs", Role: "forwarded"},
		ServiceProfileID: "youtube",
		ComponentID:      "video",
		DomainIdentityID: "googlevideo.com",
		TargetRole:       "target",
		NetworkContextID: "wan-afs",
		ConfigGeneration: 5,
		IPFamily:         "ipv4",
	}
}

func gateTestBlocking(now time.Time) detector.BlockingProfile {
	scope := gateTestScope()
	p, _, _ := detector.CompileBlockingProfile(func() *detector.EvidenceGraph {
		g := detector.NewEvidenceGraph()
		g.AddNode(detector.EvidenceNode{ID: "e", Kind: detector.NodeObservation, Authority: "authoritative-abd", Scope: scope, Supports: true, IndependentKey: "x"})
		g.AddEdge(detector.EvidenceEdge{From: "e", To: "h", Relation: "supports", Weight: 1})
		return g
	}(), detector.MonitorAssessmentRef{AssessmentID: "a", RequestID: "r", Scope: scope, ConfigGeneration: scope.ConfigGeneration}, "h", true, true, []string{"e"}, now)
	return p
}

// TestBuildSynthesisGateInputWiresRetainedABD proves the assembler builds the
// diagnostic profile and DDI prior from retained ABD outputs, and fails closed
// on the behavioral-evidence requirement instead of fabricating it.
func TestBuildSynthesisGateInputWiresRetainedABD(t *testing.T) {
	now := time.Unix(35000, 0)
	scope := gateTestScope()
	blocking := gateTestBlocking(now)
	gate, err := BuildSynthesisGateInput(SynthesisGateContext{
		Assessment:                    gateTestAssessment(scope, now),
		Blocking:                      blocking,
		CurrentConfigGeneration:       scope.ConfigGeneration,
		CandidateCoverage:             []detector.CandidateCoverageVector{{TargetID: "t1", Covered: true}},
		UserOptIn:                     true,
		PersistentRegressionQualified: true,
		RolloutIdle:                   true,
		NoConflictingRun:              true,
		VisibilityReady:               true,
		MandatoryControlsReady:        true,
		TargetPlanComplete:            true,
		ActiveTestAuthorized:          true,
		ResourceBudgetAvailable:       true,
		ResourceOwnershipReady:        true,
		CleanupComplete:               true,
		CatalogEscalationSatisfied:    true,
		Now:                           now,
	})
	if err != nil {
		t.Fatalf("build gate: %v", err)
	}
	if !gate.Profile.Valid(now) {
		t.Fatalf("assembled profile invalid: %+v", gate.Profile)
	}
	if !gate.Prior.Valid() {
		t.Fatalf("assembled prior invalid: %+v", gate.Prior)
	}
	if gate.Profile.Blocking.ProfileID != blocking.ProfileID {
		t.Fatal("profile was not wired from the retained blocking profile")
	}
	if gate.Prior.ProfileID != blocking.ProfileID {
		t.Fatal("prior was not wired from the retained blocking profile")
	}
	err = CheckAutomaticSynthesisGate(gate)
	if err == nil || !strings.Contains(err.Error(), "behavioral") {
		t.Fatalf("gate = %v, want a behavioral-evidence failure", err)
	}
}

func TestBuildSynthesisGateInputRejectsNotReadyProfile(t *testing.T) {
	now := time.Unix(36000, 0)
	blocking := gateTestBlocking(now)
	blocking.Status = detector.ProfileIncomplete
	if _, err := BuildSynthesisGateInput(SynthesisGateContext{Blocking: blocking, Now: now}); err == nil {
		t.Fatal("not-ready blocking profile must be rejected")
	}
}
