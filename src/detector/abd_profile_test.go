package detector

import (
	"github.com/daniellavrushin/b4/monitor"
	"testing"
	"time"
)

func profileGraph() *EvidenceGraph {
	g := NewEvidenceGraph()
	scope := monitorScopeForDetector()
	g.AddNode(EvidenceNode{ID: "active-a", Kind: NodeObservation, Authority: monitor.AuthorityAuthoritativeABD, Scope: scope, Supports: true, IndependentKey: "dns"})
	g.AddEdge(EvidenceEdge{From: "active-a", To: "blocked", Relation: "supports", Weight: 1})
	return g
}
func TestProfileCompilerRejectsIncompleteRun(t *testing.T) {
	now := time.Unix(17000, 0)
	scope := monitorScopeForDetector()
	p, r, err := CompileBlockingProfile(profileGraph(), MonitorAssessmentRef{AssessmentID: "a", RequestID: "r", Scope: scope, ConfigGeneration: 1}, "blocked", false, true, []string{"e"}, now)
	if err != nil || p.Valid() || r.Status != ResultIncomplete {
		t.Fatalf("incomplete run leaked profile: %+v %+v %v", p, r, err)
	}
}
func TestProfileCompilerIsDeterministicAndLinked(t *testing.T) {
	now := time.Unix(17000, 0)
	scope := monitorScopeForDetector()
	a := MonitorAssessmentRef{AssessmentID: "a", RequestID: "r", Scope: scope, ConfigGeneration: 1}
	p1, r1, err := CompileBlockingProfile(profileGraph(), a, "blocked", true, true, []string{"e1"}, now)
	if err != nil || !p1.Valid() || !r1.Valid() {
		t.Fatalf("profile rejected: %+v %+v %v", p1, r1, err)
	}
	p2, _, _ := CompileBlockingProfile(profileGraph(), a, "blocked", true, true, []string{"e1"}, now)
	if p1.ContentHash != p2.ContentHash || p1.ProfileID != p2.ProfileID {
		t.Fatal("profile compilation not deterministic")
	}
}
