package detector

import (
	"github.com/daniellavrushin/b4/monitor"
	"testing"
)

func TestEvidenceGraphIgnoresPassiveRecurrenceForConfidence(t *testing.T) {
	g := NewEvidenceGraph()
	scope := monitorScopeForDetector()
	g.AddNode(EvidenceNode{ID: "passive", Kind: NodeObservation, Authority: monitor.AuthorityPassiveObservation, Scope: scope, Supports: true, IndependentKey: "source"})
	g.AddNode(EvidenceNode{ID: "active", Kind: NodeObservation, Authority: monitor.AuthorityAuthoritativeABD, Scope: scope, Supports: true, IndependentKey: "source"})
	g.AddEdge(EvidenceEdge{From: "passive", To: "h", Relation: "supports", Weight: 1})
	g.AddEdge(EvidenceEdge{From: "active", To: "h", Relation: "supports", Weight: 1})
	r := g.Confidence("h")
	if r.Supports != 1 || r.IndependentFamilies != 1 {
		t.Fatalf("passive recurrence inflated confidence: %+v", r)
	}
}

func TestEvidenceGraphRetainsContradictionAndExclusion(t *testing.T) {
	g := NewEvidenceGraph()
	scope := monitorScopeForDetector()
	g.AddNode(EvidenceNode{ID: "bad", Kind: NodeObservation, Authority: monitor.AuthorityAuthoritativeABD, Scope: scope, Supports: false, IndependentKey: "bad"})
	g.AddNode(EvidenceNode{ID: "excluded", Kind: NodeObservation, Authority: monitor.AuthorityAuthoritativeABD, Scope: scope, Excluded: true, Supports: true})
	g.AddEdge(EvidenceEdge{From: "bad", To: "h", Relation: "contradicts", Weight: 1})
	g.AddEdge(EvidenceEdge{From: "excluded", To: "h", Relation: "supports", Weight: 1})
	r := g.Confidence("h")
	if r.Contradictions != 1 || r.Exclusions != 1 || r.Score != 0 {
		t.Fatalf("contradiction/exclusion not enforced: %+v", r)
	}
}
