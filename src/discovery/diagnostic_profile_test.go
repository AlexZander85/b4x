package discovery

import (
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
	"testing"
	"time"
)

func sampleDDIBlocking(now time.Time) detector.BlockingProfile {
	p, _, _ := detector.CompileBlockingProfile(func() *detector.EvidenceGraph {
		g := detector.NewEvidenceGraph()
		s := monitorScope()
		g.AddNode(detector.EvidenceNode{ID: "e", Kind: detector.NodeObservation, Authority: "authoritative-abd", Scope: s, Supports: true, IndependentKey: "x"})
		g.AddEdge(detector.EvidenceEdge{From: "e", To: "h", Relation: "supports", Weight: 1})
		return g
	}(), detector.MonitorAssessmentRef{AssessmentID: "a", RequestID: "r", Scope: monitorScope(), ConfigGeneration: 1}, "h", true, true, []string{"e"}, now)
	return p
}

func monitorScope() monitor.MonitorScopeKey {
	return monitor.MonitorScopeKey{ClientScope: monitor.ClientScopeKey{ID: "c", Role: "forwarded"}, TargetRole: "target", NetworkContextID: "wan", ConfigGeneration: 1}
}
func TestDiagnosticProfileHashAndRedaction(t *testing.T) {
	now := time.Unix(20000, 0)
	p, err := NewNetworkDiagnosticProfile(sampleDDIBlocking(now), now.Add(time.Minute), now)
	if err != nil || !p.Valid(now) {
		t.Fatalf("profile invalid: %+v %v", p, err)
	}
	if p.ContentHash == "" || p.Redacted()["content_hash"] == "" {
		t.Fatal("hash/redaction missing")
	}
}
