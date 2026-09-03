package detector

import (
	"sync"

	"github.com/daniellavrushin/b4/monitor"
)

type EvidenceNodeKind string

const (
	NodeObservation EvidenceNodeKind = "observation"
	NodeHypothesis  EvidenceNodeKind = "hypothesis"
	NodeControl     EvidenceNodeKind = "control"
	NodeAssessment  EvidenceNodeKind = "assessment"
	NodeResolution  EvidenceNodeKind = "resolution"
)

type EvidenceNode struct {
	ID             string
	Kind           EvidenceNodeKind
	Authority      monitor.EvidenceAuthority
	Attribution    monitor.FailureAttribution
	Scope          monitor.MonitorScopeKey
	Active         bool
	IndependentKey string
	Supports       bool
	Excluded       bool
}
type EvidenceEdge struct {
	From, To, Relation string
	Weight             float64
	Provenance         string
}
type EvidenceGraph struct {
	mu    sync.Mutex
	Nodes map[string]EvidenceNode
	Edges []EvidenceEdge
}

func NewEvidenceGraph() *EvidenceGraph { return &EvidenceGraph{Nodes: map[string]EvidenceNode{}} }
func (g *EvidenceGraph) AddNode(n EvidenceNode) {
	if g == nil || n.ID == "" || !n.Scope.Valid() {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Nodes[n.ID] = n
}
func (g *EvidenceGraph) AddEdge(e EvidenceEdge) {
	if g == nil || e.From == "" || e.To == "" || e.Relation == "" {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Edges = append(g.Edges, e)
}

type ConfidenceSummary struct {
	Score                                float64
	Supports, Contradictions, Exclusions int
	IndependentFamilies                  int
	Explanation                          string
}

func (g *EvidenceGraph) Confidence(hypothesisID string) ConfidenceSummary {
	r := ConfidenceSummary{}
	if g == nil {
		return r
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	families := map[string]struct{}{}
	seen := map[string]struct{}{}
	for _, e := range g.Edges {
		if e.To != hypothesisID {
			continue
		}
		n, ok := g.Nodes[e.From]
		if !ok || n.Excluded {
			r.Exclusions++
			continue
		}
		if _, dup := seen[n.ID]; dup {
			continue
		}
		seen[n.ID] = struct{}{}
		if n.Authority == monitor.AuthorityPassiveObservation || n.Authority == monitor.AuthorityProvisionalFast {
			continue
		}
		key := n.IndependentKey
		if key == "" {
			key = n.ID
		}
		if _, dup := families[key]; dup {
			continue
		}
		families[key] = struct{}{}
		if n.Supports {
			r.Supports++
			r.Score += e.Weight
		} else {
			r.Contradictions++
			r.Score -= e.Weight / 2
		}
	}
	r.IndependentFamilies = len(families)
	if r.Score < 0 {
		r.Score = 0
	}
	r.Explanation = "authoritative active evidence only; passive/provisional nodes are provenance"
	return r
}

func (g *EvidenceGraph) AddMonitorProvenance(assessmentID, requestID string, scope monitor.MonitorScopeKey) {
	if g == nil {
		return
	}
	g.AddNode(EvidenceNode{ID: assessmentID, Kind: NodeAssessment, Authority: monitor.AuthorityPassiveObservation, Scope: scope, Active: false, IndependentKey: "monitor:" + assessmentID})
	g.AddNode(EvidenceNode{ID: requestID, Kind: NodeObservation, Authority: monitor.AuthorityProvisionalFast, Scope: scope, Active: false, IndependentKey: "request:" + requestID})
	g.AddEdge(EvidenceEdge{From: assessmentID, To: requestID, Relation: "triggered", Weight: 0, Provenance: "monitor"})
}
