package vless

import (
	"context"
	"fmt"
	"testing"
	"time"
)

type countingProber struct {
	n     *int
	probe func(Node) ProbeResult
}

func (c countingProber) Probe(_ context.Context, n Node) ProbeResult {
	*c.n++
	return c.probe(n)
}

// A large candidate set (a bundled public list) must not make every pass probe
// thousands of nodes: the pass is bounded and takes the memory-ordered head.
func TestSelectorProbeBound(t *testing.T) {
	probed := 0
	p := countingProber{n: &probed, probe: func(n Node) ProbeResult {
		return ProbeResult{Node: n, OK: true, LatencyMs: 5, Loc: "DE"}
	}}
	s := NewSelector(SeekConfig{}, p)
	nodes := make([]Node, 500)
	for i := range nodes {
		nodes[i] = nodeAt(fmt.Sprintf("n%03d.example.org", i))
	}
	s.SetNodes(nodes)
	if _, ok := s.Select(context.Background()); !ok {
		t.Fatal("no selection")
	}
	if probed > maxProbePerPass {
		t.Fatalf("probed %d nodes, want <= %d", probed, maxProbePerPass)
	}
}

// A known-good node must stay in the bounded probe set even when it is far down
// the corpus order.
func TestSelectorProbeSetKeepsKnownGood(t *testing.T) {
	now := time.Now()
	fresh := float64(now.Add(-time.Minute).UnixNano()) / 1e9
	good := nodeAt("zzz-known-good.example.org")
	st := &StatsStore{entries: map[string]NodeStat{
		good.Identity(): {OK: 10, LastOKAt: fresh, RTTMs: 30, RTTAt: fresh},
	}}
	s := NewSelector(SeekConfig{}, nil)
	s.Stats = st
	nodes := []Node{good}
	for i := 0; i < 300; i++ {
		nodes = append(nodes, nodeAt(fmt.Sprintf("a%03d.example.org", i)))
	}
	s.SetNodes(nodes)
	set := s.probeSet(now)
	if len(set) > maxProbePerPass {
		t.Fatalf("probe set %d > %d", len(set), maxProbePerPass)
	}
	found := false
	for _, n := range set {
		if n.Identity() == good.Identity() {
			found = true
		}
	}
	if !found {
		t.Fatal("known-good node dropped from the bounded probe set")
	}
}
