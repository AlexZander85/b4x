package routing

import (
	"errors"
	"testing"
)

// FB-18B-5.17 (b4x-zq3): transport fallback graph walk + cycle detection.
// The canonical graph must be acyclic, every path must terminate at the
// direct sink (fail-open), and no edge may reference an unknown path.

func TestTransportFallbackGraphAcyclic(t *testing.T) {
	edges := TransportFallbackEdges()
	if len(edges) == 0 {
		t.Fatal("canonical fallback graph is empty")
	}
	if err := ValidateTransportFallbackAcyclic(edges); err != nil {
		t.Fatalf("canonical fallback graph must be acyclic: %v", err)
	}
	// Every edge endpoint is a known path; no self-loops.
	valid := map[FallbackPath]bool{
		FallbackNative: true, FallbackDirect: true, FallbackGeneric: true, FallbackProxy: true,
	}
	for _, e := range edges {
		if !valid[e.From] || !valid[e.To] {
			t.Fatalf("edge references unknown path: %+v", e)
		}
		if e.From == e.To {
			t.Fatalf("self-loop edge (recursive same-path fallback): %+v", e)
		}
	}
	// Every path eventually reaches the direct sink (fail-open terminal):
	// 3-colour DFS from every node — a back-edge to a grey node is a cycle,
	// while a merge onto an already-black node (e.g. native -> direct and
	// native -> generic -> direct) is a legal DAG join, not recursion.
	adj := map[FallbackPath][]FallbackPath{}
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	for start := range valid {
		const (
			white = 0
			gray  = 1
			black = 2
		)
		color := map[FallbackPath]int{}
		reachedSink := false
		var visit func(n FallbackPath)
		visit = func(n FallbackPath) {
			if FallbackPathIsTerminal(n) {
				reachedSink = true
				return
			}
			color[n] = gray
			for _, m := range adj[n] {
				switch color[m] {
				case gray:
					t.Fatalf("cycle detected walking from %q via %q (recursive fallback)", start, m)
				case white:
					visit(m)
				}
			}
			color[n] = black
		}
		visit(start)
		if !reachedSink {
			t.Fatalf("path %q never reaches the direct fail-open sink", start)
		}
	}
}

func TestTransportFallbackGraphFailsClosedOnCycle(t *testing.T) {
	// Fail-closed: a cyclic fallback graph (proxy -> native -> proxy) is
	// rejected by the validator, never executed on a live flow.
	cyclic := append([]FallbackEdge{}, TransportFallbackEdges()...)
	cyclic = append(cyclic, FallbackEdge{From: FallbackDirect, To: FallbackNative, Reason: "mutation: recursive back-edge"})
	if err := ValidateTransportFallbackAcyclic(cyclic); err == nil {
		t.Fatal("cyclic fallback graph accepted; must fail closed")
	} else if !errors.Is(err, ErrRecursiveFallback) {
		t.Fatalf("cycle error=%v, want ErrRecursiveFallback", err)
	}
	// Self-loop on the same path is the exact recursive transport fallback
	// the invariant forbids (§35 / silentpath.TransportFallbackGate).
	selfLoop := []FallbackEdge{{From: FallbackProxy, To: FallbackProxy, Reason: "mutation"}}
	if err := ValidateTransportFallbackAcyclic(selfLoop); err == nil || !errors.Is(err, ErrRecursiveFallback) {
		t.Fatalf("self-loop accepted or wrong error: %v", err)
	}
	// Unknown node must also fail closed.
	unknown := []FallbackEdge{{From: FallbackProxy, To: FallbackPath("quantum"), Reason: "mutation"}}
	if err := ValidateTransportFallbackAcyclic(unknown); err == nil || !errors.Is(err, ErrRecursiveFallback) {
		t.Fatalf("unknown node accepted or wrong error: %v", err)
	}
}

func TestFallbackCooldownLastGoodNeverSelectsSamePath(t *testing.T) {
	// Regression for the recursive same-path fallback: if the last-good
	// route is the same proxy that just entered cooldown, Decide must NOT
	// return that proxy (recursive fallback onto the same transport path).
	// It must fail open to direct instead.
	m, clk := fallbackManager(t, true, UnknownRouteProxy)
	request := fallbackRequest()
	scope := ScopeID(request.SetID, request.DeviceID, request.Client)
	if err := m.SetHealth("proxy-a", true, clk.Now()); err != nil {
		t.Fatal(err)
	}
	// Last good = proxy-a itself (the failing path), then proxy-a fails.
	if err := m.RecordSuccess(scope, "proxy-a"); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordFailure(scope, "proxy-a"); err != nil {
		t.Fatal(err)
	}
	decision, err := m.Decide(request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Route == RouteProxy || decision.RouteID == "proxy-a" {
		t.Fatalf("recursive same-path fallback: cooldown proxy selected itself as last-good: %+v", decision)
	}
	if !decision.Cooldown {
		t.Fatalf("expected cooldown decision, got %+v", decision)
	}
	if decision.Route != RouteDirect {
		t.Fatalf("expected fail-open direct, got %+v", decision)
	}
	// Sanity: a distinct last-good (generic) is still selected during
	// cooldown — the graph edge proxy -> generic stays reachable.
	if err := m.RecordSuccess(scope, "generic"); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordFailure(scope, "proxy-a"); err != nil {
		t.Fatal(err)
	}
	decision, err = m.Decide(request)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Route != RouteGeneric || !decision.LastGood {
		t.Fatalf("distinct last-good not selected during cooldown: %+v", decision)
	}
}
