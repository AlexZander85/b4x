package routing

// FB-18B-5.17 (b4x-zq3): no recursive fallback; transport/recovery graph
// acyclic. The FallbackManager escape path is modelled as an explicit graph:
// nodes are transport paths (native/direct/generic/proxy), edges are the
// transitions the runtime may take when the current path is unavailable.
// The graph has no cycle by construction, and NewFallbackManager verifies
// it fail-closed: a future code change introducing a fallback cycle (e.g.
// proxy -> same proxy) is rejected at construction time instead of looping
// in production. Mirrors silentpath.TransportFallbackGate semantics: a
// candidate path must differ from the current path.

import (
	"errors"
	"fmt"
	"sort"
)

// FallbackPath is one node of the transport fallback graph — a transport
// path the manager may route a flow onto.
type FallbackPath string

const (
	FallbackNative  FallbackPath = "native"
	FallbackDirect  FallbackPath = "direct"
	FallbackGeneric FallbackPath = "generic"
	FallbackProxy   FallbackPath = "proxy"
)

// FallbackEdge is one directed transition of the transport fallback graph:
// From is the path currently considered, To is the path the manager may
// move to when From is unavailable.
type FallbackEdge struct {
	From, To FallbackPath
	Reason   string
}

// ErrRecursiveFallback is the fail-closed error a cyclic fallback graph
// produces. It wraps ErrRouteInvalid so NewFallbackManager rejects it as a
// route configuration error.
var ErrRecursiveFallback = errors.New("recursive transport fallback: fallback graph contains a cycle")

// TransportFallbackEdges is the canonical fallback graph, mirroring
// chooseFallbackLocked/Decide exactly:
//
//	native   -> direct   (fallback disabled, processed/native action applied,
//	                      or native capability/processing miss; fail-open)
//	native   -> generic  (policy UnknownUseGeneric with capability)
//	native   -> proxy    (policy UnknownRouteProxy with capability)
//	generic  -> direct   (generic lacks protocol/family capability or
//	                      route isolation metadata is incomplete)
//	proxy    -> direct    (proxy unhealthy, cooldown without a usable last-good
//	                      path, capability miss, or metadata incomplete)
//	proxy    -> generic   (proxy cooldown with last-good generic path)
//
// There is deliberately NO proxy -> proxy edge: a proxy may never select
// itself as its own fallback (recursive transport fallback, §35). direct is
// a sink: it never transitions further (fail-open terminal).
func TransportFallbackEdges() []FallbackEdge {
	return []FallbackEdge{
		{From: FallbackNative, To: FallbackDirect, Reason: "fallback disabled or native miss; fail-open direct"},
		{From: FallbackNative, To: FallbackGeneric, Reason: "policy=generic"},
		{From: FallbackNative, To: FallbackProxy, Reason: "policy=proxy"},
		{From: FallbackGeneric, To: FallbackDirect, Reason: "generic capability/meta miss; fail-open direct"},
		{From: FallbackProxy, To: FallbackDirect, Reason: "proxy unhealthy/cooldown/no last-good; fail-open direct"},
		{From: FallbackProxy, To: FallbackGeneric, Reason: "proxy cooldown with usable generic last-good"},
	}
}

// FallbackPathIsTerminal reports whether the path never transitions further
// (fail-open sinks of the fallback graph).
func FallbackPathIsTerminal(p FallbackPath) bool { return p == FallbackDirect }

// ValidateTransportFallbackAcyclic runs a 3-colour DFS over the given
// fallback edges and returns ErrRecursiveFallback (fail-closed) if a cycle
// is found or if any edge references an unknown path. It never mutates the
// caller's slice. NewFallbackManager runs it on the canonical graph at
// construction, so a future cyclic fallback wiring fails closed before any
// flow is routed.
func ValidateTransportFallbackAcyclic(edges []FallbackEdge) error {
	// Resolve nodes.
	valid := map[FallbackPath]bool{
		FallbackNative: true, FallbackDirect: true, FallbackGeneric: true, FallbackProxy: true,
	}
	adj := map[FallbackPath][]FallbackPath{}
	known := map[FallbackPath]bool{}
	for _, e := range edges {
		if !valid[e.From] {
			return fmt.Errorf("%w: unknown fallback node %q", ErrRecursiveFallback, e.From)
		}
		if !valid[e.To] {
			return fmt.Errorf("%w: unknown fallback node %q across =", ErrRecursiveFallback, e.To)
		}
		if e.From == e.To {
			return fmt.Errorf("%w: self-loop on %q (same-path fallback)", ErrRecursiveFallback, e.From)
		}
		known[e.From] = true
		known[e.To] = true
		adj[e.From] = append(adj[e.From], e.To)
	}
	const (
		white = 0
		gray  = 1
		black = 2
	)
	color := map[FallbackPath]int{}
	var visit func(n FallbackPath) error
	visit = func(n FallbackPath) error {
		color[n] = gray
		for _, m := range adj[n] {
			switch color[m] {
			case gray:
				return fmt.Errorf("%w: cycle at %q -> %q", ErrRecursiveFallback, n, m)
			case white:
				if err := visit(m); err != nil {
					return err
				}
			}
		}
		color[n] = black
		return nil
	}
	// Visit in deterministic order (sorted) so the error is stable.
	nodes := make([]string, 0, len(known))
	for n := range known {
		nodes = append(nodes, string(n))
	}
	sort.Strings(nodes)
	for _, n := range nodes {
		if color[FallbackPath(n)] == white {
			if err := visit(FallbackPath(n)); err != nil {
				return err
			}
		}
	}
	return nil
}
