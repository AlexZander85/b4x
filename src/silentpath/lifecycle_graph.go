package silentpath

// FB-18B-5.17 (b4x-zq3): the recovery lifecycle is a strict one-way
// pipeline — authorization -> visibility -> correlation -> recovery ->
// rollback — with observe-only as the terminal state after a false-positive
// budget breach. No edge points backwards, so the graph is acyclic by
// construction; NewRollbackMonitor verifies it fail-closed so a future code
// change re-introducing recursion (e.g. recovery re-triggering
// authorization) is rejected at construction. This mirrors the routing
// package transport fallback graph: same invariant, same fail-closed
// pattern, and the runtime gates (TransportFallbackGate, RotationGate,
// RollbackTargetGate, FalsePositiveBudgetGate) make each edge conditional
// on bounded progress.

import (
	"errors"
	"fmt"
	"sort"
)

// RecoveryStage is one node of the recovery lifecycle graph.
type RecoveryStage string

const (
	StageAuthorize   RecoveryStage = "authorize"
	StageVisibility  RecoveryStage = "visibility"
	StageCorrelate   RecoveryStage = "correlate"
	StageRecover     RecoveryStage = "recover"
	StageRollback    RecoveryStage = "rollback"
	StageObserveOnly RecoveryStage = "observe-only"
)

// RecoveryEdge is one directed transition of the recovery lifecycle graph.
type RecoveryEdge struct {
	From, To RecoveryStage
	Reason   string
}

// ErrRecursiveRecovery is the fail-closed error a cyclic recovery graph
// produces.
var ErrRecursiveRecovery = errors.New("recursive recovery: recovery lifecycle graph contains a cycle")

// RecoveryLifecycleEdges is the canonical recovery graph. The lifecycle is
// one-way (hard_gate_producers.go package comment); observe-only is the
// terminal sink reached when the rollback budget is exhausted
// (FalsePositiveBudgetGate flips the monitor to observe-only and recovery
// actions are refused from then on).
func RecoveryLifecycleEdges() []RecoveryEdge {
	return []RecoveryEdge{
		{From: StageAuthorize, To: StageVisibility, Reason: "authorization precedes visibility proofs"},
		{From: StageVisibility, To: StageCorrelate, Reason: "complete bidirectional visibility required before correlation"},
		{From: StageCorrelate, To: StageRecover, Reason: "recovery only after correlation with independent evidence families"},
		{From: StageRecover, To: StageRollback, Reason: "every recovery lease carries a rollback target (RollbackTargetGate)"},
		{From: StageRollback, To: StageObserveOnly, Reason: "budget exhaustion flips monitor to observe-only (terminal)"},
	}
}

// RecoveryStageIsTerminal reports whether the stage never transitions
// further (sink of the recovery lifecycle graph).
func RecoveryStageIsTerminal(s RecoveryStage) bool { return s == StageObserveOnly }

// init verifies the canonical recovery lifecycle graph fail-closed at
// package load: a code change that makes recovery recursive (a cycle in
// RecoveryLifecycleEdges) crashes the process at startup instead of looping
// on a live flow.
func init() {
	if err := ValidateRecoveryLifecycleAcyclic(RecoveryLifecycleEdges()); err != nil {
		panic("silentpath: " + err.Error())
	}
}

// ValidateRecoveryLifecycleAcyclic runs a 3-colour DFS over the given
// recovery edges and returns ErrRecursiveRecovery (fail-closed) if a cycle
// is found or if any edge references an unknown stage. It never mutates the
// caller's slice. NewRollbackMonitor runs it on the canonical graph at
// construction.
func ValidateRecoveryLifecycleAcyclic(edges []RecoveryEdge) error {
	valid := map[RecoveryStage]bool{
		StageAuthorize: true, StageVisibility: true, StageCorrelate: true,
		StageRecover: true, StageRollback: true, StageObserveOnly: true,
	}
	adj := map[RecoveryStage][]RecoveryStage{}
	known := map[RecoveryStage]bool{}
	for _, e := range edges {
		if !valid[e.From] {
			return fmt.Errorf("%w: unknown recovery stage %q", ErrRecursiveRecovery, e.From)
		}
		if !valid[e.To] {
			return fmt.Errorf("%w: unknown recovery stage %q", ErrRecursiveRecovery, e.To)
		}
		if e.From == e.To {
			return fmt.Errorf("%w: self-loop on %q (recursive recovery)", ErrRecursiveRecovery, e.From)
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
	color := map[RecoveryStage]int{}
	var visit func(n RecoveryStage) error
	visit = func(n RecoveryStage) error {
		color[n] = gray
		for _, m := range adj[n] {
			switch color[m] {
			case gray:
				return fmt.Errorf("%w: cycle at %q -> %q", ErrRecursiveRecovery, n, m)
			case white:
				if err := visit(m); err != nil {
					return err
				}
			}
		}
		color[n] = black
		return nil
	}
	nodes := make([]string, 0, len(known))
	for n := range known {
		nodes = append(nodes, string(n))
	}
	sort.Strings(nodes)
	for _, n := range nodes {
		if color[RecoveryStage(n)] == white {
			if err := visit(RecoveryStage(n)); err != nil {
				return err
			}
		}
	}
	return nil
}
