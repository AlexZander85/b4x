package silentpath

import (
	"errors"
	"testing"
)

// FB-18B-5.17 (b4x-zq3): recovery lifecycle graph walk + cycle detection.
// The lifecycle is one-way (authorize -> visibility -> correlate -> recover
// -> rollback -> observe-only); no edge points backwards and observe-only
// is the terminal sink. A cyclic recovery wiring must fail closed.

func TestRecoveryLifecycleGraphAcyclic(t *testing.T) {
	edges := RecoveryLifecycleEdges()
	if len(edges) == 0 {
		t.Fatal("canonical recovery lifecycle graph is empty")
	}
	if err := ValidateRecoveryLifecycleAcyclic(edges); err != nil {
		t.Fatalf("canonical recovery lifecycle graph must be acyclic: %v", err)
	}
	valid := map[RecoveryStage]bool{
		StageAuthorize: true, StageVisibility: true, StageCorrelate: true,
		StageRecover: true, StageRollback: true, StageObserveOnly: true,
	}
	for _, e := range edges {
		if !valid[e.From] || !valid[e.To] {
			t.Fatalf("edge references unknown stage: %+v", e)
		}
		if e.From == e.To {
			t.Fatalf("self-loop edge (recursive recovery): %+v", e)
		}
	}
	// Walk: 3-colour DFS from every stage — a back-edge to a grey node is a
	// cycle (recursive recovery); merges onto black nodes are legal DAG
	// joins. Every stage must reach the observe-only terminal.
	adj := map[RecoveryStage][]RecoveryStage{}
	for _, e := range edges {
		adj[e.From] = append(adj[e.From], e.To)
	}
	for start := range valid {
		const (
			white = 0
			gray  = 1
			black = 2
		)
		color := map[RecoveryStage]int{}
		reachedTerminal := false
		var visit func(n RecoveryStage)
		visit = func(n RecoveryStage) {
			if RecoveryStageIsTerminal(n) {
				reachedTerminal = true
				return
			}
			color[n] = gray
			for _, m := range adj[n] {
				switch color[m] {
				case gray:
					t.Fatalf("cycle detected walking from %q via %q (recursive recovery)", start, m)
				case white:
					visit(m)
				}
			}
			color[n] = black
		}
		visit(start)
		if !reachedTerminal {
			t.Fatalf("stage %q never reaches the observe-only terminal", start)
		}
	}
}

func TestRecoveryLifecycleGraphFailsClosedOnCycle(t *testing.T) {
	// Fail-closed: rollback re-entering authorization is a recursive
	// recovery and must be rejected.
	cyclic := append([]RecoveryEdge{}, RecoveryLifecycleEdges()...)
	cyclic = append(cyclic, RecoveryEdge{From: StageRollback, To: StageAuthorize, Reason: "mutation: recursive back-edge"})
	if err := ValidateRecoveryLifecycleAcyclic(cyclic); err == nil {
		t.Fatal("cyclic recovery lifecycle graph accepted; must fail closed")
	} else if !errors.Is(err, ErrRecursiveRecovery) {
		t.Fatalf("cycle error=%v, want ErrRecursiveRecovery", err)
	}
	// Self-loop on recover is the exact recursion the invariant forbids.
	selfLoop := []RecoveryEdge{{From: StageRecover, To: StageRecover, Reason: "mutation"}}
	if err := ValidateRecoveryLifecycleAcyclic(selfLoop); err == nil || !errors.Is(err, ErrRecursiveRecovery) {
		t.Fatalf("self-loop accepted or wrong error: %v", err)
	}
	// Unknown stage must also fail closed.
	unknown := []RecoveryEdge{{From: StageRecover, To: RecoveryStage("teleport"), Reason: "mutation"}}
	if err := ValidateRecoveryLifecycleAcyclic(unknown); err == nil || !errors.Is(err, ErrRecursiveRecovery) {
		t.Fatalf("unknown stage accepted or wrong error: %v", err)
	}
}
