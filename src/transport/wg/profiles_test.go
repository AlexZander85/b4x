package transportwg

import "testing"

// TestProfileEngineGenerationGatesLadder is the PATCH-17 (WG MINOR 12)
// acceptance test: a profile whose EngineGeneration exceeds the current
// demon is SKIPPED by the ladder and re-enters after the demon updates.
func TestProfileEngineGenerationGatesLadder(t *testing.T) {
	demonGen2 := ProfileTemplate{
		ID:               "awg-sh-future",
		Target:           TargetAwgServer,
		EngineGeneration: 2,
		build: func() Profile {
			p, _ := LookupProfile("awg-sh-a")
			pp, _ := p.Build()
			return pp
		},
	}
	current := ProfileTemplate{
		ID:     "awg-sh-a",
		Target: TargetAwgServer,
		build: func() Profile {
			tpl, _ := LookupProfile("awg-sh-a")
			pp, _ := tpl.Build()
			return pp
		},
	}
	ladder := []ProfileTemplate{demonGen2, current}

	SetEngineGeneration(1)
	got := filterByEngineGeneration(ladder)
	if len(got) != 1 || got[0].ID != "awg-sh-a" {
		t.Fatalf("demon gen 1 ladder = %+v, want only awg-sh-a", idsOf(got))
	}

	SetEngineGeneration(2)
	got = filterByEngineGeneration(ladder)
	if len(got) != 2 {
		t.Fatalf("after demon upgrade ladder = %+v, want both profiles", idsOf(got))
	}

	// The seed ladder is unaffected by the gate (all seeds are gen 0).
	ResetEngineGenerationForTest()
	seedLadder, err := LadderFor(TargetAwgServer, "")
	if err != nil || len(seedLadder) == 0 {
		t.Fatalf("seed awg ladder broken: %v", err)
	}
}

func idsOf(tpls []ProfileTemplate) []string {
	out := make([]string, 0, len(tpls))
	for _, t := range tpls {
		out = append(out, t.ID)
	}
	return out
}
