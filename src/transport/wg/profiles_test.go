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

// ---- E-PROTON junk-size discipline (review P4 + §6) --------------------------------

// TestProtonJunkSizesPlausible is the deterministic wire-capture unit of
// review §6: every Proton-family profile must ship EITHER no junk at all
// (jc=0 — the I1 IS the first packet) OR plausible-size junk (>= 40 B —
// the QUIC-frame neighborhood). Sub-4-byte UDP datagrams toward 443 are
// the instant "no real protocol does this" classifier the review flagged.
func TestProtonJunkSizesPlausible(t *testing.T) {
	for _, id := range CatalogIDs() {
		tpl, err := LookupProfile(id)
		if err != nil {
			t.Fatalf("lookup %s: %v", id, err)
		}
		if tpl.Target != TargetProton {
			continue
		}
		p, err := tpl.Build()
		if err != nil {
			t.Fatalf("build %s: %v", id, err)
		}
		if p.JunkCount == 0 {
			continue // clean I1 — fine
		}
		if p.JunkMin < 40 {
			t.Fatalf("%s: JunkMin = %d — junk below 40 B is itself a DPI signature (review P4)", id, p.JunkMin)
		}
		if p.JunkMax < p.JunkMin {
			t.Fatalf("%s: JunkMax %d < JunkMin %d", id, p.JunkMax, p.JunkMin)
		}
	}
}

// TestProtonQuicIsCleanI1 pins the P4 recommendation: the preferred rung
// ships Jc=0 (pure I1) — no sub-signature junk in front of the flow.
func TestProtonQuicIsCleanI1(t *testing.T) {
	tpl, err := LookupProfile("proton-quic")
	if err != nil {
		t.Fatal(err)
	}
	p, err := tpl.Build()
	if err != nil {
		t.Fatal(err)
	}
	if p.JunkCount != 0 {
		t.Fatalf("proton-quic JunkCount = %d, want 0 (review P4)", p.JunkCount)
	}
	if !tpl.RuntimeI1 {
		t.Fatal("proton-quic must keep RuntimeI1 (the I1 is generated at runtime)")
	}
	if !p.VanillaSafe() {
		t.Fatal("proton-quic must stay vanilla-safe")
	}
}

// TestProtonQuicJ40IsFieldRung pins the experimental rung: plausible
// 40..70 B junk, RuntimeI1, vanilla-safe, available to the catalog (field
// trials pin it via obfuscation.preferred_profile) but NOT in the default
// proton ladder.
func TestProtonQuicJ40IsFieldRung(t *testing.T) {
	tpl, err := LookupProfile("proton-quic-j40")
	if err != nil {
		t.Fatal(err)
	}
	p, err := tpl.Build()
	if err != nil {
		t.Fatal(err)
	}
	if p.JunkCount != 4 || p.JunkMin < 40 || p.JunkMax > 70 {
		t.Fatalf("proton-quic-j40 junk = jc=%d %d..%d, want jc=4 40..70", p.JunkCount, p.JunkMin, p.JunkMax)
	}
	if !p.VanillaSafe() || !tpl.RuntimeI1 {
		t.Fatal("proton-quic-j40 must stay vanilla-safe with RuntimeI1")
	}
	ladder, err := LadderFor(TargetProton, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ladder {
		if id.ID == "proton-quic-j40" {
			t.Fatal("the experimental rung must NOT ride the default proton ladder")
		}
	}
}
