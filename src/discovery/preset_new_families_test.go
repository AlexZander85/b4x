package discovery

import "testing"

// TestGetPhase2PresetsNewFamilies guards the G-2.5 expanded search space:
// UDP/QUIC, window manipulation and SNI mutation axes must produce valid
// presets, and the combo axis must include max-delay/decoy variants.
func TestGetPhase2PresetsNewFamilies(t *testing.T) {
	udp := GetPhase2Presets(FamilyUDP)
	if len(udp) == 0 {
		t.Fatal("FamilyUDP produced no presets")
	}
	coalesceVariants := 0
	for _, p := range udp {
		if p.Family != FamilyUDP {
			t.Errorf("preset %s has family %s, want %s", p.Name, p.Family, FamilyUDP)
		}
		if p.Config.UDP.FilterQUIC != "parse" && p.Config.UDP.FilterQUIC != "all" {
			t.Errorf("preset %s FilterQUIC=%q, want parse|all", p.Name, p.Config.UDP.FilterQUIC)
		}
		if p.Config.UDP.Mode == "coalesce" {
			// b4 1.82 port: coalesce carries no fake knobs — the padding dummy is
			// derived from the client's Initial itself.
			coalesceVariants++
			if p.Config.UDP.FakeSeqLength != 0 {
				t.Errorf("preset %s coalesce must not carry fake packets (seq=%d)", p.Name, p.Config.UDP.FakeSeqLength)
			}
			continue
		}
		if p.Config.UDP.Mode != "fake" {
			t.Errorf("preset %s UDP.Mode=%q, want fake|coalesce", p.Name, p.Config.UDP.Mode)
		}
		if p.Config.UDP.FakeSeqLength <= 0 || p.Config.UDP.FakeLen <= 0 {
			t.Errorf("preset %s has no fake QUIC payload (seq=%d len=%d)", p.Name, p.Config.UDP.FakeSeqLength, p.Config.UDP.FakeLen)
		}
	}
	if coalesceVariants == 0 {
		t.Fatal("FamilyUDP axis has no coalesce presets — the b4 1.82 port would be dead code in discovery")
	}

	win := GetPhase2Presets(FamilyWindow)
	if len(win) == 0 {
		t.Fatal("FamilyWindow produced no presets")
	}
	for _, p := range win {
		if p.Config.TCP.Win.Mode == "" || p.Config.TCP.Win.Mode == "off" {
			t.Errorf("preset %s Win.Mode=%q, want active mode", p.Name, p.Config.TCP.Win.Mode)
		}
	}

	mut := GetPhase2Presets(FamilyMutation)
	if len(mut) == 0 {
		t.Fatal("FamilyMutation produced no presets")
	}
	modes := map[string]bool{}
	for _, p := range mut {
		modes[p.Config.Faking.SNIMutation.Mode] = true
		if p.Config.Faking.SNIMutation.Mode == "" || p.Config.Faking.SNIMutation.Mode == "off" {
			t.Errorf("preset %s SNIMutation.Mode=%q, want active mode", p.Name, p.Config.Faking.SNIMutation.Mode)
		}
	}
	for _, want := range []string{"grease", "padding", "duplicate", "reorder", "full", "advanced"} {
		if !modes[want] {
			t.Errorf("FamilyMutation missing mode %q", want)
		}
	}

	combo := GetPhase2Presets(FamilyCombo)
	hasMaxDelay := false
	for _, p := range combo {
		if p.Config.Fragmentation.Combo.FirstDelayMs >= 100 {
			hasMaxDelay = true
			break
		}
	}
	if !hasMaxDelay {
		t.Error("FamilyCombo has no max-delay (>100ms) variants")
	}
}
