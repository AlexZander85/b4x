package silentpath

import "testing"

func TestActiveModeDegradesWithoutEveryVisibilityProof(t *testing.T) {
	complete := CapabilitySnapshot{IncomingComplete: true, OutgoingComplete: true, QueueHealthy: true, GSOParityProven: true, OffloadProven: true}
	if mode, _ := EffectiveMode("auto-canary", complete); mode != "auto-canary" {
		t.Fatal(mode)
	}
	complete.QueueHealthy = false
	if mode, reason := EffectiveMode("auto-canary", complete); mode != "observe" || reason != "visibility_incomplete" {
		t.Fatalf("%s/%s", mode, reason)
	}
}
func TestMilestones(t *testing.T) {
	var m Milestones
	for _, e := range []Milestone{MilestoneSYN, MilestoneSYNACK, MilestoneClientHello, MilestoneServerHello, MilestoneApplicationData, MilestoneFIN, MilestoneRST, MilestoneTLSAlert} {
		m.Observe(e)
	}
	if !m.SYN || !m.SYNACK || !m.ClientHelloComplete || !m.ServerHello || !m.ApplicationData || !m.FIN || !m.RST || !m.TLSAlert {
		t.Fatalf("%+v", m)
	}
}
