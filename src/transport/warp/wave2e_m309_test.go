package transportwarp

import (
	"net/netip"
	"testing"
)

// M3-09: a QUIC-heavy catalog must not starve the H2 scan. selectCandidates
// reserves a floor (1/H2ReserveRatio of the budget) for H2 candidates.
func TestSelectCandidatesReservesH2Floor(t *testing.T) {
	h := newDiscHarness(t, 1)

	// 42 QUIC candidates vs 20 H2 candidates: without the M3-09 reserve the
	// QUIC list alone would consume the whole scan budget and starve H2.
	quic := make([]netip.AddrPort, 0, 42)
	for i := 0; i < 42; i++ {
		quic = append(quic, netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(443+i)))
	}
	h2 := make([]netip.AddrPort, 0, 20)
	for i := 0; i < 20; i++ {
		h2 = append(h2, netip.AddrPortFrom(netip.MustParseAddr("198.51.100.1"), uint16(443+i)))
	}

	cases := []struct {
		name      string
		strategy  ScanStrategy
		maxTarget int
		wantFloor int
	}{
		{"balanced", StrategyBalanced, 12, 4}, // 12/3
		{"turbo", StrategyTurbo, 2, 1},        // max(2/3,1) = 1
	}
	for _, tc := range cases {
		d := h.newDiscoverer(t, h2, tc.strategy, "")
		d.cfg.H3 = &H3VerifyConfig{QuicCandidatesOverride: quic}

		got := d.selectCandidates(tc.maxTarget)
		var h2Got int
		for _, c := range got {
			if !c.quic {
				h2Got++
			}
		}
		if len(got) > tc.maxTarget {
			t.Fatalf("%s: exceeded scan budget: got %d > %d", tc.name, len(got), tc.maxTarget)
		}
		if h2Got < tc.wantFloor {
			t.Fatalf("%s: H2 starved by QUIC-heavy catalog: got %d H2 slots, want >= %d (floor)",
				tc.name, h2Got, tc.wantFloor)
		}
	}
}
