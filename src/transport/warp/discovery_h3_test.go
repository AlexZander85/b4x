package transportwarp

// EH3 discovery tests: the QUIC catalog branch — candidate gate, transport
// tagging, probe-distinct death, and H2-only default preservation.

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

// Every QUIC candidate stays inside the versioned map (§34 gate) and turbo
// remains a single bootstrap seed.
func TestQuicCatalogCandidatesGate(t *testing.T) {
	if got := QuicCatalogCandidates(StrategyTurbo); len(got) != 1 ||
		got[0] != netip.MustParseAddrPort("162.159.198.1:443") {
		t.Fatalf("turbo quic candidates = %v", got)
	}
	for _, strat := range []ScanStrategy{StrategyBalanced, StrategyThorough} {
		list := QuicCatalogCandidates(strat)
		if len(list) != len(Ports)*6 { // v4 pair + two v6 pairs
			t.Fatalf("%s: quic product size = %d", strat, len(list))
		}
		for _, ep := range list {
			if !InCatalog(KindMasqueQUIC, ep.Addr()) || !KnownPort(ep.Port()) {
				t.Fatalf("%s: candidate %s outside versioned map", strat, ep)
			}
		}
	}
}

// A healthy QUIC candidate verifies over the H3 carrier and carries its
// transport tag; H2 candidates stay tagged h2 in the same scan.
func TestDiscoveryVerifiesQuicCandidateAndTagsTransport(t *testing.T) {
	h := newDiscHarness(t, 1)
	e := newFakeH3EdgeWithKey(t, h.api.key) // same pin as the API-served identity

	d, err := NewDiscoverer(DiscovererConfig{
		Template:           h.tmpl,
		Strategy:           StrategyBalanced,
		Tier:               TierMedium,
		CandidatesOverride: h.addrs(),
		H3: &H3VerifyConfig{
			QuicCandidatesOverride: []netip.AddrPort{netipMustAddrPort(e.addr)},
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "scan" || len(res.Ranked) != 2 {
		t.Fatalf("result = %+v (ranked %d)", res, len(res.Ranked))
	}
	byTransport := map[string]EndpointScore{}
	for _, s := range res.Ranked {
		if s.Class != VerifiedHealthy {
			t.Fatalf("score class = %s (%+v)", s.Class, s)
		}
		if prev, dup := byTransport[s.Transport]; dup {
			t.Fatalf("duplicate transport tag %q: %+v vs %+v", s.Transport, prev, s)
		}
		byTransport[s.Transport] = s
	}
	h3Score, ok := byTransport[TransportH3]
	if !ok || h3Score.Endpoint != netipMustAddrPort(e.addr) || h3Score.Colo != "TST" {
		t.Fatalf("h3 score = %+v", h3Score)
	}
	if _, ok := byTransport[TransportH2]; !ok {
		t.Fatalf("h2 score missing: %+v", res.Ranked)
	}
}

// A blackholed QUIC candidate is declared dead at PROBE speed (no full
// session budgets burned) and the H2 side still wins the scan.
func TestDiscoveryBlackholedQuicDiesAtProbeSpeed(t *testing.T) {
	h := newDiscHarness(t, 1)

	dead, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := dead.LocalAddr().(*net.UDPAddr).Port
	dead.Close()

	d, err := NewDiscoverer(DiscovererConfig{
		Template:           h.tmpl,
		Strategy:           StrategyBalanced,
		Tier:               TierMedium,
		CandidatesOverride: h.addrs(),
		H3: &H3VerifyConfig{
			ProbeBudget:            500 * time.Millisecond,
			QuicCandidatesOverride: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(port))},
		},
		Sleep: func(context.Context, time.Duration) error { return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 4*time.Second {
		t.Fatalf("blackholed candidate must die at probe speed, took %v", elapsed)
	}
	if res.Winner.Endpoint != h.mq[0].addr() || res.Winner.Transport != TransportH2 {
		t.Fatalf("winner = %+v, want the live H2 edge", res.Winner)
	}
	for _, s := range res.Ranked {
		if s.Endpoint.String() == "127.0.0.1:"+strconv.Itoa(port) {
			t.Fatalf("dead quic candidate must not rank: %+v", s)
		}
	}
}

// Without H3 config the discovery behavior is byte-for-byte pre-EH3:
// zero QUIC candidates are considered even when a catalog exists.
func TestDiscoveryH3BranchOffByDefault(t *testing.T) {
	h := newDiscHarness(t, 1)
	d := h.newDiscoverer(t, h.addrs(), StrategyBalanced, "")
	cands := d.selectCandidates(12)
	for _, c := range cands {
		if c.quic {
			t.Fatalf("QUIC branch leaked into H2-only discovery: %+v", c)
		}
	}
	res, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Winner.Transport != TransportH2 {
		t.Fatalf("winner transport = %q", res.Winner.Transport)
	}
}

// ---- PATCH-22 (M-10): H2 slot fairness in the scan shape ----

// TestSelectCandidatesReservesH2Slots: with a QUIC-heavy catalog, half of
// the balanced scan must stay reserved for H2 carriers — the H3-first
// ladder depends on a verified H2 fallback.
func TestSelectCandidatesReservesH2Slots(t *testing.T) {
	d, err := NewDiscoverer(DiscovererConfig{
		Strategy:           StrategyBalanced,
		CandidatesOverride: repeatEndpoints("162.159.192.1", 8),
		H3:                 &H3VerifyConfig{QuicCandidatesOverride: repeatEndpoints("162.159.193.1", 42)},
	})
	if err != nil {
		t.Fatalf("discoverer: %v", err)
	}
	shape, _ := shapeFor(StrategyBalanced)
	cands := d.selectCandidates(shape.maxTargets)
	var h2, quic int
	for _, c := range cands {
		if c.quic {
			quic++
		} else {
			h2++
		}
	}
	if h2 < shape.maxTargets/2 {
		t.Fatalf("H2 candidates = %d, want >= %d (half the scan)", h2, shape.maxTargets/2)
	}
	if quic > shape.maxTargets-shape.maxTargets/2 {
		t.Fatalf("QUIC candidates = %d, must fit within the non-reserved share", quic)
	}
}

// TestTurboKeepsBothTransports: the turbo shape (2 targets) plus the H2
// floor keeps one QUIC AND one H2 candidate in every round — the fairness
// the ladder needs when turbo rounds repeat.
func TestTurboKeepsBothTransports(t *testing.T) {
	d, err := NewDiscoverer(DiscovererConfig{
		Strategy:           StrategyTurbo,
		CandidatesOverride: repeatEndpoints("162.159.192.1", 4),
		H3:                 &H3VerifyConfig{QuicCandidatesOverride: repeatEndpoints("162.159.193.1", 42)},
	})
	if err != nil {
		t.Fatalf("discoverer: %v", err)
	}
	for round := 0; round < 3; round++ {
		cands := d.selectCandidates(2)
		var hasQ, hasH2 bool
		for _, c := range cands {
			if c.quic {
				hasQ = true
			} else {
				hasH2 = true
			}
		}
		if !hasQ || !hasH2 {
			t.Fatalf("round %d: shape = %+v, want both transports present", round, cands)
		}
	}
}

// repeatEndpoints builds n distinct endpoints from an IP prefix.
func repeatEndpoints(prefix string, n int) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, n)
	base := netip.MustParseAddrPort(prefix + ":443")
	for i := 0; i < n; i++ {
		a := base.Addr().As4()
		a[3] = byte(1 + i%250)
		out = append(out, netip.AddrPortFrom(netip.AddrFrom4(a), uint16(443+i%1000)))
	}
	return out
}
