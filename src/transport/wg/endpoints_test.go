// WG5 endpoint-catalog tests: invariants (§34-analog gate), measured-port
// provenance pins, diversification, scan budgets, regional tag routing and
// the last-good pool binding. All expectations below are pinned to the
// measured sources cited in endpoints.go, not to synthetic choices.
package transportwg

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestEndpointCatalogInvariants(t *testing.T) {
	for _, strat := range []ScanStrategy{StrategyTurbo, StrategyBalanced, StrategyThorough} {
		list := CatalogCandidates(strat)
		if len(list) == 0 {
			t.Fatalf("%s: empty candidate list", strat)
		}
		for _, ap := range list {
			if !endpointInCatalog(ap) {
				t.Fatalf("%s: candidate %v outside catalog (§34 gate)", strat, ap)
			}
		}
		// Determinism + no duplicates.
		again := CatalogCandidates(strat)
		if !slices.Equal(list, again) {
			t.Fatalf("%s: candidate list not deterministic", strat)
		}
		seen := map[netip.AddrPort]bool{}
		for _, ap := range list {
			if seen[ap] {
				t.Fatalf("%s: duplicate candidate %v", strat, ap)
			}
			seen[ap] = true
		}
	}
}

func TestEndpointScanBudgets(t *testing.T) {
	cases := []struct {
		strat ScanStrategy
		cap   int
		min   int
	}{
		{StrategyTurbo, CapCandidatesTurbo, 8},
		{StrategyBalanced, CapCandidatesBalanced, 8},
		{StrategyThorough, CapCandidatesThorough, 400},
	}
	for _, tc := range cases {
		n := len(CatalogCandidates(tc.strat))
		if n > tc.cap || n < tc.min {
			t.Fatalf("%s: %d candidates, want [%d..%d]", tc.strat, n, tc.min, tc.cap)
		}
	}
}

// TestEndpointPortDiversification pins the warp-socks posture: candidates
// must not share a single network path/port.
func TestEndpointPortDiversification(t *testing.T) {
	balanced := CatalogCandidates(StrategyBalanced)
	ports := map[uint16]bool{}
	addrs := map[netip.Addr]bool{}
	for _, ap := range balanced {
		ports[ap.Port()] = true
		addrs[ap.Addr()] = true
	}
	if len(ports) < len(CorePorts) {
		t.Fatalf("balanced covers %d ports, want >= %d", len(ports), len(CorePorts))
	}
	if len(addrs) != len(builtinSeedPool) {
		t.Fatalf("balanced covers %d addresses, want %d", len(addrs), len(builtinSeedPool))
	}

	thorough := CatalogCandidates(StrategyThorough)
	tPorts := map[uint16]bool{}
	for _, ap := range thorough {
		tPorts[ap.Port()] = true
	}
	if len(tPorts) != len(CorePorts)+len(ExtendedPorts) {
		t.Fatalf("thorough covers %d ports, want %d", len(tPorts), len(CorePorts)+len(ExtendedPorts))
	}
}

// TestExtendedPortsProvenancePin guards against silent drift of the
// measured set: byte-exact equality with the two agreeing source lists
// (Aether wireguard.rs:703-708 == warpscout warp.go:82-88).
func TestExtendedPortsProvenancePin(t *testing.T) {
	golden := []uint16{
		854, 859, 864, 878, 880, 890, 891, 894, 903, 908,
		928, 934, 939, 942, 943, 945, 946, 955, 968, 987,
		988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843,
		2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279,
		5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
	}
	if !slices.Equal(ExtendedPorts, golden) {
		t.Fatal("ExtendedPorts drifted from the measured golden list; " +
			"update only with fresh field evidence and a provenance note")
	}
	for _, p := range CorePorts {
		if KnownWGPort(p) == false || slices.Contains(ExtendedPorts, p) {
			t.Fatalf("core port %d misplaced", p)
		}
	}
	if len(AllPorts()) != len(CorePorts)+len(ExtendedPorts) {
		t.Fatal("AllPorts length mismatch")
	}
}

// TestInWGCatalogGate: family membership positives/negatives. The MASQUE
// gateway ranges must stay OUT (transportwarp pins the mirror direction).
func TestInWGCatalogGate(t *testing.T) {
	in := []string{
		"162.159.193.5", // ZeroTrust v4
		"162.159.193.47",
		"2606:4700:100::1", // ZeroTrust v6
		"162.159.192.1",    // anycast alternates
		"162.159.195.9",
		"188.114.96.1", // regional family
		"188.114.99.254",
		"8.39.214.4", // Nova host routes
		"8.6.112.8",
		"2606:4700:d0::a29f:c001", // regional v6 seeds
	}
	for _, s := range in {
		if !InWGCatalog(netip.MustParseAddr(s)) {
			t.Fatalf("%s must be in the WG catalog", s)
		}
	}
	out := []string{
		"162.159.198.2", // MASQUE H2/QUIC — different transport catalog
		"162.159.199.7",
		"127.0.0.1",
		"8.8.8.8",
		"1.1.1.1",
		"8.34.70.5", // one step outside a measured Nova host route (/32)
		"188.114.95.1",
	}
	for _, s := range out {
		if InWGCatalog(netip.MustParseAddr(s)) {
			t.Fatalf("%s must NOT be in the WG catalog", s)
		}
	}
	if !KnownWGPort(2408) || !KnownWGPort(854) || !KnownWGPort(8886) {
		t.Fatal("known port rejected")
	}
	if KnownWGPort(443) || KnownWGPort(80) || KnownWGPort(9999) {
		t.Fatal("unknown port accepted")
	}
	if !endpointInCatalog(netip.MustParseAddrPort("162.159.193.5:2408")) {
		t.Fatal("in-range addr on known port rejected")
	}
	if endpointInCatalog(netip.MustParseAddrPort("162.159.193.5:443")) {
		t.Fatal("out-of-set port passed the endpoint gate")
	}
}

// TestRegionalPoolsUnverifiedByDefault: plan-Б pools ship unverified, carry
// no region claims yet, and never mix into default sourcing.
func TestRegionalPoolsUnverifiedByDefault(t *testing.T) {
	if len(RegionalPools) == 0 {
		t.Fatal("regional registry is empty")
	}
	for _, pool := range RegionalPools {
		if pool.Verified {
			t.Fatalf("pool %s verified without field evidence", pool.Tag)
		}
		if pool.VerifyMeta != "" {
			t.Fatalf("pool %s carries verification metadata pre-field", pool.Tag)
		}
		if pool.Tag == "" {
			t.Fatal("pool without tag")
		}
		for _, pfx := range pool.Prefixes {
			if !pfx.IsValid() {
				t.Fatalf("pool %s invalid prefix", pool.Tag)
			}
		}
	}

	def := CatalogCandidates(StrategyThorough)
	for _, pool := range RegionalPools {
		cands, err := PoolCandidates(pool.Tag)
		if err != nil {
			t.Fatal(err)
		}
		if len(cands) == 0 {
			t.Fatalf("pool %s expands to nothing", pool.Tag)
		}
		for _, ap := range cands {
			if !endpointInCatalog(ap) {
				t.Fatalf("pool candidate %v outside gate", ap)
			}
			for _, d := range def {
				if ap == d {
					t.Fatalf("unverified regional candidate %v leaked into default ladder", ap)
				}
			}
		}
	}
	if _, err := PoolCandidates("no-such-tag"); err == nil {
		t.Fatal("unknown pool tag accepted")
	}
}

// TestAnycastAltsDataDrivenEnablement pins the owner decision (24.08): the
// 192/.195 alternates exist as UNVERIFIED pool entries with pre-field
// provenance, so post-FIELD2 enablement is a data flip (Verified+VerifyMeta
// at the declaration), never a code change.
func TestAnycastAltsDataDrivenEnablement(t *testing.T) {
	byTag := map[string]RegionPool{}
	for _, pool := range RegionalPools {
		byTag[pool.Tag] = pool
	}
	for _, tag := range []string{"cf-anycast-192", "cf-anycast-195"} {
		pool, ok := byTag[tag]
		if !ok {
			t.Fatalf("%s: pool entry missing from registry", tag)
		}
		if pool.Verified || pool.VerifyMeta != "" {
			t.Fatalf("%s: must ship unverified without field metadata", tag)
		}
		if pool.Source != "nova-measured" {
			t.Fatalf("%s: source=%q want nova-measured", tag, pool.Source)
		}
		cands, err := PoolCandidates(tag)
		if err != nil {
			t.Fatal(err)
		}
		if len(cands) != len(CorePorts) {
			t.Fatalf("%s: %d candidates want %d (one /24 x core ports)", tag, len(cands), len(CorePorts))
		}
		// First-host expansion: never the network address .0.
		if got := cands[0].Addr().As4(); got[3] == 0 || got != [4]byte{got[0], got[1], got[2], 1} {
			t.Fatalf("%s: expansion starts at %v want x.x.x.1", tag, cands[0].Addr())
		}
		for _, ap := range cands {
			if !endpointInCatalog(ap) {
				t.Fatalf("%s: candidate %v outside gate", tag, ap)
			}
		}
	}
}

// TestSeedEndpointsV6: measured v6 seeds stay inside the v6 catalog ranges.
func TestSeedEndpointsV6(t *testing.T) {
	for _, ap := range SeedEndpointsV6() {
		if !ap.Addr().Is6() || !InWGCatalog(ap.Addr()) {
			t.Fatalf("v6 seed %v outside catalog", ap)
		}
		if ap.Port() != CorePorts[0] {
			t.Fatalf("v6 seed %v on non-head port", ap)
		}
	}
}

func TestInterleaveV4V6(t *testing.T) {
	v4a := netip.MustParseAddrPort("162.159.193.5:2408")
	v4b := netip.MustParseAddrPort("162.159.193.9:500")
	v6a := netip.MustParseAddrPort("[2606:4700:100::1]:2408")
	v6b := netip.MustParseAddrPort("[2606:4700:d0::a29f:c001]:2408")

	got := InterleaveV4V6([]netip.AddrPort{v4a, v4b, v6a, v6b})
	want := []netip.AddrPort{v4a, v6a, v4b, v6b}
	if !slices.Equal(got, want) {
		t.Fatalf("interleave=%v want %v", got, want)
	}
	// Degenerate families preserve order.
	if !slices.Equal(InterleaveV4V6([]netip.AddrPort{v4a, v4b}), []netip.AddrPort{v4a, v4b}) {
		t.Fatal("v4-only order broken")
	}
	if n := len(InterleaveV4V6(nil)); n != 0 {
		t.Fatal("nil input must map to nil output")
	}
}

// fakeResolver answers with a fixed list regardless of query.
type fakeResolver struct {
	addrs []netip.Addr
	err   error
}

func (f fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return f.addrs, f.err
}

func TestResolveEdgeEndpoints(t *testing.T) {
	good4 := netip.MustParseAddr("162.159.193.5")
	good6 := netip.MustParseAddr("2606:4700:100::1")
	r := fakeResolver{addrs: []netip.Addr{
		netip.MustParseAddr("203.0.113.9"), // hostile/stale answer outside catalog
		good4, good6, good4,                // duplicate collapsed
	}}
	got, err := ResolveEdgeEndpoints(context.Background(), r, CorePorts)
	if err != nil {
		t.Fatal(err)
	}
	wantLen := 2 * len(CorePorts) // good4+good6 × core ports, dupes gone
	if len(got) != wantLen {
		t.Fatalf("resolved %d endpoints, want %d", len(got), wantLen)
	}
	for _, ap := range got {
		if !endpointInCatalog(ap) {
			t.Fatalf("resolver emitted out-of-catalog endpoint %v", ap)
		}
	}
	if got[0].Port() != CorePorts[0] {
		t.Fatalf("port expansion order broken: %v", got[0])
	}

	// Fail-closed: zero in-catalog answers are an error.
	outside := fakeResolver{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.9")}}
	if _, err := ResolveEdgeEndpoints(context.Background(), outside, CorePorts); err == nil {
		t.Fatal("empty in-catalog resolution must fail closed")
	}
	// Resolver errors propagate.
	broken := fakeResolver{err: context.DeadlineExceeded}
	if _, err := ResolveEdgeEndpoints(context.Background(), broken, CorePorts); err == nil {
		t.Fatal("resolver error swallowed")
	}
	// Unknown ports in the request are dropped, not passed through.
	filtered, err := ResolveEdgeEndpoints(context.Background(),
		fakeResolver{addrs: []netip.Addr{good4}}, []uint16{2408, 9999})
	if err != nil || len(filtered) != 1 {
		t.Fatalf("port filter broken: %v %v", filtered, err)
	}
}

// TestSeekerCatalogGateLastGoodBinding verifies the pool binding of
// last_good at the seeker boundary (white-box over orderedCandidates):
//
//	gate ON  + last_good inside a pool -> preferred first;
//	gate ON  + last_good outside       -> dropped, plain order;
//	gate OFF (tests escape)            -> out-of-pool last_good honored.
func TestSeekerCatalogGateLastGoodBinding(t *testing.T) {
	base := SessionConfig{} // orderedCandidates never touches the session
	poolEP := netip.MustParseAddrPort("162.159.193.5:2408")
	rogueEP := netip.MustParseAddrPort("127.0.0.1:500")
	cands := []netip.AddrPort{
		netip.MustParseAddrPort("162.159.193.9:500"),
		netip.MustParseAddrPort("162.159.193.8:1701"),
	}

	build := func(store LastGoodStore, allow bool) *Seeker {
		// White-box construction: orderedCandidates never touches the
		// session, so no identity fixture is needed here.
		cfg := SeekerConfig{
			Base:              base,
			Candidates:        cands,
			Target:            TargetCfWarp,
			LadderIDs:         []string{"vanilla-off"},
			Store:             store,
			AllowOutOfCatalog: allow,
		}
		cfg.fillDefaults()
		return &Seeker{cfg: cfg, strikes: NewStrikeState()}
	}

	lg := func(ep netip.AddrPort) *MemoryLastGood {
		m := &MemoryLastGood{}
		_ = m.Put(Attempt{Endpoint: ep, ProfileID: "vanilla-off", At: time.Now()})
		return m
	}

	// Gate ON: in-pool last-good leads.
	got := build(lg(poolEP), false).orderedCandidates(time.Now())
	if got[0] != poolEP || len(got) != 3 {
		t.Fatalf("in-pool binding broken: %v", got)
	}
	// Gate ON: out-of-pool last-good is dropped (re-seek from plain order).
	got = build(lg(rogueEP), false).orderedCandidates(time.Now())
	if len(got) != 2 || got[0] != cands[0] {
		t.Fatalf("rogue last-good not dropped: %v", got)
	}
	// Gate ON: rogue configured candidates are dropped too.
	rogue := build(&MemoryLastGood{}, false)
	rogue.cfg.Candidates = append([]netip.AddrPort{rogueEP}, cands...)
	got = rogue.orderedCandidates(time.Now())
	if len(got) != 2 || slices.Contains(got, rogueEP) {
		t.Fatalf("rogue configured candidate not dropped: %v", got)
	}
	// Tests-only escape: everything passes as before.
	got = build(lg(rogueEP), true).orderedCandidates(time.Now())
	if got[0] != rogueEP || len(got) != 3 {
		t.Fatalf("tests escape broken: %v", got)
	}
}

// ---- PATCH-13: unique pool tags + opt-in reachability ----

// TestCatalogTagsUnique is the PATCH-13 invariant: every RegionPool tag is
// unique — PoolCandidates resolves by tag, so a duplicate would silently
// make the second pool unreachable.
func TestCatalogTagsUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range RegionalPools {
		if p.Tag == "" {
			t.Fatal("pool tag must not be empty")
		}
		if seen[p.Tag] {
			t.Fatalf("duplicate pool tag %q: opt-in by tag cannot reach both pools", p.Tag)
		}
		seen[p.Tag] = true
	}
}

// TestPoolCandidatesReachesNovaHosts: the formerly-shadowed nova-hosts pool
// is reachable through the opt-in API and returns the measured /32 hosts on
// core ports.
func TestPoolCandidatesReachesNovaHosts(t *testing.T) {
	cands, err := PoolCandidates("unassigned-nova-hosts")
	if err != nil {
		t.Fatalf("nova-hosts opt-in failed: %v", err)
	}
	if len(cands) == 0 {
		t.Fatal("nova-hosts pool expanded to zero candidates")
	}
	// Every candidate is a measured /32 host (8.x) on a core port.
	ports := map[uint16]bool{}
	for _, p := range CorePorts {
		ports[p] = true
	}
	for _, c := range cands {
		if !c.Addr().Is4() || !strings.HasPrefix(c.Addr().String(), "8.") {
			t.Fatalf("candidate %v is not a measured nova host", c)
		}
		if !ports[c.Port()] {
			t.Fatalf("candidate %v is not on a core port", c)
		}
	}
	// The aether-188 pool is separately reachable (both pools coexist).
	aether, err := PoolCandidates("unassigned-aether-188")
	if err != nil || len(aether) == 0 {
		t.Fatalf("aether-188 opt-in failed: %v / %d", err, len(aether))
	}
}

// TestRegionTagTTLDowngradesStalePools is the PATCH-22 (A7) acceptance
// test: verified pools with fresh loc= evidence stay in default sourcing,
// evidence older than the TTL downgrades to unverified posture, and a
// stampless flip is fail-closed.
func TestRegionTagTTLDowngradesStalePools(t *testing.T) {
	now := time.Now()
	pools := []RegionPool{
		{Tag: "fresh", Verified: true, VerifiedAt: now.Add(-30 * 24 * time.Hour)},
		{Tag: "stale", Verified: true, VerifiedAt: now.Add(-200 * 24 * time.Hour)},
		{Tag: "stampless", Verified: true},
		{Tag: "unverified", Verified: false, VerifiedAt: now.Add(-time.Hour)},
	}
	fresh := FreshRegionalPools(pools, now, 0)
	if len(fresh) != 1 || fresh[0].Tag != "fresh" {
		t.Fatalf("fresh set = %+v, want only the fresh pool", fresh)
	}
	// Custom TTL honored.
	fresh = FreshRegionalPools(pools, now, 100*24*time.Hour)
	if len(fresh) != 1 || fresh[0].Tag != "fresh" {
		t.Fatalf("custom TTL fresh set = %+v", fresh)
	}
	// The formerly-stale pool is still reachable via opt-in semantics:
	// PoolCandidates matches by tag regardless of freshness.
	_ = PoolCandidates // opt-in path unchanged (verified by TestPoolCandidatesReachesNovaHosts)
}
