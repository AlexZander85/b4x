package transportwarp

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ---- harness ----

type discHarness struct {
	api  *fakeAPI
	mq   []*fakeServer
	tmpl SessionConfig
}

func newDiscHarness(t *testing.T, servers int) *discHarness {
	t.Helper()
	h := &discHarness{api: newFakeAPI(t)}
	h.api.start()
	for i := 0; i < servers; i++ {
		// Same key as the API-served pin: candidate verification must pass
		// endpoint pinning by construction.
		h.mq = append(h.mq, newFakeServerWithKey(t, h.api.key))
	}
	privB64, _, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	clientPriv, err := ParseClientKeyB64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	h.tmpl = SessionConfig{
		SNI:             DefaultSNI,
		ConnectURI:      DefaultConnectURI,
		ClientKey:       clientPriv,
		Pin:             &h.api.key.PublicKey,
		LocalV4:         [4]byte{172, 16, 0, 2},
		ValidateWindow:  200 * time.Millisecond, // fast validation + burst-echo wait cap
		ProbeInterval:   5 * time.Millisecond,
		HandshakeBudget: 3 * time.Second,
	}
	return h
}

func (h *discHarness) addrs() []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(h.mq))
	for _, s := range h.mq {
		out = append(out, s.addr())
	}
	return out
}

func (h *discHarness) newDiscoverer(t *testing.T, cands []netip.AddrPort, strategy ScanStrategy, lgPath string) *Discoverer {
	t.Helper()
	d, err := NewDiscoverer(DiscovererConfig{
		Template:           h.tmpl,
		Strategy:           strategy,
		Tier:               TierMedium,
		LastGoodPath:       lgPath,
		CandidatesOverride: cands,
		Sleep:              func(context.Context, time.Duration) error { return nil }, // instant burst pacing
	})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func serverConnects(servers []*fakeServer) []int {
	out := make([]int, len(servers))
	for i, s := range servers {
		c, _ := s.counters()
		out[i] = c
	}
	return out
}

// ---- scenarios (design E4 verification matrix) ----

// Ranking: healthy candidates ordered by RTT; lossy ranks last; colo
// telemetry captured from the CONNECT response.
func TestDiscoveryRanksHealthyByRTTAndLoss(t *testing.T) {
	h := newDiscHarness(t, 3)
	h.mq[1].setEchoDelay(40 * time.Millisecond) // slower in-tunnel RTT fixture
	h.mq[2].setLossy(3)                         // drops every 3rd capsule => ~33% loss

	d := h.newDiscoverer(t, h.addrs(), StrategyBalanced, "")
	res, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "scan" {
		t.Fatalf("source = %s", res.Source)
	}
	if res.Winner.Endpoint != h.mq[0].addr() {
		t.Fatalf("winner = %v, want fast healthy %v", res.Winner.Endpoint, h.mq[0].addr())
	}
	if res.Winner.Class != VerifiedHealthy || res.Winner.Colo != "TEST" {
		t.Fatalf("winner score = %+v", res.Winner)
	}
	if len(res.Ranked) != 3 {
		t.Fatalf("ranked = %+v", res.Ranked)
	}
	if res.Ranked[1].Endpoint != h.mq[1].addr() || res.Ranked[1].Class != VerifiedHealthy {
		t.Fatalf("second place must be healthy-but-slower: %+v", res.Ranked[1])
	}
	if res.Ranked[1].RTT <= res.Ranked[0].RTT {
		t.Fatalf("RTT ordering violated: fast=%v slow=%v", res.Ranked[0].RTT, res.Ranked[1].RTT)
	}
	if res.Ranked[2].Endpoint != h.mq[2].addr() || res.Ranked[2].Class != VerifiedLossy {
		t.Fatalf("lossy must rank last: %+v", res.Ranked[2])
	}
}

// Torn-down detection: a mid-burst silent teardown is NOT a winner and
// yields no verified result when it is the only candidate.
func TestDiscoveryDetectsTeardownMidBurst(t *testing.T) {
	h := newDiscHarness(t, 1)
	h.mq[0].setBehavior(200, false, false, 2) // echo 2 packets then hard-close

	d := h.newDiscoverer(t, h.addrs(), StrategyBalanced, "")
	_, err := d.Discover(context.Background())
	if !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("torn-down-only scan must fail with ErrNoCandidates, got %v", err)
	}
}

// Flap tolerance: up to MinAttempts connect rounds; a candidate that fails
// twice then succeeds is still verified; three failures are Dead.
func TestDiscoveryFlapTolerance(t *testing.T) {
	h := newDiscHarness(t, 2)
	h.mq[0].setRejectNext(2) // fails, fails, then accepts
	h.mq[1].setRejectNext(999)

	d := h.newDiscoverer(t, []netip.AddrPort{h.mq[0].addr(), h.mq[1].addr()}, StrategyBalanced, "")
	res, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Winner.Endpoint != h.mq[0].addr() {
		t.Fatalf("flapping-but-alive candidate must win, got %+v", res.Winner)
	}
	if res.Winner.Attempts != MinAttempts {
		t.Fatalf("attempts = %d, want %d", res.Winner.Attempts, MinAttempts)
	}

	// All-fail variant.
	h2 := newDiscHarness(t, 1)
	h2.mq[0].setRejectNext(999)
	d2 := h2.newDiscoverer(t, h2.addrs(), StrategyBalanced, "")
	if _, err := d2.Discover(context.Background()); !errors.Is(err, ErrNoCandidates) {
		t.Fatalf("permanently rejecting candidate is dead: %v", err)
	}
}

// Last-good cache: a passing re-verify skips the entire scan.
func TestLastGoodCacheSkipScan(t *testing.T) {
	h := newDiscHarness(t, 3)
	dir := t.TempDir()
	lgPath := filepath.Join(dir, "lastgood.json")
	lg := `{"endpoint":"` + h.mq[1].addr().String() + `","verified_at":"2026-08-23T12:00:00Z"}`
	if err := os.WriteFile(lgPath, []byte(lg), 0o600); err != nil {
		t.Fatal(err)
	}

	d := h.newDiscoverer(t, h.addrs(), StrategyBalanced, lgPath)
	res, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "last-good" {
		t.Fatalf("source = %s, want last-good", res.Source)
	}
	if res.Winner.Endpoint != h.mq[1].addr() {
		t.Fatalf("winner = %v", res.Winner.Endpoint)
	}
	conns := serverConnects(h.mq)
	if conns[0] != 0 || conns[2] != 0 {
		t.Fatalf("scan must be skipped when last-good passes: connects=%v", conns)
	}
}

// A failing last-good falls back to a full scan and the cache is refreshed
// to the new winner.
func TestLastGoodFailFallsBackToScan(t *testing.T) {
	h := newDiscHarness(t, 2)
	dir := t.TempDir()
	lgPath := filepath.Join(dir, "lastgood.json")
	lg := `{"endpoint":"` + h.mq[0].addr().String() + `","verified_at":"2026-08-23T12:00:00Z"}`
	if err := os.WriteFile(lgPath, []byte(lg), 0o600); err != nil {
		t.Fatal(err)
	}
	h.mq[0].setRejectNext(999) // last-good is gone

	d := h.newDiscoverer(t, h.addrs(), StrategyBalanced, lgPath)
	res, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Source != "scan" {
		t.Fatalf("source = %s, want scan", res.Source)
	}
	if res.Winner.Endpoint != h.mq[1].addr() {
		t.Fatalf("fallback winner = %v", res.Winner.Endpoint)
	}
	blob, err := os.ReadFile(lgPath)
	if err != nil {
		t.Fatal(err)
	}
	want := `"endpoint": "` + h.mq[1].addr().String() + `"` // MarshalIndent spacing
	if !containsStr(string(blob), want) {
		t.Fatalf("last-good cache not refreshed to winner: %s", blob)
	}
}

func containsStr(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOfStr(haystack, needle) >= 0)
}

func indexOfStr(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}

// Cooldown: two consecutive dead rounds exclude an endpoint from subsequent
// scans entirely (zero connect attempts).
func TestCooldownExcludesAfterTwoStrikes(t *testing.T) {
	h := newDiscHarness(t, 2)
	cands := []netip.AddrPort{h.mq[0].addr(), h.mq[1].addr()}
	h.mq[0].setRejectNext(999) // permanently failing edge

	d := h.newDiscoverer(t, cands, StrategyBalanced, "")

	// Round 1: dead verified-dead once (strike 1), healthy wins.
	if _, err := d.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Round 2: strike 2 -> excluded for Cooldown.
	if _, err := d.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	c1 := serverConnects(h.mq)

	// Round 3: the dead endpoint must not be contacted at all.
	if _, err := d.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	c2 := serverConnects(h.mq)
	if c2[0] != c1[0] {
		t.Fatalf("excluded endpoint was contacted again: %v -> %v", c1, c2)
	}
	if c1[0] < 6 {
		t.Fatalf("two verification rounds expected >=6 attempts on dead edge, got %v", c1)
	}
}

// Turbo early exit: only ONE candidate gets verified; the rest untouched.
func TestTurboEarlyExitStopsAtFirstVerified(t *testing.T) {
	h := newDiscHarness(t, 3)
	d := h.newDiscoverer(t, h.addrs(), StrategyTurbo, "")
	res, err := d.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	touched := 0
	for _, c := range serverConnects(h.mq) {
		total += c
		if c > 0 {
			touched++
		}
	}
	if touched != 1 {
		t.Fatalf("early exit must verify exactly one candidate, touched=%d (connects=%v)", touched, serverConnects(h.mq))
	}
	if total > MinAttempts {
		t.Fatalf("early exit must stop at first success: total connects=%d", total)
	}
	if res.Source != "scan" {
		t.Fatalf("source=%s", res.Source)
	}
}

// The §34 gate lives here: every catalog-built candidate is inside the
// versioned map and uses known ports.
func TestCatalogCandidatesInCatalogGate(t *testing.T) {
	for _, strat := range []ScanStrategy{StrategyTurbo, StrategyBalanced, StrategyThorough} {
		list := CatalogCandidates(KindMasqueH2, strat)
		if len(list) == 0 {
			t.Fatalf("%s: empty candidate list", strat)
		}
		for _, ep := range list {
			if !InCatalog(KindMasqueH2, ep.Addr()) {
				t.Fatalf("%s: candidate %s outside catalog", strat, ep)
			}
			if !KnownPort(ep.Port()) {
				t.Fatalf("%s: candidate port %d unknown", strat, ep.Port())
			}
		}
		switch strat {
		case StrategyTurbo:
			if len(list) != 1 || list[0] != DefaultH2Endpoint() {
				t.Fatalf("turbo must be default endpoint only: %v", list)
			}
		case StrategyThorough:
			if len(list) != 2*256*len(Ports) {
				t.Fatalf("thorough must cover both /24s x ports, got %d", len(list))
			}
		case StrategyBalanced:
			if len(list) < 8 || len(list) > 12+4 {
				t.Fatalf("balanced bounded list unexpected size %d", len(list))
			}
		}
	}
	// QUIC kind returns the anycast seeds.
	q := CatalogCandidates(KindMasqueQUIC, StrategyThorough)
	if len(q) != 2 { // v4 anycast .1/.2 via SeedEndpoints
		t.Fatalf("quic seeds = %v", q)
	}
}
