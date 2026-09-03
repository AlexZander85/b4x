// Happy-Eyeballs runner tests. Determinism rules learned here: the exact
// number of spawns NEAR the cap boundary is scheduler-dependent (the
// default Sleep's select may legitimately observe deadline and timer
// together), so exact-count assertions ride the injected Sleep seam only;
// real-timer tests assert intervals, never exact counts.
package transportwg

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var heCands = []netip.AddrPort{
	netip.MustParseAddrPort("162.159.193.5:2408"),
	netip.MustParseAddrPort("162.159.193.9:500"),
	netip.MustParseAddrPort("162.159.193.8:1701"),
	netip.MustParseAddrPort("162.159.193.3:4500"),
}

func TestRaceEndpointsFirstWinnerCancelsRest(t *testing.T) {
	var slowStarted atomic.Bool
	slowReady := make(chan struct{}, 1)
	cfg := HEConfig{
		Stagger: time.Millisecond,
		Cap:     5 * time.Second,
		Sleep: func(context.Context, time.Duration) error {
			return nil // spawn everything immediately
		},
	}

	val, idx, err := RaceEndpoints(context.Background(), cfg, heCands,
		func(ctx context.Context, i int, cand netip.AddrPort) (int, error) {
			switch i {
			case 0:
				// Slow favorite: signals readiness, then must LOSE to the
				// faster second attempt through win-cancellation.
				slowStarted.Store(true)
				slowReady <- struct{}{}
				<-ctx.Done()
				return 0, ctx.Err()
			case 1:
				// Winner: give the slow favorite a bounded chance to enter
				// its blocked section first (never hangs the test).
				select {
				case <-slowReady:
				case <-time.After(2 * time.Second):
				}
				return 42, nil // WINNER
			default:
				<-ctx.Done() // later attempts observe the win-cancel
				return 0, ctx.Err()
			}
		})

	if err != nil {
		t.Fatalf("race failed: %v", err)
	}
	if val != 42 || idx != 1 {
		t.Fatalf("winner=%d@%d want 42@1", val, idx)
	}
	if !slowStarted.Load() {
		t.Fatal("slow favorite never got scheduled")
	}
}

// TestRaceEndpointsStaggerOrder pins 250ms·i pacing through the Sleep seam.
func TestRaceEndpointsStaggerOrder(t *testing.T) {
	var mu sync.Mutex
	var delays []time.Duration
	cfg := HEConfig{Stagger: 250 * time.Millisecond, Cap: 10 * time.Second}
	cfg.Sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		delays = append(delays, d)
		mu.Unlock()
		return nil
	}

	_, _, err := RaceEndpoints(context.Background(), cfg, heCands,
		func(ctx context.Context, i int, _ netip.AddrPort) (int, error) { return i, nil })
	if err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{0, 250 * time.Millisecond, 500 * time.Millisecond, 750 * time.Millisecond}
	mu.Lock()
	got := slices.Clone(delays)
	mu.Unlock()
	if !slices.Equal(got, want) {
		t.Fatalf("stagger delays=%v want %v", got, want)
	}
}

// TestRaceEndpointsSpawnStopsOnBudgetExhaustion pins the structural rule:
// when the pacing seam reports budget exhaustion, spawning stops and the
// outcome is a failure carrying every completed attempt's error. Exact
// counts are safe HERE because the seam, not the wall clock, decides.
func TestRaceEndpointsSpawnStopsOnBudgetExhaustion(t *testing.T) {
	eight := make([]netip.AddrPort, len(heCands), len(heCands)+4)
	copy(eight, heCands)
	for i := 0; i < 4; i++ {
		eight = append(eight, netip.MustParseAddrPort("162.159.193.11:4500"))
	}

	var spawned atomic.Int32
	cfg := HEConfig{Stagger: time.Millisecond, Cap: time.Minute}
	budget := 3 // seam allows exactly three staggered starts
	call := 0
	cfg.Sleep = func(ctx context.Context, _ time.Duration) error {
		if call >= budget {
			return context.DeadlineExceeded // budget exhausted mid-ladder
		}
		call++
		return nil
	}

	_, _, err := RaceEndpoints(context.Background(), cfg, eight,
		func(ctx context.Context, i int, _ netip.AddrPort) (int, error) {
			spawned.Add(1)
			return 0, errors.New("edge-refused")
		})

	if err == nil {
		t.Fatal("exhausted race must fail")
	}
	if got := spawned.Load(); got != int32(budget) {
		t.Fatalf("spawned=%d want exactly %d after seam exhaustion", got, budget)
	}
	if strings.Contains(err.Error(), "happy-eyeballs-cap") {
		t.Fatalf("seam exhaustion must not be labeled as wall-clock cap: %v", err)
	}
	if !strings.Contains(err.Error(), "3 attempts") || !strings.Contains(err.Error(), "edge-refused") {
		t.Fatalf("failure report must list completed attempts and joined causes: %v", err)
	}
}

// TestRaceEndpointsCapBoundsSpawning: with a REAL clock, candidates whose
// staggered start lies beyond the cap are never attempted. Interval
// assertion only — the exact spawn count near the boundary belongs to the
// scheduler (see package doc).
func TestRaceEndpointsCapBoundsSpawning(t *testing.T) {
	eight := append([]netip.AddrPort{}, heCands...)
	for i := 0; i < 4; i++ {
		eight = append(eight, netip.MustParseAddrPort("162.159.193.11:4500"))
	}

	var spawned atomic.Int32
	cfg := HEConfig{Stagger: 250 * time.Millisecond, Cap: 900 * time.Millisecond} // fits i<=3, never i>=4 (>=1000ms)

	_, _, err := RaceEndpoints(context.Background(), cfg, eight,
		func(ctx context.Context, i int, _ netip.AddrPort) (int, error) {
			spawned.Add(1)
			<-ctx.Done()
			return 0, ctx.Err()
		})

	if err == nil {
		t.Fatal("cap-bounded race must fail")
	}
	if got := spawned.Load(); got < 1 || got > 4 {
		t.Fatalf("spawned=%d outside [1..4]: cap did not bound the ladder", got)
	}
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "happy-eyeballs-cap") {
		t.Fatalf("error lacks cap cause: %v", err)
	}
}

// TestRaceEndpointsAllFailAggregates: joined loser errors, no phantom win.
func TestRaceEndpointsAllFailAggregates(t *testing.T) {
	cfg := HEConfig{Stagger: time.Millisecond, Cap: 5 * time.Second}
	cfg.Sleep = func(context.Context, time.Duration) error { return nil }

	sentinel := errors.New("edge-refused")
	_, _, err := RaceEndpoints(context.Background(), cfg, heCands,
		func(ctx context.Context, i int, _ netip.AddrPort) (int, error) {
			return 0, sentinel
		})
	if err == nil {
		t.Fatal("all-fail race must fail")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("joined errors lost the sentinel: %v", err)
	}
	if !strings.Contains(err.Error(), "all-attempts-failed") ||
		!strings.Contains(err.Error(), "4 attempts") {
		t.Fatalf("failure report malformed: %v", err)
	}
}

func TestRaceEndpointsEmptyCandidates(t *testing.T) {
	cfg := HEConfig{Sleep: func(context.Context, time.Duration) error { return nil }}
	if _, _, err := RaceEndpoints(context.Background(), cfg, nil,
		func(context.Context, int, netip.AddrPort) (int, error) { return 0, nil }); err == nil {
		t.Fatal("empty candidate list must be rejected")
	}
}

// TestRaceEndpointsCallerCancel: caller deadline outranks everything.
func TestRaceEndpointsCallerCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	cfg := HEConfig{Stagger: 10 * time.Millisecond, Cap: 30 * time.Second}
	_, _, err := RaceEndpoints(ctx, cfg, heCands,
		func(rctx context.Context, i int, _ netip.AddrPort) (int, error) {
			<-rctx.Done()
			return 0, rctx.Err()
		})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want caller deadline surfaced, got %v", err)
	}
}
