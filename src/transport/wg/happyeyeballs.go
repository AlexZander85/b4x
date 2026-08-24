// Happy Eyeballs candidate racing (design §6): staggered interleave of
// establishment attempts, warp-socks pattern — start candidate i after
// i*Stagger (default 250 ms·i) under a total cap (default 10 s); the FIRST
// successful attempt wins immediately and cancels every other attempt.
//
// The runner is transport-agnostic: callers hand in an attempt function
// (e.g. a single-shot Seeker attempt or a supervisor dial) and an
// InterleaveV4V6-ordered candidate list. Sequential seek-ladder behavior is
// untouched — this is the parallel dial primitive for wiring stages.
package transportwg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

const (
	// DefaultHEStagger: per-candidate start delay multiplier (250 ms·i).
	DefaultHEStagger = 250 * time.Millisecond
	// DefaultHECap bounds the whole race regardless of candidate count.
	DefaultHECap = 10 * time.Second
)

// HEConfig tunes the race. Zero values map to defaults; Sleep is a pacing
// seam for deterministic tests (production leaves it nil).
type HEConfig struct {
	Stagger time.Duration
	Cap     time.Duration

	// Sleep waits d (or until ctx is done). Defaults to a timer sleep.
	Sleep func(ctx context.Context, d time.Duration) error
}

func (c *HEConfig) fillDefaults() {
	if c.Stagger <= 0 {
		c.Stagger = DefaultHEStagger
	}
	if c.Cap <= 0 {
		c.Cap = DefaultHECap
	}
	if c.Sleep == nil {
		c.Sleep = func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		}
	}
}

// RaceEndpoints races attempt over candidates with staggered starts.
//
// Semantics:
//   - candidate i starts after i*Stagger; spawning stops early when the cap
//     deadline fires first (later candidates are never attempted);
//   - the first SUCCESSFUL attempt wins at once; cancellation propagates to
//     every other in-flight attempt;
//   - when every attempted candidate fails, their errors are joined and the
//     cause (cap deadline / caller cancel) is wrapped.
//
// The candidate order is taken as given; wire InterleaveV4V6 in front for
// the v4/v6 weave. Returns the winning value with its index, or zero values
// plus an error.
func RaceEndpoints[T any](ctx context.Context, cfg HEConfig, cands []netip.AddrPort, attempt func(ctx context.Context, i int, cand netip.AddrPort) (T, error)) (T, int, error) {
	cfg.fillDefaults()
	var zero T
	if len(cands) == 0 {
		return zero, -1, errors.New("transportwg: happy-eyeballs: no candidates")
	}

	raceCtx, cancel := context.WithTimeout(ctx, cfg.Cap)
	defer cancel()

	type outcome struct {
		idx int
		val T
		err error
	}
	// Buffered to len(cands): after an early win nobody reads anymore, yet
	// every loser's send must still complete without blocking.
	results := make(chan outcome, len(cands))

	go func() {
		var wg sync.WaitGroup
		defer func() {
			wg.Wait() // close only after ALL spawned attempts finished sending
			close(results)
		}()
		for i, cand := range cands {
			if err := cfg.Sleep(raceCtx, time.Duration(i)*cfg.Stagger); err != nil {
				return // cap deadline or caller cancel: stop spawning
			}
			wg.Add(1)
			go func(i int, cand netip.AddrPort) {
				defer wg.Done()
				val, err := attempt(raceCtx, i, cand)
				results <- outcome{idx: i, val: val, err: err}
			}(i, cand)
		}
	}()

	fails := make([]error, 0, len(cands))
	for out := range results {
		if out.err == nil {
			cancel()
			return out.val, out.idx, nil
		}
		fails = append(fails, out.err)
	}

	cause := "all-attempts-failed"
	if err := raceCtx.Err(); err != nil {
		if ctx.Err() != nil {
			cause = fmt.Sprintf("caller-cancelled: %v", err)
		} else {
			cause = fmt.Sprintf("happy-eyeballs-cap: %v", err)
		}
	}
	return zero, -1, fmt.Errorf("transportwg: happy-eyeballs: %s (%d attempts): %w",
		cause, len(fails), errors.Join(fails...))
}
