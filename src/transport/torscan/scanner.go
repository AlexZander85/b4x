package torscan

// Scanner driver: source chain -> country policy -> bandwidth ranking ->
// bounded top cohort -> deterministic shuffle -> modern Tor channel probes.
// The top cohort preserves the speed signal while shuffle avoids a stable
// probe fingerprint. Persistent per-address and aggregate budgets prevent
// repeated active handshakes across daemon restarts.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ScanConfig struct {
	Ports     []int
	Countries []string
	Goal      int
	Timeout   time.Duration
	PoolSize  int
	// CreateCount is retained for config/source compatibility. Modern
	// DeepProbe no longer creates circuits.
	CreateCount int
	Seed        uint64
}

func (c *ScanConfig) normalize() {
	if len(c.Ports) == 0 {
		c.Ports = []int{443, 9001}
	}
	if c.Goal <= 0 {
		c.Goal = 6
	}
	if c.Timeout <= 0 {
		c.Timeout = 90 * time.Second
	}
	if c.PoolSize <= 0 {
		c.PoolSize = 24
	}
}

type VerifiedRelay struct {
	Relay
	Addr string
}

func (v VerifiedRelay) BridgeLine() string {
	return fmt.Sprintf("%s %s", v.Addr, v.Fingerprint)
}

type Result struct {
	Relays          []VerifiedRelay
	Source          string
	Probed          int
	Checked         int
	SkippedCooldown int
	SkippedBudget   int
}

type Scanner struct {
	fetch Fetcher
	dial  Dialer
	now   func() time.Time
}

func NewScanner(fetch Fetcher, dial Dialer) *Scanner {
	if dial == nil {
		dial = PlainDial
	}
	return &Scanner{fetch: fetch, dial: dial, now: time.Now}
}

// SetNow is a deterministic test seam for the persistent cooldown ledger.
func (s *Scanner) SetNow(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

func (s *Scanner) Scan(ctx context.Context, cfg ScanConfig, customURLs []string, cachePath string) (Result, error) {
	cfg.normalize()
	rctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	relays, source, err := Onionoo(rctx, s.fetch, customURLs, cachePath)
	if err != nil {
		return Result{}, err
	}

	// Bandwidth first, then stable country grouping: priority countries move
	// to the head while bandwidth ordering is preserved inside each group.
	ranked := BandwidthRank(relays)
	ranked = filterCountries(ranked, cfg.Countries)
	cohortN := cfg.Goal * 8
	if min := cfg.PoolSize * 2; cohortN < min {
		cohortN = min
	}
	if cohortN < cfg.Goal*3 {
		cohortN = cfg.Goal * 3
	}
	if cohortN > len(ranked) {
		cohortN = len(ranked)
	}
	cohort := ranked[:cohortN]
	shuffled := Shuffle(cohort, cfg.Seed)

	type candidate struct {
		relay Relay
		addr  string
	}
	var candidates []candidate
	for _, r := range shuffled {
		for _, addr := range AddrCandidates(r, cfg.Ports) {
			candidates = append(candidates, candidate{relay: r, addr: addr})
		}
	}

	now := s.now()
	lp := ledgerPath(cachePath)
	ledger := loadProbeLedger(lp)
	eligible := candidates[:0]
	skippedCooldown := 0
	for _, c := range candidates {
		if !ledger.eligible(c.addr, now) {
			skippedCooldown++
			continue
		}
		eligible = append(eligible, c)
	}
	candidates = eligible

	var (
		mu            sync.Mutex
		verified      []VerifiedRelay
		probed        int64
		goal          = cfg.Goal
		skippedBudget int
	)
	sem := make(chan struct{}, cfg.PoolSize)
	var wg sync.WaitGroup
	for _, cand := range candidates {
		if int(atomic.LoadInt64(&probed)) >= goal*3 {
			break
		}
		mu.Lock()
		done := len(verified) >= goal
		mu.Unlock()
		if done || rctx.Err() != nil {
			break
		}
		if !ledger.reserve(cand.addr, now) {
			skippedBudget++
			break
		}
		wg.Add(1)
		go func(c candidate) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-rctx.Done():
				return
			}
			atomic.AddInt64(&probed, 1)
			if err := DeepProbe(rctx, s.dial, c.addr, cfg.CreateCount); err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if len(verified) < goal {
				verified = append(verified, VerifiedRelay{Relay: c.relay, Addr: c.addr})
			}
		}(cand)
	}
	wg.Wait()
	// The ledger is diagnostic/rate-safety state, not correctness state. A
	// write failure must not erase a successful scanner result.
	_ = ledger.save(lp)

	if len(verified) == 0 {
		return Result{
			Source:          source,
			Probed:          int(atomic.LoadInt64(&probed)),
			Checked:         len(candidates),
			SkippedCooldown: skippedCooldown,
			SkippedBudget:   skippedBudget,
		}, fmt.Errorf("torscan: no relay passed the modern channel probe (%d probed, %d cooldown-skipped, %d budget-skipped)", atomic.LoadInt64(&probed), skippedCooldown, skippedBudget)
	}
	return Result{
		Relays:          verified,
		Source:          source,
		Probed:          int(atomic.LoadInt64(&probed)),
		Checked:         len(candidates),
		SkippedCooldown: skippedCooldown,
		SkippedBudget:   skippedBudget,
	}, nil
}

func filterCountries(relays []Relay, countries []string) []Relay {
	if len(countries) == 0 {
		return relays
	}
	var exclude, only, priority []string
	for _, c := range countries {
		c = strings.ToUpper(strings.TrimSpace(c))
		switch {
		case strings.HasPrefix(c, "-"):
			exclude = append(exclude, strings.TrimPrefix(c, "-"))
		case strings.HasPrefix(c, "!"):
			only = append(only, strings.TrimPrefix(c, "!"))
		case c != "":
			priority = append(priority, c)
		}
	}
	var out []Relay
	for _, r := range relays {
		cc := strings.ToUpper(r.Country)
		bad := false
		for _, x := range exclude {
			if cc == x {
				bad = true
				break
			}
		}
		if bad {
			continue
		}
		if len(only) > 0 {
			ok := false
			for _, x := range only {
				if cc == x {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		out = append(out, r)
	}
	if len(priority) > 0 {
		rank := func(cc string) int {
			for i, p := range priority {
				if cc == p {
					return i
				}
			}
			return len(priority)
		}
		sort.SliceStable(out, func(i, j int) bool {
			return rank(strings.ToUpper(out[i].Country)) < rank(strings.ToUpper(out[j].Country))
		})
	}
	return out
}

func (res Result) BridgeLines() []string {
	out := make([]string, 0, len(res.Relays))
	for _, v := range res.Relays {
		out = append(out, v.BridgeLine())
	}
	return out
}
