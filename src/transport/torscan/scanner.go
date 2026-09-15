package torscan

// Scanner driver (design §4.3 — the tor-relay-scanner-go skeleton FIXED:
// ALL or_addresses probed, not just [0]; goal-driven early stop; bounded
// pool; bandwidth-ranked output). The result is a set of vanilla bridge
// LINES ready for bridges.json.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanConfig bounds one scan run.
type ScanConfig struct {
	// Ports filters candidate OR ports (default 443, 9001).
	Ports []int
	// Countries PRIORITIZES (never hard-filters) relay countries (ISO
	// codes; a leading '-' excludes, '!' means ONLY these — the ValdikSS
	// filter canon simplified to priorities + excludes).
	Countries []string
	// Goal is the early-stop count of VERIFIED relays (0 => 6).
	Goal int
	// Timeout is the overall budget (0 => 90s).
	Timeout time.Duration
	// PoolSize bounds concurrent probes (0 => 24).
	PoolSize int
	// CreateCount is the dummy CREATE cell count per probe (0 => 8).
	CreateCount int
	// Seed shuffles the candidate order deterministically.
	Seed uint64
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
	if c.CreateCount <= 0 {
		c.CreateCount = 8
	}
}

// VerifiedRelay is one deep-probe-verified relay candidate.
type VerifiedRelay struct {
	Relay
	Addr string // the SPECIFIC or_address that answered the probe
}

// BridgeLine renders the vanilla bridge line for a verified relay.
func (v VerifiedRelay) BridgeLine() string {
	return fmt.Sprintf("%s %s", v.Addr, v.Fingerprint)
}

// Result is one scan run outcome.
type Result struct {
	Relays []VerifiedRelay
	Source string // the onionoo source that fed the run
	// Probed counts the deep probes attempted / verified.
	Probed  int
	Checked int
}

// Scanner ties the sources, probes and ranking together.
type Scanner struct {
	fetch Fetcher
	dial  Dialer
}

// NewScanner builds the scanner over the injected seams.
func NewScanner(fetch Fetcher, dial Dialer) *Scanner {
	if dial == nil {
		dial = PlainDial
	}
	return &Scanner{fetch: fetch, dial: dial}
}

// Scan runs one bounded scan: onionoo (fallback chain) → country
// priority sort → bandwidth ranking → shuffle → pooled deep probes with
// goal-driven early stop.
func (s *Scanner) Scan(ctx context.Context, cfg ScanConfig, customURLs []string, cachePath string) (Result, error) {
	cfg.normalize()
	rctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	relays, source, err := Onionoo(rctx, s.fetch, customURLs, cachePath)
	if err != nil {
		return Result{}, err
	}

	// country policy: excludes out, "!" only-these, plain = priority order
	relays = filterCountries(relays, cfg.Countries)
	// bandwidth top-quantile FIRST (fast guards), then the deterministic
	// shuffle inside the ranking (probe order leaks no preference)
	ranked := BandwidthRank(relays)
	shuffled := Shuffle(ranked, cfg.Seed)

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

	var (
		mu       sync.Mutex
		verified []VerifiedRelay
		probed   int64
		goal     = cfg.Goal
	)
	sem := make(chan struct{}, cfg.PoolSize)
	var wg sync.WaitGroup
	for _, cand := range candidates {
		// early stop: goal reached (verified) or the probe budget spent
		if int(atomic.LoadInt64(&probed)) >= goal*3 {
			break
		}
		mu.Lock()
		done := len(verified) >= goal
		mu.Unlock()
		if done {
			break
		}
		if rctx.Err() != nil {
			break // budget exhausted: stop scheduling, wg.Wait collects
		}
		wg.Add(1)
		go func(c candidate) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
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

	if len(verified) == 0 {
		return Result{Source: source, Probed: int(atomic.LoadInt64(&probed))},
			fmt.Errorf("torscan: no relay passed the deep probe (%d candidates probed)", atomic.LoadInt64(&probed))
	}
	return Result{Relays: verified, Source: source, Probed: int(atomic.LoadInt64(&probed)), Checked: len(candidates)}, nil
}

// filterCountries applies the ValdikSS country policy: "-xx" excludes,
// "!xx" restricts to exactly those, plain "xx" orders by priority.
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
	// priority ordering: the listed countries float to the head, keeping
	// the bandwidth order inside each group
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
			return rank(out[i].Country) < rank(out[j].Country)
		})
	}
	return out
}

// BridgeLines renders the verified set as bridge lines.
func (res Result) BridgeLines() []string {
	out := make([]string, 0, len(res.Relays))
	for _, v := range res.Relays {
		out = append(out, v.BridgeLine())
	}
	return out
}
