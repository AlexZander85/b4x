package vless

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ProbeRunner is the seam the selector probes through (Prober in production,
// a scripted fake in tests).
type ProbeRunner interface {
	Probe(ctx context.Context, n Node) ProbeResult
}

// SeekConfig carries the URLTest-inspired selection semantics (design §8):
// Interval is the probe cadence, Tolerance stops the active node from flapping
// for a marginal latency win, and the country filters implement the inverted
// geo policy (prefer NON-RU egress).
type SeekConfig struct {
	Interval     time.Duration
	Tolerance    time.Duration
	PreferNonRU  bool
	CountryAllow []string
	CountryDeny  []string
	MaxParallel  int
	// Pin, when set ("host:port"), restricts candidates to that node.
	Pin string
}

// Selector probes the node set and chooses the best acceptable node. It never
// dials user traffic itself — the runtime asks Active() (or reacts to OnChange)
// and dials the chosen node.
type Selector struct {
	cfg      SeekConfig
	prober   ProbeRunner
	OnChange func(n Node)

	mu          sync.RWMutex
	nodes       []Node
	active      *Node
	lastGood    *Node
	lastResults []ProbeResult
	lastRun     time.Time
}

// NewSelector builds a selector; zero Interval/Tolerance get sane defaults.
func NewSelector(cfg SeekConfig, prober ProbeRunner) *Selector {
	if cfg.Interval < 30*time.Second {
		cfg.Interval = 30 * time.Second
	}
	if cfg.Tolerance < 0 {
		cfg.Tolerance = 0
	}
	return &Selector{cfg: cfg, prober: prober}
}

// SetNodes replaces the candidate set (refresh rotation).
func (s *Selector) SetNodes(nodes []Node) {
	cp := make([]Node, len(nodes))
	copy(cp, nodes)
	s.mu.Lock()
	s.nodes = cp
	s.mu.Unlock()
}

// Nodes snapshots the candidate set.
func (s *Selector) Nodes() []Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Node(nil), s.nodes...)
}

// Active returns the current selection.
func (s *Selector) Active() (Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.active == nil {
		return Node{}, false
	}
	return *s.active, true
}

// LastResults snapshots the most recent probe pass.
func (s *Selector) LastResults() []ProbeResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]ProbeResult(nil), s.lastResults...)
}

// LastRun reports when the last pass finished.
func (s *Selector) LastRun() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastRun
}

// Select runs one probe pass and updates the active node. It returns
// (node, true) when an acceptable node exists, (zero, false) otherwise.
func (s *Selector) Select(ctx context.Context) (Node, bool) {
	if s.prober == nil {
		return Node{}, false
	}
	results := ProbeAll(ctx, s.prober, s.Nodes(), s.cfg.MaxParallel)
	cands := s.filter(results)
	s.mu.Lock()
	s.lastResults = results
	s.lastRun = time.Now().UTC()
	s.mu.Unlock()
	if len(cands) == 0 {
		return Node{}, false
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].LatencyMs < cands[j].LatencyMs })
	best := cands[0]
	chosen := best.Node
	s.mu.RLock()
	cur := s.active
	s.mu.RUnlock()
	if cur != nil {
		if cr, ok := findResult(cands, *cur); ok && cr.LatencyMs-best.LatencyMs <= s.tolMs() {
			chosen = *cur // within tolerance: do not flap
		}
	}
	s.setActive(chosen)
	good := chosen
	s.mu.Lock()
	s.lastGood = &good
	s.mu.Unlock()
	return chosen, true
}

// Run probes immediately then on the configured interval until ctx is done.
func (s *Selector) Run(ctx context.Context) {
	_, _ = s.Select(ctx)
	t := time.NewTicker(s.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			_, _ = s.Select(ctx)
		}
	}
}

func (s *Selector) setActive(n Node) {
	s.mu.Lock()
	prev := s.active
	nn := n
	s.active = &nn
	s.mu.Unlock()
	if prev != nil && prev.Identity() != n.Identity() && s.OnChange != nil {
		s.OnChange(n)
	}
}

func (s *Selector) tolMs() int64 { return int64(s.cfg.Tolerance / time.Millisecond) }

// filter applies the geo policy: OK probes only; prefer_nonru drops empty/RU;
// allow (if set) admits only listed countries; deny removes listed countries.
func (s *Selector) filter(results []ProbeResult) []ProbeResult {
	out := make([]ProbeResult, 0, len(results))
	for _, r := range results {
		if !r.OK {
			continue
		}
		if s.cfg.Pin != "" {
			if !strings.EqualFold(nodeEndpoint(r.Node), s.cfg.Pin) {
				continue
			}
		}
		loc := strings.ToUpper(strings.TrimSpace(r.Loc))
		if s.cfg.PreferNonRU && (loc == "" || loc == "RU") {
			continue
		}
		if len(s.cfg.CountryAllow) > 0 && !containsFold(s.cfg.CountryAllow, loc) {
			continue
		}
		if containsFold(s.cfg.CountryDeny, loc) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func findResult(results []ProbeResult, n Node) (ProbeResult, bool) {
	id := n.Identity()
	for _, r := range results {
		if r.Node.Identity() == id {
			return r, true
		}
	}
	return ProbeResult{}, false
}

// nodeEndpoint renders "host:port" for pin matching (case-insensitive).
func nodeEndpoint(n Node) string {
	return strings.ToLower(strings.TrimSpace(n.Host)) + ":" + strconv.Itoa(int(n.Port))
}

func containsFold(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(strings.TrimSpace(s), v) {
			return true
		}
	}
	return false
}
