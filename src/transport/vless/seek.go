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

// maxProbePerPass bounds one probe pass. A curated bundled list can hold
// thousands of nodes and a probe costs up to the prober timeout each; probing
// all of them every interval is unworkable on a router. The pass therefore
// takes the memory-ordered head (known-good first, then the never-tried, then
// the failures oldest-first), so each pass both keeps the working node and
// advances through the corpus, and failures eventually get retried.
const maxProbePerPass = 64

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
	// OnReady fires once, when the first node becomes active (a managed helper
	// follows the selection instead of keeping the first rendered node).
	OnReady func(n Node)
	// Stats is the optional persistent outcome memory (design §8, b4x-d0fw).
	Stats *StatsStore

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
	now := time.Now()
	results := ProbeAll(ctx, s.prober, s.probeSet(now), s.cfg.MaxParallel)
	cands := s.filter(results)
	s.mu.Lock()
	s.lastResults = results
	s.lastRun = now.UTC()
	s.mu.Unlock()
	// Order by the memory BEFORE folding this pass in: a node that just answered
	// must not be promoted above one that already has a track record.
	sort.SliceStable(cands, func(i, j int) bool { return s.orderLess(cands[i], cands[j], now) })
	s.record(results, now)
	if len(cands) == 0 {
		return Node{}, false
	}
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
	switch {
	case prev == nil:
		if s.OnReady != nil {
			s.OnReady(n)
		}
	case prev.Identity() != n.Identity() && s.OnChange != nil:
		s.OnChange(n)
	}
}

// record folds one probe pass into the persistent memory (advisory: a write or
// save failure never affects the selection).
func (s *Selector) record(results []ProbeResult, now time.Time) {
	if s.Stats == nil {
		return
	}
	s.Stats.RecordResults(results, now)
	_ = s.Stats.Save()
}

func (s *Selector) statFor(r ProbeResult) NodeStat { return s.statForNode(r.Node) }

func (s *Selector) statForNode(n Node) NodeStat {
	if s.Stats == nil {
		return NodeStat{}
	}
	return s.Stats.Stat(n.Identity())
}

// memoryBucket mirrors Nova's _vless_order (design §8): a node that recently
// carried traffic first, then one that answered an RTT probe, then the
// never-tried, then the ones failing since their last success. Evidence older
// than StatTTL is ignored.
func (s *Selector) memoryBucket(r ProbeResult, now time.Time) int {
	return s.nodeBucket(r.Node, now)
}

func (s *Selector) nodeBucket(n Node, now time.Time) int {
	st := s.statForNode(n)
	if oa := statAge(st.LastOKAt, now); oa >= 0 && oa < StatTTL && st.LastOKAt >= st.LastFailAt {
		return 0
	}
	if ra := statAge(st.RTTAt, now); ra >= 0 && ra < StatTTL {
		return 1
	}
	if st.LastFailAt <= 0 {
		return 2
	}
	return 3
}

// probeSet is the bounded, memory-ordered set of candidates for one pass.
func (s *Selector) probeSet(now time.Time) []Node {
	nodes := s.Nodes()
	if len(nodes) <= maxProbePerPass {
		return nodes
	}
	type keyed struct {
		n  Node
		b  int
		lf float64
	}
	ks := make([]keyed, 0, len(nodes))
	for _, n := range nodes {
		ks = append(ks, keyed{n: n, b: s.nodeBucket(n, now), lf: s.statForNode(n).LastFailAt})
	}
	sort.SliceStable(ks, func(i, j int) bool {
		if ks[i].b != ks[j].b {
			return ks[i].b < ks[j].b
		}
		if ks[i].lf != ks[j].lf {
			return ks[i].lf < ks[j].lf
		}
		return nodeSortKey(ks[i].n) < nodeSortKey(ks[j].n)
	})
	out := make([]Node, 0, maxProbePerPass)
	for i := 0; i < maxProbePerPass && i < len(ks); i++ {
		out = append(out, ks[i].n)
	}
	return out
}

// orderLess orders candidates by memory bucket, then current latency, then the
// least recently failed, then a stable key.
func (s *Selector) orderLess(a, b ProbeResult, now time.Time) bool {
	ba, bb := s.memoryBucket(a, now), s.memoryBucket(b, now)
	if ba != bb {
		return ba < bb
	}
	if a.LatencyMs != b.LatencyMs {
		return a.LatencyMs < b.LatencyMs
	}
	sa, sb := s.statFor(a), s.statFor(b)
	if sa.LastFailAt != sb.LastFailAt {
		return sa.LastFailAt < sb.LastFailAt
	}
	return nodeSortKey(a.Node) < nodeSortKey(b.Node)
}

// nodeSortKey is the stable tiebreak (host then name).
func nodeSortKey(n Node) string {
	return strings.ToLower(n.Host) + "#" + n.Name
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
