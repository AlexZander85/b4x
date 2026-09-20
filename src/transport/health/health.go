// Package health measures the health of reserve tunnels (availability,
// latency, bounded throughput, coarse loss) in a transport-agnostic way: one
// probe runs THROUGH a reserve.Carrier, so every registered kind
// (warp/masque/h3/opera/fxvpn/proton/tor/nonru/chains) is covered by the same
// code. Design: TUNNELS_PANEL_DESIGN.md §8.
//
// POLICY: a Metrics result is a RECOMMENDATION/score only. It never changes
// which tunnel carries traffic; selecting a tunnel is an explicit
// promote/rollback action (canary canon, src/fieldtest/promotion.go).
package health

import (
	"math"
	"sync"
	"time"
)

// Metrics is one tunnel measurement result.
type Metrics struct {
	Kind           string    `json:"kind"`
	Available      bool      `json:"available"`
	RTTms          int64     `json:"rtt_ms,omitempty"`
	TTFBms         int64     `json:"ttfb_ms,omitempty"`
	ThroughputMbps float64   `json:"throughput_mbps,omitempty"`
	LossPct        float64   `json:"loss_pct,omitempty"`
	Bytes          int64     `json:"bytes,omitempty"`
	Probes         int       `json:"probes"`
	Failures       int       `json:"failures"`
	Score          float64   `json:"score"`
	Verdict        string    `json:"verdict"`
	Error          string    `json:"error,omitempty"`
	MeasuredAt     time.Time `json:"measured_at"`
}

// Verdicts (v1 heuristic; calibrate in the field).
const (
	VerdictHealthy     = "healthy"
	VerdictDegraded    = "degraded"
	VerdictPoor        = "poor"
	VerdictUnavailable = "unavailable"
)

// Score v1: availability 40%, latency 35%, throughput 25% (0..100).
func scoreOf(m Metrics) float64 {
	if m.Probes <= 0 {
		return 0
	}
	success := float64(m.Probes-m.Failures) / float64(m.Probes)
	lat := clamp01(1 - (float64(m.TTFBms)-50)/950)
	thr := clamp01(m.ThroughputMbps / 10)
	return math.Round((0.40*success+0.35*lat+0.25*thr)*10000) / 100
}

func verdictOf(available bool, score float64) string {
	switch {
	case !available:
		return VerdictUnavailable
	case score >= 70:
		return VerdictHealthy
	case score >= 40:
		return VerdictDegraded
	default:
		return VerdictPoor
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// Cache keeps the last Metrics per tunnel kind (in-memory; Phase B persists).
type Cache struct {
	mu sync.Mutex
	m  map[string]Metrics
}

// NewCache builds an empty cache.
func NewCache() *Cache { return &Cache{m: map[string]Metrics{}} }

// Put records the latest measurement for its kind.
func (c *Cache) Put(m Metrics) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[m.Kind] = m
}

// Get returns the last measurement for kind.
func (c *Cache) Get(kind string) (Metrics, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	m, ok := c.m[kind]
	return m, ok
}

// Snapshot copies the cache.
func (c *Cache) Snapshot() map[string]Metrics {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]Metrics, len(c.m))
	for k, v := range c.m {
		out[k] = v
	}
	return out
}
