package detector

import (
	"errors"
	"hash/fnv"
	"sort"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/monitor"
)

type DynamicSelector struct{ ASN, Provider, Subnet, Service string }
type DynamicControlTarget struct {
	ID, Host, IPHash, ASN, Provider, Subnet, Service, Provenance string
	ValidUntil                                                   time.Time
}
type DynamicTargetSource interface {
	Load(selector DynamicSelector) ([]DynamicControlTarget, error)
}
type DynamicProviderConfig struct {
	MaxTargets int
	TTL        time.Duration
	SampleSeed uint64
}
type DynamicControlTargetProvider struct {
	mu     sync.Mutex
	cfg    DynamicProviderConfig
	source DynamicTargetSource
	cache  map[string]dynamicCache
}
type dynamicCache struct {
	targets   []DynamicControlTarget
	fetchedAt time.Time
}

func NewDynamicControlTargetProvider(cfg DynamicProviderConfig, source DynamicTargetSource) *DynamicControlTargetProvider {
	if cfg.MaxTargets <= 0 {
		cfg.MaxTargets = 32
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	return &DynamicControlTargetProvider{cfg: cfg, source: source, cache: map[string]dynamicCache{}}
}
func selectorKey(s DynamicSelector) string {
	return s.ASN + "|" + s.Provider + "|" + s.Subnet + "|" + s.Service
}
func (p *DynamicControlTargetProvider) Targets(selector DynamicSelector, now time.Time) ([]DynamicControlTarget, error) {
	if p == nil || p.source == nil {
		return nil, errors.New("dynamic target source unavailable")
	}
	k := selectorKey(selector)
	p.mu.Lock()
	if c, ok := p.cache[k]; ok && now.Sub(c.fetchedAt) < p.cfg.TTL {
		out := append([]DynamicControlTarget(nil), c.targets...)
		p.mu.Unlock()
		return out, nil
	}
	p.mu.Unlock()
	raw, err := p.source.Load(selector)
	if err != nil {
		return nil, err
	}
	valid := make([]DynamicControlTarget, 0, len(raw))
	for _, t := range raw {
		if t.ID == "" || t.IPHash == "" || t.Provenance == "" {
			continue
		}
		if !t.ValidUntil.IsZero() && !now.Before(t.ValidUntil) {
			continue
		}
		valid = append(valid, t)
	}
	sort.Slice(valid, func(i, j int) bool { return valid[i].ID < valid[j].ID })
	if len(valid) > p.cfg.MaxTargets {
		valid = deterministicSample(valid, p.cfg.MaxTargets, p.cfg.SampleSeed)
	}
	p.mu.Lock()
	p.cache[k] = dynamicCache{targets: append([]DynamicControlTarget(nil), valid...), fetchedAt: now}
	p.mu.Unlock()
	return valid, nil
}
func deterministicSample(in []DynamicControlTarget, n int, seed uint64) []DynamicControlTarget {
	if n >= len(in) {
		return in
	}
	out := append([]DynamicControlTarget(nil), in...)
	for i := range out {
		h := fnv.New64a()
		h.Write([]byte(out[i].ID))
		v := h.Sum64() ^ seed
		j := int(v % uint64(len(out)))
		out[i], out[j] = out[j], out[i]
	}
	out = out[:n]
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

type StaticTargetSource []DynamicControlTarget

func (s StaticTargetSource) Load(_ DynamicSelector) ([]DynamicControlTarget, error) {
	return append([]DynamicControlTarget(nil), s...), nil
}

func DynamicTargetEvidence(scope monitor.MonitorScopeKey, targets []DynamicControlTarget) []DNSAddressOutcome {
	out := make([]DNSAddressOutcome, 0, len(targets))
	for _, t := range targets {
		out = append(out, DNSAddressOutcome{SnapshotID: "dynamic-control", IPHash: t.IPHash, QueryStage: t.Provenance, ObservedAt: time.Now()})
	}
	_ = scope
	return out
}
