package monitor

import (
	"context"
	"sync"
	"time"
)

type BusConfig struct {
	Capacity   int
	P0Capacity int
	Clock      func() time.Time
}
type BusStats struct {
	Accepted, Dropped, Invalid, SafetyDropped uint64
	LastHeartbeat                             map[string]time.Time
}

type ObservationBus struct {
	mu     sync.Mutex
	normal chan MonitorObservation
	safety chan MonitorObservation
	cfg    BusConfig
	stats  BusStats
}

func NewObservationBus(cfg BusConfig) *ObservationBus {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 256
	}
	if cfg.P0Capacity <= 0 {
		cfg.P0Capacity = 32
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &ObservationBus{normal: make(chan MonitorObservation, cfg.Capacity), safety: make(chan MonitorObservation, cfg.P0Capacity), cfg: cfg, stats: BusStats{LastHeartbeat: map[string]time.Time{}}}
}

func (b *ObservationBus) Publish(o MonitorObservation) bool {
	if b == nil || !o.Valid(b.cfg.Clock()) {
		if b != nil {
			b.mu.Lock()
			b.stats.Invalid++
			b.mu.Unlock()
		}
		return false
	}
	p0 := o.Source == SourceQueueDrop || o.Source == SourcePPEVisibility || o.Source == SourceTCPRST
	if p0 {
		select {
		case b.safety <- o:
			b.record(o)
			return true
		default:
			b.mu.Lock()
			b.stats.SafetyDropped++
			b.stats.Dropped++
			b.mu.Unlock()
			return false
		}
	}
	select {
	case b.normal <- o:
		b.record(o)
		return true
	default:
		b.mu.Lock()
		b.stats.Dropped++
		b.mu.Unlock()
		return false
	}
}

func (b *ObservationBus) record(o MonitorObservation) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stats.Accepted++
	b.stats.LastHeartbeat[string(o.Source)] = o.ObservedAt
}
func (b *ObservationBus) Next(ctx context.Context) (MonitorObservation, bool) {
	select {
	case o := <-b.safety:
		return o, true
	default:
	}
	select {
	case o := <-b.safety:
		return o, true
	case o := <-b.normal:
		return o, true
	case <-ctx.Done():
		return MonitorObservation{}, false
	}
}
func (b *ObservationBus) Stats() BusStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := b.stats
	out.LastHeartbeat = map[string]time.Time{}
	for k, v := range b.stats.LastHeartbeat {
		out.LastHeartbeat[k] = v
	}
	return out
}
