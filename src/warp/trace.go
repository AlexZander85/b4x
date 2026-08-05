package warp

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type TracePriority uint8

const (
	P0 TracePriority = iota
	P1
	P2
)

type TransportTraceEnvelope struct {
	SchemaVersion                                                                    uint16
	BootID, ProcessID, SessionID, ParentSessionID, RouteGeneration, ConfigGeneration string
	Sequence                                                                         uint64
	Priority                                                                         TracePriority
	Event                                                                            string
	StateAfter                                                                       string
	Payload                                                                          map[string]string
	ObservedAt                                                                       time.Time
	Checksum                                                                         string
}

func (e TransportTraceEnvelope) Seal() TransportTraceEnvelope {
	h := sha256.Sum256([]byte(e.BootID + e.ProcessID + e.SessionID + e.Event + string(e.Priority) + e.ObservedAt.UTC().String()))
	e.Checksum = hex.EncodeToString(h[:])
	return e
}
func (e TransportTraceEnvelope) Valid(prev uint64) bool {
	return e.SchemaVersion == 2 && e.BootID != "" && e.ProcessID != "" && e.SessionID != "" && e.Sequence > prev && !e.ObservedAt.IsZero() && e.Checksum == e.Seal().Checksum
}

type TracePipeline struct {
	mu       sync.Mutex
	last     uint64
	events   []TransportTraceEnvelope
	capacity int
	degraded bool
}

func NewTracePipeline(capacity int) *TracePipeline {
	if capacity <= 0 {
		capacity = 256
	}
	return &TracePipeline{capacity: capacity}
}

// Publish stores one trace event under the addendum §61.2 durability rules:
//   - P2 performance samples are dropped when the ring is full (allowed);
//   - P0/P1 required events are never evicted in favor of other events; when
//     the ring is full the oldest P2 sample is evicted instead;
//   - when the ring holds only P0/P1 events, a new required event cannot be
//     stored and is rejected (the production layer counts the rejection as
//     warp_trace_dropped_required_event_total).
func (p *TracePipeline) Publish(e TransportTraceEnvelope) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e.Sequence <= p.last {
		return false
	}
	if len(p.events) >= p.capacity {
		if e.Priority > P1 {
			return false
		}
		idx := -1
		for i, ev := range p.events {
			if ev.Priority > P1 {
				idx = i
				break
			}
		}
		if idx < 0 {
			return false
		}
		p.events = append(p.events[:idx], p.events[idx+1:]...)
	}
	p.last = e.Sequence
	p.events = append(p.events, e)
	return true
}

// HasCapacityFor reports whether the event would be accepted by Publish
// without mutating the pipeline. The runtime layer uses it on the violating
// branch before publishing: a P0/P1 required event that cannot be stored is a
// dropped required event (warp_trace_dropped_required_event_total).
func (p *TracePipeline) HasCapacityFor(e TransportTraceEnvelope) bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if e.Sequence <= p.last {
		return false
	}
	if len(p.events) >= p.capacity {
		if e.Priority > P1 {
			return false
		}
		for _, ev := range p.events {
			if ev.Priority > P1 {
				return true
			}
		}
		return false
	}
	return true
}
func (p *TracePipeline) Snapshot() []TransportTraceEnvelope {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]TransportTraceEnvelope(nil), p.events...)
}
func ValidateTraceCompatibility(e TransportTraceEnvelope) error {
	if e.SchemaVersion != 2 {
		return errors.New("trace schema mismatch")
	}
	return nil
}
