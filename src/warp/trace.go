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
func (p *TracePipeline) Publish(e TransportTraceEnvelope) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if e.Sequence <= p.last {
		return false
	}
	if e.Priority > P1 && len(p.events) >= p.capacity {
		return false
	}
	if len(p.events) >= p.capacity {
		p.events = p.events[1:]
	}
	p.last = e.Sequence
	p.events = append(p.events, e)
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
