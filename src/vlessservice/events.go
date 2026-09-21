package vlessservice

import (
	"sync"
	"time"
)

// Event is one bounded observability record (opera/eventRing parity): the
// status page renders the tail, the daemon log mirrors it. No secrets.
type Event struct {
	Time   time.Time `json:"time"`
	Level  string    `json:"level"`
	Type   string    `json:"type"`
	Detail string    `json:"detail,omitempty"`
}

// eventRing keeps the last N events; a slow consumer never blocks a dial.
type eventRing struct {
	mu    sync.Mutex
	items []Event
	max   int
}

func newEventRing(max int) *eventRing {
	if max <= 0 {
		max = 64
	}
	return &eventRing{max: max}
}

func (r *eventRing) push(level, typ, detail string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items = append(r.items, Event{Time: time.Now().UTC(), Level: level, Type: typ, Detail: detail})
	if len(r.items) > r.max {
		r.items = r.items[len(r.items)-r.max:]
	}
}

func (r *eventRing) snapshot() []Event {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.items))
	copy(out, r.items)
	return out
}
