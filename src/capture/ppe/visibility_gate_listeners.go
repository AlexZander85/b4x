package ppe

import (
	"strings"
	"sync"
	"time"
)

func (g *VisibilityGate) SubscribeBlocked(listener func(CaptureVisibilitySnapshot)) func() {
	if g == nil || listener == nil {
		return func() {}
	}
	g.mu.Lock()
	g.nextID++
	id := g.nextID
	g.listeners[id] = listener
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			delete(g.listeners, id)
			g.mu.Unlock()
		})
	}
}

func (g *VisibilityGate) publish(next CaptureVisibilitySnapshot) CaptureVisibilitySnapshot {
	previous := g.Snapshot()
	next.UpdatedAt = time.Now().UTC()
	next.Epoch = previous.Epoch + 1
	g.state.Store(&next)
	if next.Enforced && next.Mode != VisibilityComplete {
		g.mu.Lock()
		listeners := make([]func(CaptureVisibilitySnapshot), 0, len(g.listeners))
		for _, listener := range g.listeners {
			listeners = append(listeners, listener)
		}
		g.mu.Unlock()
		for _, listener := range listeners {
			listener(next)
		}
	}
	return next
}

func cleanVisibilityReason(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = fallback
	}
	if len(value) > 256 {
		value = value[:256]
	}
	return value
}
