// Package clock provides the small time interface shared by bounded runtime
// state and deterministic tests. Production code uses Real; tests use Fixed.
package clock

import (
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

type FixedClock struct {
	mu  sync.RWMutex
	now time.Time
}

func NewFixed(now time.Time) *FixedClock {
	return &FixedClock{now: now}
}

func (c *FixedClock) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}

func (c *FixedClock) Set(now time.Time) {
	c.mu.Lock()
	c.now = now
	c.mu.Unlock()
}

func (c *FixedClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}
