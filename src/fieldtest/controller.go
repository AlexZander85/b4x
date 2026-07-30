package fieldtest

import (
	"errors"
	"path/filepath"
	"sync"
	"time"
)

type ClockSample struct {
	RouterUnixNS, LocalUnixNS, OffsetNS int64
	At                                  time.Time
}
type Controller struct {
	BaseURL, ResultsDir string
	mu                  sync.Mutex
	runs                map[string]TestSession
	clocks              []ClockSample
}

func NewController(base, results string) (*Controller, error) {
	if base == "" || results == "" {
		return nil, errors.New("controller requires base URL and results directory")
	}
	return &Controller{BaseURL: base, ResultsDir: filepath.Clean(results), runs: map[string]TestSession{}}, nil
}
func (c *Controller) AddClockSample(s ClockSample) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clocks = append(c.clocks, s)
}
func (c *Controller) Start(id string, req SessionRequest, gen uint64) (TestSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.runs[id]; ok {
		return TestSession{}, errors.New("run already exists")
	}
	s, e := NewSession(id, req, gen, time.Now().UTC())
	if e != nil {
		return TestSession{}, e
	}
	s.Status = StatusRunning
	c.runs[id] = s
	return s, nil
}
func (c *Controller) Stop(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.runs[id]
	if !ok {
		return errors.New("unknown run")
	}
	if s.Status != StatusRunning {
		return errors.New("run not running")
	}
	s.Status = StatusStopped
	c.runs[id] = s
	return nil
}
func (c *Controller) Get(id string) (TestSession, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.runs[id]
	return s, ok
}
