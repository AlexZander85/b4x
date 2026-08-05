package fieldtest

import (
	"errors"
	"path/filepath"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/validation"
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

// RecordGateEvaluation stores the structured hard-gate result (FB-03) on a
// running session; a non-PASS verdict is not a stop error — the verdict is
// recorded so the controller/reporting path can act on it.
func (c *Controller) RecordGateEvaluation(id string, eval validation.GateEvaluation) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.runs[id]
	if !ok {
		return errors.New("unknown run")
	}
	if s.Status != StatusRunning {
		return errors.New("run not running")
	}
	copyEval := eval
	copyEval.Violations = append([]validation.GateViolation(nil), eval.Violations...)
	copyEval.Missing = append([]validation.GateID(nil), eval.Missing...)
	copyEval.Stale = append([]validation.GateID(nil), eval.Stale...)
	copyEval.NotRun = append([]validation.GateID(nil), eval.NotRun...)
	s.GateEvaluation = &copyEval
	c.runs[id] = s
	return nil
}

// EvaluateHardGates runs the production hard-gate evaluation (FT-C: the
// controller calls the canonical evaluator — fieldtest.EvaluateHardGates —
// against observed counters, never a shadow copy) and records the structured
// result on a running session. The recorded verdict drives canary/promotion.
func (c *Controller) EvaluateHardGates(id string, scope validation.ReleaseScope, caps validation.CapabilitySet, claim validation.VerdictID, generation validation.GenerationSet, counters map[string]uint64, produced map[string]bool) (validation.GateEvaluation, error) {
	eval := EvaluateHardGates(scope, caps, claim, generation, counters, produced)
	if err := c.RecordGateEvaluation(id, eval); err != nil {
		return validation.GateEvaluation{}, err
	}
	return eval, nil
}
