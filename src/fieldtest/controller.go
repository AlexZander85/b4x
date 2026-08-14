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
	streams             map[string]*EventStream
	markers             map[string][]Marker
	idem                map[string]string
	clocks              []ClockSample
}

func NewController(base, results string) (*Controller, error) {
	if base == "" || results == "" {
		return nil, errors.New("controller requires base URL and results directory")
	}
	return &Controller{
		BaseURL:    base,
		ResultsDir: filepath.Clean(results),
		runs:       map[string]TestSession{},
		streams:    map[string]*EventStream{},
		markers:    map[string][]Marker{},
		idem:       map[string]string{},
	}, nil
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
	if c.streams == nil {
		c.streams = map[string]*EventStream{}
	}
	if c.markers == nil {
		c.markers = map[string][]Marker{}
	}
	c.streams[id] = &EventStream{}
	_ = c.streams[id].Append(Event{
		Schema: 1, SessionID: id, Timestamp: time.Now().UTC(), Event: "session_start",
		ConfigGen: gen, ClientPseudonym: Pseudonym(req.ClientID),
	})
	return s, nil
}

// Create is the production TestSession API entry: optional Idempotency-Key
// replays the original session instead of creating a duplicate.
func (c *Controller) Create(id string, req SessionRequest, gen uint64, idemKey string) (TestSession, bool, error) {
	c.mu.Lock()
	if c.idem == nil {
		c.idem = map[string]string{}
	}
	if idemKey != "" {
		if existing, ok := c.idem[idemKey]; ok {
			s := c.runs[existing]
			c.mu.Unlock()
			return s, true, nil
		}
	}
	c.mu.Unlock()
	s, err := c.Start(id, req, gen)
	if err != nil {
		return TestSession{}, false, err
	}
	if idemKey != "" {
		c.mu.Lock()
		c.idem[idemKey] = s.SessionID
		c.mu.Unlock()
	}
	return s, false, nil
}

func (c *Controller) AddMarker(id string, m Marker) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.runs[id]
	if !ok {
		return errors.New("unknown run")
	}
	if s.Status != StatusRunning {
		return errors.New("run not running")
	}
	if m.At.IsZero() {
		m.At = time.Now().UTC()
	}
	c.markers[id] = append(c.markers[id], m)
	if stream := c.streams[id]; stream != nil {
		_ = stream.Append(Event{
			Schema: 1, SessionID: id, Timestamp: m.At, Event: "marker",
			Fields: map[string]string{"marker": m.Marker, "source": m.Source},
		})
	}
	return nil
}

func (c *Controller) AppendEvent(id string, e Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.runs[id]; !ok {
		return errors.New("unknown run")
	}
	stream := c.streams[id]
	if stream == nil {
		stream = &EventStream{}
		c.streams[id] = stream
	}
	if e.SessionID == "" {
		e.SessionID = id
	}
	if e.Schema == 0 {
		e.Schema = 1
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	return stream.Append(e)
}

func (c *Controller) Events(id string) ([]Event, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.runs[id]; !ok {
		return nil, errors.New("unknown run")
	}
	if c.streams[id] == nil {
		return nil, nil
	}
	return c.streams[id].Snapshot(), nil
}

func (c *Controller) Report(id string) (SessionReport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.runs[id]
	if !ok {
		return SessionReport{}, errors.New("unknown run")
	}
	var events []Event
	if stream := c.streams[id]; stream != nil {
		events = stream.Snapshot()
	}
	return SessionReport{
		Session:     s,
		Events:      events,
		Markers:     append([]Marker(nil), c.markers[id]...),
		Status:      string(s.Status),
		Redacted:    true,
		GeneratedAt: time.Now().UTC(),
	}, nil
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
