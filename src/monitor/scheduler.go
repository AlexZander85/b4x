package monitor

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"
)

type DiagnosticKind string

const (
	DiagnosticQuick DiagnosticKind = "quick"
	DiagnosticDeep  DiagnosticKind = "deep"
)

type DiagnosticRequest struct {
	RequestID      string
	IdempotencyKey string
	Scope          MonitorScopeKey
	Kind           DiagnosticKind
	Reason         string
	RequestedAt    time.Time
	Deadline       time.Time
}

type DiagnosticLease struct {
	LeaseID    string
	Request    DiagnosticRequest
	AcquiredAt time.Time
	ExpiresAt  time.Time
}

type SchedulerConfig struct {
	QuickCapacity, DeepCapacity int
	LeaseTTL, Cooldown, Backoff time.Duration
}

func DefaultSchedulerConfig() SchedulerConfig {
	return SchedulerConfig{QuickCapacity: 32, DeepCapacity: 8, LeaseTTL: 30 * time.Second, Cooldown: 5 * time.Second, Backoff: 10 * time.Second}
}

type schedulerEntry struct {
	req      DiagnosticRequest
	nextAt   time.Time
	attempts int
	running  *DiagnosticLease
}

// DiagnosticScheduler owns bounded diagnostic requests only. It has no
// profile, action, transport, or configuration mutation fields by design.
type DiagnosticScheduler struct {
	mu          sync.Mutex
	cfg         SchedulerConfig
	quick, deep []*schedulerEntry
	byKey       map[string]*schedulerEntry
	seq         uint64
}

func NewDiagnosticScheduler(cfg SchedulerConfig) *DiagnosticScheduler {
	d := DefaultSchedulerConfig()
	if cfg.QuickCapacity <= 0 {
		cfg.QuickCapacity = d.QuickCapacity
	}
	if cfg.DeepCapacity <= 0 {
		cfg.DeepCapacity = d.DeepCapacity
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = d.LeaseTTL
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = d.Cooldown
	}
	if cfg.Backoff <= 0 {
		cfg.Backoff = d.Backoff
	}
	return &DiagnosticScheduler{cfg: cfg, byKey: map[string]*schedulerEntry{}}
}

var ErrSchedulerOverloaded = errors.New("diagnostic scheduler overloaded")
var ErrNoDiagnostic = errors.New("no diagnostic available")

func (s *DiagnosticScheduler) Enqueue(req DiagnosticRequest, now time.Time) error {
	if s == nil || !req.Scope.Valid() || req.IdempotencyKey == "" || (req.Kind != DiagnosticQuick && req.Kind != DiagnosticDeep) {
		return errors.New("invalid diagnostic request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.byKey[req.IdempotencyKey]; old != nil {
		if old.running == nil {
			old.req.Reason = req.Reason
			old.req.Deadline = req.Deadline
		}
		return nil
	}
	entry := &schedulerEntry{req: req, nextAt: now}
	s.byKey[req.IdempotencyKey] = entry
	if req.Kind == DiagnosticQuick {
		if len(s.quick) >= s.cfg.QuickCapacity {
			delete(s.byKey, req.IdempotencyKey)
			return ErrSchedulerOverloaded
		}
		s.quick = append(s.quick, entry)
	} else {
		if len(s.deep) >= s.cfg.DeepCapacity {
			delete(s.byKey, req.IdempotencyKey)
			return ErrSchedulerOverloaded
		}
		s.deep = append(s.deep, entry)
	}
	return nil
}

func (s *DiagnosticScheduler) Acquire(ctx context.Context, kind DiagnosticKind, now time.Time) (DiagnosticLease, error) {
	if s == nil {
		return DiagnosticLease{}, ErrNoDiagnostic
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return DiagnosticLease{}, err
	}
	var q *[]*schedulerEntry
	if kind == DiagnosticQuick {
		q = &s.quick
	} else if kind == DiagnosticDeep {
		q = &s.deep
	} else {
		return DiagnosticLease{}, ErrNoDiagnostic
	}
	for i, e := range *q {
		if e.running != nil || now.Before(e.nextAt) || (!e.req.Deadline.IsZero() && !now.Before(e.req.Deadline)) {
			continue
		}
		s.seq++
		lease := DiagnosticLease{LeaseID: e.req.IdempotencyKey + "/" + strconv.FormatUint(s.seq, 10), Request: e.req, AcquiredAt: now, ExpiresAt: now.Add(s.cfg.LeaseTTL)}
		e.running = &lease
		(*q)[i] = e
		return lease, nil
	}
	return DiagnosticLease{}, ErrNoDiagnostic
}

func (s *DiagnosticScheduler) Complete(leaseID string, success bool, now time.Time) bool {
	if s == nil || leaseID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, q := range []*[]*schedulerEntry{&s.quick, &s.deep} {
		for i, e := range *q {
			if e.running == nil || e.running.LeaseID != leaseID {
				continue
			}
			if success {
				delete(s.byKey, e.req.IdempotencyKey)
				*q = append((*q)[:i], (*q)[i+1:]...)
				return true
			}
			e.running = nil
			e.attempts++
			e.nextAt = now.Add(s.cfg.Backoff * time.Duration(e.attempts))
			return true
		}
	}
	return false
}

func (s *DiagnosticScheduler) Cancel(idempotencyKey string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.byKey[idempotencyKey]
	if e == nil || e.running != nil {
		return false
	}
	delete(s.byKey, idempotencyKey)
	for _, q := range []*[]*schedulerEntry{&s.quick, &s.deep} {
		for i, v := range *q {
			if v == e {
				*q = append((*q)[:i], (*q)[i+1:]...)
				return true
			}
		}
	}
	return false
}

func (s *DiagnosticScheduler) Reap(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, q := range []*[]*schedulerEntry{&s.quick, &s.deep} {
		for _, e := range *q {
			if e.running != nil && !now.Before(e.running.ExpiresAt) {
				e.running = nil
				e.attempts++
				e.nextAt = now.Add(s.cfg.Backoff * time.Duration(e.attempts))
				n++
			}
		}
	}
	return n
}

func (s *DiagnosticScheduler) Depth(kind DiagnosticKind) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind == DiagnosticQuick {
		return len(s.quick)
	}
	return len(s.deep)
}
