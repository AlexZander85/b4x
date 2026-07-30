package monitor

import (
	"sort"
	"sync"
	"time"
)

type VisibilityState string

const (
	VisibilityComplete VisibilityState = "complete"
	VisibilityPartial  VisibilityState = "partial"
	VisibilityStale    VisibilityState = "stale"
	VisibilityInvalid  VisibilityState = "invalid"
)

type SourceHeartbeat struct {
	Source     ObservationSource
	SourceID   string
	ObservedAt time.Time
	ExpiresAt  time.Time
	Sequence   uint64
	Visible    bool
	DropCount  uint64
}

func (h SourceHeartbeat) Fresh(now time.Time) bool {
	if h.Source == "" || h.ObservedAt.IsZero() || !h.Visible {
		return false
	}
	return h.ExpiresAt.IsZero() || now.Before(h.ExpiresAt)
}

type VisibilitySnapshot struct {
	SnapshotID      string
	ObservedAt      time.Time
	ExpiresAt       time.Time
	State           VisibilityState
	CaptureReady    bool
	PPEReady        bool
	RequiredSources []ObservationSource
	FreshSources    []ObservationSource
	StaleSources    []ObservationSource
}

func (s VisibilitySnapshot) Fresh(now time.Time) bool {
	return s.State == VisibilityComplete && s.CaptureReady && s.PPEReady && (s.ExpiresAt.IsZero() || now.Before(s.ExpiresAt))
}

type SourceHealthStore struct {
	mu         sync.RWMutex
	heartbeats map[ObservationSource]SourceHeartbeat
}

func NewSourceHealthStore() *SourceHealthStore {
	return &SourceHealthStore{heartbeats: map[ObservationSource]SourceHeartbeat{}}
}

func (s *SourceHealthStore) Publish(h SourceHeartbeat) {
	if s == nil || h.Source == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.heartbeats[h.Source]
	if ok && h.Sequence < old.Sequence {
		return
	}
	s.heartbeats[h.Source] = h
}

func (s *SourceHealthStore) Snapshot(now time.Time, required []ObservationSource, id string) VisibilitySnapshot {
	if s == nil {
		return VisibilitySnapshot{SnapshotID: id, State: VisibilityInvalid}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	v := VisibilitySnapshot{SnapshotID: id, ObservedAt: now, ExpiresAt: now.Add(time.Minute), RequiredSources: append([]ObservationSource(nil), required...), CaptureReady: true, PPEReady: true}
	for _, source := range required {
		h, ok := s.heartbeats[source]
		if !ok || !h.Fresh(now) {
			v.StaleSources = append(v.StaleSources, source)
		} else {
			v.FreshSources = append(v.FreshSources, source)
		}
	}
	if len(v.StaleSources) > 0 {
		v.State = VisibilityPartial
	} else {
		v.State = VisibilityComplete
	}
	if len(required) == 0 {
		v.State = VisibilityInvalid
	}
	sort.Slice(v.FreshSources, func(i, j int) bool { return v.FreshSources[i] < v.FreshSources[j] })
	sort.Slice(v.StaleSources, func(i, j int) bool { return v.StaleSources[i] < v.StaleSources[j] })
	return v
}

type SuppressorReason string

const (
	SuppressStaleSource       SuppressorReason = "stale-source"
	SuppressInvalidVisibility SuppressorReason = "invalid-visibility"
	SuppressInfrastructure    SuppressorReason = "infrastructure-transition"
	SuppressGlobalOutage      SuppressorReason = "global-outage"
	SuppressConfigTransition  SuppressorReason = "config-transition"
)

type Suppressor struct {
	Reason      SuppressorReason
	Scope       MonitorScopeKey
	StartedAt   time.Time
	ExpiresAt   time.Time
	Explanation string
}

func (s Suppressor) Active(now time.Time) bool {
	return s.Reason != "" && (s.ExpiresAt.IsZero() || now.Before(s.ExpiresAt))
}

type SuppressionDecision struct {
	Suppressed      bool
	Reasons         []Suppressor
	CanAutoDiagnose bool
}

// SuppressorEngine is a pure gate for diagnostic scheduling. It never creates
// a BlockingProfile or authorizes an action.
type SuppressorEngine struct {
	mu         sync.Mutex
	active     map[string]Suppressor
	defaultTTL time.Duration
}

func NewSuppressorEngine(defaultTTL time.Duration) *SuppressorEngine {
	if defaultTTL <= 0 {
		defaultTTL = 2 * time.Minute
	}
	return &SuppressorEngine{active: map[string]Suppressor{}, defaultTTL: defaultTTL}
}

func suppressorKey(scope MonitorScopeKey, reason SuppressorReason) string {
	return correlationKey(scope) + "|" + string(reason)
}

func (e *SuppressorEngine) Add(scope MonitorScopeKey, reason SuppressorReason, now time.Time, ttl time.Duration, explanation string) {
	if e == nil || reason == "" {
		return
	}
	if ttl <= 0 {
		ttl = e.defaultTTL
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.active[suppressorKey(scope, reason)] = Suppressor{Reason: reason, Scope: scope, StartedAt: now, ExpiresAt: now.Add(ttl), Explanation: explanation}
}

func (e *SuppressorEngine) Evaluate(scope MonitorScopeKey, now time.Time, visibility VisibilitySnapshot, infrastructureHealthy, configStable, globalOutage bool) SuppressionDecision {
	if e == nil {
		return SuppressionDecision{CanAutoDiagnose: visibility.Fresh(now) && infrastructureHealthy && configStable && !globalOutage}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, s := range e.active {
		if !s.Active(now) {
			delete(e.active, k)
		}
	}
	add := func(reason SuppressorReason, explanation string) {
		e.active[suppressorKey(scope, reason)] = Suppressor{Reason: reason, Scope: scope, StartedAt: now, ExpiresAt: now.Add(e.defaultTTL), Explanation: explanation}
	}
	if !visibility.Fresh(now) {
		if visibility.State == VisibilityInvalid {
			add(SuppressInvalidVisibility, "capture/PPE visibility is invalid")
		} else {
			add(SuppressStaleSource, "one or more required observation sources are stale")
		}
	}
	if !infrastructureHealthy {
		add(SuppressInfrastructure, "infrastructure integrity is unhealthy")
	}
	if !configStable {
		add(SuppressConfigTransition, "configuration or WAN transition is in progress")
	}
	if globalOutage {
		add(SuppressGlobalOutage, "global outage suppresses per-subject diagnosis")
	}
	var reasons []Suppressor
	prefix := correlationKey(scope) + "|"
	for k, s := range e.active {
		if len(k) >= len(prefix) && k[:len(prefix)] == prefix && s.Active(now) {
			reasons = append(reasons, s)
		}
	}
	sort.Slice(reasons, func(i, j int) bool { return reasons[i].Reason < reasons[j].Reason })
	return SuppressionDecision{Suppressed: len(reasons) > 0, Reasons: reasons, CanAutoDiagnose: len(reasons) == 0}
}
