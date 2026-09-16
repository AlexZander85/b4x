package monitor

import (
	"fmt"
	"sync"
	"time"
)

type HealthState string

const (
	HealthUnknown    HealthState = "unknown"
	HealthHealthy    HealthState = "healthy"
	HealthDegraded   HealthState = "degraded"
	HealthFailing    HealthState = "failing"
	HealthRecovering HealthState = "recovering"
	HealthRecovered  HealthState = "recovered"
)

type EndpointHealth struct {
	Scope               MonitorScopeKey
	EndpointHash        string
	Successes, Failures uint32
	LastOutcome         string
	LastObserved        time.Time
}
type CorrelationSnapshot struct {
	Scope               MonitorScopeKey
	Health              HealthState
	Successes, Failures uint32
	Endpoints           []EndpointHealth
	Forwarded           bool
	RouterOrigin        bool
	Control             bool
	AdaptiveSynthesis   AdaptiveSynthesisStatus
}
type FlowCorrelator struct {
	mu    sync.Mutex
	flows map[string]*CorrelationSnapshot
}

func NewFlowCorrelator() *FlowCorrelator {
	return &FlowCorrelator{flows: map[string]*CorrelationSnapshot{}}
}
func correlationKey(s MonitorScopeKey) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d|%s", s.ClientScope.ID, s.ServiceProfileID, s.ComponentID, s.DomainIdentityID, s.ConfigGeneration, s.NetworkContextID)
}

// EnsureScope registers an already-observed monitoring scope without
// fabricating a success/failure sample. This lets the existing status
// projection and AFS lifecycle share one scope owner while neutral evidence
// remains neutral.
func (c *FlowCorrelator) EnsureScope(scope MonitorScopeKey) bool {
	if c == nil || !scope.Valid() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := correlationKey(scope)
	if _, ok := c.flows[key]; ok {
		return true
	}
	c.flows[key] = newCorrelationSnapshot(scope)
	return true
}

func (c *FlowCorrelator) Observe(o MonitorObservation, endpoint string, success bool) {
	if c == nil || !o.Scope.Valid() {
		return
	}
	c.observeOutcome(o.Scope, endpoint, success, o.OutcomeCode, o.ObservedAt)
}

// ObserveHealth records only explicit decided monitor outcomes. Unknown health
// is intentionally ignored so neutral/incomplete evidence cannot qualify a
// persistent regression by accident.
func (c *FlowCorrelator) ObserveHealth(scope MonitorScopeKey, endpoint string, health HealthState, observedAt time.Time) {
	if c == nil || !scope.Valid() {
		return
	}
	switch health {
	case HealthFailing, HealthDegraded:
		c.observeOutcome(scope, endpoint, false, string(health), observedAt)
	case HealthHealthy, HealthRecovered:
		c.observeOutcome(scope, endpoint, true, string(health), observedAt)
	}
}

// PersistentRegressionQualified is the monitor-owned recurrence check used by
// AFS. A single failure cannot qualify: at least three decided failures are
// required and the current correlated health must remain degraded/failing.
func (c *FlowCorrelator) PersistentRegressionQualified(scope MonitorScopeKey) bool {
	snapshot, ok := c.Snapshot(scope)
	if !ok || snapshot.Failures < 3 {
		return false
	}
	return snapshot.Health == HealthFailing || snapshot.Health == HealthDegraded
}

func (c *FlowCorrelator) observeOutcome(scope MonitorScopeKey, endpoint string, success bool, outcome string, observedAt time.Time) {
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	if endpoint == "" {
		endpoint = correlationEndpoint(scope)
	}
	k := correlationKey(scope)
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.flows[k]
	if s == nil {
		s = newCorrelationSnapshot(scope)
		c.flows[k] = s
	}
	if success {
		s.Successes++
	} else {
		s.Failures++
	}
	if s.Successes == 0 && s.Failures >= 3 {
		s.Health = HealthFailing
	} else if s.Failures > 0 && s.Successes > 0 {
		s.Health = HealthDegraded
	} else if s.Successes > 0 {
		s.Health = HealthHealthy
	}
	for i := range s.Endpoints {
		if s.Endpoints[i].EndpointHash == endpoint {
			if success {
				s.Endpoints[i].Successes++
			} else {
				s.Endpoints[i].Failures++
			}
			s.Endpoints[i].LastOutcome = outcome
			s.Endpoints[i].LastObserved = observedAt
			return
		}
	}
	e := EndpointHealth{Scope: scope, EndpointHash: endpoint, LastOutcome: outcome, LastObserved: observedAt}
	if success {
		e.Successes = 1
	} else {
		e.Failures = 1
	}
	s.Endpoints = append(s.Endpoints, e)
}

func newCorrelationSnapshot(scope MonitorScopeKey) *CorrelationSnapshot {
	return &CorrelationSnapshot{
		Scope:        scope,
		Health:       HealthUnknown,
		Forwarded:    scope.ClientScope.Role == "forwarded",
		RouterOrigin: scope.ClientScope.Role == "router-origin",
		Control:      scope.TargetRole == "control",
	}
}

func correlationEndpoint(scope MonitorScopeKey) string {
	if scope.DestinationIPHash != "" {
		return scope.DestinationIPHash
	}
	if scope.ComponentID != "" {
		return scope.ComponentID
	}
	if scope.ServiceProfileID != "" {
		return scope.ServiceProfileID
	}
	return scope.TargetRole
}

func (c *FlowCorrelator) Snapshot(s MonitorScopeKey) (CorrelationSnapshot, bool) {
	if c == nil {
		return CorrelationSnapshot{}, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.flows[correlationKey(s)]
	if !ok {
		return CorrelationSnapshot{}, false
	}
	out := *v
	out.Endpoints = append([]EndpointHealth(nil), v.Endpoints...)
	out.AdaptiveSynthesis.Reasons = append([]string(nil), v.AdaptiveSynthesis.Reasons...)
	return out, true
}
