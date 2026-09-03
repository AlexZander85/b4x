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
func (c *FlowCorrelator) Observe(o MonitorObservation, endpoint string, success bool) {
	if c == nil || !o.Scope.Valid() {
		return
	}
	k := correlationKey(o.Scope)
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.flows[k]
	if s == nil {
		s = &CorrelationSnapshot{Scope: o.Scope, Health: HealthUnknown}
		c.flows[k] = s
	}
	if o.Scope.ClientScope.Role == "router-origin" {
		s.RouterOrigin = true
	} else {
		s.Forwarded = true
	}
	s.Control = o.Scope.TargetRole == "control"
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
			s.Endpoints[i].LastOutcome = o.OutcomeCode
			s.Endpoints[i].LastObserved = o.ObservedAt
			return
		}
	}
	e := EndpointHealth{Scope: o.Scope, EndpointHash: endpoint, LastOutcome: o.OutcomeCode, LastObserved: o.ObservedAt}
	if success {
		e.Successes = 1
	} else {
		e.Failures = 1
	}
	s.Endpoints = append(s.Endpoints, e)
}
func (c *FlowCorrelator) Snapshot(s MonitorScopeKey) (CorrelationSnapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.flows[correlationKey(s)]
	if !ok {
		return CorrelationSnapshot{}, false
	}
	v.Endpoints = append([]EndpointHealth(nil), v.Endpoints...)
	return *v, true
}
