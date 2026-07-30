package nfq

import (
	"fmt"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

const (
	PassiveRSTEnvironmentProduction = "production"
	PassiveRSTEnvironmentCandidate  = "candidate"
	PassiveRSTEnvironmentDiscovery  = "discovery"
)

type PassiveRSTHealthSample struct {
	SetID             string    `json:"set_id"`
	DeviceScope       string    `json:"device_scope"`
	ConfigGeneration  uint64    `json:"config_generation"`
	Environment       string    `json:"environment"`
	ReconnectFailures int       `json:"reconnect_failures"`
	NoProgress        int       `json:"no_progress"`
	ControlFailures   int       `json:"control_failures"`
	QueueDrops        int       `json:"queue_drops"`
	RouterPressure    int       `json:"router_pressure"`
	ObservedAt        time.Time `json:"observed_at"`
}

type PassiveRSTRollbackState struct {
	SetID            string    `json:"set_id"`
	DeviceScope      string    `json:"device_scope"`
	ConfigGeneration uint64    `json:"config_generation"`
	Environment      string    `json:"environment"`
	FromMode         string    `json:"from_mode"`
	EffectiveMode    string    `json:"effective_mode"`
	Reason           string    `json:"reason"`
	TriggeredAt      time.Time `json:"triggered_at"`
	WindowStartedAt  time.Time `json:"window_started_at"`
}

type passiveRSTHealthKey struct {
	SetID            string
	DeviceScope      string
	ConfigGeneration uint64
	Environment      string
}

type passiveRSTHealthWindow struct {
	startedAt        time.Time
	lastObservedAt   time.Time
	reconnectFailure int
	noProgress       int
	controlFailure   int
	queueDrops       int
	routerPressure   int
}

func normalizePassiveRSTHealthSample(in PassiveRSTHealthSample) (PassiveRSTHealthSample, passiveRSTHealthKey, bool) {
	in.SetID = strings.ToLower(strings.TrimSpace(in.SetID))
	in.DeviceScope = strings.ToLower(strings.TrimSpace(in.DeviceScope))
	in.Environment = strings.ToLower(strings.TrimSpace(in.Environment))
	if in.Environment == "" {
		in.Environment = PassiveRSTEnvironmentProduction
	}
	if in.SetID == "" || in.DeviceScope == "" || in.ConfigGeneration == 0 {
		return in, passiveRSTHealthKey{}, false
	}
	switch in.Environment {
	case PassiveRSTEnvironmentProduction, PassiveRSTEnvironmentCandidate, PassiveRSTEnvironmentDiscovery:
	default:
		return in, passiveRSTHealthKey{}, false
	}
	return in, passiveRSTHealthKey{SetID: in.SetID, DeviceScope: in.DeviceScope, ConfigGeneration: in.ConfigGeneration, Environment: in.Environment}, true
}

// RecordHealth performs a scope-local runtime rollback. It does not mutate the
// durable config or last-good metadata: the exact generation is forced to
// observe in runtime state and the active suppression window is invalidated.
func (s *PassiveRSTStore) RecordHealth(cfg config.PassiveRSTRuntimeConfig, sample PassiveRSTHealthSample) (PassiveRSTRollbackState, bool) {
	if s == nil {
		return PassiveRSTRollbackState{}, false
	}
	cfg = normalizedPassiveRSTConfig(cfg)
	if cfg.Mode != config.PassiveRSTConservative && cfg.Mode != config.PassiveRSTAggressive {
		return PassiveRSTRollbackState{}, false
	}
	sample, key, ok := normalizePassiveRSTHealthSample(sample)
	if !ok {
		return PassiveRSTRollbackState{}, false
	}
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if key.Environment != s.environment {
		return PassiveRSTRollbackState{}, false
	}
	if rollback, exists := s.rollbacks[key]; exists {
		return rollback, false
	}
	window := s.health[key]
	windowTTL := time.Duration(cfg.RollbackWindowSeconds) * time.Second
	if window == nil || !window.startedAt.Add(windowTTL).After(now) {
		window = &passiveRSTHealthWindow{startedAt: now}
		s.health[key] = window
	}
	window.lastObservedAt = now
	window.reconnectFailure += nonNegative(sample.ReconnectFailures)
	window.noProgress += nonNegative(sample.NoProgress)
	window.controlFailure += nonNegative(sample.ControlFailures)
	window.queueDrops += nonNegative(sample.QueueDrops)
	window.routerPressure += nonNegative(sample.RouterPressure)

	reason := passiveRSTRollbackReason(cfg, window)
	if reason == "" {
		return PassiveRSTRollbackState{}, false
	}
	state := PassiveRSTRollbackState{
		SetID: key.SetID, DeviceScope: key.DeviceScope, ConfigGeneration: key.ConfigGeneration, Environment: key.Environment,
		FromMode: cfg.Mode, EffectiveMode: config.PassiveRSTObserve, Reason: reason, TriggeredAt: now, WindowStartedAt: window.startedAt,
	}
	// This assignment is the transaction commit. Every subsequent enforcement
	// lookup for the exact scope/generation sees observe before another packet
	// can consume suppression budget.
	s.rollbacks[key] = state
	for _, flow := range s.flows {
		if flow.generation == key.ConfigGeneration && strings.EqualFold(flow.setID, key.SetID) && strings.EqualFold(flow.deviceScope, key.DeviceScope) {
			flow.suppressionBudget = 0
			flow.suppressionDeadline = now
		}
	}
	s.appendRollbackLocked(state)
	observability.Default().Trace.Record(observability.TraceEvent{Timestamp: now, Kind: "passive_rst_rollback", Fields: map[string]string{
		"set_id": observability.RedactIdentifier(key.SetID), "device_scope": observability.RedactIdentifier(key.DeviceScope),
		"config_generation": fmt.Sprintf("%d", key.ConfigGeneration), "environment": key.Environment,
		"from": cfg.Mode, "to": config.PassiveRSTObserve, "reason": reason,
	}})
	return state, true
}

func passiveRSTRollbackReason(cfg config.PassiveRSTRuntimeConfig, window *passiveRSTHealthWindow) string {
	if window == nil {
		return ""
	}
	switch {
	case window.controlFailure >= cfg.ControlFailureThreshold:
		return "control service regression"
	case window.queueDrops >= cfg.QueueDropThreshold:
		return "NFQUEUE drop regression"
	case window.routerPressure >= cfg.RouterPressureThreshold:
		return "router resource pressure"
	case window.reconnectFailure >= cfg.ReconnectFailureThreshold:
		return "reconnect failure regression"
	case window.noProgress >= cfg.NoProgressThreshold:
		return "no progress after suppression"
	default:
		return ""
	}
}

func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func (s *PassiveRSTStore) rollbackForLocked(setID, device string, generation uint64, environment string) (PassiveRSTRollbackState, bool) {
	key := passiveRSTHealthKey{SetID: strings.ToLower(strings.TrimSpace(setID)), DeviceScope: strings.ToLower(strings.TrimSpace(device)), ConfigGeneration: generation, Environment: environment}
	state, ok := s.rollbacks[key]
	return state, ok
}

func (s *PassiveRSTStore) RecentRollbacks(limit int) []PassiveRSTRollbackState {
	if s == nil || limit <= 0 {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit > len(s.rollbackRecent) {
		limit = len(s.rollbackRecent)
	}
	out := make([]PassiveRSTRollbackState, limit)
	copy(out, s.rollbackRecent[len(s.rollbackRecent)-limit:])
	return out
}

func (s *PassiveRSTStore) appendRollbackLocked(state PassiveRSTRollbackState) {
	limit := s.cfg.RecentDecisionLimit
	if limit <= 0 {
		return
	}
	if len(s.rollbackRecent) >= limit {
		copy(s.rollbackRecent, s.rollbackRecent[len(s.rollbackRecent)-limit+1:])
		s.rollbackRecent = s.rollbackRecent[:limit-1]
	}
	s.rollbackRecent = append(s.rollbackRecent, state)
}

func (s *PassiveRSTStore) SetEnvironment(environment string) {
	if s == nil {
		return
	}
	environment = strings.ToLower(strings.TrimSpace(environment))
	switch environment {
	case PassiveRSTEnvironmentProduction, PassiveRSTEnvironmentCandidate, PassiveRSTEnvironmentDiscovery:
	default:
		environment = PassiveRSTEnvironmentProduction
	}
	s.mu.Lock()
	s.environment = environment
	s.mu.Unlock()
}
