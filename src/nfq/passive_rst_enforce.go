package nfq

import (
	"strings"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
)

type PassiveRSTEnforcementResult struct {
	FlowKey              classifier.FlowKey `json:"flow_key"`
	ConfigGeneration     uint64             `json:"config_generation"`
	RequestedMode        string             `json:"requested_mode"`
	EffectiveMode        string             `json:"effective_mode"`
	Decision             PassiveRSTDecision `json:"decision"`
	Reason               string             `json:"reason"`
	StrongSignals        int                `json:"strong_signals"`
	CorroboratingSignals int                `json:"corroborating_signals"`
	DiagnosticSignals    int                `json:"diagnostic_signals"`
	BudgetRemaining      int                `json:"budget_remaining"`
	SuppressionExpiresAt time.Time          `json:"suppression_expires_at,omitempty"`
}

func (r PassiveRSTEnforcementResult) Suppress() bool {
	return r.Decision == PassiveRSTDecisionSuppress
}

func (s *PassiveRSTStore) Enforce(cfg config.PassiveRSTRuntimeConfig, evidence PassiveRSTEvidence) PassiveRSTEnforcementResult {
	cfg = normalizedPassiveRSTConfig(cfg)
	result := PassiveRSTEnforcementResult{
		FlowKey: evidence.Flow.FlowKey.Normalize(), ConfigGeneration: evidence.Flow.ConfigGeneration,
		RequestedMode: cfg.Mode, EffectiveMode: config.PassiveRSTObserve,
		Decision: PassiveRSTDecisionObserve, Reason: "passive RST observe-only mode",
		BudgetRemaining: evidence.Flow.SuppressionBudget,
	}
	for _, signal := range evidence.Signals {
		switch signal.Strength {
		case PassiveRSTStrengthStrong:
			result.StrongSignals++
		case PassiveRSTStrengthCorroborating:
			result.CorroboratingSignals++
		default:
			result.DiagnosticSignals++
		}
	}
	if cfg.Mode == config.PassiveRSTOff {
		result.EffectiveMode = config.PassiveRSTOff
		result.Decision = PassiveRSTDecisionPass
		result.Reason = "passive RST protection disabled"
		return result
	}
	if cfg.Mode == config.PassiveRSTObserve || s == nil {
		return result
	}

	// Budget and expiry use the store clock, never a packet-provided timestamp.
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.flows[result.FlowKey]
	if state == nil || state.generation != result.ConfigGeneration {
		return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionFailOpen, "exact flow or immutable generation unavailable")
	}
	result.BudgetRemaining = state.suppressionBudget
	result.SuppressionExpiresAt = state.suppressionDeadline
	if !passiveRSTScopeMatches(cfg.SetScopes, state.setID) || !passiveRSTScopeMatches(cfg.DeviceScopes, state.deviceScope) {
		return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionFailOpen, "set/device scope is not explicitly authorized")
	}
	if rollback, ok := s.rollbackForLocked(state.setID, state.deviceScope, state.generation, s.environment); ok {
		result.EffectiveMode = config.PassiveRSTObserve
		return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionObserve, "scope rolled back to observe: "+rollback.Reason)
	}
	if !state.visibility || !evidence.Flow.VisibilityComplete {
		return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionFailOpen, "incoming visibility is incomplete")
	}
	if !state.synSeen || !state.synAckSeen {
		return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionPass, "legitimate or unknown pre-established RST")
	}
	if state.serverPayload > 0 || evidence.Flow.ServerPayloadProgress {
		return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionPass, "server payload progress confirms legitimate peer path")
	}

	impossibleWindow := (evidence.Sequence.Reliable && !evidence.Sequence.InWindow) ||
		(evidence.Acknowledgment.Reliable && !evidence.Acknowledgment.InWindow)
	qualified := impossibleWindow || (result.StrongSignals > 0 && result.CorroboratingSignals > 0)
	result.EffectiveMode = config.PassiveRSTConservative
	if cfg.Mode == config.PassiveRSTAggressive {
		if cfg.AggressiveConfirmationToken != config.PassiveRSTAggressiveConfirmation {
			return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionFailOpen, "aggressive mode lacks explicit confirmation token")
		}
		if evidence.Baseline.Quality == PassiveRSTBaselineRouteChangeSuspected {
			return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionFailOpen, "route change suspected")
		}
		result.EffectiveMode = config.PassiveRSTAggressive
		qualified = result.StrongSignals > 0
	}
	if !qualified {
		return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionObserve, "signal matrix does not authorize suppression")
	}

	if state.suppressionDeadline.IsZero() {
		state.suppressionDeadline = now.Add(time.Duration(cfg.SuppressionWindowSeconds) * time.Second)
	} else if !state.suppressionDeadline.After(now) {
		result.SuppressionExpiresAt = state.suppressionDeadline
		s.stats.BudgetExhausted++
		return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionFailOpen, "non-sliding suppression window expired")
	}
	result.SuppressionExpiresAt = state.suppressionDeadline
	if state.suppressionBudget <= 0 {
		s.stats.BudgetExhausted++
		return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionFailOpen, "per-flow suppression budget exhausted")
	}
	if s.globalWindowStart.IsZero() || !s.globalWindowStart.Add(time.Minute).After(now) {
		s.globalWindowStart = now
		s.globalSuppressed = 0
	}
	if s.globalSuppressed >= cfg.GlobalSuppressionsPerMinute {
		s.stats.BudgetExhausted++
		return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionFailOpen, "global suppression rate budget exhausted")
	}
	state.suppressionBudget--
	s.globalSuppressed++
	result.BudgetRemaining = state.suppressionBudget
	return s.finishEnforcementLocked(evidence, result, PassiveRSTDecisionSuppress, "bounded exact-flow passive RST suppression authorized")
}

func (s *PassiveRSTStore) finishEnforcementLocked(evidence PassiveRSTEvidence, result PassiveRSTEnforcementResult, decision PassiveRSTDecision, reason string) PassiveRSTEnforcementResult {
	result.Decision = decision
	result.Reason = reason
	switch decision {
	case PassiveRSTDecisionSuppress:
		s.stats.Suppressed++
	case PassiveRSTDecisionPass:
		s.stats.Passed++
	case PassiveRSTDecisionFailOpen:
		s.stats.FailOpen++
	}
	for i := len(s.recent) - 1; i >= 0; i-- {
		if s.recent[i].Flow.FlowKey.Normalize() == result.FlowKey && s.recent[i].ObservedAt.Equal(evidence.ObservedAt) {
			s.recent[i].Decision = decision
			s.recent[i].Reason = reason
			break
		}
	}
	return result
}

func passiveRSTScopeMatches(scopes []string, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(scopes) == 0 {
		return false
	}
	for _, scope := range scopes {
		if strings.ToLower(strings.TrimSpace(scope)) == value {
			return true
		}
	}
	return false
}

func (s *PassiveRSTStore) DeleteIncoming(clientIP, serverIP string, clientPort, serverPort uint16, family uint8) int {
	if s == nil {
		return 0
	}
	key := passiveRSTEndpointKey{Family: family, ClientIP: clientIP, ServerIP: serverIP, ClientPort: clientPort, ServerPort: serverPort}
	s.mu.Lock()
	defer s.mu.Unlock()
	flow, ok := s.endpoints[key]
	if !ok {
		return 0
	}
	s.deleteFlowLocked(flow)
	s.stats.FlowInvalidated++
	return 1
}
