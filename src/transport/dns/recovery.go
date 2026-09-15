package dnspath

import (
	"time"
)

// FailoverDecision is the monitoring-driven action recommendation
// (addendum §81). Monitoring triggers; runtimecontrol mutates
// (ADR-ADNS-010): the controller only recommends, the Manager/Transaction
// executes.
type FailoverDecision string

const (
	DecisionNone           FailoverDecision = "none"
	DecisionFastFailover   FailoverDecision = "fast_failover"
	DecisionDeepDiagnosis  FailoverDecision = "deep_diagnosis"
	DecisionHoldLastSafe   FailoverDecision = "hold_last_safe"
	DecisionRecoveryCanary FailoverDecision = "recovery_canary"
	DecisionCooldownWait   FailoverDecision = "cooldown_wait"
)

// FailoverController implements fast failover vs deep diagnosis (§81),
// cooldown/hysteresis (§77) and recovery-to-simpler-path scheduling.
type FailoverController struct {
	Cooldown             time.Duration
	FailedSearchCooldown time.Duration
	RecoveryHysteresis   time.Duration
	MinRecoveryProofs    int

	lastSwitch       time.Time
	lastFailedSearch time.Time
	recoveryProofs   map[string]int
	recoveryFirst    map[string]time.Time
}

func NewFailoverController(policy AdaptivePolicy) *FailoverController {
	return &FailoverController{
		Cooldown:             policy.Cooldown,
		FailedSearchCooldown: policy.FailedSearchCooldown,
		RecoveryHysteresis:   policy.RecoveryHysteresis,
		MinRecoveryProofs:    3,
		recoveryProofs:       map[string]int{},
		recoveryFirst:        map[string]time.Time{},
	}
}

// OnPrimaryFailure decides the action after a primary path failure.
// Fast failover is allowed only toward an already promoted/ready fallback
// (§81); without one the system holds last safe behavior and schedules deep
// diagnosis — never a blind resolver switch.
func (c *FailoverController) OnPrimaryFailure(m *Manager, now time.Time) FailoverDecision {
	if now.Sub(c.lastSwitch) < c.Cooldown {
		return DecisionCooldownWait
	}
	binding := m.ActiveBinding()
	if binding == nil {
		if now.Sub(c.lastFailedSearch) < c.FailedSearchCooldown {
			return DecisionCooldownWait
		}
		return DecisionDeepDiagnosis
	}
	for _, fb := range binding.Fallbacks {
		if m.pathReady(fb) {
			return DecisionFastFailover
		}
	}
	if now.Sub(c.lastFailedSearch) < c.FailedSearchCooldown {
		return DecisionHoldLastSafe
	}
	return DecisionDeepDiagnosis
}

// NoteSwitch records a performed switch for cooldown accounting.
func (c *FailoverController) NoteSwitch(now time.Time) { c.lastSwitch = now }

// NoteFailedSearch records a failed diagnosis for failed-search cooldown.
func (c *FailoverController) NoteFailedSearch(now time.Time) { c.lastFailedSearch = now }

// OnSimplerPathProven records repeated proof that a simpler path works
// again (§77). Recovery canary is recommended only after hysteresis and
// minimum stability samples; flapping is prevented by both.
func (c *FailoverController) OnSimplerPathProven(simpler DNSPathID, currentPrimary DNSPathID, now time.Time) FailoverDecision {
	if simpler.Family.Complexity() >= currentPrimary.Family.Complexity() {
		return DecisionNone
	}
	key := simpler.Hash()
	if c.recoveryProofs[key] == 0 {
		c.recoveryFirst[key] = now
	}
	c.recoveryProofs[key]++
	if c.recoveryProofs[key] < c.MinRecoveryProofs {
		return DecisionNone
	}
	if now.Sub(c.recoveryFirst[key]) < c.RecoveryHysteresis {
		return DecisionNone
	}
	return DecisionRecoveryCanary
}

// ResetRecovery clears recovery proof state after a switch or failure.
func (c *FailoverController) ResetRecovery(path DNSPathID) {
	delete(c.recoveryProofs, path.Hash())
	delete(c.recoveryFirst, path.Hash())
}
