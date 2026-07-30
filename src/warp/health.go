package warp

import "time"

type HealthState string

const (
	HealthUnknown    HealthState = "unknown"
	HealthProtocolUp HealthState = "protocol-up"
	HealthDataAlive  HealthState = "data-alive"
	HealthDegraded   HealthState = "degraded"
	HealthFailed     HealthState = "failed"
	HealthCooldown   HealthState = "cooldown"
)

type HealthTracker struct {
	State                    HealthState
	FailureStreak            int
	LastSuccess, LastFailure time.Time
	CooldownUntil            time.Time
	VariantExpiry            time.Time
}

func (h *HealthTracker) Observe(protocol, data bool, now time.Time) {
	if protocol && data {
		h.State = HealthDataAlive
		h.FailureStreak = 0
		h.LastSuccess = now
		return
	}
	if protocol {
		h.State = HealthProtocolUp
	} else {
		h.State = HealthDegraded
	}
	h.FailureStreak++
	h.LastFailure = now
	if h.FailureStreak >= 3 {
		h.State = HealthCooldown
		h.CooldownUntil = now.Add(time.Minute)
	}
}
func (h HealthTracker) CanRetry(now time.Time) bool {
	return h.State != HealthCooldown || !now.Before(h.CooldownUntil)
}

type FailurePolicy string

const (
	FailOpenScoped   FailurePolicy = "fail-open-scoped"
	FailClosedScoped FailurePolicy = "fail-closed-scoped"
)

type HealthEvent struct {
	State  HealthState
	Reason string
	At     time.Time
	Policy FailurePolicy
}
