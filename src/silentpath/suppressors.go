package silentpath

import "time"

// Suppression is evaluated before correlation or recovery. A single active
// suppressor always wins over positive evidence.
type Suppression struct {
	Reason    ReasonCode
	ExpiresAt time.Time
}

func (s Suppression) Active(now time.Time) bool {
	return s.ExpiresAt.IsZero() || now.Before(s.ExpiresAt)
}
func HasActiveSuppressor(values []Suppression, now time.Time) (ReasonCode, bool) {
	for _, v := range values {
		if v.Active(now) {
			return v.Reason, true
		}
	}
	return "", false
}
func FreshSuccessSuppressor(now time.Time, window time.Duration) Suppression {
	return Suppression{Reason: ReasonFreshScopeSuccess, ExpiresAt: now.Add(window)}
}
func CompatibleSuccessSuppressor(now time.Time, window time.Duration) Suppression {
	return Suppression{Reason: ReasonCompatiblePathSuccess, ExpiresAt: now.Add(window)}
}
