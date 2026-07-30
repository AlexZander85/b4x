package warp

type EnrollmentPolicy struct {
	DirectOnly             bool
	MaxAttempts            int
	AllowedStrategies      []string
	DataPlaneAuthorization bool
}

func DefaultEnrollmentPolicy() EnrollmentPolicy {
	return EnrollmentPolicy{DirectOnly: true, MaxAttempts: 3, AllowedStrategies: []string{"native", "tls-handshake"}}
}
func (p EnrollmentPolicy) Valid() bool {
	return p.DirectOnly && p.MaxAttempts > 0 && p.MaxAttempts <= 5 && !p.DataPlaneAuthorization && len(p.AllowedStrategies) > 0
}
