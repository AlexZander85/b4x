package silentpath

import "time"

// Classify keeps a single family at suspicion; only distinct live families
// reach correlated, and suppressors always terminate automatic eligibility.
func Classify(class FailureClass, scope Scope, positive []Evidence, suppressors []Suppression, now time.Time) Assessment {
	a := ObserveAssessment(class, scope, ReasonNoUniqueProgress)
	a.PositiveEvidence = append([]Evidence(nil), positive...)
	if r, ok := HasActiveSuppressor(suppressors, now); ok {
		a.Confidence = ConfidenceNone
		a.ReasonCode = r
		return a
	}
	f := map[string]bool{}
	for _, e := range positive {
		if !e.Expired(now) && e.IndependentFamily != "" {
			f[e.IndependentFamily] = true
		}
	}
	if len(f) >= 2 {
		a.Confidence = ConfidenceCorrelated
		a.ReasonCode = ReasonRetryObserved
	}
	return a
}
