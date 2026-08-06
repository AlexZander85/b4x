package monitor

import (
	"sort"
	"time"
)

// AxisState is the independent per-axis verdict of a monitor assessment.
// Health and diagnostic axes are kept separate so an origin failure is never
// misattributed to transport and vice versa (MON addendum v1.0 §77, phase A
// canonical model: independent health and diagnostic axes).
type AxisState string

const (
	AxisUnknown  AxisState = "unknown"
	AxisHealthy  AxisState = "healthy"
	AxisDegraded AxisState = "degraded"
	AxisFailing  AxisState = "failing"
)

// MonitorAssessment is the canonical per-scope assessment of one monitoring
// window. It aggregates independent source observations into a health axis
// (passive/authoritative) plus diagnostic axes (transport, visibility,
// origin), records source independence and contradiction counts, and binds
// itself to a temporal bucket via the assessment window.
type MonitorAssessment struct {
	SchemaVersion uint16
	AssessmentID  string
	SubjectID     string
	Scope         MonitorScopeKey

	// Health is the independent health axis of the subject.
	Health AxisState
	// Diagnostic holds the independent diagnostic axes:
	// "transport", "visibility", "origin" (ATTRIBUTION_* vocabulary).
	Diagnostic map[string]AxisState

	// IndependentSourceCount is the number of mutually independent
	// observation sources contributing to this assessment.
	IndependentSourceCount int
	// ContradictionCount is the number of evidence contradictions the
	// assessment had to resolve (source independence).
	ContradictionCount int
	// Contradictions lists the resolved contradiction pairs, bounded.
	Contradictions []string

	// TemporalBucket is the coarse window identifier (bucket) this
	// assessment aggregates (recurrence/decay happen per bucket).
	TemporalBucket string

	EvidenceRefs []string
	AssessedAt   time.Time
	ExpiresAt    time.Time
}

// Valid reports whether the assessment is structurally sound and still
// within its temporal window at now (decay: expired assessments must not
// authorize anything).
func (a MonitorAssessment) Valid(now time.Time) bool {
	if a.SchemaVersion != SchemaVersion || a.AssessmentID == "" || !a.Scope.Valid() || a.Health == "" || a.AssessedAt.IsZero() {
		return false
	}
	return now.Before(a.ExpiresAt)
}

// Aggregate returns the worst combined axis state (health axis wins ties;
// diagnostic failures escalate only their own axis). This is the read-only
// projection consumers use; no axis may downgrade another's verdict.
func (a MonitorAssessment) Aggregate() AxisState {
	worst := a.Health
	for _, d := range a.Diagnostic {
		if axisRank(d) > axisRank(worst) {
			worst = d
		}
	}
	return worst
}

// AxisFromHealth maps the correlation health vocabulary onto the assessment
// axis vocabulary (both live in this package; the mapping is total).
func AxisFromHealth(h HealthState) AxisState {
	switch h {
	case HealthHealthy:
		return AxisHealthy
	case HealthDegraded:
		return AxisDegraded
	case HealthFailing:
		return AxisFailing
	case HealthRecovering, HealthRecovered:
		return AxisRecovering
	default:
		return AxisUnknown
	}
}

// axisRank orders the axis states for the worst-of aggregation:
// unknown < healthy < degraded < failing.
func axisRank(s AxisState) int {
	switch s {
	case AxisFailing:
		return 4
	case AxisDegraded:
		return 3
	case AxisHealthy:
		return 2
	default:
		return 1 // AxisUnknown and anything empty
	}
}

// SortedContradictions returns the resolved contradiction pairs in a stable
// order (deterministic evidence output).
func (a MonitorAssessment) SortedContradictions() []string {
	out := append([]string(nil), a.Contradictions...)
	sort.Strings(out)
	return out
}
