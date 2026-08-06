package monitor

import (
	"fmt"
	"sync"
	"time"
)

// ShadowParity is the outcome of comparing the legacy Watchdog decision with
// the Monitoring assessment for the same scope (phase A shadow mode: both
// count, only the legacy transaction path mutates, parity/contradiction
// evidence is collected).
type ShadowParity string

const (
	ParityUnknown       ShadowParity = "unknown"
	ParityMatch         ShadowParity = "match"
	ParityContradiction ShadowParity = "contradiction"
)

// ShadowParityEvidence is one recorded shadow comparison: the legacy
// Watchdog state and the monitoring assessment side by side. Evidence is
// read-only and never feeds a mutating path; it exists to prove shadow
// parity before the phase C cutover.
type ShadowParityEvidence struct {
	Scope            MonitorScopeKey
	WatchdogState    string
	AssessmentID     string
	AssessmentHealth AxisState
	Parity           ShadowParity
	ObservedAt       time.Time
}

// ShadowParityTracker collects bounded per-scope parity/contradiction
// evidence between the legacy Watchdog and the monitoring pipeline.
type ShadowParityTracker struct {
	mu   sync.Mutex
	seen map[string]ShadowParityEvidence
}

// NewShadowParityTracker creates an empty evidence tracker.
func NewShadowParityTracker() *ShadowParityTracker {
	return &ShadowParityTracker{seen: map[string]ShadowParityEvidence{}}
}

// classifyParity compares a legacy Watchdog state with the monitoring
// assessment health axis. A watchdog failure against a healthy assessment
// (or a watchdog success against a failing one) is a contradiction; any
// other observable comparison is a match; unknown sides stay unknown.
func classifyParity(watchdogState string, assessmentHealth AxisState) ShadowParity {
	wdOk := watchdogOk(watchdogState)
	if wdOk == nil || assessmentHealth == AxisUnknown || assessmentHealth == "" {
		return ParityUnknown
	}
	if *wdOk != axisHealthyBool(assessmentHealth) {
		return ParityContradiction
	}
	return ParityMatch
}

// watchdogOk normalizes the legacy Watchdog state vocabulary
// (StatusHealthy/StatusDegraded/StatusEscalating/StatusDisabled) to a
// healthy/unhealthy opinion; nil means the state is not an opinion.
func watchdogOk(state string) *bool {
	switch state {
	case "healthy":
		b := true
		return &b
	case "degraded", "escalating", "failing":
		b := false
		return &b
	default:
		return nil
	}
}

func axisHealthyBool(s AxisState) bool {
	switch s {
	case AxisHealthy, AxisRecovering:
		return true
	default:
		return false
	}
}

// Observe records one shadow comparison for the scope. A second observation
// for the same scope replaces the previous evidence (per-scope latest
// wins); the map stays bounded by the number of scopes seen.
func (t *ShadowParityTracker) Observe(scope MonitorScopeKey, watchdogState string, a MonitorAssessment, now time.Time) ShadowParityEvidence {
	ev := ShadowParityEvidence{
		Scope:            scope,
		WatchdogState:    watchdogState,
		AssessmentID:     a.AssessmentID,
		AssessmentHealth: a.Health,
		Parity:           classifyParity(watchdogState, a.Health),
		ObservedAt:       now,
	}
	if t == nil || !scope.Valid() {
		return ev
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.seen[correlationKey(scope)] = ev
	return ev
}

// Latest returns the last recorded evidence for the scope.
func (t *ShadowParityTracker) Latest(scope MonitorScopeKey) (ShadowParityEvidence, bool) {
	if t == nil {
		return ShadowParityEvidence{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	v, ok := t.seen[correlationKey(scope)]
	return v, ok
}

// Counts returns the total recorded comparisons and the number of
// contradictions (readiness input for the phase C cutover: shadow parity
// requires zero unresolved contradictions).
func (t *ShadowParityTracker) Counts() (total, contradictions int) {
	if t == nil {
		return 0, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, ev := range t.seen {
		total++
		if ev.Parity == ParityContradiction {
			contradictions++
		}
	}
	return total, contradictions
}

// String renders the evidence in a stable, debuggable form.
func (e ShadowParityEvidence) String() string {
	return fmt.Sprintf("scope=%s watchdog=%s monitor=%s parity=%s", e.Scope.ClientScope.ID, e.WatchdogState, e.AssessmentHealth, e.Parity)
}

// AxisRecovering is the assessment-axis spelling of the correlation
// vocabulary used by the shadow parity classifier: a recovering subject is
// on its way to healthy and never contradicts a healthy watchdog opinion.
const AxisRecovering AxisState = "recovering"
