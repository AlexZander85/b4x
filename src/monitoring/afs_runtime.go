package monitoring

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

// SetAdaptiveSynthesisEnabled reuses the production Monitoring projection as
// the live opt-in/cancel surface. Turning the setting off cancels lifecycle
// ownership but performs no configuration mutation itself.
func (rt *Runtime) SetAdaptiveSynthesisEnabled(scope monitor.MonitorScopeKey, enabled bool, now time.Time) error {
	if rt == nil || rt.projector == nil {
		return errors.New("monitoring runtime is unavailable")
	}
	return rt.projector.SetAdaptiveSynthesisEnabled(scope, enabled, now)
}

func (rt *Runtime) PersistentRegressionQualified(scope monitor.MonitorScopeKey) bool {
	if rt == nil || rt.projector == nil || rt.projector.Correlator() == nil {
		return false
	}
	return rt.projector.Correlator().PersistentRegressionQualified(scope)
}

// OpenAdaptiveSynthesis starts only the Monitoring-owned lifecycle. The
// persistent-regression verdict is derived here from the existing correlator;
// callers cannot force synthesis after a single transient failure.
func (rt *Runtime) OpenAdaptiveSynthesis(assessment monitor.MonitorAssessment, runID string, enabled bool, deadline, now time.Time) error {
	if rt == nil || rt.projector == nil {
		return errors.New("monitoring runtime is unavailable")
	}
	persistent := rt.PersistentRegressionQualified(assessment.Scope)
	return rt.projector.OpenAdaptiveSynthesis(assessment, runID, enabled, persistent, deadline, now)
}

func (rt *Runtime) UpdateAdaptiveSynthesis(scope monitor.MonitorScopeKey, update monitor.AdaptiveSynthesisUpdate, now time.Time) error {
	if rt == nil || rt.projector == nil {
		return errors.New("monitoring runtime is unavailable")
	}
	return rt.projector.UpdateAdaptiveSynthesis(scope, update, now)
}

func (rt *Runtime) CancelAdaptiveSynthesis(scope monitor.MonitorScopeKey, runID, reason string, nextEligibleRun, now time.Time) error {
	if rt == nil || rt.projector == nil {
		return errors.New("monitoring runtime is unavailable")
	}
	return rt.projector.CancelAdaptiveSynthesis(scope, runID, reason, nextEligibleRun, now)
}

func (rt *Runtime) MarkAdaptiveSynthesisStale(scope monitor.MonitorScopeKey, runID, reason string, now time.Time) error {
	if rt == nil || rt.projector == nil {
		return errors.New("monitoring runtime is unavailable")
	}
	return rt.projector.MarkAdaptiveSynthesisStale(scope, runID, reason, now)
}

func (rt *Runtime) ObserveAdaptiveSynthesisStability(scope monitor.MonitorScopeKey, runID, winnerID string, stable bool, nextEligibleRun time.Time, reason string, now time.Time) error {
	if rt == nil || rt.projector == nil {
		return errors.New("monitoring runtime is unavailable")
	}
	return rt.projector.ObserveAdaptiveSynthesisStability(scope, runID, winnerID, stable, nextEligibleRun, reason, now)
}

func (rt *Runtime) ResetAdaptiveSynthesis(scope monitor.MonitorScopeKey, now time.Time) error {
	if rt == nil || rt.projector == nil {
		return errors.New("monitoring runtime is unavailable")
	}
	return rt.projector.ResetAdaptiveSynthesis(scope, now)
}

// PublishBehavioralFingerprint projects only bounded, privacy-safe metadata
// from detector's authoritative evidence into the existing /api/monitor/v1
// status surface. No raw SNI/domain/client/payload/pcap data crosses here.
func (rt *Runtime) PublishBehavioralFingerprint(evidence detector.BehavioralFingerprintEvidence, now time.Time) error {
	if rt == nil || rt.projector == nil {
		return errors.New("monitoring runtime is unavailable")
	}
	if !evidence.Valid(now) {
		return errors.New("fresh behavioral fingerprint evidence required")
	}
	summary := monitor.BehavioralFingerprintSummary{
		EvidenceID:        evidence.EvidenceID,
		PanelHash:         evidence.PanelHash,
		FeatureVectorHash: evidence.FeatureVectorHash,
		Confidence:        evidence.Confidence,
		NoiseScore:        evidence.NoiseScore,
		ConclusiveCount:   evidence.ConclusiveCount,
		InconclusiveCount: evidence.InconclusiveCount,
		CreatedAt:         evidence.CreatedAt,
		ValidUntil:        evidence.ValidUntil,
	}
	rt.projector.PatchBehavioralFingerprint(evidence.Scope, &summary, now)
	return nil
}
