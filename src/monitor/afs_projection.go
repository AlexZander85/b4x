package monitor

import (
	"errors"
	"time"
)

// SetAdaptiveSynthesisEnabled updates the existing status projection and
// delegates lifecycle ownership to the projection's FlowCorrelator.
func (p *MonitorAPIProjection) SetAdaptiveSynthesisEnabled(scope MonitorScopeKey, enabled bool, now time.Time) error {
	if p == nil || p.correlator == nil {
		return errors.New("monitor projection is unavailable")
	}
	if err := p.correlator.SetAdaptiveSynthesisEnabled(scope, enabled, now); err != nil {
		return err
	}
	status, ok := p.correlator.AdaptiveSynthesisStatus(scope)
	if !ok {
		return errors.New("adaptive synthesis status unavailable")
	}
	p.PatchAdaptiveSynthesis(scope, status, now)
	return nil
}

// OpenAdaptiveSynthesis records a monitor-qualified persistent regression and
// starts the bounded AFS lifecycle. The caller supplies the persistent
// regression verdict from the existing Monitoring policy; a false verdict
// always fails closed.
func (p *MonitorAPIProjection) OpenAdaptiveSynthesis(assessment MonitorAssessment, runID string, enabled, persistentRegressionQualified bool, deadline, now time.Time) error {
	if p == nil || p.correlator == nil {
		return errors.New("monitor projection is unavailable")
	}
	if err := p.correlator.OpenAdaptiveSynthesis(assessment, runID, enabled, persistentRegressionQualified, deadline, now); err != nil {
		return err
	}
	status, _ := p.correlator.AdaptiveSynthesisStatus(assessment.Scope)
	p.PatchAdaptiveSynthesis(assessment.Scope, status, now)
	return nil
}

func (p *MonitorAPIProjection) UpdateAdaptiveSynthesis(scope MonitorScopeKey, update AdaptiveSynthesisUpdate, now time.Time) error {
	if p == nil || p.correlator == nil {
		return errors.New("monitor projection is unavailable")
	}
	if err := p.correlator.UpdateAdaptiveSynthesis(scope, update, now); err != nil {
		return err
	}
	status, _ := p.correlator.AdaptiveSynthesisStatus(scope)
	p.PatchAdaptiveSynthesis(scope, status, now)
	return nil
}

func (p *MonitorAPIProjection) CancelAdaptiveSynthesis(scope MonitorScopeKey, runID, reason string, nextEligibleRun, now time.Time) error {
	if p == nil || p.correlator == nil {
		return errors.New("monitor projection is unavailable")
	}
	if err := p.correlator.CancelAdaptiveSynthesis(scope, runID, reason, nextEligibleRun, now); err != nil {
		return err
	}
	status, _ := p.correlator.AdaptiveSynthesisStatus(scope)
	p.PatchAdaptiveSynthesis(scope, status, now)
	return nil
}

func (p *MonitorAPIProjection) MarkAdaptiveSynthesisStale(scope MonitorScopeKey, runID, reason string, now time.Time) error {
	if p == nil || p.correlator == nil {
		return errors.New("monitor projection is unavailable")
	}
	if err := p.correlator.MarkAdaptiveSynthesisStale(scope, runID, reason, now); err != nil {
		return err
	}
	status, _ := p.correlator.AdaptiveSynthesisStatus(scope)
	p.PatchAdaptiveSynthesis(scope, status, now)
	return nil
}

func (p *MonitorAPIProjection) ObserveAdaptiveSynthesisStability(scope MonitorScopeKey, runID, winnerID string, stable bool, nextEligibleRun time.Time, reason string, now time.Time) error {
	if p == nil || p.correlator == nil {
		return errors.New("monitor projection is unavailable")
	}
	if err := p.correlator.ObserveAdaptiveSynthesisStability(scope, runID, winnerID, stable, nextEligibleRun, reason, now); err != nil {
		return err
	}
	status, _ := p.correlator.AdaptiveSynthesisStatus(scope)
	p.PatchAdaptiveSynthesis(scope, status, now)
	return nil
}

func (p *MonitorAPIProjection) ResetAdaptiveSynthesis(scope MonitorScopeKey, now time.Time) error {
	if p == nil || p.correlator == nil {
		return errors.New("monitor projection is unavailable")
	}
	if err := p.correlator.ResetAdaptiveSynthesis(scope, now); err != nil {
		return err
	}
	status, _ := p.correlator.AdaptiveSynthesisStatus(scope)
	p.PatchAdaptiveSynthesis(scope, status, now)
	return nil
}
