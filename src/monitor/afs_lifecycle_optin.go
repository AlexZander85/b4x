package monitor

import (
	"errors"
	"time"
)

// SetAdaptiveSynthesisEnabled updates the monitor-owned opt-in projection for
// one existing scope. Disabling an active run is a safe lifecycle cancel; it
// never mutates production configuration or performs rollback itself.
func (c *FlowCorrelator) SetAdaptiveSynthesisEnabled(scope MonitorScopeKey, enabled bool, now time.Time) error {
	if c == nil || !scope.Valid() {
		return errors.New("valid monitoring scope required")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	key := correlationKey(scope)
	snapshot := c.flows[key]
	if snapshot == nil {
		snapshot = newCorrelationSnapshot(scope)
		c.flows[key] = snapshot
	}
	status := normalizeSynthesisStatus(snapshot.AdaptiveSynthesis, scope)
	status.Enabled = enabled
	status.UpdatedAt = now
	if !enabled && synthesisStateActive(status.State) {
		status.State = SynthesisCancelled
		status.Reasons = appendSynthesisReason(status.Reasons, "user-disabled-adaptive-synthesis; cleanup-required")
	}
	if status.State == "" {
		status.State = SynthesisIdle
	}
	snapshot.AdaptiveSynthesis = status
	return nil
}
