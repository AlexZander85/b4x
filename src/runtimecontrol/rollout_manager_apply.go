package runtimecontrol

import (
	"context"
	"errors"
	"fmt"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

func cooldownKey(meta GenerationMeta, spec CanarySpec) CooldownKey {
	return CooldownKey{SetID: spec.SetID, ClientGroup: spec.ClientGroup, Protocol: spec.Protocol, CandidateGeneration: meta.ID}
}

// Apply is the single-phase convenience wrapper over the two-phase pipeline
// (Prepare → RunCanary → PromotePending). It never holds the manager mutex
// while the canary is running: the mutex is acquired only for the short
// prepare and promote critical sections, so status reads, rollback and
// shutdown stay responsive while a canary (up to MaxCanaryDuration) is
// active. A concurrent Prepare/Apply during an active canary fails fast with
// ErrPendingExists instead of blocking; a canary that is aborted or closed
// mid-flight surfaces ErrNoPending to the stale Apply caller.
func (m *Manager) Apply(ctx context.Context, candidate *config.Config, request ApplyRequest) (ApplyResult, error) {
	if m == nil {
		return ApplyResult{}, ErrInvalidRuntime
	}
	if !m.Enabled() {
		return ApplyResult{}, ErrDisabled
	}
	if ctx == nil {
		ctx = context.Background()
	}
	prepared, err := m.Prepare(ctx, candidate, request)
	if err != nil {
		return ApplyResult{Generation: prepared.Generation, Readiness: prepared.Readiness}, err
	}
	outcome, err := m.RunCanary(ctx)
	if err != nil {
		return ApplyResult{Generation: prepared.Generation, Readiness: prepared.Readiness, Canary: outcome}, err
	}
	return m.PromotePending(ctx)
}

func resumeRuntime(ctx context.Context, state *runtimeState) error {
	if state == nil || state.runtime == nil {
		return nil
	}
	return state.runtime.Resume(ctx)
}

func (m *Manager) Rollback(ctx context.Context, reason string) (RollbackResult, error) {
	if m == nil {
		return RollbackResult{}, ErrInvalidRuntime
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current := m.active.Load()
	if current == nil {
		return RollbackResult{}, ErrNoActive
	}
	if m.retired == nil {
		return RollbackResult{}, ErrNoRollback
	}
	if err := ctx.Err(); err != nil {
		return RollbackResult{}, &TransactionError{Stage: StageRollback, Err: err}
	}
	previous := m.retired
	previousRecord := m.recordForStateLocked(previous)
	if err := m.store.Prepare(previousRecord); err != nil {
		return RollbackResult{}, &TransactionError{Stage: StagePrepare, Err: err}
	}
	if err := previous.runtime.Resume(ctx); err != nil {
		_ = m.store.Abort()
		return RollbackResult{}, &TransactionError{Stage: StageRollback, Err: err}
	}
	m.active.Store(previous)
	if err := m.store.Commit(previousRecord); err != nil {
		m.active.Store(current)
		_ = m.store.Abort()
		if restoreErr := resumeRuntime(ctx, current); restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore current runtime: %w", restoreErr))
		}
		return RollbackResult{}, &TransactionError{Stage: StageCommit, Err: err}
	}
	if err := current.runtime.Rollback(ctx, reason); err != nil {
		return RollbackResult{}, &TransactionError{Stage: StageRollback, Err: err}
	}
	_ = current.runtime.Close(ctx)
	m.retired = nil
	if m.previousGood != nil {
		m.lastGood = m.previousGood
		m.previousGood = nil
	} else {
		m.lastGood = nil
	}
	m.appendHistoryLocked(HistoryEntry{Action: "rollback", Generation: previous.meta.ID, Reason: limitString(reason, 256), Success: true, At: m.clk.Now()})
	observability.Default().Metrics.Inc(observability.MetricDiscoveryCandidateRollback, map[string]string{"reason": sanitizeLabel(reason)}, 1)
	return RollbackResult{Generation: previous.meta.clone(), Reason: limitString(reason, 256)}, nil
}

func (m *Manager) recordForStateLocked(state *runtimeState) LastGoodRecord {
	if state == nil {
		return LastGoodRecord{SchemaVersion: LastGoodSchemaVersion, B4Version: m.b4Version, Timestamp: m.clk.Now()}
	}
	if m.previousGood != nil && m.retired == state {
		r := m.previousGood.clone()
		r.Timestamp = m.clk.Now()
		return r
	}
	return recordFrom(state.meta, CanaryOutcome{Passed: true, Samples: 1, StartedAt: state.meta.CreatedAt, CompletedAt: m.clk.Now()}, m.b4Version, m.clk.Now())
}

func (m *Manager) cleanupCandidateLocked(ctx context.Context, runtime Runtime, generation string, cause error) {
	_ = runtime.Rollback(ctx, cause.Error())
	_ = runtime.Close(ctx)
	observability.Default().Metrics.Inc(observability.MetricDiscoveryCandidateRollback, map[string]string{"reason": sanitizeLabel(cause.Error())}, 1)
}

func (m *Manager) appendHistoryLocked(entry HistoryEntry) {
	entry.Generation = limitString(entry.Generation, 128)
	entry.Reason = limitString(entry.Reason, 256)
	m.history = append(m.history, entry)
	if len(m.history) > m.historyMax {
		m.history = append([]HistoryEntry(nil), m.history[len(m.history)-m.historyMax:]...)
	}
}
