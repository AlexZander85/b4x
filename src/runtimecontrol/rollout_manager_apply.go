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

func (m *Manager) Apply(ctx context.Context, candidate *config.Config, request ApplyRequest) (ApplyResult, error) {
	if m == nil {
		return ApplyResult{}, ErrInvalidRuntime
	}
	if !m.Enabled() {
		return ApplyResult{}, ErrDisabled
	}
	if candidate == nil {
		return ApplyResult{}, &TransactionError{Stage: StageValidate, Err: errors.New("candidate config is nil")}
	}
	if err := request.Canary.Validate(); err != nil {
		return ApplyResult{}, &TransactionError{Stage: StageValidate, Err: err}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return ApplyResult{}, &TransactionError{Stage: StageValidate, Err: err}
	}
	clone := candidate.CloneForRuntimeUpdate()
	if err := clone.Validate(); err != nil {
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Reason: err.Error(), Success: false, At: m.clk.Now()})
		return ApplyResult{}, &TransactionError{Stage: StageValidate, Err: err}
	}
	meta := makeGenerationMeta(clone, m.clk.Now())
	key := CooldownKey{SetID: request.Canary.SetID, ClientGroup: request.Canary.ClientGroup, Protocol: request.Canary.Protocol, CandidateGeneration: meta.ID}
	if err := m.cooldown.Check(key); err != nil {
		return ApplyResult{}, &TransactionError{Stage: StageCanary, Err: err}
	}

	runtime, err := m.builder.Build(ctx, clone, meta.clone())
	if err != nil || runtime == nil {
		if err == nil {
			err = ErrInvalidRuntime
		}
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now()})
		return ApplyResult{}, &TransactionError{Stage: StageBuild, Err: err}
	}
	readiness, err := runtime.Readiness(ctx)
	if err != nil || !readiness.Ready {
		if err == nil {
			err = errors.New(readiness.Reason)
		}
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now()})
		return ApplyResult{Generation: meta, Readiness: readiness}, &TransactionError{Stage: StageReadiness, Err: err}
	}
	canary, err := runtime.Canary(ctx, request.Canary)
	if err == nil {
		err = validateCanaryOutcome(request.Canary, canary)
	}
	if err != nil {
		m.cooldown.RecordFailure(key)
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: canary})
		return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StageCanary, Err: err}
	}
	record := recordFrom(meta, canary, m.b4Version, m.clk.Now())
	if err := m.store.Prepare(record); err != nil {
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StagePrepare, Err: err}
	}
	old := m.active.Load()
	if m.hardGateCheck != nil {
		if err := m.hardGateCheck(meta.clone()); err != nil {
			m.cooldown.RecordFailure(key)
			_ = m.store.Abort()
			m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
			m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: canary})
			return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StagePromote, Err: err}
		}
	}
	if m.beforePromote != nil {
		if err := m.beforePromote(meta.clone()); err != nil {
			_ = m.store.Abort()
			m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
			m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: canary})
			return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StagePromote, Err: err}
		}
	}
	if err := runtime.Promote(ctx); err != nil {
		_ = m.store.Abort()
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: canary})
		return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StagePromote, Err: err}
	}
	candidateState := &runtimeState{meta: meta, runtime: runtime}
	m.active.Store(candidateState)
	if err := m.store.Commit(record); err != nil {
		m.active.Store(old)
		_ = m.store.Abort()
		restoreErr := resumeRuntime(ctx, old)
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		if restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore previous runtime: %w", restoreErr))
		}
		m.appendHistoryLocked(HistoryEntry{Action: "apply", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: canary})
		return ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}, &TransactionError{Stage: StageCommit, Err: err}
	}
	result := ApplyResult{Generation: meta, Readiness: readiness, Canary: canary}
	if old != nil {
		if err := old.runtime.Drain(ctx); err != nil {
			result.DrainError = err.Error()
		}
		if m.retired != nil {
			_ = m.retired.runtime.Close(ctx)
		}
		m.retired = old
		if m.lastGood != nil {
			previous := m.lastGood.clone()
			m.previousGood = &previous
		}
	}
	m.lastGood = &record
	m.cooldown.RecordSuccess(key)
	if result.DrainError != "" {
		observability.Default().Metrics.Inc(observability.MetricDiscoveryCandidateRollback, map[string]string{"reason": "drain-error"}, 1)
	}
	m.appendHistoryLocked(HistoryEntry{Action: "promote", Generation: meta.ID, Success: true, At: m.clk.Now(), Canary: canary})
	observability.Default().Metrics.Inc(observability.MetricDiscoveryCandidatePromote, map[string]string{"generation": meta.ID[:minInt(len(meta.ID), 16)]}, 1)
	return result, nil
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
