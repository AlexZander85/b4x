package runtimecontrol

import (
	"context"
	"errors"
	"fmt"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
)

func (m *Manager) Prepare(ctx context.Context, candidate *config.Config, request ApplyRequest) (PrepareResult, error) {
	if m == nil {
		return PrepareResult{}, ErrInvalidRuntime
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return PrepareResult{}, ErrDisabled
	}
	if m.pending != nil {
		return PrepareResult{}, ErrPendingExists
	}
	if candidate == nil {
		return PrepareResult{}, &TransactionError{Stage: StageValidate, Err: errors.New("candidate config is nil")}
	}
	if err := request.Canary.Validate(); err != nil {
		return PrepareResult{}, &TransactionError{Stage: StageValidate, Err: err}
	}
	if err := ctx.Err(); err != nil {
		return PrepareResult{}, &TransactionError{Stage: StageValidate, Err: err}
	}
	clone := candidate.CloneForRuntimeUpdate()
	if err := clone.Validate(); err != nil {
		m.appendHistoryLocked(HistoryEntry{Action: "prepare", Reason: err.Error(), Success: false, At: m.clk.Now()})
		return PrepareResult{}, &TransactionError{Stage: StageValidate, Err: err}
	}
	meta := makeGenerationMeta(clone, m.clk.Now())
	key := cooldownKey(meta, request.Canary)
	if err := m.cooldown.Check(key); err != nil {
		return PrepareResult{}, &TransactionError{Stage: StageCanary, Err: err}
	}
	runtime, err := m.builder.Build(ctx, clone, meta.clone())
	if err != nil || runtime == nil {
		if err == nil {
			err = ErrInvalidRuntime
		}
		m.appendHistoryLocked(HistoryEntry{Action: "prepare", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now()})
		return PrepareResult{}, &TransactionError{Stage: StageBuild, Err: err}
	}
	readiness, err := runtime.Readiness(ctx)
	if err != nil || !readiness.Ready {
		if err == nil {
			err = errors.New(readiness.Reason)
		}
		m.cleanupCandidateLocked(ctx, runtime, meta.ID, err)
		m.appendHistoryLocked(HistoryEntry{Action: "prepare", Generation: meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now()})
		return PrepareResult{Generation: meta, Readiness: readiness}, &TransactionError{Stage: StageReadiness, Err: err}
	}
	m.pending = &pendingState{meta: meta, runtime: runtime, request: request, readiness: readiness, preparedAt: m.clk.Now()}
	m.appendHistoryLocked(HistoryEntry{Action: "prepare", Generation: meta.ID, Success: true, At: m.clk.Now()})
	return PrepareResult{Generation: meta.clone(), Readiness: readiness}, nil
}

func (m *Manager) RunCanary(ctx context.Context) (CanaryOutcome, error) {
	if m == nil {
		return CanaryOutcome{}, ErrInvalidRuntime
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.pending == nil {
		m.mu.Unlock()
		return CanaryOutcome{}, ErrNoPending
	}
	pending := m.pending
	if pending.canaryRunning {
		m.mu.Unlock()
		return CanaryOutcome{}, ErrPendingBusy
	}
	pending.canaryRunning = true
	m.mu.Unlock()
	outcome, err := pending.runtime.Canary(ctx, pending.request.Canary)
	if err == nil {
		err = validateCanaryOutcome(pending.request.Canary, outcome)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending != pending {
		return outcome, ErrNoPending
	}
	pending.canaryRunning = false
	if err != nil {
		m.cooldown.RecordFailure(cooldownKey(pending.meta, pending.request.Canary))
		m.cleanupCandidateLocked(ctx, pending.runtime, pending.meta.ID, err)
		m.appendHistoryLocked(HistoryEntry{Action: "canary", Generation: pending.meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: outcome})
		m.pending = nil
		return outcome, &TransactionError{Stage: StageCanary, Err: err}
	}
	pending.canary = outcome
	pending.canaryComplete = true
	m.appendHistoryLocked(HistoryEntry{Action: "canary", Generation: pending.meta.ID, Success: true, At: m.clk.Now(), Canary: outcome})
	return cloneCanary(outcome), nil
}

func (m *Manager) PromotePending(ctx context.Context) (ApplyResult, error) {
	if m == nil {
		return ApplyResult{}, ErrInvalidRuntime
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return ApplyResult{}, ErrNoPending
	}
	pending := m.pending
	if pending.canaryRunning {
		return ApplyResult{}, ErrPendingBusy
	}
	if !pending.canaryComplete || !pending.canary.Passed {
		return ApplyResult{}, ErrCanaryRequired
	}
	record := recordFrom(pending.meta, pending.canary, m.b4Version, m.clk.Now())
	if err := m.store.Prepare(record); err != nil {
		return ApplyResult{}, &TransactionError{Stage: StagePrepare, Err: err}
	}
	old := m.active.Load()
	if m.beforePromote != nil {
		if err := m.beforePromote(pending.meta.clone()); err != nil {
			_ = m.store.Abort()
			m.cooldown.RecordFailure(cooldownKey(pending.meta, pending.request.Canary))
			m.cleanupCandidateLocked(ctx, pending.runtime, pending.meta.ID, err)
			m.appendHistoryLocked(HistoryEntry{Action: "promotion-gate", Generation: pending.meta.ID, Reason: err.Error(), Success: false, At: m.clk.Now(), Canary: pending.canary})
			m.pending = nil
			return ApplyResult{}, &TransactionError{Stage: StagePromote, Err: err}
		}
	}
	if err := pending.runtime.Promote(ctx); err != nil {
		_ = m.store.Abort()
		return ApplyResult{}, &TransactionError{Stage: StagePromote, Err: err}
	}
	candidateState := &runtimeState{meta: pending.meta, runtime: pending.runtime}
	m.active.Store(candidateState)
	if err := m.store.Commit(record); err != nil {
		m.active.Store(old)
		_ = m.store.Abort()
		restoreErr := resumeRuntime(ctx, old)
		m.cleanupCandidateLocked(ctx, pending.runtime, pending.meta.ID, err)
		m.pending = nil
		if restoreErr != nil {
			err = errors.Join(err, fmt.Errorf("restore previous runtime: %w", restoreErr))
		}
		return ApplyResult{}, &TransactionError{Stage: StageCommit, Err: err}
	}
	result := ApplyResult{Generation: pending.meta.clone(), Readiness: pending.readiness, Canary: cloneCanary(pending.canary)}
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
	m.cooldown.RecordSuccess(cooldownKey(pending.meta, pending.request.Canary))
	m.appendHistoryLocked(HistoryEntry{Action: "promote", Generation: pending.meta.ID, Success: true, At: m.clk.Now(), Canary: pending.canary})
	m.pending = nil
	observability.Default().Metrics.Inc(observability.MetricDiscoveryCandidatePromote, map[string]string{"generation": candidateState.meta.ID[:minInt(len(candidateState.meta.ID), 16)]}, 1)
	return result, nil
}

func (m *Manager) AbortPending(ctx context.Context, reason string) error {
	if m == nil {
		return ErrInvalidRuntime
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.pending == nil {
		return ErrNoPending
	}
	pending := m.pending
	if pending.canaryRunning {
		return ErrPendingBusy
	}
	err := pending.runtime.Rollback(ctx, reason)
	closeErr := pending.runtime.Close(ctx)
	m.pending = nil
	_ = m.store.Abort()
	if err == nil {
		err = closeErr
	}
	m.appendHistoryLocked(HistoryEntry{Action: "abort", Generation: pending.meta.ID, Reason: limitString(reason, 256), Success: err == nil, At: m.clk.Now()})
	if err != nil {
		return &TransactionError{Stage: StageAbort, Err: err}
	}
	return nil
}

func (m *Manager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	seen := make(map[Runtime]struct{})
	closeRuntime := func(runtime Runtime) {
		if runtime == nil {
			return
		}
		if _, ok := seen[runtime]; ok {
			return
		}
		seen[runtime] = struct{}{}
		if err := runtime.Close(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if m.pending != nil {
		_ = m.pending.runtime.Rollback(ctx, "manager shutdown")
		closeRuntime(m.pending.runtime)
		m.pending = nil
	}
	if active := m.active.Load(); active != nil {
		closeRuntime(active.runtime)
	}
	if m.retired != nil {
		closeRuntime(m.retired.runtime)
		m.retired = nil
	}
	_ = m.store.Abort()
	return errors.Join(errs...)
}
