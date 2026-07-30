package runtimecontrol

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/capture"
)

const (
	StageTopologyValidate         Stage = "topology-validate"
	StageTopologyReserve          Stage = "topology-reserve"
	StageTopologyStartSecondary   Stage = "topology-start-secondary"
	StageTopologySecondaryReady   Stage = "topology-secondary-readiness"
	StageTopologyStartClassifier  Stage = "topology-start-classifier"
	StageTopologyClassifierReady  Stage = "topology-classifier-readiness"
	StageTopologySwitchRules      Stage = "topology-switch-rules"
	StageTopologyDrainPrevious    Stage = "topology-drain-previous"
	StageTopologyCommitGeneration Stage = "topology-commit-generation"
	StageTopologyRollback         Stage = "topology-rollback"
)

// TopologyBackend owns live queue handles, firewall state and generation-local
// transient resources. Methods must be bounded and idempotent; the transaction
// deliberately calls compensating operations even after partial startup.
type TopologyBackend interface {
	Validate(context.Context, capture.GSOTopologyPlan) error
	Reserve(context.Context, capture.GSOTopologyPlan) error
	StartSecondary(context.Context, capture.GSOTopologyPlan) error
	SecondaryReadiness(context.Context, capture.GSOTopologyPlan) (RuntimeReadiness, error)
	StartClassifier(context.Context, capture.GSOTopologyPlan) error
	ClassifierReadiness(context.Context, capture.GSOTopologyPlan) (RuntimeReadiness, error)
	SwitchRules(context.Context, capture.GSOTopologyPlan) error
	DrainPrevious(context.Context, capture.GSOTopologyPlan) error
	CommitGeneration(context.Context, capture.GSOTopologyPlan) error

	RestorePreviousRules(context.Context) error
	ReleaseHeldUnchanged(context.Context) error
	InvalidateGSOTokens(context.Context) error
	ClearOwnedTransientState(context.Context) error
	RestoreLastGoodGeneration(context.Context) error
	CloseNewTopology(context.Context) error
}

type TopologyTransitionReport struct {
	Plan                capture.GSOTopologyPlan `json:"plan"`
	Completed           []Stage                 `json:"completed"`
	SecondaryReadiness  RuntimeReadiness        `json:"secondary_readiness"`
	ClassifierReadiness RuntimeReadiness        `json:"classifier_readiness"`
	StartedAt           time.Time               `json:"started_at"`
	CompletedAt         time.Time               `json:"completed_at"`
	RolledBack          bool                    `json:"rolled_back"`
	RollbackErrors      []string                `json:"rollback_errors,omitempty"`
}

type TopologyTransaction struct {
	backend TopologyBackend
	now     func() time.Time
}

func NewTopologyTransaction(backend TopologyBackend) (*TopologyTransaction, error) {
	if backend == nil {
		return nil, errors.New("GSO topology backend is nil")
	}
	return &TopologyTransaction{backend: backend, now: time.Now}, nil
}

func (t *TopologyTransaction) Apply(ctx context.Context, plan capture.GSOTopologyPlan) (TopologyTransitionReport, error) {
	if t == nil || t.backend == nil {
		return TopologyTransitionReport{}, ErrInvalidRuntime
	}
	if ctx == nil {
		ctx = context.Background()
	}
	report := TopologyTransitionReport{Plan: plan, StartedAt: t.now().UTC()}
	step := func(stage Stage, fn func() error) error {
		if err := ctx.Err(); err != nil {
			return &TransactionError{Stage: stage, Err: err}
		}
		if err := fn(); err != nil {
			return &TransactionError{Stage: stage, Err: err}
		}
		report.Completed = append(report.Completed, stage)
		return nil
	}
	fail := func(err error) (TopologyTransitionReport, error) {
		report.RolledBack = true
		report.RollbackErrors = t.rollback(ctx)
		report.CompletedAt = t.now().UTC()
		if len(report.RollbackErrors) > 0 {
			err = errors.Join(err, fmt.Errorf("topology rollback: %v", report.RollbackErrors))
		}
		return report, err
	}

	if err := step(StageTopologyValidate, func() error {
		if err := plan.Validate(); err != nil {
			return err
		}
		return t.backend.Validate(ctx, plan)
	}); err != nil {
		return fail(err)
	}
	if err := step(StageTopologyReserve, func() error { return t.backend.Reserve(ctx, plan) }); err != nil {
		return fail(err)
	}
	if err := step(StageTopologyStartSecondary, func() error { return t.backend.StartSecondary(ctx, plan) }); err != nil {
		return fail(err)
	}
	if err := step(StageTopologySecondaryReady, func() error {
		ready, err := t.backend.SecondaryReadiness(ctx, plan)
		report.SecondaryReadiness = ready
		if err != nil {
			return err
		}
		if plan.Normalizer.Enabled && !ready.Ready {
			return errors.New(ready.Reason)
		}
		return nil
	}); err != nil {
		return fail(err)
	}
	if err := step(StageTopologyStartClassifier, func() error { return t.backend.StartClassifier(ctx, plan) }); err != nil {
		return fail(err)
	}
	if err := step(StageTopologyClassifierReady, func() error {
		ready, err := t.backend.ClassifierReadiness(ctx, plan)
		report.ClassifierReadiness = ready
		if err != nil {
			return err
		}
		if !ready.Ready {
			return errors.New(ready.Reason)
		}
		return nil
	}); err != nil {
		return fail(err)
	}
	if err := step(StageTopologySwitchRules, func() error { return t.backend.SwitchRules(ctx, plan) }); err != nil {
		return fail(err)
	}
	if err := step(StageTopologyDrainPrevious, func() error { return t.backend.DrainPrevious(ctx, plan) }); err != nil {
		return fail(err)
	}
	if err := step(StageTopologyCommitGeneration, func() error { return t.backend.CommitGeneration(ctx, plan) }); err != nil {
		return fail(err)
	}
	report.CompletedAt = t.now().UTC()
	return report, nil
}

func (t *TopologyTransaction) rollback(ctx context.Context) []string {
	// Rollback order is normative. Every operation is attempted even if an
	// earlier compensation fails, preserving fail-open packet release/cleanup.
	steps := []func(context.Context) error{
		t.backend.RestorePreviousRules,
		t.backend.ReleaseHeldUnchanged,
		t.backend.InvalidateGSOTokens,
		t.backend.ClearOwnedTransientState,
		t.backend.RestoreLastGoodGeneration,
		t.backend.CloseNewTopology,
	}
	var out []string
	for _, fn := range steps {
		if err := fn(ctx); err != nil {
			out = append(out, err.Error())
		}
	}
	return out
}
