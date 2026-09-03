package ppe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrInvalidDesiredState = errors.New("invalid PPE desired state")
	ErrXTablesLockMissing  = errors.New("xtables lock support was not proven")
)

const defaultRollbackTimeout = 10 * time.Second

type FamilySnapshot struct {
	Family        string           `json:"family"`
	Binary        string           `json:"binary"`
	WaitSupported bool             `json:"wait_supported"`
	PreExists     bool             `json:"pre_exists"`
	FwdExists     bool             `json:"fwd_exists"`
	PreRules      [][]string       `json:"pre_rules,omitempty"`
	FwdRules      [][]string       `json:"fwd_rules,omitempty"`
	PreJumps      []PositionedRule `json:"pre_jumps,omitempty"`
	FwdJumps      []PositionedRule `json:"fwd_jumps,omitempty"`
}

type PositionedRule struct {
	Position int      `json:"position"`
	Args     []string `json:"args"`
}

type TransactionBackend interface {
	Snapshot(context.Context, FamilyPlan) (FamilySnapshot, error)
	Install(context.Context, FamilyPlan) error
	Verify(context.Context, FamilyPlan) error
	Remove(context.Context, FamilyPlan) error
	VerifyRemoved(context.Context, FamilyPlan) error
	Restore(context.Context, FamilySnapshot) error
}

type TransactionResult struct {
	Generation         string    `json:"generation"`
	PreviousGeneration string    `json:"previous_generation,omitempty"`
	Families           []string  `json:"families"`
	Removed            bool      `json:"removed"`
	CompletedAt        time.Time `json:"completed_at"`
}

type TransactionManager struct {
	mu              sync.Mutex
	backend         TransactionBackend
	active          DesiredState
	hasActive       bool
	rollbackTimeout time.Duration
	now             func() time.Time
}

func NewTransactionManager(backend TransactionBackend) *TransactionManager {
	if backend == nil {
		backend = NewIPTablesBackend(nil)
	}
	return &TransactionManager{
		backend:         backend,
		rollbackTimeout: defaultRollbackTimeout,
		now:             time.Now,
	}
}

func (m *TransactionManager) Current() (DesiredState, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hasActive {
		return DesiredState{}, false
	}
	return cloneDesiredState(m.active), true
}

func (m *TransactionManager) Apply(ctx context.Context, desired DesiredState) (TransactionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateDesiredState(desired); err != nil {
		return TransactionResult{}, err
	}
	previous := ""
	if m.hasActive {
		previous = m.active.Generation
	}
	if err := m.reconcile(ctx, desired, false); err != nil {
		return TransactionResult{}, err
	}
	m.active = cloneDesiredState(desired)
	m.hasActive = true
	return TransactionResult{
		Generation:         desired.Generation,
		PreviousGeneration: previous,
		Families:           familyNames(desired),
		CompletedAt:        m.now().UTC(),
	}, nil
}

func (m *TransactionManager) Remove(ctx context.Context, desired DesiredState) (TransactionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := validateDesiredState(desired); err != nil {
		return TransactionResult{}, err
	}
	previous := ""
	if m.hasActive {
		previous = m.active.Generation
	}
	if err := m.reconcile(ctx, desired, true); err != nil {
		return TransactionResult{}, err
	}
	m.active = DesiredState{}
	m.hasActive = false
	return TransactionResult{
		Generation:         desired.Generation,
		PreviousGeneration: previous,
		Families:           familyNames(desired),
		Removed:            true,
		CompletedAt:        m.now().UTC(),
	}, nil
}

func (m *TransactionManager) reconcile(ctx context.Context, desired DesiredState, remove bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	snapshots := make([]FamilySnapshot, 0, len(desired.Families))
	plans := make([]FamilyPlan, 0, len(desired.Families))
	for _, plan := range desired.Families {
		snapshot, err := m.backend.Snapshot(ctx, plan)
		if err != nil {
			return fmt.Errorf("snapshot %s: %w", plan.Family, err)
		}
		snapshots = append(snapshots, snapshot)
		plans = append(plans, plan)
	}

	for _, plan := range plans {
		var err error
		if remove || !plan.Enabled {
			err = m.backend.Remove(ctx, plan)
			if err == nil {
				err = m.backend.VerifyRemoved(ctx, plan)
			}
		} else {
			if !plan.WaitSupported {
				err = ErrXTablesLockMissing
			} else {
				err = m.backend.Install(ctx, plan)
				if err == nil {
					err = m.backend.Verify(ctx, plan)
				}
			}
		}
		if err != nil {
			rollbackErr := m.restoreSnapshots(snapshots)
			if rollbackErr != nil {
				return fmt.Errorf("reconcile %s at family %s: %w; rollback: %v", operationName(remove), plan.Family, err, rollbackErr)
			}
			return fmt.Errorf("reconcile %s at family %s: %w", operationName(remove), plan.Family, err)
		}
	}
	return nil
}

func (m *TransactionManager) restoreSnapshots(snapshots []FamilySnapshot) error {
	timeout := m.rollbackTimeout
	if timeout <= 0 {
		timeout = defaultRollbackTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var errs []error
	for i := len(snapshots) - 1; i >= 0; i-- {
		if err := m.backend.Restore(ctx, snapshots[i]); err != nil {
			errs = append(errs, fmt.Errorf("restore %s: %w", snapshots[i].Family, err))
		}
	}
	return errors.Join(errs...)
}

func validateDesiredState(desired DesiredState) error {
	if desired.Generation == "" || len(desired.Families) == 0 {
		return ErrInvalidDesiredState
	}
	seen := make(map[string]struct{}, len(desired.Families))
	for _, plan := range desired.Families {
		if plan.Family == "" || plan.Binary == "" {
			return ErrInvalidDesiredState
		}
		if _, ok := seen[plan.Family]; ok {
			return fmt.Errorf("%w: duplicate family %s", ErrInvalidDesiredState, plan.Family)
		}
		seen[plan.Family] = struct{}{}
	}
	return nil
}

func operationName(remove bool) string {
	if remove {
		return "remove"
	}
	return "apply"
}

func familyNames(desired DesiredState) []string {
	out := make([]string, 0, len(desired.Families))
	for _, family := range desired.Families {
		out = append(out, family.Family)
	}
	return out
}

func cloneDesiredState(in DesiredState) DesiredState {
	out := in
	out.EffectiveTCPPorts = append([]uint16(nil), in.EffectiveTCPPorts...)
	out.EffectiveUDPPorts = append([]uint16(nil), in.EffectiveUDPPorts...)
	out.Warnings = append([]string(nil), in.Warnings...)
	out.Families = make([]FamilyPlan, len(in.Families))
	for i, family := range in.Families {
		out.Families[i] = family
		out.Families[i].Rules = append([]string(nil), family.Rules...)
	}
	return out
}
