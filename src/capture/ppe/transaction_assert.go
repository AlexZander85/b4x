package ppe

import (
	"context"
	"errors"
	"fmt"
)

var ErrNoActiveGeneration = errors.New("no active PPE generation")

// Assert verifies the exact active PPE generation without mutating firewall state.
func (m *TransactionManager) Assert(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hasActive {
		return ErrNoActiveGeneration
	}
	return m.assertLocked(ctx, m.active)
}

// Reapply reconciles the currently active generation after an external table wipe.
// The active generation is retained only when exact verification succeeds.
func (m *TransactionManager) Reapply(ctx context.Context) (TransactionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.hasActive {
		return TransactionResult{}, ErrNoActiveGeneration
	}
	desired := cloneDesiredState(m.active)
	if err := m.reconcile(ctx, desired, false); err != nil {
		return TransactionResult{}, err
	}
	return TransactionResult{
		Generation:         desired.Generation,
		PreviousGeneration: desired.Generation,
		Families:           familyNames(desired),
		CompletedAt:        m.now().UTC(),
	}, nil
}

func (m *TransactionManager) assertLocked(ctx context.Context, desired DesiredState) error {
	if ctx == nil {
		ctx = context.Background()
	}
	for _, plan := range desired.Families {
		var err error
		if plan.Enabled {
			err = m.backend.Verify(ctx, plan)
		} else {
			err = m.backend.VerifyRemoved(ctx, plan)
		}
		if err != nil {
			return fmt.Errorf("assert family %s: %w", plan.Family, err)
		}
	}
	return nil
}
