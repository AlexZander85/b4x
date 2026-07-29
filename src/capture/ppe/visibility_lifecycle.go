package ppe

import "context"

type visibilityLifecycleManager struct {
	next LifecycleManager
	gate *VisibilityGate
}

func WrapLifecycleWithVisibility(next LifecycleManager, gate *VisibilityGate) LifecycleManager {
	if next == nil {
		return nil
	}
	if gate == nil {
		gate = DefaultVisibilityGate()
	}
	return &visibilityLifecycleManager{next: next, gate: gate}
}

func WrapLifecycleWithDefaultVisibility(next LifecycleManager) LifecycleManager {
	return WrapLifecycleWithVisibility(next, DefaultVisibilityGate())
}

func (m *visibilityLifecycleManager) Current() (DesiredState, bool) {
	desired, ok := m.next.Current()
	if ok && desired.Policy == "exclude" {
		m.gate.EnsureRequired(desired.Generation, "active PPE exclusion generation requires controlled visibility proof")
	}
	return desired, ok
}

func (m *visibilityLifecycleManager) Assert(ctx context.Context) error {
	desired, _ := m.next.Current()
	err := m.next.Assert(ctx)
	if err != nil {
		m.gate.Degrade(desired.Generation, "PPE rules disappeared or failed exact verification")
	}
	return err
}

func (m *visibilityLifecycleManager) Reapply(ctx context.Context) (TransactionResult, error) {
	desired, _ := m.next.Current()
	result, err := m.next.Reapply(ctx)
	if err != nil {
		m.gate.Degrade(desired.Generation, "PPE rule reapply failed")
		return result, err
	}
	m.gate.Invalidate(desired.Generation, "PPE rules were reasserted; visibility must be revalidated")
	return result, nil
}
