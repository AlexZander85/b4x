package ppe

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type fakeLifecycleManager struct {
	mu         sync.Mutex
	active     bool
	present    bool
	reapplyErr error
	reapplies  int
	state      DesiredState
}

func (f *fakeLifecycleManager) Current() (DesiredState, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return cloneDesiredState(f.state), f.active
}

func (f *fakeLifecycleManager) Assert(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.active {
		return ErrNoActiveGeneration
	}
	if !f.present {
		return errors.New("owned PPE rules missing")
	}
	return nil
}

func (f *fakeLifecycleManager) Reapply(context.Context) (TransactionResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reapplies++
	if f.reapplyErr != nil {
		return TransactionResult{}, f.reapplyErr
	}
	f.present = true
	return TransactionResult{Generation: f.state.Generation}, nil
}

func (f *fakeLifecycleManager) wipe() {
	f.mu.Lock()
	f.present = false
	f.mu.Unlock()
}

func (f *fakeLifecycleManager) reapplyCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reapplies
}

func TestReconcilerRestoresSimulatedTableWipeOnce(t *testing.T) {
	manager := &fakeLifecycleManager{active: true, state: desiredTransactionState("active")}
	clock := time.Date(2026, 7, 28, 20, 0, 0, 0, time.UTC)
	r := NewReconciler(manager, ReconcilerConfig{MinReapplyInterval: time.Minute, FailureBackoff: time.Minute, OperationTimeout: time.Second})
	r.now = func() time.Time { return clock }

	if err := r.ReconcileNow(context.Background(), ReconcileNDMEvent); err != nil {
		t.Fatal(err)
	}
	if manager.reapplyCount() != 1 {
		t.Fatalf("reapplies=%d", manager.reapplyCount())
	}
	if err := r.ReconcileNow(context.Background(), ReconcilePeriodic); err != nil {
		t.Fatalf("healthy assert failed: %v", err)
	}
	if manager.reapplyCount() != 1 {
		t.Fatalf("healthy assert caused duplicate reapply: %d", manager.reapplyCount())
	}
	status := r.Status()
	if status.Reapplied != 1 || !status.RulesPresent {
		t.Fatalf("status=%+v", status)
	}
}

func TestReconcilerSuppressesReapplyStorm(t *testing.T) {
	manager := &fakeLifecycleManager{active: true, state: desiredTransactionState("active")}
	clock := time.Date(2026, 7, 28, 20, 0, 0, 0, time.UTC)
	r := NewReconciler(manager, ReconcilerConfig{MinReapplyInterval: time.Minute, FailureBackoff: time.Minute, OperationTimeout: time.Second})
	r.now = func() time.Time { return clock }

	if err := r.ReconcileNow(context.Background(), ReconcileNDMEvent); err != nil {
		t.Fatal(err)
	}
	manager.wipe()
	if err := r.ReconcileNow(context.Background(), ReconcileNDMEvent); !errors.Is(err, ErrReapplySuppressed) {
		t.Fatalf("expected storm suppression, got %v", err)
	}
	if manager.reapplyCount() != 1 {
		t.Fatalf("reapply storm count=%d", manager.reapplyCount())
	}
	if r.Status().Suppressed != 1 {
		t.Fatalf("status=%+v", r.Status())
	}
}

func TestReconcilerFailureBackoff(t *testing.T) {
	manager := &fakeLifecycleManager{active: true, state: desiredTransactionState("active"), reapplyErr: errors.New("lock busy")}
	clock := time.Date(2026, 7, 28, 20, 0, 0, 0, time.UTC)
	r := NewReconciler(manager, ReconcilerConfig{MinReapplyInterval: time.Second, FailureBackoff: time.Minute, OperationTimeout: time.Second})
	r.now = func() time.Time { return clock }
	if err := r.ReconcileNow(context.Background(), ReconcileNDMEvent); err == nil {
		t.Fatal("failed reapply was accepted")
	}
	clock = clock.Add(2 * time.Second)
	if err := r.ReconcileNow(context.Background(), ReconcilePeriodic); !errors.Is(err, ErrReapplySuppressed) {
		t.Fatalf("failure backoff not applied: %v", err)
	}
	if manager.reapplyCount() != 1 {
		t.Fatalf("failure storm count=%d", manager.reapplyCount())
	}
}

func TestReconcilerCoalescesQueuedEvents(t *testing.T) {
	manager := &fakeLifecycleManager{active: true, present: true, state: desiredTransactionState("active")}
	r := NewReconciler(manager, DefaultReconcilerConfig(time.Hour))
	r.Notify(ReconcileNDMEvent)
	r.Notify(ReconcileNDMEvent)
	if r.Status().CoalescedEvents != 1 {
		t.Fatalf("status=%+v", r.Status())
	}
}
