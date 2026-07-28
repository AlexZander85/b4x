package ppe

import (
	"context"
	"errors"
	"testing"
)

func TestTransactionAssertAndReapplyAfterWipe(t *testing.T) {
	backend := newFakeTransactionBackend()
	manager := NewTransactionManager(backend)
	state := desiredTransactionState("active")
	state.Families = state.Families[:1]
	if _, err := manager.Apply(context.Background(), state); err != nil {
		t.Fatal(err)
	}
	if err := manager.Assert(context.Background()); err != nil {
		t.Fatalf("active generation did not verify: %v", err)
	}
	delete(backend.current, "ipv4")
	if err := manager.Assert(context.Background()); err == nil {
		t.Fatal("simulated table wipe was not detected")
	}
	if _, err := manager.Reapply(context.Background()); err != nil {
		t.Fatalf("reapply failed: %v", err)
	}
	if err := manager.Assert(context.Background()); err != nil {
		t.Fatalf("reapplied generation did not verify: %v", err)
	}
}

func TestTransactionAssertWithoutActiveGeneration(t *testing.T) {
	manager := NewTransactionManager(newFakeTransactionBackend())
	if err := manager.Assert(context.Background()); !errors.Is(err, ErrNoActiveGeneration) {
		t.Fatalf("assert error=%v", err)
	}
	if _, err := manager.Reapply(context.Background()); !errors.Is(err, ErrNoActiveGeneration) {
		t.Fatalf("reapply error=%v", err)
	}
}
