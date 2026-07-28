package ppe

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestTransactionApplyInterruptedRestoresEveryFamily(t *testing.T) {
	backend := newFakeTransactionBackend()
	old4 := oldSnapshot("ipv4", "iptables", "old4")
	old6 := oldSnapshot("ipv6", "ip6tables", "old6")
	backend.current["ipv4"] = old4
	backend.current["ipv6"] = old6
	backend.failOperation = "install"
	backend.failFamily = "ipv6"
	manager := NewTransactionManager(backend)

	_, err := manager.Apply(context.Background(), desiredTransactionState("new"))
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected interrupted apply, got %v", err)
	}
	if !reflect.DeepEqual(backend.current["ipv4"], old4) || !reflect.DeepEqual(backend.current["ipv6"], old6) {
		t.Fatalf("previous generation was not restored: %+v", backend.current)
	}
	if backend.restoreCancelled {
		t.Fatal("rollback reused cancelled request context")
	}
}

func TestTransactionVerifyFailureRestoresPreviousGeneration(t *testing.T) {
	backend := newFakeTransactionBackend()
	old := oldSnapshot("ipv4", "iptables", "old")
	backend.current["ipv4"] = old
	backend.failOperation = "verify"
	backend.failFamily = "ipv4"
	manager := NewTransactionManager(backend)
	state := desiredTransactionState("candidate")
	state.Families = state.Families[:1]

	if _, err := manager.Apply(context.Background(), state); err == nil {
		t.Fatal("verification failure was accepted")
	}
	if !reflect.DeepEqual(backend.current["ipv4"], old) {
		t.Fatalf("previous generation was not restored: %+v", backend.current["ipv4"])
	}
}

func TestTransactionRemoveFailureRestoresPreviousGeneration(t *testing.T) {
	backend := newFakeTransactionBackend()
	old4 := oldSnapshot("ipv4", "iptables", "old4")
	old6 := oldSnapshot("ipv6", "ip6tables", "old6")
	backend.current["ipv4"] = old4
	backend.current["ipv6"] = old6
	backend.failOperation = "remove"
	backend.failFamily = "ipv6"
	manager := NewTransactionManager(backend)

	if _, err := manager.Remove(context.Background(), desiredTransactionState("active")); err == nil {
		t.Fatal("remove failure was accepted")
	}
	if !reflect.DeepEqual(backend.current["ipv4"], old4) || !reflect.DeepEqual(backend.current["ipv6"], old6) {
		t.Fatalf("remove rollback failed: %+v", backend.current)
	}
}

func TestTransactionRejectsUnprovenXTablesLock(t *testing.T) {
	backend := newFakeTransactionBackend()
	manager := NewTransactionManager(backend)
	state := desiredTransactionState("candidate")
	state.Families = state.Families[:1]
	state.Families[0].WaitSupported = false
	if _, err := manager.Apply(context.Background(), state); !errors.Is(err, ErrXTablesLockMissing) {
		t.Fatalf("unproven lock support accepted: %v", err)
	}
}
