package mtproto

import (
	"testing"
	"time"
)

func TestPendingManagerBudgetsAndCleanup(t *testing.T) {
	m := NewPendingHandshakeManager(2, 1)
	now := time.Unix(28000, 0)
	a, err := m.Acquire("a", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Acquire("a", now); err != ErrPendingOverflow {
		t.Fatal("per-client overflow missing")
	}
	if _, err := m.Acquire("b", now); err != nil {
		t.Fatal(err)
	}
	if m.Len() != 2 {
		t.Fatal("global count wrong")
	}
	m.Reload()
	if m.Len() != 0 {
		t.Fatal("reload leaked pending")
	}
	if m.Release(a.ID) {
		t.Fatal("old token released after reload")
	}
	m.Close()
	if _, err := m.Acquire("c", now); err != ErrPendingOverflow {
		t.Fatal("closed manager accepted token")
	}
}
