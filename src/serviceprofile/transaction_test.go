package serviceprofile

import "testing"

func TestTransactionRollback(t *testing.T) {
	a := CompiledProfile{Sets: []OrdinarySet{{ID: "a", Ownership: Managed}}}
	b := CompiledProfile{Sets: []OrdinarySet{{ID: "b", Ownership: Managed}}}
	tx := Begin(a, b, 4)
	if len(tx.Preview.Changes) != 2 {
		t.Fatal(tx.Preview)
	}
	if got := tx.State(); len(got.Sets) != 1 || got.Sets[0].ID != "a" {
		t.Fatalf("state before apply must be previous, got %+v", got)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if got := tx.State(); len(got.Sets) != 1 || got.Sets[0].ID != "b" {
		t.Fatalf("state after apply must be candidate, got %+v", got)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if got := tx.State(); len(got.Sets) != 1 || got.Sets[0].ID != "a" {
		t.Fatalf("state after rollback must be previous again, got %+v", got)
	}
}

func TestTransactionApplyMovesStateAndLocks(t *testing.T) {
	a := CompiledProfile{Sets: []OrdinarySet{{ID: "a", Ownership: Managed}}}
	b := CompiledProfile{Sets: []OrdinarySet{{ID: "b", Ownership: Managed}}}
	tx := Begin(a, b, 1)
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	// A second Apply is a programming error and must be rejected.
	if err := tx.Apply(); err == nil {
		t.Fatal("second apply must fail")
	}
	// A rolled-back transaction is sealed: no Apply after Rollback.
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Apply(); err == nil {
		t.Fatal("apply after rollback must fail")
	}
	if err := tx.Rollback(); err == nil {
		t.Fatal("second rollback must fail")
	}
	if got := tx.State(); len(got.Sets) != 1 || got.Sets[0].ID != "a" {
		t.Fatalf("sealed transaction must expose previous profile, got %+v", got)
	}
}
