package serviceprofile

import "testing"

func TestTransactionRollback(t *testing.T) {
	a := CompiledProfile{Sets: []OrdinarySet{{ID: "a", Ownership: Managed}}}
	b := CompiledProfile{Sets: []OrdinarySet{{ID: "b", Ownership: Managed}}}
	tx := Begin(a, b, 4)
	if len(tx.Preview.Changes) != 2 {
		t.Fatal(tx.Preview)
	}
	if err := tx.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
}
