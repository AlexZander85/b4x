package warp

import "testing"

func TestSecretStoreCopiesAndRedacts(t *testing.T) {
	s := NewSecretStore()
	raw := []byte("secret")
	if err := s.Put("id", raw); err != nil {
		t.Fatal(err)
	}
	raw[0] = 'x'
	got, _ := s.Get("id")
	if string(got) != "secret" {
		t.Fatal("secret alias")
	}
	if s.Redacted()["id"] != "[redacted]" {
		t.Fatal("secret not redacted")
	}
}
func TestEnrollmentRollback(t *testing.T) {
	tx := EnrollmentTransaction{CandidateID: "c", Previous: "old", Next: "new"}
	tx.Commit()
	tx.Rollback()
	if tx.Committed || tx.Next != "old" {
		t.Fatal(tx)
	}
}
