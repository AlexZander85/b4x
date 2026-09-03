package warp

import (
	"errors"
	"sync"
)

type SecretStore struct {
	mu         sync.Mutex
	data       map[string][]byte
	generation uint64
}

func NewSecretStore() *SecretStore { return &SecretStore{data: map[string][]byte{}} }
func (s *SecretStore) Put(id string, secret []byte) error {
	if s == nil || id == "" || len(secret) == 0 {
		return errors.New("invalid secret")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[id] = append([]byte(nil), secret...)
	s.generation++
	return nil
}
func (s *SecretStore) Get(id string) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[id]
	return append([]byte(nil), v...), ok
}
func (s *SecretStore) Delete(id string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, id)
	s.generation++
}
func (s *SecretStore) Redacted() map[string]string {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for id := range s.data {
		out[id] = "[redacted]"
	}
	return out
}

type EnrollmentTransaction struct {
	CandidateID    string
	Previous, Next string
	Committed      bool
}

func (t *EnrollmentTransaction) Commit() {
	if t != nil {
		t.Committed = true
	}
}
func (t *EnrollmentTransaction) Rollback() {
	if t != nil {
		t.Committed = false
		t.Next = t.Previous
	}
}
