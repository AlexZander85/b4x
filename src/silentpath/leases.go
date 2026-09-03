package silentpath

import (
	"sync"
	"time"
)

type Lease struct {
	ID                    string
	Scope                 Scope
	From, To              string
	ConfigGen             uint64
	ExpiresAt             time.Time
	Attempts, MaxAttempts uint8
	Rollback              string
}
type LeaseStore struct {
	mu sync.Mutex
	m  map[string]Lease
}

func NewLeaseStore() *LeaseStore { return &LeaseStore{m: map[string]Lease{}} }
func (s *LeaseStore) Put(l Lease, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l.ID == "" || l.Scope.ConfigGen == 0 || l.Scope.ConfigGen != l.ConfigGen || l.From == "" || l.To == "" || l.From == l.To || l.Rollback == "" || !now.Before(l.ExpiresAt) || l.Attempts >= l.MaxAttempts {
		return false
	}
	s.m[l.ID] = l
	return true
}
func (s *LeaseStore) Get(id string, scope Scope, now time.Time) (Lease, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.m[id]
	if !ok || !now.Before(l.ExpiresAt) || l.Scope != scope {
		delete(s.m, id)
		return Lease{}, false
	}
	return l, true
}
