package discovery

import (
	"errors"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/detector"
)

func CompileNetworkDiagnosticProfile(p detector.BlockingProfile, expires, now time.Time) (NetworkDiagnosticProfile, error) {
	return NewNetworkDiagnosticProfile(p, expires, now)
}

type ProfileStore struct {
	mu       sync.Mutex
	max      int
	profiles map[string]NetworkDiagnosticProfile
	revoked  map[string]time.Time
}

func NewProfileStore(max int) *ProfileStore {
	if max <= 0 {
		max = 128
	}
	return &ProfileStore{max: max, profiles: map[string]NetworkDiagnosticProfile{}, revoked: map[string]time.Time{}}
}
func (s *ProfileStore) Put(p NetworkDiagnosticProfile, now time.Time) error {
	if s == nil || !p.Valid(now) {
		return errors.New("invalid diagnostic profile")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.profiles) >= s.max {
		return errors.New("profile store capacity exceeded")
	}
	if _, ok := s.revoked[p.ProfileID]; ok {
		return errors.New("profile revoked")
	}
	s.profiles[p.ProfileID] = p
	return nil
}
func (s *ProfileStore) Get(id string, now time.Time) (NetworkDiagnosticProfile, bool) {
	if s == nil {
		return NetworkDiagnosticProfile{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.profiles[id]
	if !ok || !p.Valid(now) {
		return NetworkDiagnosticProfile{}, false
	}
	if _, rev := s.revoked[id]; rev {
		return NetworkDiagnosticProfile{}, false
	}
	return p, true
}
func (s *ProfileStore) Revoke(id string, now time.Time) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.profiles[id]; !ok {
		return false
	}
	delete(s.profiles, id)
	s.revoked[id] = now
	return true
}
func (s *ProfileStore) Delete(id string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.profiles[id]; !ok {
		return false
	}
	delete(s.profiles, id)
	return true
}
func (s *ProfileStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.profiles)
}
