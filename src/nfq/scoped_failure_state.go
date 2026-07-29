package nfq

import (
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

type scopedAttempt struct {
	count     int
	firstSeen time.Time
	lastSeen  time.Time
}

type scopedEscalation struct {
	nextSetID string
	hops      int
	expiresAt time.Time
}

type scopedFailureState struct {
	mu          sync.Mutex
	attempts    map[classifier.ScopedFailureKey]scopedAttempt
	blocked     map[classifier.ScopedFailureKey]time.Time
	escalations map[classifier.ScopedEscalationKey]scopedEscalation
	rstSent     map[classifier.FlowKey]time.Time
	maxEntries  int
}

func newScopedFailureState() *scopedFailureState {
	return &scopedFailureState{
		attempts: make(map[classifier.ScopedFailureKey]scopedAttempt), blocked: make(map[classifier.ScopedFailureKey]time.Time),
		escalations: make(map[classifier.ScopedEscalationKey]scopedEscalation), rstSent: make(map[classifier.FlowKey]time.Time), maxEntries: 8192,
	}
}

func normalizeScopedFailureKey(key classifier.ScopedFailureKey) classifier.ScopedFailureKey {
	key.DomainKey = strings.ToLower(strings.TrimSpace(key.DomainKey))
	key.SetID = strings.TrimSpace(key.SetID)
	if key.DestinationIP.Is4In6() {
		key.DestinationIP = key.DestinationIP.Unmap()
	}
	return key
}

func (s *scopedFailureState) RecordAttempt(key classifier.ScopedFailureKey, now time.Time) (int, time.Time) {
	key = normalizeScopedFailureKey(key)
	if s == nil || key.Client.IsZero() || !key.DestinationIP.IsValid() || key.DomainKey == "" || key.SetID == "" {
		return 0, time.Time{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	entry := s.attempts[key]
	if entry.firstSeen.IsZero() {
		entry.firstSeen = now
	}
	entry.count++
	entry.lastSeen = now
	s.attempts[key] = entry
	return entry.count, entry.firstSeen
}

func (s *scopedFailureState) IsBlocked(key classifier.ScopedFailureKey, now time.Time) bool {
	key = normalizeScopedFailureKey(key)
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	expires, ok := s.blocked[key]
	return ok && now.Before(expires)
}

func (s *scopedFailureState) AddBlocked(key classifier.ScopedFailureKey, ttl time.Duration, now time.Time) bool {
	key = normalizeScopedFailureKey(key)
	if s == nil || key.Client.IsZero() || !key.DestinationIP.IsValid() || key.DomainKey == "" || key.SetID == "" {
		return false
	}
	if ttl <= 0 || ttl > 5*time.Minute {
		ttl = 5 * time.Minute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	s.blocked[key] = now.Add(ttl)
	return true
}

func (s *scopedFailureState) GetEscalation(key classifier.ScopedEscalationKey, now time.Time) (string, int, bool) {
	key.DomainKey = strings.ToLower(strings.TrimSpace(key.DomainKey))
	key.SetID = strings.TrimSpace(key.SetID)
	if s == nil {
		return "", 0, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	entry, ok := s.escalations[key]
	return entry.nextSetID, entry.hops, ok && now.Before(entry.expiresAt)
}

func (s *scopedFailureState) SetEscalation(key classifier.ScopedEscalationKey, nextSetID string, ttl time.Duration, now time.Time) bool {
	key.DomainKey = strings.ToLower(strings.TrimSpace(key.DomainKey))
	key.SetID = strings.TrimSpace(key.SetID)
	nextSetID = strings.TrimSpace(nextSetID)
	if s == nil || key.Client.IsZero() || key.DomainKey == "" || key.SetID == "" || nextSetID == "" {
		return false
	}
	if ttl <= 0 || ttl > time.Hour {
		ttl = time.Hour
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	entry := s.escalations[key]
	entry.hops++
	if entry.hops > MaxEscalationHops {
		return false
	}
	entry.nextSetID = nextSetID
	entry.expiresAt = now.Add(ttl)
	s.escalations[key] = entry
	return true
}

func (s *scopedFailureState) HasRSTSent(flow classifier.FlowKey, now time.Time) bool {
	if s == nil {
		return false
	}
	flow = flow.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	_, ok := s.rstSent[flow]
	return ok
}
func (s *scopedFailureState) MarkRSTSent(flow classifier.FlowKey, now time.Time) {
	if s == nil {
		return
	}
	flow = flow.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	s.rstSent[flow] = now.Add(2 * time.Minute)
}
func (s *scopedFailureState) DeleteFlow(flow classifier.FlowKey) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.rstSent, flow.Normalize())
	s.mu.Unlock()
}
func (s *scopedFailureState) InvalidateGeneration(generation uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.attempts {
		if k.ConfigGen == generation {
			delete(s.attempts, k)
		}
	}
	for k := range s.blocked {
		if k.ConfigGen == generation {
			delete(s.blocked, k)
		}
	}
	for k := range s.escalations {
		if k.ConfigGen == generation {
			delete(s.escalations, k)
		}
	}
}
func (s *scopedFailureState) GC(now time.Time) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
}
func (s *scopedFailureState) gcLocked(now time.Time) {
	for k, v := range s.attempts {
		if now.Sub(v.lastSeen) > 2*time.Minute {
			delete(s.attempts, k)
		}
	}
	for k, expiry := range s.blocked {
		if !now.Before(expiry) {
			delete(s.blocked, k)
		}
	}
	for k, v := range s.escalations {
		if !now.Before(v.expiresAt) {
			delete(s.escalations, k)
		}
	}
	for k, expiry := range s.rstSent {
		if !now.Before(expiry) {
			delete(s.rstSent, k)
		}
	}
}
