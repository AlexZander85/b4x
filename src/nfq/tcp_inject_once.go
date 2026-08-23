package nfq

import (
	"sync"
	"time"
)

// tcpInjectOnceStore remembers 4-tuples that already received fake-SNI /
// fragmentation. Later segments of the same ClientHello (ECH ~1.8KiB split
// across MSS) must be accepted unchanged — a second fake SNI on the tail
// desynchronizes the server and stalls seek.
type tcpInjectOnceStore struct {
	mu     sync.Mutex
	claims map[string]time.Time
	ttl    time.Duration
	max    int
}

func newTCPInjectOnceStore() *tcpInjectOnceStore {
	return &tcpInjectOnceStore{
		claims: make(map[string]time.Time),
		ttl:    2 * time.Minute,
		max:    4096,
	}
}

// Claim is true only the first time key is seen within ttl.
func (s *tcpInjectOnceStore) Claim(key string, now time.Time) bool {
	if s == nil || key == "" {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	if _, exists := s.claims[key]; exists {
		return false
	}
	if len(s.claims) >= s.max {
		var oldest string
		var oldestAt time.Time
		first := true
		for k, at := range s.claims {
			if first || at.Before(oldestAt) {
				oldest, oldestAt, first = k, at, false
			}
		}
		if !first {
			delete(s.claims, oldest)
		}
	}
	s.claims[key] = now
	return true
}

func (s *tcpInjectOnceStore) gcLocked(now time.Time) {
	for k, at := range s.claims {
		if now.Sub(at) >= s.ttl {
			delete(s.claims, k)
		}
	}
}
