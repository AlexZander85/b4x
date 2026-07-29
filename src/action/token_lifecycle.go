package action

import (
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
)

func (s *ActionTokenStore) CloseServerProgress(flowHash uint64) bool {
	if s == nil || flowHash == 0 {
		return false
	}
	if !ppe.DefaultVisibilityGate().Decision(ppe.VisibilityFeatureACKReplay).Allowed {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[flowHash]
	if entry == nil || entry.closed {
		return false
	}
	entry.closed = true
	s.stats.ServerProgressClosed++
	return true
}

func (s *ActionTokenStore) InvalidateGeneration(generation uint64) int {
	if s == nil || generation == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidated[generation] = struct{}{}
	if len(s.invalidated) > 64 {
		for candidate := range s.invalidated {
			if candidate != generation {
				delete(s.invalidated, candidate)
				break
			}
		}
	}
	removed := 0
	for flow, entry := range s.entries {
		if entry.token.ConfigGen == generation {
			delete(s.entries, flow)
			removed++
		}
	}
	return removed
}

func (s *ActionTokenStore) GC(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneExpiredLocked(now)
}

func (s *ActionTokenStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *ActionTokenStore) Stats() ActionTokenStats {
	if s == nil {
		return ActionTokenStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *ActionTokenStore) oldestFlowLocked() uint64 {
	var oldest uint64
	var order uint64
	first := true
	for flow, entry := range s.entries {
		if first || entry.order < order {
			oldest, order, first = flow, entry.order, false
		}
	}
	return oldest
}

func (s *ActionTokenStore) pruneExpiredLocked(now time.Time) int {
	removed := 0
	for flow, entry := range s.entries {
		if now.Sub(entry.lastSeen) >= s.config.Timeout {
			delete(s.entries, flow)
			removed++
			s.stats.Expired++
		}
	}
	return removed
}
