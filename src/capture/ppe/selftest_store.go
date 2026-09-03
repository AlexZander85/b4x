package ppe

import "sync"

type MemorySelfTestStore struct {
	mu      sync.RWMutex
	limit   int
	order   []string
	results map[string]CaptureVisibilityResult
}

func NewMemorySelfTestStore(limit int) *MemorySelfTestStore {
	if limit <= 0 {
		limit = 64
	}
	return &MemorySelfTestStore{limit: limit, results: make(map[string]CaptureVisibilityResult)}
}

func (s *MemorySelfTestStore) Put(result CaptureVisibilityResult) {
	if s == nil || result.RunID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.results[result.RunID]; !exists {
		s.order = append(s.order, result.RunID)
	}
	s.results[result.RunID] = cloneVisibilityResult(result)
	for len(s.order) > s.limit {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.results, oldest)
	}
}

func (s *MemorySelfTestStore) Get(runID string) (CaptureVisibilityResult, bool) {
	if s == nil {
		return CaptureVisibilityResult{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result, ok := s.results[runID]
	return cloneVisibilityResult(result), ok
}

func cloneVisibilityResult(in CaptureVisibilityResult) CaptureVisibilityResult {
	out := in
	out.Evidence = append([]string(nil), in.Evidence...)
	out.RuleCountersBefore = cloneCounters(in.RuleCountersBefore)
	out.RuleCountersAfter = cloneCounters(in.RuleCountersAfter)
	return out
}

func cloneCounters(in map[string]uint64) map[string]uint64 {
	if in == nil {
		return nil
	}
	out := make(map[string]uint64, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}
