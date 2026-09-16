package discovery

import (
	"errors"
	"sync"

	"github.com/daniellavrushin/b4/observability"
)

// SynthesisRunStore is intentionally transient and run-scoped. It provides
// immutable references for GuidedSearchPlan without creating a second
// optimizer or permanent candidate catalog.
type SynthesisRunStore struct {
	mu         sync.RWMutex
	requestID  string
	maxEntries int
	plans      map[string]SynthesizedCandidatePlan
	order      []string
}

func NewSynthesisRunStore(requestID string, maxEntries int) *SynthesisRunStore {
	if maxEntries <= 0 {
		maxEntries = int(DefaultSynthesisLimits().MaxCandidates)
	}
	return &SynthesisRunStore{requestID: requestID, maxEntries: maxEntries, plans: make(map[string]SynthesizedCandidatePlan)}
}

func (s *SynthesisRunStore) Put(plan SynthesizedCandidatePlan) error {
	if s == nil || s.requestID == "" {
		return errors.New("synthesis run store unavailable")
	}
	if !plan.ValidIdentity() {
		return errors.New("invalid synthesized candidate identity")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.plans[plan.CandidateID]; ok {
		if existing.CanonicalHash != plan.CanonicalHash {
			observability.RecordSynthesisViolation(observability.MetricSynthesisCandidateIdentityCollision)
			return errors.New("candidate identity collision")
		}
		return nil
	}
	if len(s.plans) >= s.maxEntries {
		observability.RecordSynthesisViolation(observability.MetricSynthesisUnboundedExecution)
		return errors.New("synthesis run store bound reached")
	}
	s.plans[plan.CandidateID] = plan
	s.order = append(s.order, plan.CandidateID)
	return nil
}

func (s *SynthesisRunStore) Get(candidateID string) (SynthesizedCandidatePlan, bool) {
	if s == nil {
		return SynthesizedCandidatePlan{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	plan, ok := s.plans[candidateID]
	return plan, ok
}

func (s *SynthesisRunStore) IDs() []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.order...)
}

func (s *SynthesisRunStore) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.plans {
		delete(s.plans, k)
	}
	s.order = nil
}
