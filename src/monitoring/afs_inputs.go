package monitoring

import (
	"fmt"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

// SynthesisInputs is the per-scope AFS preflight snapshot retained by the
// production monitoring runtime: the last decided assessment and the compiled
// ABD blocking profile for that scope. It lets a later bounded synthesis run be
// gated from real ABD evidence instead of re-deriving (or fabricating) it.
//
// It carries no apply authority and no packet program; promotion stays with the
// existing transactional runtime.
type SynthesisInputs struct {
	Scope      monitor.MonitorScopeKey
	Assessment monitor.MonitorAssessment
	Profile    detector.BlockingProfile
	UpdatedAt  time.Time
}

type synthesisInputStore struct {
	mu      sync.Mutex
	entries map[string]SynthesisInputs
}

func newSynthesisInputStore() *synthesisInputStore {
	return &synthesisInputStore{entries: map[string]SynthesisInputs{}}
}

func (s *synthesisInputStore) put(in SynthesisInputs) {
	if s == nil || !in.Scope.Valid() {
		return
	}
	s.mu.Lock()
	s.entries[synthesisInputKey(in.Scope)] = in
	s.mu.Unlock()
}

func (s *synthesisInputStore) get(scope monitor.MonitorScopeKey) (SynthesisInputs, bool) {
	if s == nil || !scope.Valid() {
		return SynthesisInputs{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	in, ok := s.entries[synthesisInputKey(scope)]
	return in, ok
}

// synthesisInputKey mirrors the monitor correlation key: service/component/
// client/domain scope plus config generation and network context.
func synthesisInputKey(scope monitor.MonitorScopeKey) string {
	return fmt.Sprintf("%s|%s|%s|%s|%d|%s",
		scope.ClientScope.ID, scope.ServiceProfileID, scope.ComponentID,
		scope.DomainIdentityID, scope.ConfigGeneration, scope.NetworkContextID)
}

// SynthesisInputs returns the last retained AFS preflight snapshot for the
// scope (read-only). It is false until a decided diagnostic has run for it.
func (rt *Runtime) SynthesisInputs(scope monitor.MonitorScopeKey) (SynthesisInputs, bool) {
	if rt == nil || rt.inputs == nil {
		return SynthesisInputs{}, false
	}
	return rt.inputs.get(scope)
}
