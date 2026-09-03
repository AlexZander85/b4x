package routing

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/classifier"
)

var (
	ErrBindingAuthorization = errors.New("route binding requires final exact-flow action authorization")
	ErrBindingCapability    = errors.New("platform cannot isolate the requested route scope")
	ErrBindingScope         = errors.New("route binding scope is incomplete")
)

type BindingCapabilities struct {
	ExactFlow         bool
	ClientDestination bool
}

type AuthorizedFlowBinding struct {
	ID            string
	Owner         string
	SetID         string
	Client        classifier.ClientKey
	FlowKey       classifier.FlowKey
	ConfigGen     uint64
	Provenance    string
	TransactionID string
	RouteID       string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type BindingRequest struct {
	Authorization classifier.ActionAuthorization
	Owner         string
	Provenance    string
	TransactionID string
	RouteID       string
	Timeout       time.Duration
}

type BindingStore struct {
	mu           sync.Mutex
	bindings     map[string]AuthorizedFlowBinding
	capabilities BindingCapabilities
	maxEntries   int
}

func NewBindingStore(capabilities BindingCapabilities, maxEntries int) *BindingStore {
	if maxEntries <= 0 {
		maxEntries = 4096
	}
	return &BindingStore{bindings: make(map[string]AuthorizedFlowBinding), capabilities: capabilities, maxEntries: maxEntries}
}

func (s *BindingStore) Bind(request BindingRequest, now time.Time) (AuthorizedFlowBinding, error) {
	if s == nil || !s.capabilities.ExactFlow {
		return AuthorizedFlowBinding{}, ErrBindingCapability
	}
	auth := request.Authorization
	if !auth.ValidFor(auth.FlowKey, auth.Client, auth.SetID, auth.ConfigGen, 0, auth.FlowKey.Proto, now) {
		return AuthorizedFlowBinding{}, ErrBindingAuthorization
	}
	if strings.TrimSpace(request.Owner) == "" || strings.TrimSpace(request.RouteID) == "" || strings.TrimSpace(auth.SetID) == "" || auth.Client.IsZero() {
		return AuthorizedFlowBinding{}, ErrBindingScope
	}
	if request.Timeout <= 0 || request.Timeout > 5*time.Minute {
		request.Timeout = 2 * time.Minute
	}
	binding := AuthorizedFlowBinding{
		ID: auth.ID, Owner: strings.TrimSpace(request.Owner), SetID: auth.SetID, Client: auth.Client, FlowKey: auth.FlowKey.Normalize(),
		ConfigGen: auth.ConfigGen, Provenance: strings.TrimSpace(request.Provenance), TransactionID: strings.TrimSpace(request.TransactionID),
		RouteID: strings.TrimSpace(request.RouteID), CreatedAt: now, ExpiresAt: now.Add(request.Timeout),
	}
	if binding.ID == "" {
		binding.ID = fmt.Sprintf("%v|%s|%d", binding.FlowKey, binding.SetID, binding.ConfigGen)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	if len(s.bindings) >= s.maxEntries {
		var oldestID string
		var oldest time.Time
		first := true
		for id, candidate := range s.bindings {
			if first || candidate.CreatedAt.Before(oldest) {
				oldestID, oldest, first = id, candidate.CreatedAt, false
			}
		}
		if oldestID != "" {
			delete(s.bindings, oldestID)
		}
	}
	s.bindings[binding.ID] = binding
	return binding, nil
}

func (s *BindingStore) Lookup(id string, now time.Time) (AuthorizedFlowBinding, bool) {
	if s == nil {
		return AuthorizedFlowBinding{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gcLocked(now)
	binding, ok := s.bindings[id]
	return binding, ok
}
func (s *BindingStore) DeleteOwned(owner, transactionID string) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, binding := range s.bindings {
		if binding.Owner == owner && (transactionID == "" || binding.TransactionID == transactionID) {
			delete(s.bindings, id)
			removed++
		}
	}
	return removed
}
func (s *BindingStore) DeleteFlow(flow classifier.FlowKey) int {
	if s == nil {
		return 0
	}
	flow = flow.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, binding := range s.bindings {
		if binding.FlowKey == flow {
			delete(s.bindings, id)
			removed++
		}
	}
	return removed
}
func (s *BindingStore) InvalidateGeneration(generation uint64) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, binding := range s.bindings {
		if binding.ConfigGen == generation {
			delete(s.bindings, id)
			removed++
		}
	}
	return removed
}
func (s *BindingStore) GC(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	before := len(s.bindings)
	s.gcLocked(now)
	return before - len(s.bindings)
}
func (s *BindingStore) gcLocked(now time.Time) {
	for id, binding := range s.bindings {
		if !now.Before(binding.ExpiresAt) {
			delete(s.bindings, id)
		}
	}
}
