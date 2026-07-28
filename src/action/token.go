package action

import (
	"sync"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

type ActionToken struct {
	FlowHash      uint64
	ClientHelloID uint64
	StrategyID    string
	ConfigGen     uint64
}

type ActionTokenRequest struct {
	FlowHash       uint64
	ClientHelloID  uint64
	StrategyID     string
	ConfigGen      uint64
	StreamStart    uint64
	StreamEnd      uint64
	InputBytes     int
	Writes         int
	GeneratedBytes int
	PacketMark     uint32
	ProcessedMark  uint32
}

type ActionTokenResult struct {
	Applied    bool
	Reused     bool
	Suppressed bool
	Reason     string
	Token      ActionToken
}

type ActionTokenStoreConfig struct {
	MaxFlows int
	Timeout  time.Duration
	Clock    clock.Clock
	Budgets  ActionBudgets
}

func DefaultActionTokenStoreConfig() ActionTokenStoreConfig {
	return ActionTokenStoreConfig{MaxFlows: 4096, Timeout: 5 * time.Minute, Clock: clock.RealClock{}, Budgets: DefaultActionBudgets()}
}

type ActionTokenStats struct {
	Claims                uint64
	Applied               uint64
	Reused                uint64
	Suppressed            uint64
	BudgetRejected        uint64
	GenerationInvalidated uint64
	ServerProgressClosed  uint64
	Expired               uint64
	Evicted               uint64
}

type actionTokenEntry struct {
	token       ActionToken
	streamStart uint64
	streamEnd   uint64
	lastSeen    time.Time
	order       uint64
	closed      bool
}

// ActionTokenStore is bounded, race-safe and independent of packet I/O. A
// claim reserves one logical first-flight action; retransmissions and all
// later overlapping/new spans for that logical ClientHello are suppressed.
type ActionTokenStore struct {
	mu          sync.Mutex
	entries     map[uint64]*actionTokenEntry
	invalidated map[uint64]struct{}
	config      ActionTokenStoreConfig
	clock       clock.Clock
	order       uint64
	nextHelloID uint64
	stats       ActionTokenStats
}

func NewActionTokenStore(cfg ActionTokenStoreConfig) *ActionTokenStore {
	defaults := DefaultActionTokenStoreConfig()
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = defaults.MaxFlows
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaults.Timeout
	}
	if cfg.Clock == nil {
		cfg.Clock = defaults.Clock
	}
	if cfg.Budgets == (ActionBudgets{}) {
		cfg.Budgets = defaults.Budgets
	}
	return &ActionTokenStore{entries: make(map[uint64]*actionTokenEntry, cfg.MaxFlows), invalidated: make(map[uint64]struct{}), config: cfg, clock: cfg.Clock}
}

func (s *ActionTokenStore) Claim(request ActionTokenRequest) ActionTokenResult {
	if s == nil || request.FlowHash == 0 || request.StreamEnd <= request.StreamStart {
		return ActionTokenResult{Suppressed: true, Reason: "invalid action token request"}
	}
	if request.PacketMark != 0 && IsProcessedMark(request.PacketMark, request.ProcessedMark) {
		return ActionTokenResult{Suppressed: true, Reason: "processed provenance mark"}
	}
	if err := s.config.Budgets.Check(request.InputBytes, request.Writes, request.GeneratedBytes); err != nil {
		s.mu.Lock()
		s.stats.BudgetRejected++
		s.mu.Unlock()
		return ActionTokenResult{Suppressed: true, Reason: err.Error()}
	}
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Claims++
	s.pruneExpiredLocked(now)
	if _, invalid := s.invalidated[request.ConfigGen]; invalid && request.ConfigGen != 0 {
		s.stats.GenerationInvalidated++
		return ActionTokenResult{Suppressed: true, Reason: "config generation invalidated"}
	}
	if entry := s.entries[request.FlowHash]; entry != nil {
		if entry.token.ConfigGen != request.ConfigGen {
			delete(s.entries, request.FlowHash)
		} else {
			entry.lastSeen = now
			s.order++
			entry.order = s.order
			s.stats.Suppressed++
			if entry.closed {
				return ActionTokenResult{Suppressed: true, Reason: "server progress closed first-flight window", Token: entry.token}
			}
			s.stats.Reused++
			return ActionTokenResult{Reused: true, Suppressed: true, Reason: "logical ClientHello already claimed", Token: entry.token}
		}
	}
	for len(s.entries) >= s.config.MaxFlows {
		oldest := s.oldestFlowLocked()
		if oldest == 0 {
			break
		}
		delete(s.entries, oldest)
		s.stats.Evicted++
	}
	s.nextHelloID++
	helloID := request.ClientHelloID
	if helloID == 0 {
		helloID = s.nextHelloID
	}
	token := ActionToken{FlowHash: request.FlowHash, ClientHelloID: helloID, StrategyID: request.StrategyID, ConfigGen: request.ConfigGen}
	s.order++
	s.entries[request.FlowHash] = &actionTokenEntry{token: token, streamStart: request.StreamStart, streamEnd: request.StreamEnd, lastSeen: now, order: s.order}
	s.stats.Applied++
	return ActionTokenResult{Applied: true, Reason: "first logical ClientHello action claimed", Token: token}
}

func (s *ActionTokenStore) CloseServerProgress(flowHash uint64) bool {
	if s == nil || flowHash == 0 {
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
