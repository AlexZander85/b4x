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
