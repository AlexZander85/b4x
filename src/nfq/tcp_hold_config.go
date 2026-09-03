package nfq

import (
	"sync"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/florianl/go-nfqueue"
)

const (
	tcpHoldAbortTimeout    = "timeout"
	tcpHoldAbortPressure   = "pressure"
	tcpHoldAbortGeneration = "config-generation-change"
	tcpHoldAbortFIN        = "fin"
	tcpHoldAbortRST        = "rst"
	tcpHoldAbortServer     = "server-progress"
	tcpHoldAbortShutdown   = "shutdown"
	tcpHoldAbortVisibility = "capture-visibility-incomplete"
)

type TCPHoldConfig struct {
	MaxFlows          int
	MaxPacketsPerFlow int
	MaxBytesTotal     int
	Timeout           time.Duration
	Clock             clock.Clock
}

func DefaultTCPHoldConfig() TCPHoldConfig {
	return TCPHoldConfig{
		MaxFlows:          256,
		MaxPacketsPerFlow: 8,
		MaxBytesTotal:     64 * 1024,
		Timeout:           750 * time.Millisecond,
		Clock:             clock.RealClock{},
	}
}

type TCPHoldStats struct {
	HeldPackets        uint64
	ReleasedPackets    uint64
	BytesHeld          uint64
	MaxBytesHeld       uint64
	TimeoutReleases    uint64
	PressureReleases   uint64
	GenerationReleases uint64
	FINReleases        uint64
	RSTReleases        uint64
	LifecycleReleases  uint64
	ShutdownReleases   uint64
	VerdictErrors      uint64
}

type tcpHeldPacket struct {
	queue      *nfqueue.Nfqueue
	packetID   uint32
	bytes      int
	generation uint64
}

type tcpHoldEntry struct {
	key        classifier.FlowKey
	generation uint64
	lastSeen   time.Time
	order      uint64
	bytes      int
	packets    []tcpHeldPacket
}

// TCPHoldStore tracks original NFQUEUE packet IDs, not rewritten buffers.
// Releasing a held entry therefore accepts the exact kernel-queued packet and
// is fail-open on every abort path. It never stores mutable config pointers.
type TCPHoldStore struct {
	mu               sync.Mutex
	flows            map[classifier.FlowKey]*tcpHoldEntry
	config           TCPHoldConfig
	clock            clock.Clock
	order            uint64
	totalBytes       int
	stats            TCPHoldStats
	visibilityCancel func()
	visibilityOnce   sync.Once
}

func NewTCPHoldStore(cfg TCPHoldConfig) *TCPHoldStore {
	defaults := DefaultTCPHoldConfig()
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = defaults.MaxFlows
	}
	if cfg.MaxPacketsPerFlow <= 0 {
		cfg.MaxPacketsPerFlow = defaults.MaxPacketsPerFlow
	}
	if cfg.MaxBytesTotal <= 0 {
		cfg.MaxBytesTotal = defaults.MaxBytesTotal
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaults.Timeout
	}
	if cfg.Clock == nil {
		cfg.Clock = defaults.Clock
	}
	store := &TCPHoldStore{flows: make(map[classifier.FlowKey]*tcpHoldEntry, cfg.MaxFlows), config: cfg, clock: cfg.Clock}
	store.visibilityCancel = ppe.DefaultVisibilityGate().SubscribeBlocked(func(ppe.CaptureVisibilitySnapshot) {
		store.ReleaseAll(tcpHoldAbortVisibility)
	})
	return store
}
