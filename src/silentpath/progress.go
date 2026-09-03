package silentpath

import (
	"sort"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
)

type Direction string

const (
	DirectionOutbound Direction = "outbound"
	DirectionInbound  Direction = "inbound"
)

type VisibilityState string

const (
	VisibilityUnknown  VisibilityState = "unknown"
	VisibilityComplete VisibilityState = "complete"
	VisibilityPartial  VisibilityState = "partial"
)

// FlowProgressState only records immutable observation facts.  The store does
// not infer an outage or select a packet/routing action.
type FlowProgressState struct {
	FlowKey              classifier.FlowKey
	ClientKey            classifier.ClientKey
	ConfigGen            uint64
	FirstSeenAt          time.Time
	LastOutboundAt       time.Time
	LastInboundAt        time.Time
	LastUniqueInboundAt  time.Time
	LastUniqueOutboundAt time.Time
	UniqueOutboundBytes  uint64
	UniqueInboundBytes   uint64
	OutboundDataPackets  uint32
	InboundDataPackets   uint32
	RetransmissionCount  uint32
	Visibility           VisibilityState
}

type ProgressObservation struct {
	FlowKey   classifier.FlowKey
	Direction Direction
	Sequence  uint32
	Bytes     int
	ConfigGen uint64
}

type ProgressResult struct {
	State             FlowProgressState
	NewBytes          uint64
	Duplicate         bool
	TrackingStopped   bool
	GenerationChanged bool
	Reason            string
}

type ProgressConfig struct {
	MaxFlows         int
	MaxRangesPerFlow int
	IdleTimeout      time.Duration
	Clock            clock.Clock
}

func DefaultProgressConfig() ProgressConfig {
	return ProgressConfig{MaxFlows: 4096, MaxRangesPerFlow: 64, IdleTimeout: 30 * time.Minute, Clock: clock.RealClock{}}
}

type ProgressStats struct {
	FlowsCreated        uint64
	FlowsClosed         uint64
	FlowsExpired        uint64
	GenerationResets    uint64
	UniqueInboundBytes  uint64
	UniqueOutboundBytes uint64
	Retransmissions     uint64
	BoundedStops        uint64
}

type sequenceRange struct{ start, end int64 }

// uniqueRangeTracker counts TCP sequence-space exactly once.  Coordinates are
// signed deltas from the first observed sequence, so nearby packets that cross
// uint32 wrap (or arrive out of order) remain ordered without special casing.
// TCP's maximum valid in-flight span is below 2^31, which is the domain of the
// signed sequence comparison used here.
type uniqueRangeTracker struct {
	anchor      uint32
	initialized bool
	ranges      []sequenceRange
	unique      uint64
	maxRanges   int
}

func newUniqueRangeTracker(maxRanges int) uniqueRangeTracker {
	if maxRanges <= 0 {
		maxRanges = DefaultProgressConfig().MaxRangesPerFlow
	}
	return uniqueRangeTracker{maxRanges: maxRanges}
}

func (t *uniqueRangeTracker) add(sequence uint32, bytes int) (uint64, bool, bool) {
	if bytes <= 0 {
		return 0, false, false
	}
	if !t.initialized {
		t.anchor, t.initialized = sequence, true
	}
	start := int64(int32(sequence - t.anchor))
	end := start + int64(bytes)
	if end <= start {
		return 0, false, true
	}
	newBytes := end - start
	for _, r := range t.ranges {
		if r.end <= start {
			continue
		}
		if r.start >= end {
			break
		}
		left, right := maxInt64(start, r.start), minInt64(end, r.end)
		if right > left {
			newBytes -= right - left
		}
	}
	if newBytes == 0 {
		return 0, true, false
	}

	merged := make([]sequenceRange, 0, len(t.ranges)+1)
	candidate := sequenceRange{start: start, end: end}
	placed := false
	for _, r := range t.ranges {
		if r.end < candidate.start {
			merged = append(merged, r)
			continue
		}
		if candidate.end < r.start {
			if !placed {
				merged = append(merged, candidate)
				placed = true
			}
			merged = append(merged, r)
			continue
		}
		candidate.start = minInt64(candidate.start, r.start)
		candidate.end = maxInt64(candidate.end, r.end)
	}
	if !placed {
		merged = append(merged, candidate)
	}
	if len(merged) > t.maxRanges {
		return 0, false, true
	}
	t.ranges = merged
	t.unique += uint64(newBytes)
	return uint64(newBytes), false, false
}

type progressEntry struct {
	state    FlowProgressState
	inbound  uniqueRangeTracker
	outbound uniqueRangeTracker
	lastSeen time.Time
	order    uint64
}

// ProgressStore is a bounded per-flow observation store.  Limit pressure is
// fail-open: it removes only accounting state and never changes traffic.
type ProgressStore struct {
	mu      sync.Mutex
	entries map[classifier.FlowKey]*progressEntry
	config  ProgressConfig
	clock   clock.Clock
	order   uint64
	stats   ProgressStats
}

func NewProgressStore(cfg ProgressConfig) *ProgressStore {
	d := DefaultProgressConfig()
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = d.MaxFlows
	}
	if cfg.MaxRangesPerFlow <= 0 {
		cfg.MaxRangesPerFlow = d.MaxRangesPerFlow
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = d.IdleTimeout
	}
	if cfg.Clock == nil {
		cfg.Clock = d.Clock
	}
	return &ProgressStore{entries: make(map[classifier.FlowKey]*progressEntry, cfg.MaxFlows), config: cfg, clock: cfg.Clock}
}

func (s *ProgressStore) Observe(observation ProgressObservation) ProgressResult {
	key := observation.FlowKey.Normalize()
	if key.IsZero() || (observation.Direction != DirectionInbound && observation.Direction != DirectionOutbound) || observation.Bytes < 0 {
		return ProgressResult{Reason: "invalid observation"}
	}
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[key]
	changed := entry != nil && entry.state.ConfigGen != 0 && observation.ConfigGen != 0 && entry.state.ConfigGen != observation.ConfigGen
	if changed {
		s.closeLocked(key)
		s.stats.GenerationResets++
	}
	if entry = s.entries[key]; entry == nil {
		s.ensureCapacityLocked()
		s.order++
		entry = &progressEntry{state: FlowProgressState{FlowKey: key, ClientKey: key.Client, ConfigGen: observation.ConfigGen, FirstSeenAt: now, Visibility: VisibilityUnknown}, inbound: newUniqueRangeTracker(s.config.MaxRangesPerFlow), outbound: newUniqueRangeTracker(s.config.MaxRangesPerFlow), lastSeen: now, order: s.order}
		s.entries[key] = entry
		s.stats.FlowsCreated++
	}
	entry.lastSeen, s.order, entry.order = now, s.order+1, s.order+1
	if observation.Bytes == 0 {
		return ProgressResult{State: entry.state, GenerationChanged: changed, Reason: "non-data packet"}
	}
	var tracker *uniqueRangeTracker
	if observation.Direction == DirectionInbound {
		entry.state.LastInboundAt = now
		entry.state.InboundDataPackets++
		tracker = &entry.inbound
	} else {
		entry.state.LastOutboundAt = now
		entry.state.OutboundDataPackets++
		tracker = &entry.outbound
	}
	newBytes, duplicate, stopped := tracker.add(observation.Sequence, observation.Bytes)
	if stopped {
		s.stats.BoundedStops++
		state := entry.state
		s.closeLocked(key)
		return ProgressResult{State: state, TrackingStopped: true, GenerationChanged: changed, Reason: "range budget exhausted"}
	}
	if duplicate {
		entry.state.RetransmissionCount++
		s.stats.Retransmissions++
	}
	if newBytes > 0 && observation.Direction == DirectionInbound {
		entry.state.UniqueInboundBytes += newBytes
		entry.state.LastUniqueInboundAt = now
		s.stats.UniqueInboundBytes += newBytes
	} else if newBytes > 0 {
		entry.state.UniqueOutboundBytes += newBytes
		entry.state.LastUniqueOutboundAt = now
		s.stats.UniqueOutboundBytes += newBytes
	}
	return ProgressResult{State: entry.state, NewBytes: newBytes, Duplicate: duplicate, GenerationChanged: changed, Reason: "observed"}
}

func (s *ProgressStore) Close(key classifier.FlowKey) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	key = key.Normalize()
	if _, ok := s.entries[key]; !ok {
		return false
	}
	s.closeLocked(key)
	return true
}

func (s *ProgressStore) InvalidateGeneration(generation uint64) int {
	if generation == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, entry := range s.entries {
		if entry.state.ConfigGen == generation {
			s.closeLocked(key)
			removed++
		}
	}
	return removed
}

func (s *ProgressStore) GC(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, entry := range s.entries {
		if !now.Before(entry.lastSeen.Add(s.config.IdleTimeout)) {
			s.closeLocked(key)
			s.stats.FlowsExpired++
			removed++
		}
	}
	return removed
}

func (s *ProgressStore) Len() int             { s.mu.Lock(); defer s.mu.Unlock(); return len(s.entries) }
func (s *ProgressStore) Stats() ProgressStats { s.mu.Lock(); defer s.mu.Unlock(); return s.stats }

func (s *ProgressStore) ensureCapacityLocked() {
	if len(s.entries) < s.config.MaxFlows {
		return
	}
	keys := make([]classifier.FlowKey, 0, len(s.entries))
	for key := range s.entries {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return s.entries[keys[i]].order < s.entries[keys[j]].order })
	s.closeLocked(keys[0])
}
func (s *ProgressStore) closeLocked(key classifier.FlowKey) {
	delete(s.entries, key)
	s.stats.FlowsClosed++
}
func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
