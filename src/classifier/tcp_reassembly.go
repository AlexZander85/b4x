package classifier

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/sni"
)

type ReassemblyStatus uint8

const (
	ReassemblyPartial ReassemblyStatus = iota
	ReassemblyComplete
	ReassemblyAborted
)

func (s ReassemblyStatus) String() string {
	switch s {
	case ReassemblyPartial:
		return "partial"
	case ReassemblyComplete:
		return "complete"
	case ReassemblyAborted:
		return "aborted"
	default:
		return "unknown"
	}
}

const (
	ReassemblyAbortTimeout            = "timeout"
	ReassemblyAbortFIN                = "fin"
	ReassemblyAbortRST                = "rst"
	ReassemblyAbortConfigGeneration   = "config-generation-change"
	ReassemblyAbortBudget             = "budget"
	ReassemblyAbortConflictingOverlap = "conflicting-overlap"
	ReassemblyAbortMalformed          = "malformed"
	ReassemblyAbortSequenceBeforeBase = "sequence-before-base"
	ReassemblyAbortManual             = "manual"
)

type TCPReassemblyConfig struct {
	MaxFlows        int
	MaxBytesPerFlow int
	MaxBytesTotal   int
	MaxSegments     int
	MaxClientHello  int
	Timeout         time.Duration
	Clock           clock.Clock
}

func DefaultTCPReassemblyConfig() TCPReassemblyConfig {
	return TCPReassemblyConfig{
		MaxFlows:        1024,
		MaxBytesPerFlow: 32 * 1024,
		MaxBytesTotal:   4 * 1024 * 1024,
		MaxSegments:     64,
		MaxClientHello:  32 * 1024,
		Timeout:         5 * time.Second,
		Clock:           clock.RealClock{},
	}
}

type TCPReassemblyResult struct {
	Status             ReassemblyStatus
	Reason             string
	Key                FlowKey
	BaseSequence       uint32
	Sequence           uint32
	NewBytes           int
	BufferedBytes      int
	SegmentCount       int
	Duplicate          bool
	IdenticalOverlap   bool
	ConflictingOverlap bool
	Metadata           sni.TLSClientHelloMetadata
	ConfigGen          uint64
	ClientHelloID      uint64
}

type TCPReassemblyStats struct {
	FlowsCreated        uint64
	SegmentsObserved    uint64
	BytesObserved       uint64
	Partial             uint64
	Complete            uint64
	Aborted             uint64
	Retransmissions     uint64
	IdenticalOverlaps   uint64
	ConflictingOverlaps uint64
	Timeouts            uint64
	GenerationAborts    uint64
	BudgetAborts        uint64
	MalformedAborts     uint64
}

type tcpReassemblyEntry struct {
	key              FlowKey
	baseSequence     uint32
	configGeneration uint64
	lastSeen         time.Time
	order            uint64
	segments         int
	ranges           *RangeSet
	metadata         sni.TLSClientHelloMetadata
	lastNewBytes     int
	lastDuplicate    bool
	lastIdentical    bool
}

// TCPReassemblyStore is an observe-only bounded store. It owns no packet
// buffers after copying segment bytes into RangeSet and never retains config
// pointers. Callers remain responsible for deciding whether to mutate.
type TCPReassemblyStore struct {
	mu         sync.Mutex
	flows      map[FlowKey]*tcpReassemblyEntry
	config     TCPReassemblyConfig
	clock      clock.Clock
	totalBytes int
	order      uint64
	stats      TCPReassemblyStats
}

func NewTCPReassemblyStore(cfg TCPReassemblyConfig) *TCPReassemblyStore {
	defaults := DefaultTCPReassemblyConfig()
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = defaults.MaxFlows
	}
	if cfg.MaxBytesPerFlow <= 0 {
		cfg.MaxBytesPerFlow = defaults.MaxBytesPerFlow
	}
	if cfg.MaxBytesTotal <= 0 {
		cfg.MaxBytesTotal = defaults.MaxBytesTotal
	}
	if cfg.MaxSegments <= 0 {
		cfg.MaxSegments = defaults.MaxSegments
	}
	if cfg.MaxClientHello <= 0 || cfg.MaxClientHello > TLSClientHelloBound() {
		cfg.MaxClientHello = defaults.MaxClientHello
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaults.Timeout
	}
	if cfg.Clock == nil {
		cfg.Clock = defaults.Clock
	}
	return &TCPReassemblyStore{flows: make(map[FlowKey]*tcpReassemblyEntry, cfg.MaxFlows), config: cfg, clock: cfg.Clock}
}

// TLSClientHelloBound keeps the reassembler and TLS metadata parser aligned
// without exposing the parser's internal allocation policy.
func TLSClientHelloBound() int { return 32 * 1024 }

func (s *TCPReassemblyStore) Start(key FlowKey, baseSequence uint32, configGeneration uint64) {
	key = key.Normalize()
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(key)
	s.ensureFlowCapacityLocked()
	s.order++
	s.flows[key] = &tcpReassemblyEntry{
		key:              key,
		baseSequence:     baseSequence,
		configGeneration: configGeneration,
		lastSeen:         now,
		order:            s.order,
		ranges:           NewRangeSet(s.config.MaxBytesPerFlow, s.config.MaxSegments),
	}
	s.stats.FlowsCreated++
}

// Observe inserts one client-to-server TCP segment and parses only the
// contiguous prefix beginning at the flow base sequence. Original packets
// are never delayed, rewritten, or dropped by this store.
func (s *TCPReassemblyStore) Observe(key FlowKey, sequence uint32, payload []byte, configGeneration uint64) TCPReassemblyResult {
	key = key.Normalize()
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.flows[key]
	if entry == nil {
		s.ensureFlowCapacityLocked()
		s.order++
		entry = &tcpReassemblyEntry{
			key:              key,
			baseSequence:     sequence,
			configGeneration: configGeneration,
			lastSeen:         now,
			order:            s.order,
			ranges:           NewRangeSet(s.config.MaxBytesPerFlow, s.config.MaxSegments),
		}
		s.flows[key] = entry
		s.stats.FlowsCreated++
	}
	if entry.configGeneration != 0 && configGeneration != 0 && entry.configGeneration != configGeneration {
		s.stats.GenerationAborts++
		s.abortLocked(key, ReassemblyAbortConfigGeneration)
		return s.startAfterAbortLocked(key, sequence, configGeneration, now, payload)
	}
	entry.lastSeen = now
	s.order++
	entry.order = s.order
	s.stats.SegmentsObserved++
	s.stats.BytesObserved += uint64(len(payload))
	if len(payload) == 0 {
		return s.resultLocked(entry, ReassemblyPartial, "empty payload")
	}
	offset, ok := tcpSequenceOffset(entry.baseSequence, sequence)
	if !ok {
		s.abortLocked(key, ReassemblyAbortSequenceBeforeBase)
		return TCPReassemblyResult{Status: ReassemblyAborted, Reason: ReassemblyAbortSequenceBeforeBase, Key: key, BaseSequence: entry.baseSequence, Sequence: sequence}
	}
	newBytes, identical, conflicting, err := entry.ranges.EstimateNewBytes(offset, payload)
	if err != nil {
		s.abortLocked(key, ReassemblyAbortBudget)
		return TCPReassemblyResult{Status: ReassemblyAborted, Reason: ReassemblyAbortBudget, Key: key, BaseSequence: entry.baseSequence, Sequence: sequence}
	}
	if conflicting {
		s.stats.ConflictingOverlaps++
		s.abortLocked(key, ReassemblyAbortConflictingOverlap)
		return TCPReassemblyResult{Status: ReassemblyAborted, Reason: ReassemblyAbortConflictingOverlap, Key: key, BaseSequence: entry.baseSequence, Sequence: sequence, ConflictingOverlap: true, IdenticalOverlap: identical}
	}
	if s.totalBytes+newBytes > s.config.MaxBytesTotal {
		s.stats.BudgetAborts++
		s.abortLocked(key, ReassemblyAbortBudget)
		return TCPReassemblyResult{Status: ReassemblyAborted, Reason: ReassemblyAbortBudget, Key: key, BaseSequence: entry.baseSequence, Sequence: sequence}
	}
	inserted := entry.ranges.Insert(offset, payload)
	if !inserted.Accepted {
		s.stats.BudgetAborts++
		s.abortLocked(key, ReassemblyAbortBudget)
		return TCPReassemblyResult{Status: ReassemblyAborted, Reason: ReassemblyAbortBudget, Key: key, BaseSequence: entry.baseSequence, Sequence: sequence}
	}
	s.totalBytes += inserted.NewBytes
	entry.segments++
	if inserted.NewBytes == 0 {
		s.stats.Retransmissions++
	}
	if inserted.IdenticalOverlap {
		s.stats.IdenticalOverlaps++
	}
	entry.lastNewBytes = inserted.NewBytes
	entry.lastDuplicate = inserted.NewBytes == 0
	entry.lastIdentical = inserted.IdenticalOverlap
	contiguous := entry.ranges.Contiguous(0, s.config.MaxClientHello)
	entry.metadata = sni.ParseTLSClientHelloMetadata(contiguous)
	if entry.metadata.ParseError != "" {
		s.stats.MalformedAborts++
		s.abortLocked(key, ReassemblyAbortMalformed)
		return TCPReassemblyResult{Status: ReassemblyAborted, Reason: ReassemblyAbortMalformed, Key: key, BaseSequence: entry.baseSequence, Sequence: sequence, NewBytes: inserted.NewBytes, BufferedBytes: entry.ranges.Bytes(), SegmentCount: entry.segments, Metadata: entry.metadata}
	}
	if entry.metadata.Complete {
		s.stats.Complete++
		return s.resultLocked(entry, ReassemblyComplete, "ClientHello complete")
	}
	s.stats.Partial++
	return s.resultLocked(entry, ReassemblyPartial, "ClientHello incomplete")
}

func (s *TCPReassemblyStore) startAfterAbortLocked(key FlowKey, sequence uint32, generation uint64, now time.Time, payload []byte) TCPReassemblyResult {
	s.ensureFlowCapacityLocked()
	s.order++
	entry := &tcpReassemblyEntry{key: key, baseSequence: sequence, configGeneration: generation, lastSeen: now, order: s.order, ranges: NewRangeSet(s.config.MaxBytesPerFlow, s.config.MaxSegments)}
	s.flows[key] = entry
	s.stats.FlowsCreated++
	s.stats.SegmentsObserved++
	s.stats.BytesObserved += uint64(len(payload))
	// Avoid recursive locking while preserving the generation-abort boundary.
	return s.observeEntryLocked(entry, sequence, payload)
}

func (s *TCPReassemblyStore) observeEntryLocked(entry *tcpReassemblyEntry, sequence uint32, payload []byte) TCPReassemblyResult {
	if len(payload) == 0 {
		return s.resultLocked(entry, ReassemblyPartial, "empty payload after generation change")
	}
	offset, ok := tcpSequenceOffset(entry.baseSequence, sequence)
	if !ok {
		s.abortLocked(entry.key, ReassemblyAbortSequenceBeforeBase)
		return TCPReassemblyResult{Status: ReassemblyAborted, Reason: ReassemblyAbortSequenceBeforeBase, Key: entry.key, BaseSequence: entry.baseSequence, Sequence: sequence}
	}
	newBytes, identical, conflicting, err := entry.ranges.EstimateNewBytes(offset, payload)
	if err != nil || conflicting || s.totalBytes+newBytes > s.config.MaxBytesTotal {
		if conflicting {
			s.stats.ConflictingOverlaps++
			entry.lastNewBytes = newBytes
			entry.lastIdentical = identical
			s.abortLocked(entry.key, ReassemblyAbortConflictingOverlap)
			return TCPReassemblyResult{Status: ReassemblyAborted, Reason: ReassemblyAbortConflictingOverlap, Key: entry.key, BaseSequence: entry.baseSequence, Sequence: sequence, NewBytes: newBytes, IdenticalOverlap: identical, ConflictingOverlap: true}
		}
		s.stats.BudgetAborts++
		s.abortLocked(entry.key, ReassemblyAbortBudget)
		return TCPReassemblyResult{Status: ReassemblyAborted, Reason: ReassemblyAbortBudget, Key: entry.key, BaseSequence: entry.baseSequence, Sequence: sequence, NewBytes: newBytes}
	}
	inserted := entry.ranges.Insert(offset, payload)
	if !inserted.Accepted {
		s.stats.BudgetAborts++
		s.abortLocked(entry.key, ReassemblyAbortBudget)
		return TCPReassemblyResult{Status: ReassemblyAborted, Reason: ReassemblyAbortBudget, Key: entry.key, BaseSequence: entry.baseSequence, Sequence: sequence}
	}
	s.totalBytes += inserted.NewBytes
	entry.segments++
	entry.lastNewBytes = inserted.NewBytes
	entry.lastDuplicate = inserted.NewBytes == 0
	entry.lastIdentical = inserted.IdenticalOverlap
	if inserted.NewBytes == 0 {
		s.stats.Retransmissions++
	}
	if inserted.IdenticalOverlap {
		s.stats.IdenticalOverlaps++
	}
	entry.metadata = sni.ParseTLSClientHelloMetadata(entry.ranges.Contiguous(0, s.config.MaxClientHello))
	if entry.metadata.ParseError != "" {
		s.abortLocked(entry.key, ReassemblyAbortMalformed)
		return s.resultLocked(entry, ReassemblyAborted, ReassemblyAbortMalformed)
	}
	if entry.metadata.Complete {
		s.stats.Complete++
		return s.resultLocked(entry, ReassemblyComplete, "ClientHello complete after generation change")
	}
	s.stats.Partial++
	return s.resultLocked(entry, ReassemblyPartial, "ClientHello incomplete after generation change")
}

func (s *TCPReassemblyStore) resultLocked(entry *tcpReassemblyEntry, status ReassemblyStatus, reason string) TCPReassemblyResult {
	return TCPReassemblyResult{Status: status, Reason: reason, Key: entry.key, BaseSequence: entry.baseSequence, NewBytes: entry.lastNewBytes, BufferedBytes: entry.ranges.Bytes(), SegmentCount: entry.segments, Duplicate: entry.lastDuplicate, IdenticalOverlap: entry.lastIdentical, Metadata: entry.metadata, ConfigGen: entry.configGeneration, ClientHelloID: clientHelloIdentity(entry)}
}

func clientHelloIdentity(entry *tcpReassemblyEntry) uint64 {
	if entry == nil {
		return 0
	}
	return LogicalClientHelloID(entry.key, entry.baseSequence, entry.configGeneration)
}

// LogicalClientHelloID is representation-independent: a full GSO skb and the
// equivalent MSS segment stream produce the same identity when their exact
// flow, first TCP sequence and immutable config generation are equal.
func LogicalClientHelloID(key FlowKey, baseSequence uint32, configGeneration uint64) uint64 {
	key = key.Normalize()
	h := fnv.New64a()
	var scratch [8]byte
	binary.BigEndian.PutUint32(scratch[:4], baseSequence)
	_, _ = h.Write(scratch[:4])
	binary.BigEndian.PutUint64(scratch[:], configGeneration)
	_, _ = h.Write(scratch[:])
	_, _ = h.Write([]byte(fmt.Sprintf("%v", key)))
	return h.Sum64()
}

func (s *TCPReassemblyStore) ObserveEvent(key FlowKey, event TCPFlowEvent, configGeneration uint64) TCPReassemblyResult {
	switch event {
	case TCPEventFIN:
		return s.Close(key, ReassemblyAbortFIN)
	case TCPEventRST:
		return s.Close(key, ReassemblyAbortRST)
	case TCPEventConfigGenerationChange:
		return s.Close(key, ReassemblyAbortConfigGeneration)
	default:
		return TCPReassemblyResult{Status: ReassemblyPartial, Reason: "event ignored"}
	}
}

func (s *TCPReassemblyStore) Close(key FlowKey, reason string) TCPReassemblyResult {
	key = key.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.flows[key]
	if entry == nil {
		return TCPReassemblyResult{Status: ReassemblyAborted, Reason: reason, Key: key}
	}
	result := s.resultLocked(entry, ReassemblyAborted, reason)
	s.abortLocked(key, reason)
	return result
}

func (s *TCPReassemblyStore) GC(now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, entry := range s.flows {
		if now.Sub(entry.lastSeen) >= s.config.Timeout {
			s.stats.Timeouts++
			s.abortLocked(key, ReassemblyAbortTimeout)
			removed++
		}
	}
	return removed
}

func (s *TCPReassemblyStore) Lookup(key FlowKey) (TCPReassemblyResult, bool) {
	key = key.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.flows[key]
	if !ok {
		return TCPReassemblyResult{}, false
	}
	status := ReassemblyPartial
	if entry.metadata.Complete {
		status = ReassemblyComplete
	}
	return s.resultLocked(entry, status, "lookup"), true
}

// ClientHelloBytes returns a bounded copy of the contiguous ClientHello
// prefix for a completed flow. It is intended for diagnostics/lab hashing;
// callers must not retain the returned bytes longer than necessary. The
// reassembler remains the single owner of segment ordering and overlap rules.
func (s *TCPReassemblyStore) ClientHelloBytes(key FlowKey) ([]byte, bool) {
	if s == nil {
		return nil, false
	}
	key = key.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.flows[key]
	if !ok || !entry.metadata.Complete {
		return nil, false
	}
	return append([]byte(nil), entry.ranges.Contiguous(0, s.config.MaxClientHello)...), true
}

func (s *TCPReassemblyStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.flows)
}

func (s *TCPReassemblyStore) Bytes() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalBytes
}

func (s *TCPReassemblyStore) Stats() TCPReassemblyStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *TCPReassemblyStore) ensureFlowCapacityLocked() {
	for len(s.flows) >= s.config.MaxFlows {
		var oldestKey FlowKey
		var oldestOrder uint64
		first := true
		for key, entry := range s.flows {
			if first || entry.order < oldestOrder {
				oldestKey, oldestOrder, first = key, entry.order, false
			}
		}
		if first {
			return
		}
		s.abortLocked(oldestKey, ReassemblyAbortBudget)
		s.stats.BudgetAborts++
	}
}

func (s *TCPReassemblyStore) removeLocked(key FlowKey) {
	if entry := s.flows[key]; entry != nil {
		s.totalBytes -= entry.ranges.Bytes()
		if s.totalBytes < 0 {
			s.totalBytes = 0
		}
		delete(s.flows, key)
	}
}

func (s *TCPReassemblyStore) abortLocked(key FlowKey, reason string) {
	if entry := s.flows[key]; entry != nil {
		s.totalBytes -= entry.ranges.Bytes()
		if s.totalBytes < 0 {
			s.totalBytes = 0
		}
		delete(s.flows, key)
		s.stats.Aborted++
	}
}

func tcpSequenceOffset(base, sequence uint32) (uint64, bool) {
	delta := int32(sequence - base)
	if delta < 0 {
		return 0, false
	}
	return uint64(delta), true
}
