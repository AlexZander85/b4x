package classifier

import (
	"bytes"
	"net/netip"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/clock"
)

const (
	TCPFlagFIN byte = 0x01
	TCPFlagSYN byte = 0x02
	TCPFlagRST byte = 0x04
	TCPFlagACK byte = 0x10
)

// IsCleanSYN is the single gate used before generic TLS/action dispatch.
// TCP options are deliberately not inspected here: an explicit SYN technique
// is supplied by the caller and a SYN carrying data is not a clean SYN.
func IsCleanSYN(flags byte, payloadLen int, explicitSYNTechnique bool) bool {
	return flags&TCPFlagSYN != 0 &&
		flags&(TCPFlagACK|TCPFlagFIN|TCPFlagRST) == 0 &&
		payloadLen == 0 &&
		!explicitSYNTechnique
}

type TCPFlowPhase uint8

const (
	TCPNew TCPFlowPhase = iota
	TCPSynSeen
	TCPEstablished
	TCPClientHelloPartial
	TCPClientHelloComplete
	TCPActionPlanned
	TCPActionApplied
	TCPServerProgress
	TCPClosed
)

func (p TCPFlowPhase) String() string {
	switch p {
	case TCPNew:
		return "new"
	case TCPSynSeen:
		return "syn-seen"
	case TCPEstablished:
		return "established"
	case TCPClientHelloPartial:
		return "clienthello-partial"
	case TCPClientHelloComplete:
		return "clienthello-complete"
	case TCPActionPlanned:
		return "action-planned"
	case TCPActionApplied:
		return "action-applied"
	case TCPServerProgress:
		return "server-progress"
	case TCPClosed:
		return "closed"
	default:
		return "unknown"
	}
}

type TCPFlowEvent uint8

const (
	TCPEventSYN TCPFlowEvent = iota
	TCPEventSYNACK
	TCPEventACK
	TCPEventTFO
	TCPEventClientHelloPartial
	TCPEventClientHelloComplete
	TCPEventActionPlanned
	TCPEventActionApplied
	TCPEventServerProgress
	TCPEventRetransmission
	TCPEventFIN
	TCPEventRST
	TCPEventConfigGenerationChange
)

func (e TCPFlowEvent) String() string {
	switch e {
	case TCPEventSYN:
		return "syn"
	case TCPEventSYNACK:
		return "syn-ack"
	case TCPEventACK:
		return "ack"
	case TCPEventTFO:
		return "tfo"
	case TCPEventClientHelloPartial:
		return "clienthello-partial"
	case TCPEventClientHelloComplete:
		return "clienthello-complete"
	case TCPEventActionPlanned:
		return "action-planned"
	case TCPEventActionApplied:
		return "action-applied"
	case TCPEventServerProgress:
		return "server-progress"
	case TCPEventRetransmission:
		return "retransmission"
	case TCPEventFIN:
		return "fin"
	case TCPEventRST:
		return "rst"
	case TCPEventConfigGenerationChange:
		return "config-generation-change"
	default:
		return "unknown"
	}
}

type TCPTransitionResult struct {
	From          TCPFlowPhase
	To            TCPFlowPhase
	Accepted      bool
	Changed       bool
	ConfigChanged bool
	Reason        string
}

// Transition is the pure phase transition function. It does not retain
// packet data, config pointers, or timers.
func Transition(phase TCPFlowPhase, event TCPFlowEvent) (TCPFlowPhase, string) {
	to, _, reason := transition(phase, event)
	return to, reason
}

func transition(phase TCPFlowPhase, event TCPFlowEvent) (TCPFlowPhase, bool, string) {
	if event == TCPEventFIN || event == TCPEventRST {
		if phase == TCPClosed {
			return TCPClosed, true, "flow already closed"
		}
		if event == TCPEventRST {
			return TCPClosed, true, "rst"
		}
		return TCPClosed, true, "fin"
	}

	if phase == TCPClosed {
		return phase, false, "closed flow ignores non-terminal event"
	}

	switch event {
	case TCPEventConfigGenerationChange:
		return TCPNew, true, "config generation change"
	case TCPEventRetransmission:
		return phase, true, "retransmission ignored"
	case TCPEventSYN:
		switch phase {
		case TCPNew:
			return TCPSynSeen, true, "client SYN seen"
		case TCPSynSeen:
			return TCPSynSeen, true, "SYN retransmission"
		default:
			return phase, true, "late SYN ignored after handshake progress"
		}
	case TCPEventSYNACK, TCPEventACK, TCPEventTFO:
		switch phase {
		case TCPNew, TCPSynSeen:
			if event == TCPEventTFO {
				return TCPEstablished, true, "TCP Fast Open payload accepted"
			}
			return TCPEstablished, true, "TCP handshake progress"
		case TCPEstablished, TCPClientHelloPartial, TCPClientHelloComplete,
			TCPActionPlanned, TCPActionApplied, TCPServerProgress:
			return phase, true, "handshake progress already recorded"
		default:
			return phase, false, "handshake event not valid in current phase"
		}
	case TCPEventClientHelloPartial:
		switch phase {
		case TCPNew, TCPSynSeen, TCPEstablished, TCPClientHelloPartial:
			return TCPClientHelloPartial, true, "partial ClientHello observed"
		case TCPClientHelloComplete, TCPActionPlanned, TCPActionApplied:
			return phase, true, "partial retransmission does not regress ClientHello"
		case TCPServerProgress:
			return phase, false, "server progress closed first-flight mutation"
		}
	case TCPEventClientHelloComplete:
		switch phase {
		case TCPNew, TCPSynSeen, TCPEstablished, TCPClientHelloPartial,
			TCPClientHelloComplete:
			return TCPClientHelloComplete, true, "complete ClientHello observed"
		case TCPActionPlanned, TCPActionApplied:
			return phase, true, "duplicate ClientHello does not regress action state"
		case TCPServerProgress:
			return phase, false, "server progress closed first-flight mutation"
		}
	case TCPEventActionPlanned:
		switch phase {
		case TCPClientHelloComplete:
			return TCPActionPlanned, true, "action planned for complete ClientHello"
		case TCPActionPlanned, TCPActionApplied:
			return phase, true, "action plan already recorded"
		case TCPServerProgress:
			return phase, false, "server progress closed first-flight mutation"
		default:
			return phase, false, "action requires complete ClientHello"
		}
	case TCPEventActionApplied:
		switch phase {
		case TCPActionPlanned:
			return TCPActionApplied, true, "action applied once"
		case TCPActionApplied:
			return phase, true, "duplicate action application suppressed"
		case TCPServerProgress:
			return phase, false, "server progress closed first-flight mutation"
		default:
			return phase, false, "action application requires a plan"
		}
	case TCPEventServerProgress:
		return TCPServerProgress, true, "server progress closes first-flight mutation"
	}

	return phase, false, "event not valid in current phase"
}

type TCPFlowState struct {
	Key                  FlowKey
	Phase                TCPFlowPhase
	ConfigGeneration     uint64
	LastSeen             time.Time
	FastOpen             bool
	ActionApplied        bool
	MutationWindowClosed bool
	TerminalReason       string
}

func NewTCPFlowState(key FlowKey, configGeneration uint64, now time.Time) TCPFlowState {
	return TCPFlowState{
		Key:              key.Normalize(),
		Phase:            TCPNew,
		ConfigGeneration: configGeneration,
		LastSeen:         now,
	}
}

func (s *TCPFlowState) Apply(event TCPFlowEvent, configGeneration uint64, now time.Time) TCPTransitionResult {
	from := s.Phase
	result := TCPTransitionResult{From: from, To: from}
	if event == TCPEventConfigGenerationChange ||
		(s.ConfigGeneration != 0 && configGeneration != 0 && s.ConfigGeneration != configGeneration) {
		s.Phase = TCPNew
		s.ConfigGeneration = configGeneration
		s.FastOpen = false
		s.ActionApplied = false
		s.MutationWindowClosed = false
		s.TerminalReason = ""
		s.LastSeen = now
		result.ConfigChanged = true
		result.To = TCPNew
		result.Changed = from != TCPNew
		result.Accepted = true
		result.Reason = "config generation change"
		if event == TCPEventConfigGenerationChange {
			return result
		}
		from = TCPNew
	}
	if s.ConfigGeneration == 0 && configGeneration != 0 {
		s.ConfigGeneration = configGeneration
	}

	to, accepted, reason := transition(s.Phase, event)
	s.Phase = to
	s.LastSeen = now
	result.From = from
	result.To = to
	result.Accepted = accepted
	result.Changed = from != to
	result.Reason = reason
	if event == TCPEventTFO && accepted {
		s.FastOpen = true
	}
	if event == TCPEventActionApplied && accepted {
		s.ActionApplied = true
	}
	if to == TCPServerProgress {
		s.MutationWindowClosed = true
	}
	if to == TCPClosed {
		s.TerminalReason = reason
		s.MutationWindowClosed = true
	}
	return result
}

type tcpFlowEntry struct {
	state TCPFlowState
	order uint64
}

// TCPFlowStore is a bounded, lock-protected skeleton for lifecycle state.
// FIN/RST removes state immediately; no per-packet goroutine or config pointer
// is retained.
type TCPFlowStore struct {
	mu    sync.Mutex
	flows map[FlowKey]*tcpFlowEntry
	limit int
	clock clock.Clock
	order uint64
}

func NewTCPFlowStore(limit int, clk clock.Clock) *TCPFlowStore {
	if limit <= 0 {
		limit = 4096
	}
	if clk == nil {
		clk = clock.RealClock{}
	}
	return &TCPFlowStore{flows: make(map[FlowKey]*tcpFlowEntry, limit), limit: limit, clock: clk}
}

func (s *TCPFlowStore) Observe(key FlowKey, event TCPFlowEvent, configGeneration uint64) (TCPFlowState, TCPTransitionResult) {
	key = key.Normalize()
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.order++

	entry, ok := s.flows[key]
	if !ok {
		state := NewTCPFlowState(key, configGeneration, now)
		entry = &tcpFlowEntry{state: state}
		s.flows[key] = entry
	}
	result := entry.state.Apply(event, configGeneration, now)
	entry.order = s.order
	state := entry.state
	if state.Phase == TCPClosed {
		delete(s.flows, key)
		return state, result
	}
	if len(s.flows) > s.limit {
		s.evictOldestLocked()
	}
	return state, result
}

func (s *TCPFlowStore) Lookup(key FlowKey) (TCPFlowState, bool) {
	key = key.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.flows[key]
	if !ok {
		return TCPFlowState{}, false
	}
	s.order++
	entry.order = s.order
	return entry.state, true
}

func (s *TCPFlowStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.flows)
}

func (s *TCPFlowStore) Delete(key FlowKey) bool {
	key = key.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.flows[key]; !ok {
		return false
	}
	delete(s.flows, key)
	return true
}

func (s *TCPFlowStore) GC(now time.Time, maxAge time.Duration) int {
	if maxAge <= 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, entry := range s.flows {
		if now.Sub(entry.state.LastSeen) >= maxAge {
			delete(s.flows, key)
			removed++
		}
	}
	return removed
}

func (s *TCPFlowStore) evictOldestLocked() {
	var oldestKey FlowKey
	var oldest *tcpFlowEntry
	for key, entry := range s.flows {
		if oldest == nil || entry.order < oldest.order || (entry.order == oldest.order && flowKeyLess(key, oldestKey)) {
			oldestKey = key
			oldest = entry
		}
	}
	if oldest != nil {
		delete(s.flows, oldestKey)
	}
}

func normalizeFlowAddr(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		return addr.Unmap()
	}
	return addr
}

func flowEndpointLess(a netip.Addr, aport uint16, b netip.Addr, bport uint16) bool {
	if cmp := a.Compare(b); cmp != 0 {
		return cmp < 0
	}
	return aport < bport
}

func flowKeyLess(a, b FlowKey) bool {
	if flowEndpointLess(a.SrcIP, a.SrcPort, b.SrcIP, b.SrcPort) {
		return true
	}
	if flowEndpointLess(b.SrcIP, b.SrcPort, a.SrcIP, a.SrcPort) {
		return false
	}
	if flowEndpointLess(a.DstIP, a.DstPort, b.DstIP, b.DstPort) {
		return true
	}
	if flowEndpointLess(b.DstIP, b.DstPort, a.DstIP, a.DstPort) {
		return false
	}
	if a.Proto != b.Proto {
		return a.Proto < b.Proto
	}
	if cmp := a.Client.SourceIP.Compare(b.Client.SourceIP); cmp != 0 {
		return cmp < 0
	}
	if cmp := bytes.Compare(a.Client.SourceMAC[:], b.Client.SourceMAC[:]); cmp != 0 {
		return cmp < 0
	}
	if a.Client.IfIndex != b.Client.IfIndex {
		return a.Client.IfIndex < b.Client.IfIndex
	}
	return a.Client.VLAN < b.Client.VLAN
}
