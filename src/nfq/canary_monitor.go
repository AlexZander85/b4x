package nfq

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

const (
	defaultCanaryMaxFlows = 100000
	defaultCanaryFlowTTL  = 10 * time.Minute
)

type CanarySnapshot struct {
	FlowsStarted     uint64    `json:"flows_started"`
	Samples          uint64    `json:"samples"`
	Failures         uint64    `json:"failures"`
	IncomingProgress uint64    `json:"incoming_progress"`
	ActiveFlows      int       `json:"active_flows"`
	Evictions        uint64    `json:"evictions"`
	CapturedAt       time.Time `json:"captured_at"`
}

type canaryFlowState struct {
	createdAt time.Time
	updatedAt time.Time
	eligible  bool
	accounted bool
	completed bool
	failed    bool
	progress  bool
}

// CanaryMonitor counts logical candidate flows without retaining packet
// payloads. It is bounded and shared by all candidate workers.
type CanaryMonitor struct {
	mu           sync.Mutex
	flows        map[string]*canaryFlowState
	maxFlows     int
	flowTTL      time.Duration
	flowsStarted uint64
	samples      uint64
	failures     uint64
	progress     uint64
	evictions    uint64
	generation   uint64
}

func NewCanaryMonitor(maxFlows int, ttl time.Duration) *CanaryMonitor {
	if maxFlows <= 0 {
		maxFlows = defaultCanaryMaxFlows
	}
	if ttl <= 0 {
		ttl = defaultCanaryFlowTTL
	}
	return &CanaryMonitor{flows: make(map[string]*canaryFlowState), maxFlows: maxFlows, flowTTL: ttl}
}

func (m *CanaryMonitor) Reset() {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.flows = make(map[string]*canaryFlowState)
	m.flowsStarted = 0
	m.samples = 0
	m.failures = 0
	m.progress = 0
	m.evictions = 0
	m.generation++
	m.mu.Unlock()
}

func (m *CanaryMonitor) Snapshot(now time.Time) CanarySnapshot {
	if m == nil {
		return CanarySnapshot{CapturedAt: now}
	}
	m.mu.Lock()
	m.gcLocked(now)
	out := CanarySnapshot{
		FlowsStarted:     m.flowsStarted,
		Samples:          m.samples,
		Failures:         m.failures,
		IncomingProgress: m.progress,
		ActiveFlows:      len(m.flows),
		Evictions:        m.evictions,
		CapturedAt:       now,
	}
	m.mu.Unlock()
	return out
}

func (m *CanaryMonitor) Observe(pkt *pktInfo, cfgPorts canaryPortMatcher) {
	if m == nil || pkt == nil || len(pkt.raw) < pkt.ihl+4 {
		return
	}
	now := time.Now()
	switch pkt.proto {
	case 6:
		m.observeTCP(pkt, cfgPorts, now)
	case 17:
		m.observeUDP(pkt, cfgPorts, now)
	}
}

type canaryPortMatcher interface {
	IsTCPPort(int) bool
	IsUDPPort(int) bool
}

func (m *CanaryMonitor) observeTCP(pkt *pktInfo, ports canaryPortMatcher, now time.Time) {
	tcp := pkt.raw[pkt.ihl:]
	if len(tcp) < TCPHeaderMinLen {
		return
	}
	sport := int(binary.BigEndian.Uint16(tcp[0:2]))
	dport := int(binary.BigEndian.Uint16(tcp[2:4]))
	flags := tcp[13]
	incoming := ports != nil && ports.IsTCPPort(sport)
	key := canaryFlowKey(pkt, sport, dport, incoming)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked(now)
	state, ok := m.flows[key]
	if !ok {
		if incoming {
			return
		}
		if flags&0x02 == 0 || flags&0x10 != 0 {
			return
		}
		state = m.addFlowLocked(key, now)
	}
	state.updatedAt = now
	if incoming && !state.completed {
		if flags&0x04 != 0 {
			state.completed = true
			state.failed = true
			m.accountOutcomeLocked(state)
			return
		}
		dataOffset := int((tcp[12]>>4)&0x0f) * 4
		if flags&0x12 == 0x12 || len(tcp) > dataOffset {
			state.completed = true
			state.progress = true
			m.accountOutcomeLocked(state)
		}
	}
}

func (m *CanaryMonitor) observeUDP(pkt *pktInfo, ports canaryPortMatcher, now time.Time) {
	udp := pkt.raw[pkt.ihl:]
	if len(udp) < UDPHeaderLen {
		return
	}
	sport := int(binary.BigEndian.Uint16(udp[0:2]))
	dport := int(binary.BigEndian.Uint16(udp[2:4]))
	incoming := ports != nil && ports.IsUDPPort(sport)
	key := canaryFlowKey(pkt, sport, dport, incoming)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked(now)
	state, ok := m.flows[key]
	if !ok {
		if incoming {
			return
		}
		state = m.addFlowLocked(key, now)
	}
	state.updatedAt = now
	if incoming && !state.completed {
		state.completed = true
		state.progress = true
		m.accountOutcomeLocked(state)
	}
}

// MarkEligible scopes canary accounting to the requested B4 set. Packets are
// still observed before classification so an early SYN-ACK/RST can be retained;
// only flows later resolved to the candidate set contribute samples.
func (m *CanaryMonitor) MarkEligible(pkt *pktInfo, ports canaryPortMatcher) {
	if m == nil || pkt == nil || len(pkt.raw) < pkt.ihl+4 {
		return
	}
	now := time.Now()
	var sport, dport int
	var incoming bool
	switch pkt.proto {
	case 6:
		tcp := pkt.raw[pkt.ihl:]
		if len(tcp) < TCPHeaderMinLen {
			return
		}
		sport = int(binary.BigEndian.Uint16(tcp[0:2]))
		dport = int(binary.BigEndian.Uint16(tcp[2:4]))
		incoming = ports != nil && ports.IsTCPPort(sport)
	case 17:
		udp := pkt.raw[pkt.ihl:]
		if len(udp) < UDPHeaderLen {
			return
		}
		sport = int(binary.BigEndian.Uint16(udp[0:2]))
		dport = int(binary.BigEndian.Uint16(udp[2:4]))
		incoming = ports != nil && ports.IsUDPPort(sport)
	default:
		return
	}
	if incoming {
		return
	}
	key := canaryFlowKey(pkt, sport, dport, false)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gcLocked(now)
	state, ok := m.flows[key]
	if !ok {
		state = m.addFlowLocked(key, now)
	}
	state.updatedAt = now
	if state.eligible {
		return
	}
	state.eligible = true
	m.flowsStarted++
	m.accountOutcomeLocked(state)
}

func (m *CanaryMonitor) accountOutcomeLocked(state *canaryFlowState) {
	if state == nil || !state.eligible || !state.completed || state.accounted {
		return
	}
	state.accounted = true
	m.samples++
	if state.failed {
		m.failures++
	}
	if state.progress {
		m.progress++
	}
}

func (m *CanaryMonitor) addFlowLocked(key string, now time.Time) *canaryFlowState {
	if len(m.flows) >= m.maxFlows {
		var oldestKey string
		var oldest time.Time
		for candidate, state := range m.flows {
			if oldest.IsZero() || state.updatedAt.Before(oldest) {
				oldestKey, oldest = candidate, state.updatedAt
			}
		}
		if oldestKey != "" {
			delete(m.flows, oldestKey)
			m.evictions++
		}
	}
	state := &canaryFlowState{createdAt: now, updatedAt: now}
	m.flows[key] = state
	return state
}

func (m *CanaryMonitor) gcLocked(now time.Time) {
	for key, state := range m.flows {
		if now.Sub(state.updatedAt) > m.flowTTL {
			delete(m.flows, key)
		}
	}
}

func canaryFlowKey(pkt *pktInfo, sport, dport int, incoming bool) string {
	if incoming {
		return fmt.Sprintf("%d|%s|%d|%s|%d", pkt.proto, pkt.dstStr, dport, pkt.srcStr, sport)
	}
	return fmt.Sprintf("%d|%s|%d|%s|%d", pkt.proto, pkt.srcStr, sport, pkt.dstStr, dport)
}
