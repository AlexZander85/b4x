package nfq

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sort"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
)

type PassiveRSTDirection string

const (
	PassiveRSTClientToServer PassiveRSTDirection = "client-to-server"
	PassiveRSTServerToClient PassiveRSTDirection = "server-to-client"
)

type PassiveRSTBaselineQuality string

const (
	PassiveRSTBaselineNone                 PassiveRSTBaselineQuality = "none"
	PassiveRSTBaselineWeak                 PassiveRSTBaselineQuality = "weak"
	PassiveRSTBaselineStable               PassiveRSTBaselineQuality = "stable"
	PassiveRSTBaselineStale                PassiveRSTBaselineQuality = "stale"
	PassiveRSTBaselineRouteChangeSuspected PassiveRSTBaselineQuality = "route-change-suspected"
)

type PassiveRSTSignalStrength string

const (
	PassiveRSTStrengthStrong        PassiveRSTSignalStrength = "strong"
	PassiveRSTStrengthCorroborating PassiveRSTSignalStrength = "corroborating"
	PassiveRSTStrengthDiagnostic    PassiveRSTSignalStrength = "diagnostic"
)

type PassiveRSTSignal string

const (
	PassiveRSTSignalPreServerPayload  PassiveRSTSignal = "pre-server-payload-rst"
	PassiveRSTSignalBurst             PassiveRSTSignal = "rst-burst"
	PassiveRSTSignalTTLMismatch       PassiveRSTSignal = "ttl-hop-mismatch"
	PassiveRSTSignalWeakTTLMismatch   PassiveRSTSignal = "weak-ttl-hop-mismatch"
	PassiveRSTSignalSequenceOutside   PassiveRSTSignal = "sequence-outside-receive-window"
	PassiveRSTSignalAckOutside        PassiveRSTSignal = "ack-outside-send-window"
	PassiveRSTSignalOptionsMismatch   PassiveRSTSignal = "tcp-options-fingerprint-mismatch"
	PassiveRSTSignalMissingACK        PassiveRSTSignal = "rst-without-ack"
	PassiveRSTSignalIPIDAnomaly       PassiveRSTSignal = "ipid-anomaly"
	PassiveRSTSignalIncompleteCapture PassiveRSTSignal = "incomplete-capture-visibility"
)

type PassiveRSTDecision string

const (
	PassiveRSTDecisionObserve  PassiveRSTDecision = "observe"
	PassiveRSTDecisionPass     PassiveRSTDecision = "pass"
	PassiveRSTDecisionSuppress PassiveRSTDecision = "suppress"
	PassiveRSTDecisionFailOpen PassiveRSTDecision = "fail-open"
)

type PassiveRSTSignalObservation struct {
	Signal   PassiveRSTSignal         `json:"signal"`
	Strength PassiveRSTSignalStrength `json:"strength"`
	Reason   string                   `json:"reason,omitempty"`
}

type PassiveRSTWindowDecision struct {
	Reliable bool   `json:"reliable"`
	InWindow bool   `json:"in_window"`
	Value    uint32 `json:"value"`
	Start    uint32 `json:"start"`
	Size     uint32 `json:"size"`
}

type PassiveRSTBaselineSnapshot struct {
	Family             uint8                     `json:"family"`
	Quality            PassiveRSTBaselineQuality `json:"quality"`
	Samples            int                       `json:"samples"`
	Center             uint8                     `json:"center"`
	Spread             uint8                     `json:"spread"`
	EffectiveTolerance uint8                     `json:"effective_tolerance"`
	LastObservedAt     time.Time                 `json:"last_observed_at,omitempty"`
}

type PassiveRSTFlowSnapshot struct {
	FlowKey                  classifier.FlowKey         `json:"flow_key"`
	ConfigGeneration         uint64                     `json:"config_generation"`
	SetID                    string                     `json:"set_id,omitempty"`
	DeviceScope              string                     `json:"device_scope,omitempty"`
	SYNSeen                  bool                       `json:"syn_seen"`
	SYNACKSeen               bool                       `json:"syn_ack_seen"`
	ServerPayloadBytes       uint64                     `json:"server_payload_bytes"`
	ServerPayloadProgress    bool                       `json:"server_payload_progress"`
	VisibilityComplete       bool                       `json:"visibility_complete"`
	RSTCount                 int                        `json:"rst_count"`
	LastRSTAt                time.Time                  `json:"last_rst_at,omitempty"`
	SuppressionBudget        int                        `json:"suppression_budget"`
	SuppressionExpiresAt     time.Time                  `json:"suppression_expires_at,omitempty"`
	ServerOptionsKnown       bool                       `json:"server_options_known"`
	ServerOptionsFingerprint uint64                     `json:"server_options_fingerprint,omitempty"`
	IPv4Baseline             PassiveRSTBaselineSnapshot `json:"ipv4_baseline"`
	IPv6Baseline             PassiveRSTBaselineSnapshot `json:"ipv6_baseline"`
	CreatedAt                time.Time                  `json:"created_at"`
	LastSeen                 time.Time                  `json:"last_seen"`
}

type PassiveRSTEvidence struct {
	Flow               PassiveRSTFlowSnapshot        `json:"flow"`
	ObservedAt         time.Time                     `json:"observed_at"`
	Family             uint8                         `json:"family"`
	TTLOrHopLimit      uint8                         `json:"ttl_or_hop_limit"`
	Signals            []PassiveRSTSignalObservation `json:"signals"`
	Baseline           PassiveRSTBaselineSnapshot    `json:"baseline"`
	Sequence           PassiveRSTWindowDecision      `json:"sequence"`
	Acknowledgment     PassiveRSTWindowDecision      `json:"acknowledgment"`
	RSTHasACK          bool                          `json:"rst_has_ack"`
	OptionsFingerprint uint64                        `json:"options_fingerprint,omitempty"`
	IPID               uint16                        `json:"ipid,omitempty"`
	Decision           PassiveRSTDecision            `json:"decision"`
	Reason             string                        `json:"reason,omitempty"`
}

type PassiveRSTPacketObservation struct {
	Direction          PassiveRSTDirection
	Family             uint8
	Flags              uint8
	Sequence           uint32
	Acknowledgment     uint32
	Window             uint16
	PayloadBytes       int
	TTLOrHopLimit      uint8
	IPID               uint16
	OptionsFingerprint uint64
	OptionsKnown       bool
	WindowScale        uint8
	WindowScaleKnown   bool
	VisibilityComplete bool
	ObservedAt         time.Time
	SetID              string
	DeviceScope        string
}

type PassiveRSTStoreStats struct {
	Created               uint64 `json:"created"`
	Observed              uint64 `json:"observed"`
	RSTObserved           uint64 `json:"rst_observed"`
	Evicted               uint64 `json:"evicted"`
	Expired               uint64 `json:"expired"`
	FlowInvalidated       uint64 `json:"flow_invalidated"`
	GenerationInvalidated uint64 `json:"generation_invalidated"`
	Cleared               uint64 `json:"cleared"`
	Passed                uint64 `json:"passed"`
	Suppressed            uint64 `json:"suppressed"`
	FailOpen              uint64 `json:"fail_open"`
	BudgetExhausted       uint64 `json:"budget_exhausted"`
}

type passiveRSTEndpointKey struct {
	Family     uint8
	ClientIP   string
	ServerIP   string
	ClientPort uint16
	ServerPort uint16
}

type passiveRSTTTLState struct {
	samples []uint8
	next    int
	lastAt  time.Time
}

type passiveRSTFlowState struct {
	flow                 classifier.FlowKey
	generation           uint64
	setID                string
	deviceScope          string
	createdAt            time.Time
	lastSeen             time.Time
	synSeen              bool
	synAckSeen           bool
	serverPayload        uint64
	visibility           bool
	clientWindowScale    uint8
	clientScaleKnown     bool
	serverWindowScale    uint8
	serverScaleKnown     bool
	clientReceiveNext    uint32
	clientReceiveWindow  uint32
	clientWindowReliable bool
	serverReceiveNext    uint32
	serverReceiveWindow  uint32
	serverWindowReliable bool
	serverOptions        uint64
	serverOptionsKnown   bool
	serverIPID           uint16
	serverIPIDKnown      bool
	ttl4                 passiveRSTTTLState
	ttl6                 passiveRSTTTLState
	rstTimes             []time.Time
	suppressionBudget    int
	suppressionDeadline  time.Time
	order                uint64
}

type PassiveRSTStore struct {
	mu                sync.RWMutex
	flows             map[classifier.FlowKey]*passiveRSTFlowState
	endpoints         map[passiveRSTEndpointKey]classifier.FlowKey
	recent            []PassiveRSTEvidence
	cfg               config.PassiveRSTRuntimeConfig
	clock             clock.Clock
	order             uint64
	stats             PassiveRSTStoreStats
	globalWindowStart time.Time
	globalSuppressed  int
}

func NewPassiveRSTStore(cfg config.PassiveRSTRuntimeConfig, c clock.Clock) *PassiveRSTStore {
	cfg = normalizedPassiveRSTConfig(cfg)
	if c == nil {
		c = clock.RealClock{}
	}
	return &PassiveRSTStore{
		flows:     make(map[classifier.FlowKey]*passiveRSTFlowState, cfg.MaxFlows),
		endpoints: make(map[passiveRSTEndpointKey]classifier.FlowKey, cfg.MaxFlows),
		recent:    make([]PassiveRSTEvidence, 0, cfg.RecentDecisionLimit),
		cfg:       cfg,
		clock:     c,
	}
}

func normalizedPassiveRSTConfig(cfg config.PassiveRSTRuntimeConfig) config.PassiveRSTRuntimeConfig {
	d := config.DefaultClassifierRuntimeConfig.PassiveRST
	if cfg.Mode == "" {
		cfg.Mode = d.Mode
	}
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = d.MaxFlows
	}
	if cfg.FlowTTLSeconds <= 0 {
		cfg.FlowTTLSeconds = d.FlowTTLSeconds
	}
	if cfg.BaselineSamples <= 0 {
		cfg.BaselineSamples = d.BaselineSamples
	}
	if cfg.BaselineFreshnessSeconds <= 0 {
		cfg.BaselineFreshnessSeconds = d.BaselineFreshnessSeconds
	}
	if cfg.MinTTLTolerance <= 0 {
		cfg.MinTTLTolerance = d.MinTTLTolerance
	}
	if cfg.TTLSafetyMargin <= 0 {
		cfg.TTLSafetyMargin = d.TTLSafetyMargin
	}
	if cfg.BurstThreshold <= 0 {
		cfg.BurstThreshold = d.BurstThreshold
	}
	if cfg.BurstWindowMS <= 0 {
		cfg.BurstWindowMS = d.BurstWindowMS
	}
	if cfg.SuppressionBudgetPerFlow <= 0 {
		cfg.SuppressionBudgetPerFlow = d.SuppressionBudgetPerFlow
	}
	if cfg.SuppressionWindowSeconds <= 0 {
		cfg.SuppressionWindowSeconds = d.SuppressionWindowSeconds
	}
	if cfg.GlobalSuppressionsPerMinute <= 0 {
		cfg.GlobalSuppressionsPerMinute = d.GlobalSuppressionsPerMinute
	}
	if cfg.RecentDecisionLimit <= 0 {
		cfg.RecentDecisionLimit = d.RecentDecisionLimit
	}
	if cfg.BaselineSamples > 32 {
		cfg.BaselineSamples = 32
	}
	return cfg
}

func (s *PassiveRSTStore) Reconfigure(cfg config.PassiveRSTRuntimeConfig) {
	if s == nil {
		return
	}
	cfg = normalizedPassiveRSTConfig(cfg)
	s.mu.Lock()
	s.cfg = cfg
	now := s.clock.Now()
	s.pruneExpiredLocked(now)
	for len(s.flows) > cfg.MaxFlows {
		s.evictOldestLocked()
	}
	if len(s.recent) > cfg.RecentDecisionLimit {
		s.recent = append([]PassiveRSTEvidence(nil), s.recent[len(s.recent)-cfg.RecentDecisionLimit:]...)
	}
	s.mu.Unlock()
}

func (s *PassiveRSTStore) ObserveOutgoing(flow classifier.FlowKey, generation uint64, obs PassiveRSTPacketObservation) PassiveRSTFlowSnapshot {
	if s == nil || generation == 0 || flow.IsZero() {
		return PassiveRSTFlowSnapshot{}
	}
	flow = flow.Normalize()
	obs.Direction = PassiveRSTClientToServer
	now := normalizedObservationTime(obs.ObservedAt, s.clock.Now())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(now)
	state := s.ensureFlowLocked(flow, generation, obs, now)
	if state == nil {
		return PassiveRSTFlowSnapshot{}
	}
	s.applyObservationLocked(state, obs, now)
	return s.snapshotLocked(state, now)
}

func (s *PassiveRSTStore) ObserveIncoming(clientIP, serverIP string, clientPort, serverPort uint16, generation uint64, obs PassiveRSTPacketObservation) (PassiveRSTEvidence, bool) {
	if s == nil || generation == 0 {
		return PassiveRSTEvidence{}, false
	}
	obs.Direction = PassiveRSTServerToClient
	now := normalizedObservationTime(obs.ObservedAt, s.clock.Now())
	key := passiveRSTEndpointKey{Family: obs.Family, ClientIP: clientIP, ServerIP: serverIP, ClientPort: clientPort, ServerPort: serverPort}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(now)
	flow, ok := s.endpoints[key]
	if !ok {
		return PassiveRSTEvidence{}, false
	}
	state := s.flows[flow]
	if state == nil || state.generation != generation {
		return PassiveRSTEvidence{}, false
	}
	isRST := obs.Flags&classifier.TCPFlagRST != 0
	var evidence PassiveRSTEvidence
	if isRST {
		evidence = s.evaluateRSTLocked(state, obs, now)
	}
	s.applyObservationLocked(state, obs, now)
	if isRST {
		evidence.Flow = s.snapshotLocked(state, now)
		s.appendRecentLocked(evidence)
		s.stats.RSTObserved++
		return clonePassiveRSTEvidence(evidence), true
	}
	return PassiveRSTEvidence{}, true
}

func normalizedObservationTime(got, fallback time.Time) time.Time {
	if got.IsZero() {
		return fallback
	}
	return got
}

func (s *PassiveRSTStore) ensureFlowLocked(flow classifier.FlowKey, generation uint64, obs PassiveRSTPacketObservation, now time.Time) *passiveRSTFlowState {
	if existing := s.flows[flow]; existing != nil {
		if existing.generation != generation {
			s.deleteFlowLocked(flow)
		} else {
			if obs.SetID != "" {
				existing.setID = obs.SetID
			}
			if obs.DeviceScope != "" {
				existing.deviceScope = obs.DeviceScope
			}
			return existing
		}
	}
	for len(s.flows) >= s.cfg.MaxFlows {
		s.evictOldestLocked()
	}
	s.order++
	state := &passiveRSTFlowState{
		flow: flow, generation: generation, setID: obs.SetID, deviceScope: obs.DeviceScope,
		createdAt: now, lastSeen: now, visibility: obs.VisibilityComplete,
		suppressionBudget: s.cfg.SuppressionBudgetPerFlow, order: s.order,
	}
	s.flows[flow] = state
	s.endpoints[endpointKeyFromFlow(flow)] = flow
	s.stats.Created++
	return state
}

func endpointKeyFromFlow(flow classifier.FlowKey) passiveRSTEndpointKey {
	clientIP := flow.Client.SourceIP
	clientPort := flow.SrcPort
	serverIP := flow.DstIP
	serverPort := flow.DstPort
	if flow.SrcIP != clientIP {
		clientPort, serverPort = flow.DstPort, flow.SrcPort
		serverIP = flow.SrcIP
	}
	family := flow.Client.L3Family
	return passiveRSTEndpointKey{Family: family, ClientIP: clientIP.String(), ServerIP: serverIP.String(), ClientPort: clientPort, ServerPort: serverPort}
}

func (s *PassiveRSTStore) applyObservationLocked(state *passiveRSTFlowState, obs PassiveRSTPacketObservation, now time.Time) {
	state.lastSeen = now
	state.visibility = state.visibility || obs.VisibilityComplete
	if obs.SetID != "" {
		state.setID = obs.SetID
	}
	if obs.DeviceScope != "" {
		state.deviceScope = obs.DeviceScope
	}
	flags := obs.Flags
	if obs.Direction == PassiveRSTClientToServer {
		if flags&classifier.TCPFlagSYN != 0 {
			state.synSeen = true
			if obs.WindowScaleKnown {
				state.clientWindowScale, state.clientScaleKnown = obs.WindowScale, true
			}
		}
		if flags&classifier.TCPFlagACK != 0 {
			state.clientReceiveNext = obs.Acknowledgment
			state.clientReceiveWindow = scaledWindow(obs.Window, state.clientWindowScale, state.clientScaleKnown)
			state.clientWindowReliable = state.synAckSeen
		}
	} else {
		isRST := flags&classifier.TCPFlagRST != 0
		if flags&(classifier.TCPFlagSYN|classifier.TCPFlagACK) == (classifier.TCPFlagSYN | classifier.TCPFlagACK) {
			state.synAckSeen = true
			if obs.WindowScaleKnown {
				state.serverWindowScale, state.serverScaleKnown = obs.WindowScale, true
			}
		}
		if flags&classifier.TCPFlagACK != 0 {
			state.serverReceiveNext = obs.Acknowledgment
			state.serverReceiveWindow = scaledWindow(obs.Window, state.serverWindowScale, state.serverScaleKnown)
			state.serverWindowReliable = state.synSeen
		}
		if !isRST {
			if obs.PayloadBytes > 0 {
				state.serverPayload += uint64(obs.PayloadBytes)
			}
			if obs.TTLOrHopLimit > 0 {
				s.addTTLSampleLocked(state, obs.Family, obs.TTLOrHopLimit, now)
			}
			if obs.OptionsKnown && (obs.OptionsFingerprint != 0 || flags&classifier.TCPFlagSYN != 0 || !state.serverOptionsKnown) {
				state.serverOptions = obs.OptionsFingerprint
				state.serverOptionsKnown = true
			}
			if obs.Family == 4 {
				state.serverIPID, state.serverIPIDKnown = obs.IPID, true
			}
		}
		if isRST {
			state.rstTimes = append(state.rstTimes, now)
			if len(state.rstTimes) > 16 {
				state.rstTimes = append([]time.Time(nil), state.rstTimes[len(state.rstTimes)-16:]...)
			}
		}
	}
	s.stats.Observed++
}

func scaledWindow(window uint16, scale uint8, known bool) uint32 {
	if !known || scale > 14 {
		return uint32(window)
	}
	return uint32(window) << scale
}

func (s *PassiveRSTStore) addTTLSampleLocked(state *passiveRSTFlowState, family, value uint8, now time.Time) {
	target := &state.ttl4
	if family == 6 {
		target = &state.ttl6
	}
	limit := s.cfg.BaselineSamples
	if cap(target.samples) < limit {
		target.samples = make([]uint8, 0, limit)
		target.next = 0
	}
	if len(target.samples) < limit {
		target.samples = append(target.samples, value)
	} else {
		target.samples[target.next] = value
		target.next = (target.next + 1) % limit
	}
	target.lastAt = now
}

func (s *PassiveRSTStore) evaluateRSTLocked(state *passiveRSTFlowState, obs PassiveRSTPacketObservation, now time.Time) PassiveRSTEvidence {
	baseline := s.baselineLocked(state, obs.Family, now)
	seqDecision := windowDecision(obs.Sequence, state.clientReceiveNext, state.clientReceiveWindow, state.clientWindowReliable)
	ackDecision := windowDecision(obs.Acknowledgment, state.serverReceiveNext, state.serverReceiveWindow, state.serverWindowReliable && obs.Flags&classifier.TCPFlagACK != 0)
	signals := make([]PassiveRSTSignalObservation, 0, 8)
	add := func(signal PassiveRSTSignal, strength PassiveRSTSignalStrength, reason string) {
		signals = append(signals, PassiveRSTSignalObservation{Signal: signal, Strength: strength, Reason: reason})
	}
	if state.synAckSeen && state.serverPayload == 0 {
		strength := PassiveRSTStrengthDiagnostic
		if state.visibility {
			strength = PassiveRSTStrengthStrong
		}
		add(PassiveRSTSignalPreServerPayload, strength, "RST arrived after SYN-ACK and before observed server payload")
	}
	windowStart := now.Add(-time.Duration(s.cfg.BurstWindowMS) * time.Millisecond)
	burst := 1
	for _, at := range state.rstTimes {
		if !at.Before(windowStart) {
			burst++
		}
	}
	if burst >= s.cfg.BurstThreshold {
		add(PassiveRSTSignalBurst, PassiveRSTStrengthCorroborating, fmt.Sprintf("%d RST packets in bounded flow window", burst))
	}
	if baseline.Samples > 0 && obs.TTLOrHopLimit > 0 {
		delta := absInt(int(obs.TTLOrHopLimit) - int(baseline.Center))
		if delta > int(baseline.EffectiveTolerance) {
			if baseline.Quality == PassiveRSTBaselineStable {
				add(PassiveRSTSignalTTLMismatch, PassiveRSTStrengthStrong, fmt.Sprintf("observed=%d center=%d tolerance=%d", obs.TTLOrHopLimit, baseline.Center, baseline.EffectiveTolerance))
			} else {
				add(PassiveRSTSignalWeakTTLMismatch, PassiveRSTStrengthDiagnostic, fmt.Sprintf("baseline=%s observed=%d center=%d tolerance=%d", baseline.Quality, obs.TTLOrHopLimit, baseline.Center, baseline.EffectiveTolerance))
			}
		}
	}
	if seqDecision.Reliable && !seqDecision.InWindow {
		add(PassiveRSTSignalSequenceOutside, PassiveRSTStrengthStrong, "RST sequence is outside the reliable client receive window")
	}
	if ackDecision.Reliable && !ackDecision.InWindow {
		add(PassiveRSTSignalAckOutside, PassiveRSTStrengthStrong, "RST acknowledgment is outside the reliable server receive window")
	}
	if state.serverOptionsKnown && (!obs.OptionsKnown || obs.OptionsFingerprint != state.serverOptions) {
		add(PassiveRSTSignalOptionsMismatch, PassiveRSTStrengthCorroborating, "RST TCP option layout differs from observed server packets")
	}
	if state.synAckSeen && obs.Flags&classifier.TCPFlagACK == 0 {
		add(PassiveRSTSignalMissingACK, PassiveRSTStrengthCorroborating, "RST has no ACK in a post-SYN-ACK phase")
	}
	if obs.Family == 4 && state.serverIPIDKnown && ipidDiagnosticAnomaly(state.serverIPID, obs.IPID) {
		add(PassiveRSTSignalIPIDAnomaly, PassiveRSTStrengthDiagnostic, "IPv4 IPID differs sharply from the latest server observation")
	}
	if !state.visibility {
		add(PassiveRSTSignalIncompleteCapture, PassiveRSTStrengthDiagnostic, "incoming visibility is not proven complete")
	}
	decision := PassiveRSTDecisionObserve
	reason := "passive RST observe-only model"
	return PassiveRSTEvidence{
		ObservedAt: now, Family: obs.Family, TTLOrHopLimit: obs.TTLOrHopLimit, Signals: signals,
		Baseline: baseline, Sequence: seqDecision, Acknowledgment: ackDecision,
		RSTHasACK: obs.Flags&classifier.TCPFlagACK != 0, OptionsFingerprint: obs.OptionsFingerprint,
		IPID: obs.IPID, Decision: decision, Reason: reason,
	}
}

func windowDecision(value, start, size uint32, reliable bool) PassiveRSTWindowDecision {
	decision := PassiveRSTWindowDecision{Reliable: reliable, Value: value, Start: start, Size: size, InWindow: true}
	if reliable {
		decision.InWindow = sequenceWithinWindow(value, start, size)
	}
	return decision
}

func sequenceWithinWindow(value, start, size uint32) bool {
	if size == 0 {
		return value == start
	}
	delta := uint32(value - start)
	return delta <= size
}

func ipidDiagnosticAnomaly(previous, current uint16) bool {
	if previous == 0 || current == 0 {
		return false
	}
	delta := int(current) - int(previous)
	if delta < 0 {
		delta = -delta
	}
	if delta > 32768 {
		delta = 65536 - delta
	}
	return delta > 4096
}

func (s *PassiveRSTStore) baselineLocked(state *passiveRSTFlowState, family uint8, now time.Time) PassiveRSTBaselineSnapshot {
	ttl := state.ttl4
	if family == 6 {
		ttl = state.ttl6
	}
	out := PassiveRSTBaselineSnapshot{Family: family, Quality: PassiveRSTBaselineNone, Samples: len(ttl.samples), LastObservedAt: ttl.lastAt}
	if len(ttl.samples) == 0 {
		return out
	}
	values := append([]uint8(nil), ttl.samples...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	out.Center = values[len(values)/2]
	out.Spread = values[len(values)-1] - values[0]
	tolerance := maxInt(s.cfg.MinTTLTolerance, int(out.Spread)+s.cfg.TTLSafetyMargin)
	if tolerance > 255 {
		tolerance = 255
	}
	out.EffectiveTolerance = uint8(tolerance)
	if now.Sub(ttl.lastAt) > time.Duration(s.cfg.BaselineFreshnessSeconds)*time.Second {
		out.Quality = PassiveRSTBaselineStale
		return out
	}
	if len(values) < 3 {
		out.Quality = PassiveRSTBaselineWeak
		return out
	}
	routeThreshold := maxInt(8, s.cfg.MinTTLTolerance+s.cfg.TTLSafetyMargin*2)
	if int(out.Spread) > routeThreshold {
		out.Quality = PassiveRSTBaselineRouteChangeSuspected
		return out
	}
	out.Quality = PassiveRSTBaselineStable
	return out
}

func (s *PassiveRSTStore) snapshotLocked(state *passiveRSTFlowState, now time.Time) PassiveRSTFlowSnapshot {
	var lastRST time.Time
	if len(state.rstTimes) > 0 {
		lastRST = state.rstTimes[len(state.rstTimes)-1]
	}
	return PassiveRSTFlowSnapshot{
		FlowKey: state.flow, ConfigGeneration: state.generation, SetID: state.setID, DeviceScope: state.deviceScope,
		SYNSeen: state.synSeen, SYNACKSeen: state.synAckSeen, ServerPayloadBytes: state.serverPayload,
		ServerPayloadProgress: state.serverPayload > 0, VisibilityComplete: state.visibility,
		RSTCount: len(state.rstTimes), LastRSTAt: lastRST, SuppressionBudget: state.suppressionBudget, SuppressionExpiresAt: state.suppressionDeadline,
		ServerOptionsKnown: state.serverOptionsKnown, ServerOptionsFingerprint: state.serverOptions,
		IPv4Baseline: s.baselineLocked(state, 4, now), IPv6Baseline: s.baselineLocked(state, 6, now),
		CreatedAt: state.createdAt, LastSeen: state.lastSeen,
	}
}

func (s *PassiveRSTStore) UpdateScope(flow classifier.FlowKey, generation uint64, setID, deviceScope string) bool {
	if s == nil || generation == 0 || flow.IsZero() {
		return false
	}
	flow = flow.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.flows[flow]
	if state == nil || state.generation != generation {
		return false
	}
	if setID != "" {
		state.setID = setID
	}
	if deviceScope != "" {
		state.deviceScope = deviceScope
	}
	return true
}

func (s *PassiveRSTStore) Lookup(flow classifier.FlowKey) (PassiveRSTFlowSnapshot, bool) {
	if s == nil {
		return PassiveRSTFlowSnapshot{}, false
	}
	flow = flow.Normalize()
	now := s.clock.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneExpiredLocked(now)
	state := s.flows[flow]
	if state == nil {
		return PassiveRSTFlowSnapshot{}, false
	}
	return s.snapshotLocked(state, now), true
}

func (s *PassiveRSTStore) Recent(limit int) []PassiveRSTEvidence {
	if s == nil || limit <= 0 {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit > len(s.recent) {
		limit = len(s.recent)
	}
	out := make([]PassiveRSTEvidence, 0, limit)
	for i := len(s.recent) - limit; i < len(s.recent); i++ {
		out = append(out, clonePassiveRSTEvidence(s.recent[i]))
	}
	return out
}

func (s *PassiveRSTStore) appendRecentLocked(e PassiveRSTEvidence) {
	limit := s.cfg.RecentDecisionLimit
	if limit <= 0 {
		return
	}
	if len(s.recent) >= limit {
		copy(s.recent, s.recent[len(s.recent)-limit+1:])
		s.recent = s.recent[:limit-1]
	}
	s.recent = append(s.recent, clonePassiveRSTEvidence(e))
}

func clonePassiveRSTEvidence(in PassiveRSTEvidence) PassiveRSTEvidence {
	out := in
	out.Signals = append([]PassiveRSTSignalObservation(nil), in.Signals...)
	return out
}

func (s *PassiveRSTStore) DeleteFlow(flow classifier.FlowKey) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	flow = flow.Normalize()
	if s.flows[flow] == nil {
		return 0
	}
	s.deleteFlowLocked(flow)
	s.stats.FlowInvalidated++
	return 1
}

func (s *PassiveRSTStore) InvalidateGeneration(generation uint64) int {
	if s == nil || generation == 0 {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for flow, state := range s.flows {
		if state.generation == generation {
			s.deleteFlowLocked(flow)
			removed++
		}
	}
	s.stats.GenerationInvalidated += uint64(removed)
	return removed
}

func (s *PassiveRSTStore) GC(now time.Time) int {
	if s == nil {
		return 0
	}
	if now.IsZero() {
		now = s.clock.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneExpiredLocked(now)
}

func (s *PassiveRSTStore) Clear() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := len(s.flows)
	clear(s.flows)
	clear(s.endpoints)
	s.recent = s.recent[:0]
	s.stats.Cleared += uint64(removed)
	return removed
}

func (s *PassiveRSTStore) Stats() PassiveRSTStoreStats {
	if s == nil {
		return PassiveRSTStoreStats{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.stats
}

func (s *PassiveRSTStore) pruneExpiredLocked(now time.Time) int {
	ttl := time.Duration(s.cfg.FlowTTLSeconds) * time.Second
	removed := 0
	for flow, state := range s.flows {
		if !state.lastSeen.Add(ttl).After(now) {
			s.deleteFlowLocked(flow)
			removed++
		}
	}
	s.stats.Expired += uint64(removed)
	return removed
}

func (s *PassiveRSTStore) evictOldestLocked() {
	var oldest classifier.FlowKey
	var order uint64
	first := true
	for flow, state := range s.flows {
		if first || state.order < order {
			oldest, order, first = flow, state.order, false
		}
	}
	if !first {
		s.deleteFlowLocked(oldest)
		s.stats.Evicted++
	}
}

func (s *PassiveRSTStore) deleteFlowLocked(flow classifier.FlowKey) {
	state := s.flows[flow]
	if state == nil {
		return
	}
	delete(s.endpoints, endpointKeyFromFlow(state.flow))
	delete(s.flows, flow)
}

func ParsePassiveRSTTCPObservation(pkt *pktInfo, tcp []byte, payloadBytes int, direction PassiveRSTDirection, visibilityComplete bool, observedAt time.Time) (PassiveRSTPacketObservation, bool) {
	if pkt == nil || len(tcp) < TCPHeaderMinLen {
		return PassiveRSTPacketObservation{}, false
	}
	headerLen := int((tcp[12]>>4)&0x0f) * 4
	if headerLen < TCPHeaderMinLen || headerLen > len(tcp) {
		return PassiveRSTPacketObservation{}, false
	}
	fingerprint, known, scale, scaleKnown := passiveRSTOptionsFingerprint(tcp[TCPHeaderMinLen:headerLen])
	obs := PassiveRSTPacketObservation{
		Direction: direction, Family: pkt.ver, Flags: tcp[13], Sequence: binary.BigEndian.Uint32(tcp[4:8]),
		Acknowledgment: binary.BigEndian.Uint32(tcp[8:12]), Window: binary.BigEndian.Uint16(tcp[14:16]),
		PayloadBytes: payloadBytes, TTLOrHopLimit: packetTTLOrHop(pkt), OptionsFingerprint: fingerprint,
		OptionsKnown: known, WindowScale: scale, WindowScaleKnown: scaleKnown,
		VisibilityComplete: visibilityComplete, ObservedAt: observedAt,
	}
	if pkt.ver == IPv4 && len(pkt.raw) >= 6 {
		obs.IPID = binary.BigEndian.Uint16(pkt.raw[4:6])
	}
	return obs, true
}

func packetTTLOrHop(pkt *pktInfo) uint8 {
	if pkt == nil {
		return 0
	}
	if pkt.ver == IPv4 && len(pkt.raw) > 8 {
		return pkt.raw[8]
	}
	if pkt.ver == IPv6 && len(pkt.raw) > 7 {
		return pkt.raw[7]
	}
	return 0
}

func passiveRSTOptionsFingerprint(options []byte) (fingerprint uint64, known bool, windowScale uint8, scaleKnown bool) {
	if len(options) == 0 {
		return 0, true, 0, false
	}
	h := fnv.New64a()
	for i := 0; i < len(options); {
		kind := options[i]
		_, _ = h.Write([]byte{kind})
		switch kind {
		case 0:
			return h.Sum64(), true, windowScale, scaleKnown
		case 1:
			i++
			continue
		default:
			if i+1 >= len(options) {
				return h.Sum64(), false, windowScale, scaleKnown
			}
			length := int(options[i+1])
			if length < 2 || i+length > len(options) {
				return h.Sum64(), false, windowScale, scaleKnown
			}
			_, _ = h.Write([]byte{byte(length)})
			if kind == 3 && length == 3 {
				windowScale, scaleKnown = options[i+2], true
			}
			i += length
		}
	}
	return h.Sum64(), true, windowScale, scaleKnown
}

func absInt(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
