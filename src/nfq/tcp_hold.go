package nfq

import (
	"net/netip"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/clock"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
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
	mu         sync.Mutex
	flows      map[classifier.FlowKey]*tcpHoldEntry
	config     TCPHoldConfig
	clock      clock.Clock
	order      uint64
	totalBytes int
	stats      TCPHoldStats
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
	return &TCPHoldStore{flows: make(map[classifier.FlowKey]*tcpHoldEntry, cfg.MaxFlows), config: cfg, clock: cfg.Clock}
}

func (s *TCPHoldStore) Hold(key classifier.FlowKey, generation uint64, queue *nfqueue.Nfqueue, packetID uint32, bytes int) bool {
	if s == nil || bytes < 0 {
		return false
	}
	key = key.Normalize()
	now := s.clock.Now()
	s.mu.Lock()
	var releases []tcpHeldPacket
	if existing := s.flows[key]; existing != nil && existing.generation != 0 && generation != 0 && existing.generation != generation {
		releases = append(releases, s.detachLocked(key, tcpHoldAbortGeneration)...)
	}
	if bytes > s.config.MaxBytesTotal || s.totalBytes+bytes > s.config.MaxBytesTotal {
		releases = append(releases, s.detachLocked(key, tcpHoldAbortPressure)...)
		s.mu.Unlock()
		s.releasePackets(releases)
		return false
	}
	if entry := s.flows[key]; entry != nil && len(entry.packets) >= s.config.MaxPacketsPerFlow {
		releases = append(releases, s.detachLocked(key, tcpHoldAbortPressure)...)
		s.mu.Unlock()
		s.releasePackets(releases)
		return false
	}
	for len(s.flows) >= s.config.MaxFlows {
		oldest := s.oldestKeyLocked()
		if !oldest.Client.SourceIP.IsValid() && !oldest.SrcIP.IsValid() && !oldest.DstIP.IsValid() {
			break
		}
		releases = append(releases, s.detachLocked(oldest, tcpHoldAbortPressure)...)
	}
	s.order++
	entry := s.flows[key]
	if entry == nil {
		entry = &tcpHoldEntry{key: key, generation: generation, order: s.order}
		s.flows[key] = entry
	} else if entry.generation == 0 {
		entry.generation = generation
	}
	entry.lastSeen = now
	entry.order = s.order
	entry.bytes += bytes
	entry.packets = append(entry.packets, tcpHeldPacket{queue: queue, packetID: packetID, bytes: bytes, generation: generation})
	s.totalBytes += bytes
	s.stats.HeldPackets++
	s.stats.BytesHeld = uint64(s.totalBytes)
	if s.stats.BytesHeld > s.stats.MaxBytesHeld {
		s.stats.MaxBytesHeld = s.stats.BytesHeld
	}
	s.mu.Unlock()
	s.releasePackets(releases)
	return true
}

func (s *TCPHoldStore) Release(key classifier.FlowKey, reason string) int {
	if s == nil {
		return 0
	}
	key = key.Normalize()
	s.mu.Lock()
	packets := s.detachLocked(key, reason)
	s.mu.Unlock()
	s.releasePackets(packets)
	return len(packets)
}

func (s *TCPHoldStore) ReleaseWhere(match func(classifier.FlowKey) bool, reason string) int {
	if s == nil || match == nil {
		return 0
	}
	s.mu.Lock()
	var packets []tcpHeldPacket
	for key := range s.flows {
		if match(key) {
			packets = append(packets, s.detachLocked(key, reason)...)
		}
	}
	s.mu.Unlock()
	s.releasePackets(packets)
	return len(packets)
}

func (s *TCPHoldStore) ReleaseAll(reason string) int {
	return s.ReleaseWhere(func(classifier.FlowKey) bool { return true }, reason)
}

func (s *TCPHoldStore) GC(now time.Time) int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	var packets []tcpHeldPacket
	flows := 0
	for key, entry := range s.flows {
		if now.Sub(entry.lastSeen) >= s.config.Timeout {
			packets = append(packets, s.detachLocked(key, tcpHoldAbortTimeout)...)
			flows++
		}
	}
	s.mu.Unlock()
	s.releasePackets(packets)
	return flows
}

func (s *TCPHoldStore) Len() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.flows)
}

func (s *TCPHoldStore) Bytes() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalBytes
}

func (s *TCPHoldStore) Stats() TCPHoldStats {
	if s == nil {
		return TCPHoldStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stats
}

func (s *TCPHoldStore) detachLocked(key classifier.FlowKey, reason string) []tcpHeldPacket {
	entry := s.flows[key]
	if entry == nil {
		return nil
	}
	delete(s.flows, key)
	s.totalBytes -= entry.bytes
	if s.totalBytes < 0 {
		s.totalBytes = 0
	}
	s.stats.BytesHeld = uint64(s.totalBytes)
	s.stats.ReleasedPackets += uint64(len(entry.packets))
	switch reason {
	case tcpHoldAbortTimeout:
		s.stats.TimeoutReleases += uint64(len(entry.packets))
	case tcpHoldAbortPressure:
		s.stats.PressureReleases += uint64(len(entry.packets))
	case tcpHoldAbortGeneration:
		s.stats.GenerationReleases += uint64(len(entry.packets))
	case tcpHoldAbortShutdown:
		s.stats.ShutdownReleases += uint64(len(entry.packets))
	default:
		s.stats.LifecycleReleases += uint64(len(entry.packets))
	}
	return entry.packets
}

func (s *TCPHoldStore) oldestKeyLocked() classifier.FlowKey {
	var oldest classifier.FlowKey
	var order uint64
	first := true
	for key, entry := range s.flows {
		if first || entry.order < order {
			oldest, order, first = key, entry.order, false
		}
	}
	return oldest
}

func (s *TCPHoldStore) releasePackets(packets []tcpHeldPacket) {
	for _, packet := range packets {
		if packet.queue == nil {
			continue
		}
		if err := packet.queue.SetVerdict(packet.packetID, nfqueue.NfAccept); err != nil {
			log.Tracef("failed to release held packet %d: %v", packet.packetID, err)
			s.mu.Lock()
			s.stats.VerdictErrors++
			s.mu.Unlock()
		}
	}
}

func holdReplayMode(cfg *config.Config) string {
	if cfg == nil {
		return config.HoldReplayOff
	}
	mode := cfg.System.Classifier.Flags.TCPHoldReplayMode
	if mode == "" {
		if cfg.System.Classifier.Flags.AutoHoldReplayEnabled {
			return config.HoldReplayAuto
		}
		return config.HoldReplayOff
	}
	if mode == config.HoldReplayOff && cfg.System.Classifier.Flags.AutoHoldReplayEnabled {
		return config.HoldReplayAuto
	}
	return mode
}

func holdReplayActive(cfg *config.Config) bool {
	mode := holdReplayMode(cfg)
	return mode == config.HoldReplayAuto || mode == config.HoldReplayDebug
}

func holdReplayObserve(cfg *config.Config) bool {
	return holdReplayMode(cfg) == config.HoldReplayObserve
}

func flowMatchesEndpoints(key classifier.FlowKey, clientIP, serverIP netip.Addr, clientPort, serverPort uint16) bool {
	if key.Client.SourceIP != clientIP {
		return false
	}
	return (key.SrcIP == clientIP && key.DstIP == serverIP && key.SrcPort == clientPort && key.DstPort == serverPort) ||
		(key.SrcIP == serverIP && key.DstIP == clientIP && key.SrcPort == serverPort && key.DstPort == clientPort)
}

func tcpFlowKeyForPacket(pkt *pktInfo, sport, dport uint16) (classifier.FlowKey, bool) {
	if pkt == nil {
		return classifier.FlowKey{}, false
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return classifier.FlowKey{}, false
	}
	return classifier.NewFlowKey(client, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), sport, dport, 6), true
}

func (w *Worker) releaseTCPHoldOnServerProgress(pkt *pktInfo, sport, dport uint16) int {
	if w == nil || w.tcpHold == nil || pkt == nil {
		return 0
	}
	clientIP := netIPToAddr(pkt.dst)
	serverIP := netIPToAddr(pkt.src)
	return w.tcpHold.ReleaseWhere(func(key classifier.FlowKey) bool {
		return flowMatchesEndpoints(key, clientIP, serverIP, dport, sport)
	}, tcpHoldAbortServer)
}

// maybeHoldTCPPacket is the only active hold entry point. It requires the
// observe-only reassembler to report a bounded, incomplete ClientHello and a
// decision that has not yet reached scoped domain confidence. false,true
// means pressure forced fail-open acceptance of the current packet.
func (w *Worker) maybeHoldTCPPacket(cfg *config.Config, pkt *pktInfo, key classifier.FlowKey, generation uint64, dport uint16, payload []byte, flags byte, tlsMetadata classifier.TLSMetadata, reassembly classifier.TCPReassemblyResult, matchedScopedHint bool, queue *nfqueue.Nfqueue, packetID uint32) (held, failOpen bool) {
	if cfg == nil || pkt == nil || w == nil || w.tcpHold == nil || !cfg.IsTCPPort(dport) || cfg.System.Classifier.Flags.TCPReassemblyMode != config.ReassemblyObserve {
		return false, false
	}
	if flags&(classifier.TCPFlagFIN|classifier.TCPFlagRST) != 0 || reassembly.Status != classifier.ReassemblyPartial || reassembly.Metadata.ParseError != "" || reassembly.Metadata.NeedBytes <= 0 || len(payload) == 0 || payload[0] != 0x16 {
		return false, false
	}
	if tlsMetadata.ClearSNI || reassembly.Metadata.SNI != "" || matchedScopedHint {
		w.tcpHold.Release(key, "evidence-confirmed")
		return false, false
	}
	mode := holdReplayMode(cfg)
	if mode != config.HoldReplayObserve && !holdReplayActive(cfg) {
		w.tcpHold.Release(key, tcpHoldAbortGeneration)
		return false, false
	}
	if mode == config.HoldReplayObserve {
		w.tcpHold.Release(key, "mode-observe")
		log.Tracef("tcp hold/replay observe flow=%v need=%d bytes=%d", key, reassembly.Metadata.NeedBytes, reassembly.BufferedBytes)
		return false, false
	}
	if w.tcpHold.Hold(key, generation, queue, packetID, len(payload)) {
		log.Tracef("tcp hold/replay held incomplete ClientHello flow=%v need=%d bytes=%d mode=%s", key, reassembly.Metadata.NeedBytes, reassembly.BufferedBytes, mode)
		return true, false
	}
	log.Tracef("tcp hold/replay pressure; released unchanged flow=%v", key)
	return false, true
}
