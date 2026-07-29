package nfq

import (
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/log"
	"github.com/florianl/go-nfqueue"
)

func (s *TCPHoldStore) Hold(key classifier.FlowKey, generation uint64, queue *nfqueue.Nfqueue, packetID uint32, bytes int) bool {
	if s == nil || bytes < 0 {
		return false
	}
	if !ppe.DefaultVisibilityGate().Decision(ppe.VisibilityFeatureHoldReplay).Allowed {
		s.ReleaseAll(tcpHoldAbortVisibility)
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
	released := s.ReleaseWhere(func(classifier.FlowKey) bool { return true }, reason)
	if reason == tcpHoldAbortShutdown {
		s.visibilityOnce.Do(func() {
			if s.visibilityCancel != nil {
				s.visibilityCancel()
			}
		})
	}
	return released
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
