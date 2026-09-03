package nfq

import (
	"encoding/binary"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/metrics"
	"github.com/daniellavrushin/b4/sni"
	"github.com/daniellavrushin/b4/sock"
)

// L-quicsynrst (Часть 2.6, owner-approved 23.08). See quicsynrst_off.go for
// scope and the v1/v2/v3 distinction. This layer REUSES the v2-armed
// client-scope store (steerClients) but replaces the silent SYN drop with an
// immediate spoofed RST|ACK ("connection refused") toward the client.

// qbDoomedClassify is steerDecision without the steer enable gate: the
// arming trigger is the classification itself.
func qbDoomedClassify(set *config.SetConfig, payload []byte) bool {
	return isYouTubeVideoSet(set) && len(payload) >= 6 &&
		sni.ParseTLSClientHelloMetadata(payload).ECHPresent
}

// maybeArmQuicSynRst arms the (clientMAC|srcIP -> dstIP) pair after the
// first classified doomed flow; every later classification re-arms. The
// triggering flow itself proceeds through the regular holdch3 path — it is
// the arming trigger, not a victim.
func (w *Worker) maybeArmQuicSynRst(pkt *pktInfo, set *config.SetConfig, raw []byte) {
	if pkt == nil || set == nil || len(raw) == 0 || pkt.ver != IPv4 {
		return
	}
	if !isYouTubeVideoSet(set) {
		return
	}
	var pi PacketInfo
	var ok bool
	if pi, ok = ExtractPacketInfoV4(raw); !ok || len(pi.Payload) < 6 {
		return
	}
	if !qbDoomedClassify(set, pi.Payload) {
		return
	}

	now := time.Now()
	scopeKey := steerClientKey(pkt)
	steerClients.suppress(scopeKey, now)
	log.Warnf("[quicsynrst] armed %s for %v (%s)", scopeKey, steerClientTTL, pkt.dstStr)
	metrics.GetMetricsCollector().RecordPacket(uint64(len(raw)))
}

// buildSynRefusedRSTv4 builds a spoofed RST|ACK answering a bare client SYN:
// server->client, SEQ=0, ACK=client_ISN+1, flags=RST|ACK. That combination
// is accepted by strict stacks in SYN-SENT as "connection refused".
func buildSynRefusedRSTv4(raw []byte) []byte {
	pi, ok := ExtractPacketInfoV4(raw)
	if !ok {
		return nil
	}
	tcp := raw[pi.IPHdrLen:]
	if len(tcp) < 20 {
		return nil
	}
	clientPort := binary.BigEndian.Uint16(tcp[0:2])
	serverPort := binary.BigEndian.Uint16(tcp[2:4])
	clientSeq := binary.BigEndian.Uint32(tcp[4:8])

	rst := make([]byte, 40)
	rst[0] = 0x45
	binary.BigEndian.PutUint16(rst[2:4], 40)
	rst[8] = 64
	rst[9] = 6
	copy(rst[12:16], raw[16:20]) // src = server (was dst of the SYN)
	copy(rst[16:20], raw[12:16]) // dst = client

	binary.BigEndian.PutUint16(rst[20:22], serverPort)
	binary.BigEndian.PutUint16(rst[22:24], clientPort)
	binary.BigEndian.PutUint32(rst[24:28], 0)           // seq = 0
	binary.BigEndian.PutUint32(rst[28:32], clientSeq+1) // ack = ISN+1
	rst[32] = 0x50                                      // data offset 5
	rst[33] = 0x14                                      // RST | ACK
	binary.BigEndian.PutUint16(rst[34:36], 0)           // window 0

	sock.FixIPv4Checksum(rst[:20])
	sock.FixTCPChecksum(rst)
	return rst
}

// quicSynRstShouldRefuse is the pure decision part: armed pair + bare SYN.
func quicSynRstShouldRefuse(pkt *pktInfo, tcpFlags byte) bool {
	if pkt == nil || pkt.ver != IPv4 {
		return false
	}
	if tcpFlags != classifierFlagSYNOnly { // bare SYN only
		return false
	}
	return steerClients.suppressed(steerClientKey(pkt), time.Now())
}

// quicSynRstOnSyn handles an outbound bare SYN while its pair is armed:
// send the refused-RST immediately (synchronous, <5 ms budget) and drop the
// original SYN. Returns true when the packet was consumed. Mirrors the
// steer-v1 tolerance for a missing client sender (prod always has one via
// InitSender before packets flow) while still classifying the packet.
func (w *Worker) quicSynRstOnSyn(vc *verdictCtx, pkt *pktInfo, tcpFlags byte) bool {
	if !quicSynRstEnabled || !quicSynRstShouldRefuse(pkt, tcpFlags) {
		return false
	}
	cs := w.clientSender()

	rst := buildSynRefusedRSTv4(pkt.raw)
	if rst == nil {
		return false
	}
	start := time.Now()
	if cs == nil {
		log.Warnf("[quicsynrst] client sender unavailable; dropping SYN without RST (unexpected in prod)")
	} else if err := cs.SendIPv4(rst, pkt.src); err == nil {
		log.Warnf("[quicsynrst] refused-RST to %s:%d (dst=%s) built+sent=%v",
			pkt.srcStr, binaryPort(pkt.raw[pkt.ihl:]), pkt.dstStr, time.Since(start))
	} else {
		log.Tracef("[quicsynrst] RST send failed to %s: %v", pkt.srcStr, err)
	}
	if w.quicbound != nil {
		w.quicbound.noteRefused(pkt.dstStr, pkt.srcMac)
	}
	vc.drop()
	return true
}

// ---- quicbound store extension: refusal counters ----

func (s *quicboundStore) noteRefused(ip, mac string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refusedTotal++
	s.refusedSinceSummary++
	k := s.keys[ip]
	if k == nil {
		k = s.keyLocked(ip)
	}
	if k.refusedByMac == nil {
		k.refusedByMac = make(map[string]int)
	}
	k.refusedByMac[mac]++
}

func (s *quicboundStore) maxRefusedPerPairLocked() int {
	max := 0
	for _, k := range s.keys {
		for _, n := range k.refusedByMac {
			if n > max {
				max = n
			}
		}
	}
	return max
}
