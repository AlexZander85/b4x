package nfq

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/metrics"
	"github.com/daniellavrushin/b4/sni"
)

// L-steer (bd b4x-p0.8): TSPU silently drops TCP-to-Google flows by the mere
// presence of an ECH extension in the ClientHello record
// (YOUTUBE_DATAPLANE.md §2, proven 21→22.08). Phone Chromium/Cronet always
// sends ECH GREASE and cannot disable it on Android, so every phone TCP media
// handshake to youtube-video GGC IPs dies after 20–30 s of silence while
// masked QUIC keeps working. Instead of injecting a doomed handshake, b4
// sends one raw TCP RST spoofed from the server IP so Cronet instantly falls
// back to live masked QUIC.
//
// Guards (hard, bd spec):
//   - youtube-video set ONLY (never youtube-ui / combo-timestamp / Gmail);
//   - steering fires on ECH detection in the record, so ECH-free clients
//     (Firefox .40, curl probes) keep the working fake+combo path;
//   - config untouched: build-time experiment like prior layers;
//   - PPE off; QUIC/UDP path untouched;
//   - repeated packets of a steered flow are dropped for steerSuppressTTL.
//
// v2 field lesson (22.08, YOUTUBE_DATAPLANE.md §7): a fast RST does not send
// Cronet to QUIC — it storms NEW TCP connections from fresh source ports
// every 3–13 s for 30 s+, each cycle SYN->SYN-ACK->CH->hold->RST; Chromium
// treats RST as transient. Per-flow suppression cannot match a fresh tuple
// by design. v2 therefore arms a client-scoped window on the first steer:
// bare SYNs from that device toward that dstIP are dropped silently for
// steerClientTTL, so retries die at SYN (<1 RTT) and masked QUIC stays the
// only live path. Owner-approved risk: during the window every gv-TCP SYN of
// that client to that IP is gated (phone GREASE is always ECH — proven).
//
// RST point chosen during code reading: post-first-payload ECH detect at the
// dropAndInjectHandshake funnel. SYN-stage RST was rejected: without static
// IPs in the set config a SYN cannot be classified youtube-video, and a port
// fallback would RST every TCP:443 destination.

const (
	// steerECHEnabled gates the whole layer; flip to false to disable.
	// Diagnostic experiment builds (-tags tlsrcediag / -tags ipfragdiag /
	// -tags quicbound / -tags quicsynrst / -tags l5ppe / -tags echflow /
	// -tags ggcdisc) disable the closed steer family: v1/v2 actions would
	// consume or distort the flows those layers observe, and L-quicsynrst
	// replaces v2's silent SYN drop with refused-RST.
	steerECHEnabled = !tlsrecDiagEnabled && !ipfragDiagEnabled && !quicboundEnabled && !quicSynRstEnabled && !l5PPEEnabled && !echFlowEnabled && !ggcDiscEnabled && !qbpEnabled && !vnbEnabled && !ja4Enabled && !stormEnabled
	// steerSuppressTTL silences retransmits and client retries of a steered flow.
	steerSuppressTTL = 10 * time.Second
	// steerSuppressMax bounds the store; beyond it stale entries are pruned.
	steerSuppressMax = 1024
	// steerClientTTL is the v2 client-scoped window: after the first steer of
	// a (device -> dstIP) pair, bare SYNs toward that dstIP are dropped
	// silently so Cronet retry storms die at SYN instead of looping
	// SYN->CH->hold->RST on fresh tuples.
	steerClientTTL = 10 * time.Second
)

type steerSuppressStore struct {
	mu    sync.Mutex
	flows map[string]time.Time
}

var (
	steerFlows   = &steerSuppressStore{flows: make(map[string]time.Time)}
	steerClients = &steerSuppressStore{flows: make(map[string]time.Time)}
)

func (s *steerSuppressStore) suppress(key string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.flows) >= steerSuppressMax {
		for k, ts := range s.flows {
			if now.Sub(ts) > steerSuppressTTL {
				delete(s.flows, k)
			}
		}
	}
	if len(s.flows) >= steerSuppressMax {
		s.flows = make(map[string]time.Time)
	}
	s.flows[key] = now
}

func (s *steerSuppressStore) suppressed(key string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts, ok := s.flows[key]
	if !ok {
		return false
	}
	if now.Sub(ts) > steerSuppressTTL {
		delete(s.flows, key)
		return false
	}
	return true
}

// steerDecision reports whether this handshake must be steered instead of
// injected: exactly the youtube-video set AND an ECH extension detected in
// the ClientHello record.
func steerDecision(set *config.SetConfig, payload []byte) bool {
	if !steerECHEnabled || !isYouTubeVideoSet(set) || len(payload) < 6 {
		return false
	}
	return sni.ParseTLSClientHelloMetadata(payload).ECHPresent
}

func steerKey(pkt *pktInfo, sport, dport uint16) string {
	return fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
}

// steerClientKey scopes v2 suppression to a device and the doomed destination:
// MAC when resolvable (NAT-proof device identity), otherwise the source IP.
// Source ports are deliberately excluded — Cronet retries steered flows from
// fresh tuples, which is exactly what per-flow suppression cannot catch.
func steerClientKey(pkt *pktInfo) string {
	id := pkt.srcMac
	if id == "" {
		id = pkt.srcStr
	}
	return "c:" + id + "|d:" + pkt.dstStr
}

// steerClientSYNSuppressedDrop reports whether this packet is a bare SYN from
// a device whose (device -> dstIP) pair was steered within steerClientTTL.
// Only bare SYNs are gated: established-flow packets keep per-flow handling,
// and anything without the SYN flag passes to regular processing untouched.
func steerClientSYNSuppressedDrop(tcpFlags byte, pkt *pktInfo) bool {
	if !steerECHEnabled || pkt == nil {
		return false
	}
	if tcpFlags&classifier.TCPFlagSYN == 0 || tcpFlags&(classifier.TCPFlagACK|classifier.TCPFlagRST|classifier.TCPFlagFIN) != 0 {
		return false
	}
	return steerClients.suppressed(steerClientKey(pkt), time.Now())
}

// steerSuppressedDrop reports whether this packet belongs to a flow steered
// within steerSuppressTTL; such packets are silently dropped so Cronet does
// not hammer the doomed TCP path after the RST.
func steerSuppressedDrop(pkt *pktInfo, sport, dport uint16) bool {
	if !steerECHEnabled || pkt == nil {
		return false
	}
	return steerFlows.suppressed(steerKey(pkt, sport, dport), time.Now())
}

// maybeSteerECHFlow intercepts handshake injection at the single funnel used
// by every inject call site (complete CH, hold-assembled CH, hint-started
// hold). When the resolved set is exactly youtube-video AND the ClientHello
// record carries an ECH extension, send one raw RST from the server to the
// client, drop the packet, suppress the flow and arm the v2 client-scoped
// SYN window for the (device -> dstIP) pair. Returns true when the packet
// was consumed by steering.
func (w *Worker) maybeSteerECHFlow(vc *verdictCtx, pkt *pktInfo, set *config.SetConfig, raw []byte) bool {
	if !steerECHEnabled || vc == nil || pkt == nil || len(raw) == 0 || !isYouTubeVideoSet(set) {
		return false
	}

	var pi PacketInfo
	var ok bool
	if pkt.ver == IPv4 {
		pi, ok = ExtractPacketInfoV4(raw)
	} else {
		pi, ok = ExtractPacketInfoV6(raw)
	}
	if !ok || len(pi.Payload) < 6 {
		return false
	}

	if !steerDecision(set, pi.Payload) {
		return false
	}
	meta := sni.ParseTLSClientHelloMetadata(pi.Payload)

	sport := binary.BigEndian.Uint16(raw[pi.IPHdrLen : pi.IPHdrLen+2])
	dport := binary.BigEndian.Uint16(raw[pi.IPHdrLen+2 : pi.IPHdrLen+4])
	key := steerKey(pkt, sport, dport)
	now := time.Now()

	if steerFlows.suppressed(key, now) {
		vc.drop()
		return true
	}
	steerFlows.suppress(key, now)
	// v2: arm the client-scoped SYN window for this (device -> dstIP) pair.
	// Re-arming here is intentional: every CH-stage steer that slips through
	// an expired window restarts steerClientTTL, so a persistent storm never
	// gets more than one hold+RST cycle per window.
	scopeKey := steerClientKey(pkt)
	steerClients.suppress(scopeKey, now)

	host := meta.ECHOuterName
	if host == "" {
		host = meta.SNI
	}

	cfg := w.getConfig()
	if cfg == nil || !cfg.Queue.IsDiscovery {
		log.LogConnection("TCP", setName(set), host, pkt.srcStr, sport, setName(set), pkt.dstStr, dport,
			pkt.srcMac, config.TLSVersionString(meta.MaxVersion), "steer")
		log.Warnf("L-steer: RST to client %s:%d dst=%s:%d set=%s ech=1 ch=%dB",
			pkt.srcStr, sport, pkt.dstStr, dport, setName(set), len(pi.Payload))
		log.Infof("L-steer v2: armed client scope %s for %v (bare SYNs dropped)", scopeKey, steerClientTTL)
	}

	m := metrics.GetMetricsCollector()
	m.RecordConnection("TCP", host, pkt.srcStr, pkt.dstStr, true, pkt.srcMac, setName(set),
		config.TLSVersionString(meta.MaxVersion))
	m.RecordPacket(uint64(len(raw)))

	// RST spoofed from the server IP toward the client. Built from the real
	// client packet header (ports + ACK), so seq lands in-window for both a
	// first data segment (ACK=ISN+1) and later retransmits.
	if cs := w.clientSender(); cs != nil {
		if pkt.ver == IPv4 {
			w.sendRSTToClientV4(pkt.raw, pkt.ihl, pkt.src, pkt.dst)
		} else {
			w.sendRSTToClientV6(pkt.raw, pkt.src, pkt.dst)
		}
	}

	vc.drop()
	return true
}
