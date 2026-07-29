package nfq

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4/capture"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
	"github.com/daniellavrushin/b4/discord"
	"github.com/daniellavrushin/b4/lab"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/metrics"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/quic"
	"github.com/daniellavrushin/b4/sni"
	"github.com/daniellavrushin/b4/sock"
	"github.com/daniellavrushin/b4/stun"
	"github.com/daniellavrushin/b4/utils"
	"github.com/florianl/go-nfqueue"
)

type pktInfo struct {
	raw     []byte
	ver     uint8
	proto   uint8
	src     net.IP
	dst     net.IP
	srcStr  string
	dstStr  string
	srcMac  string
	ihl     int
	offload OffloadMetadata
}

func (w *Worker) handlePacket(q *nfqueue.Nfqueue, a nfqueue.Attribute, mark uint) int {
	if a.PacketID == nil || a.Payload == nil || len(*a.Payload) == 0 {
		if a.PacketID != nil && q != nil {
			if err := q.SetVerdict(*a.PacketID, nfqueue.NfAccept); err != nil {
				log.Tracef("failed to set verdict on invalid packet %d: %v", *a.PacketID, err)
			}
		}
		return 0
	}

	offload := DecodeOffloadMetadata(a)
	w.observeOffloadMetadata(offload)
	vc := &verdictCtx{id: *a.PacketID, q: q, offload: offload}

	if a.Mark != nil && capture.IsProcessedMark(uint32(*a.Mark), mark) {
		return vc.accept()
	}

	if !w.matchesInterface(a) {
		return vc.accept()
	}

	select {
	case <-w.ctx.Done():
		return 0
	default:
	}

	return w.dispatch(vc, *a.Payload)
}

func (w *Worker) dispatch(vc *verdictCtx, raw []byte) int {
	cfg := w.getConfig()
	matcher := w.getMatcher()

	atomic.AddUint64(&w.packetsProcessed, 1)

	pkt, ok := w.parseIPHeaders(raw)
	if !ok {
		return vc.accept()
	}

	pkt.offload = vc.offload
	if pkt.offload.PayloadLength == 0 {
		pkt.offload.PayloadLength = uint32(len(raw))
	}
	if pkt.offload.OriginalLength == 0 {
		pkt.offload.OriginalLength = pkt.offload.PayloadLength
	}

	matched, st := matcher.MatchIPWithSource(pkt.dst, pkt.srcMac)
	var set *config.SetConfig
	if matched {
		set = st
	}

	switch pkt.proto {
	case 6:
		if len(pkt.raw) >= pkt.ihl+TCPHeaderMinLen {
			return w.handleTCPPacket(vc, pkt, cfg, matcher, matched, set, st)
		}
	case 17:
		if len(pkt.raw) >= pkt.ihl+UDPHeaderLen {
			return w.handleUDPPacket(vc, pkt, cfg, matcher, matched, set, st)
		}
	}

	return vc.accept()
}

func needsTCPInjection(set *config.SetConfig) bool {
	if set == nil {
		return false
	}

	return set.TCP.DropSACK ||
		set.Faking.SNI ||
		set.Faking.SNIMutation.Mode != config.ConfigOff ||
		set.TCP.Desync.Mode != config.ConfigOff ||
		set.TCP.Desync.PostDesync ||
		set.TCP.Win.Mode != config.ConfigOff ||
		set.Fragmentation.Strategy != config.ConfigNone ||
		len(set.Fragmentation.StrategyPool) > 0
}

func needsTCPSynInjection(set *config.SetConfig) bool {
	if set == nil {
		return false
	}

	hasActiveStrategy := set.Fragmentation.Strategy != config.ConfigNone || len(set.Fragmentation.StrategyPool) > 0
	return set.TCP.SynFake || (hasActiveStrategy && set.Faking.TCPMD5)
}

func (w *Worker) parseIPHeaders(raw []byte) (*pktInfo, bool) {
	v := raw[0] >> 4
	if v != IPv4 && v != IPv6 {
		return nil, false
	}

	p := &pktInfo{raw: raw, ver: v}

	if v == IPv4 {
		if len(raw) < IPv4HeaderMinLen {
			return nil, false
		}
		ihl := int(raw[0]&0x0f) * 4
		if len(raw) < ihl {
			return nil, false
		}

		fragOffset := binary.BigEndian.Uint16(raw[6:8]) & 0x1FFF
		moreFragments := (binary.BigEndian.Uint16(raw[6:8]) & 0x2000) != 0
		if fragOffset != 0 || moreFragments {
			return nil, false
		}

		p.proto = raw[9]
		p.src = net.IP(raw[12:16])
		p.dst = net.IP(raw[16:20])
		p.ihl = ihl
	} else {
		if len(raw) < IPv6HeaderLen {
			return nil, false
		}
		nextHeader := raw[6]
		offset := 40

		for {
			switch nextHeader {
			case 0, 43, 60:
				if len(raw) < offset+2 {
					return nil, false
				}
				nextHeader = raw[offset]
				hdrLen := int(raw[offset+1])*8 + 8
				offset += hdrLen
			case 44:
				return nil, false
			default:
				goto done
			}
		}
	done:
		p.proto = nextHeader
		p.ihl = offset
		p.src = net.IP(raw[8:24])
		p.dst = net.IP(raw[24:40])
	}

	if p.src.IsLoopback() || p.dst.IsLoopback() {
		return nil, false
	}

	if w.srcResolver != nil && v == IPv4 && (p.proto == 6 || p.proto == 17) && len(raw) >= p.ihl+4 {
		sport := uint16(raw[p.ihl])<<8 | uint16(raw[p.ihl+1])
		dport := uint16(raw[p.ihl+2])<<8 | uint16(raw[p.ihl+3])
		if lan, ok := w.srcResolver.resolve(p.proto, p.src, sport, p.dst, dport); ok {
			p.src = lan
		}
	}

	p.srcStr = p.src.String()
	p.dstStr = p.dst.String()
	p.srcMac = w.getMacByIp(p.srcStr)

	return p, true
}

func (w *Worker) handleTCPPacket(vc *verdictCtx, pkt *pktInfo, cfg *config.Config, matcher *sni.SuffixSet, matched bool, set *config.SetConfig, st *config.SetConfig) int {
	tcp := pkt.raw[pkt.ihl:]
	if len(tcp) < TCPHeaderMinLen {
		return vc.accept()
	}
	datOff := int((tcp[12]>>4)&0x0f) * 4
	if len(tcp) < datOff {
		return vc.accept()
	}
	payload := tcp[datOff:]
	sport := binary.BigEndian.Uint16(tcp[0:2])
	dport := binary.BigEndian.Uint16(tcp[2:4])
	var reassemblyResult classifier.TCPReassemblyResult
	sequence, sequenceOK := tcpPacketSequence(tcp)
	if sequenceOK && !pkt.offload.Truncated {
		reassemblyResult = w.observeTCPReassembly(cfg, pkt, sequence, sport, dport, tcp[13], payload)
		w.submitClientHelloSegment(pkt, sequence, sport, dport, tcp[13], payload)
	}
	tlsMetadata := w.tcpTLSDecisionMetadata(cfg, pkt, sport, dport, payload)

	if cfg.IsTCPPort(sport) {
		w.releaseTCPHoldOnServerProgress(pkt, sport, dport)
		return w.HandleIncoming(vc, pkt.ver, pkt.raw, pkt.ihl, pkt.src, pkt.dstStr, dport, pkt.srcStr, sport, payload)
	}
	flowKey, flowKeyOK := tcpFlowKeyForPacket(pkt, sport, dport)
	tlsObservation := resolveAuthoritativeTLSObservationWithOffload(payload, reassemblyResult, pkt.offload)
	if flowKeyOK && tlsObservation.Complete {
		if tlsObservation.ConfigGen == 0 {
			tlsObservation.ConfigGen = dnsHintConfigGeneration(cfg)
		}
		if tlsObservation.ClientHelloID == 0 && sequenceOK {
			tlsObservation.ClientHelloID = classifier.LogicalClientHelloID(flowKey, sequence, tlsObservation.ConfigGen)
		}
	}
	host := tlsObservation.Host
	tlsVersion := tlsObservation.TLSVersion
	isClientHello := host != ""
	matchedSNI := false
	if tlsObservation.Conflict || (reassemblyResult.Status == classifier.ReassemblyAborted && reassemblyResult.Reason == classifier.ReassemblyAbortConflictingOverlap) {
		if flowKeyOK && w.tcpHold != nil {
			w.tcpHold.Release(flowKey, classifier.ReassemblyAbortConflictingOverlap)
		}
		if client, ok := dnsClientKey(pkt.src, pkt.srcMac); ok {
			_, _ = diagnostics.Default().Observe(diagnostics.FailureObservation{
				Signal: diagnostics.SignalReassemblyAbort, Client: client, DestinationIP: netIPToAddr(pkt.dst),
				DestinationPort: dport, Protocol: 6, Reason: "authoritative SNI conflict; mutation suppressed",
			})
		}
		observability.Default().Trace.Record(observability.TraceEvent{Timestamp: time.Now(), FlowID: fmt.Sprintf("%v", flowKey), Kind: "reassembled_sni_conflict", Fields: map[string]string{"reason": tlsObservation.Reason, "result": "fail-open"}})
		return vc.accept()
	}

	if matched && !set.MatchesTCPDPort(dport) {
		matched = false
		set = nil
	}
	if matched && st != nil && !w.allowNFQDomainDecisionWithMetadata(cfg, pkt, dport, 6, st, classifier.EvidenceStaticIP, "", false, "static-ip", tlsMetadata) {
		matched = false
		set = nil
		st = nil
	}

	matchedLearned := false
	if !classifierDecisionEnabled(cfg) {
		if mLearned, learnedSet, _ := matcher.MatchLearnedIPWithSource(pkt.dst, pkt.srcMac); mLearned && learnedSet.MatchesTCPDPort(dport) {
			matched, set, st, matchedLearned = true, learnedSet, learnedSet, true
		}
	}

	if !matched && cfg.IsTCPPort(dport) {
		if portMatched, portSet := matcher.MatchTCPPort(dport); portMatched {
			if w.allowNFQDomainDecision(cfg, pkt, dport, 6, portSet, classifier.EvidencePortProtocol, "", false, "port-fallback") {
				matched = true
				set = portSet
			}
		}
	}
	matchedScopedHint := false
	if !matched {
		if hintSet, ok := w.matchScopedDNSHintWithMetadata(cfg, pkt, sport, dport, 6, tlsMetadata); ok {
			matched = true
			set = hintSet
			matchedScopedHint = true
		}
	}

	// Clear or completely reassembled hostname evidence is both positive and
	// negative evidence: no provisional IP/port/learned selection survives it.
	var provisional *config.SetConfig
	if host != "" {
		provisional = set
		matched, set, st = false, nil, nil
		matchedLearned = false
		matchedScopedHint = false
		eligible := matcher.MatchSNICandidatesWithSourceTLS(host, pkt.srcMac, tlsVersion, pkt.ver)
		eligibleIDs := make([]string, 0, len(eligible))
		for _, candidateSet := range eligible {
			if candidateSet != nil && candidateSet.MatchesTCPDPort(dport) {
				eligibleIDs = append(eligibleIDs, classifierSetID(candidateSet))
			}
		}
		disposition := classifier.CandidateInsufficient
		if provisional != nil {
			disposition = classifier.ResolveCandidateDisposition(classifier.CaptureCandidate{CandidateSetID: classifierSetID(provisional)}, eligibleIDs)
		} else if len(eligibleIDs) == 1 {
			disposition = classifier.CandidateEligible
		} else if len(eligibleIDs) > 1 {
			disposition = classifier.CandidateAmbiguous
		}
		recordCandidateDisposition(flowKey, provisional, host, tlsObservation.Source, disposition, eligibleIDs)
		if len(eligibleIDs) > 1 {
			if client, ok := dnsClientKey(pkt.src, pkt.srcMac); ok {
				_, _ = diagnostics.Default().Observe(diagnostics.FailureObservation{Signal: diagnostics.SignalClassifierAmbiguous, Client: client, DestinationIP: netIPToAddr(pkt.dst), DestinationPort: dport, Protocol: 6, SetCandidates: eligibleIDs, Reason: "authoritative hostname matched multiple eligible sets"})
			}
		} else if len(eligibleIDs) == 1 {
			stSNI := eligible[0]
			strategy := "clear-sni"
			if tlsObservation.Source == classifier.EvidenceReassembledSNI {
				strategy = "reassembled-tcp-sni"
			}
			claimed := true
			if flowKeyOK && tlsObservation.ClientHelloID != 0 && w.clientHelloClaims != nil {
				claimed = w.clientHelloClaims.Claim(flowKey, tlsObservation.ClientHelloID, tlsObservation.ConfigGen, time.Now())
			}
			if !claimed {
				log.Tracef("duplicate logical ClientHello decision suppressed before classifier side effects flow=%v id=%d", flowKey, tlsObservation.ClientHelloID)
			} else {
				scope := nfqDecisionScope{
					FlowKey:             flowKey,
					ClientHelloID:       tlsObservation.ClientHelloID,
					EvidenceConfigGen:   tlsObservation.ConfigGen,
					CompleteClientHello: tlsObservation.Complete,
					TLSVersion:          tlsObservation.TLSVersion,
				}
				if w.allowNFQDomainDecisionScoped(cfg, pkt, dport, 6, stSNI, tlsObservation.Source, host, true, strategy, tlsMetadata, scope) {
					matchedSNI = true
					matched = true
					set = stSNI
				}
			}
		}
	}
	if flowKeyOK && w.tcpHold != nil && (reassemblyResult.Status == classifier.ReassemblyComplete || reassemblyResult.Status == classifier.ReassemblyAborted) {
		w.tcpHold.Release(flowKey, reassemblyResult.Reason)
	}

	routeTProxy := matched && set != nil && set.Routing.Enabled && config.RoutingUsesTProxy(set.Routing.Mode)

	tcpFlags := tcp[13]
	isSyn := (tcpFlags & 0x02) != 0
	isAck := (tcpFlags & 0x10) != 0
	isRst := (tcpFlags & 0x04) != 0
	if cfg.IsTCPPort(dport) && shouldPassCleanSYN(tcpFlags, len(payload), set) {
		log.Tracef("clean TCP SYN to %s:%d accepted before generic TLS action", pkt.dstStr, dport)
		return vc.accept()
	}
	if flowKeyOK && w.tcpHold != nil {
		generation := dnsHintConfigGeneration(cfg)
		if held, failOpen := w.maybeHoldTCPPacket(cfg, pkt, flowKey, generation, dport, payload, tcpFlags, tlsMetadata, reassemblyResult, matchedScopedHint, vc.q, vc.id); held {
			return 0
		} else if failOpen {
			return vc.accept()
		}
	}

	if matched && !routeTProxy && cfg.IsTCPPort(dport) && set.TCP.Duplicate.Enabled && set.TCP.Duplicate.Count > 0 {
		log.Tracef("TCP duplicate to %s:%d (%d copies, set: %s)", pkt.dstStr, dport, set.TCP.Duplicate.Count, set.Name)

		dupConnKey := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
		dupHost, dupTLS, _ := w.tlsCache.Lookup(dupConnKey)

		m := metrics.GetMetricsCollector()
		m.RecordConnection("TCP-DUP", dupHost, pkt.srcStr, pkt.dstStr, true, pkt.srcMac, set.Name, config.TLSVersionString(dupTLS))
		m.RecordPacket(uint64(len(pkt.raw)))

		if !cfg.Queue.IsDiscovery {
			log.LogConnection("TCP", "", dupHost, pkt.srcStr, sport, set.Name, pkt.dstStr, dport, pkt.srcMac, config.TLSVersionString(dupTLS), "tcp-dup")
		}

		if !vc.drop() {
			return 0
		}

		for i := 0; i < set.TCP.Duplicate.Count; i++ {
			if pkt.ver == IPv4 {
				_ = w.sock.SendIPv4(pkt.raw, pkt.dst)
			} else {
				_ = w.sock.SendIPv6(pkt.raw, pkt.dst)
			}
		}
		return 0
	}

	if isRst && cfg.IsTCPPort(dport) {
		log.Tracef("RST to %s:%d", pkt.dstStr, dport)
		if matched && set != nil && set.TCP.RSTProtection.Enabled {
			connKey := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
			if w.connTracker.ShouldDropOutboundRST(connKey) {
				log.Warnf("RST protection: dropped outbound RST to %s:%d — connection not established", pkt.dstStr, dport)
				metrics.GetMetricsCollector().RecordRSTDrop()
				vc.drop()
				return 0
			}
		}
	}

	if isAck && !isSyn && !isRst && cfg.IsTCPPort(dport) && matched && set != nil && set.TCP.RSTProtection.Enabled {
		connKey := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
		w.connTracker.MarkEstablished(connKey)
	}

	if isSyn && !isAck && !routeTProxy && cfg.IsTCPPort(dport) && matched && !set.TCP.Duplicate.Enabled && needsTCPSynInjection(set) {
		log.Tracef("TCP SYN to %s:%d (set: %s)", pkt.dstStr, dport, set.Name)

		m := metrics.GetMetricsCollector()
		m.RecordConnection("TCP-SYN", "", pkt.srcStr, pkt.dstStr, true, pkt.srcMac, set.Name, "")

		if pkt.ver == IPv4 {
			if set.TCP.SynFake {
				w.sendFakeSyn(set, pkt.raw, pkt.ihl, datOff)
			}
			if set.Fragmentation.Strategy != config.ConfigNone && set.Faking.TCPMD5 {
				w.sendFakeSynWithMD5(set, pkt.raw, pkt.ihl, pkt.dst)
			}
			_ = w.sock.SendIPv4(pkt.raw, pkt.dst)
		} else {
			if set.TCP.SynFake {
				w.sendFakeSynV6(set, pkt.raw, pkt.ihl, datOff)
			}
			if set.Fragmentation.Strategy != config.ConfigNone && set.Faking.TCPMD5 {
				w.sendFakeSynWithMD5V6(set, pkt.raw, pkt.dst)
			}
			_ = w.sock.SendIPv6(pkt.raw, pkt.dst)
		}

		if set.TCP.Incoming.Mode != config.ConfigOff || set.TCP.RSTProtection.Enabled || set.Escalate.To != "" {
			connKey := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
			w.connTracker.RegisterOutgoing(connKey, set)
		}

		vc.drop()
		return 0
	}

	matchedIP := st != nil
	ipTarget := ""
	sniTarget := ""

	if !matchedIP && matched && set != nil {
		ipTarget = set.Name
	}

	if cfg.IsTCPPort(dport) && len(payload) > 0 {
		log.Tracef("TCP payload to %s: len=%d, first5=%x", pkt.dstStr, len(payload), payload[:min(5, len(payload))])
		if len(payload) >= 5 && payload[0] == 0x16 {
			log.Tracef("TLS record: type=%x ver=%x%x len=%d", payload[0], payload[1], payload[2],
				int(payload[3])<<8|int(payload[4]))
		}
		connKey := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)

		if host != "" && tlsVersion != 0 {
			w.tlsCache.Store(connKey, host, tlsVersion)
		}

		if captureManager := capture.GetManager(cfg); captureManager != nil {
			captureManager.CapturePayload(connKey, host, "tls", payload)
		}

		// Hostname matching already ran through the authoritative packet/reassembly
		// path above. Reassembled SNI never creates a destination-global learned
		// IP or routing side effect. Packet-local compatibility learning is left
		// for the scoped-observation migration stage.
		if matchedSNI && set != nil {
			w.observeScopedLearnedObservation(cfg, pkt, dport, 6, host, set, tlsObservation.Source)
		}

		if matched && !matchedSNI && set != nil && !set.MatchesTLSVersion(tlsVersion) {
			matched = false
			set = nil
		}

		if matchedLearned && !matchedSNI && !(len(payload) >= 1 && payload[0] == 0x16) {
			if set != nil && set.Fragmentation.Strategy == config.ConfigNone && len(set.Fragmentation.StrategyPool) == 0 && set.TCP.Desync.Mode == config.ConfigOff {
				matched = false
				set = nil
			}
		}
	}

	if host == "" || tlsVersion == 0 {
		connKey := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
		if cachedHost, cachedTLS, found := w.tlsCache.Lookup(connKey); found {
			if host == "" {
				host = cachedHost
			}
			if tlsVersion == 0 {
				tlsVersion = cachedTLS
			}
		}
	}

	if matchedSNI {
		sniTarget = set.Name
	} else if matchedIP {
		ipTarget = st.Name
	}

	if matched && isClientHello && host != "" && cfg.IsTCPPort(dport) {
		escID, escOK := "", false
		if key, ok := scopedEscalationKey(cfg, pkt, set, host); ok && w.scopedFailures != nil {
			escID, _, escOK = w.scopedFailures.GetEscalation(key, time.Now())
		} else if !classifierDecisionEnabled(cfg) {
			escID, _, escOK = w.destState.GetEscalation(host)
		}
		if escOK {
			if escSet := cfg.GetSetById(escID); escSet != nil && escSet.Enabled {
				log.Tracef("scoped escalation hit for %s: %s -> %s", host, set.Name, escSet.Name)
				set = escSet
				if sniTarget != "" {
					sniTarget = set.Name
				}
				if ipTarget != "" {
					ipTarget = set.Name
				}
			}
		}
	}

	if matched && isClientHello && set.TCP.IPBlockDetect.Enabled && host != "" && cfg.IsTCPPort(dport) {
		ibd := &set.TCP.IPBlockDetect
		blocked := false
		if failureKey, ok := scopedFailureKey(cfg, pkt, dport, 6, set, host); ok && w.scopedFailures != nil {
			blocked = ibd.CacheBlockedIPs && w.scopedFailures.IsBlocked(failureKey, time.Now())
		} else if !classifierDecisionEnabled(cfg) {
			blocked = ibd.CacheBlockedIPs && w.destState.IsBlocked(fmt.Sprintf("%s:%d", pkt.dstStr, dport))
		}

		if blocked {
			if !cfg.Queue.IsDiscovery {
				log.LogConnection("TCP", sniTarget, host, pkt.srcStr, sport, ipTarget, pkt.dstStr, dport, pkt.srcMac, config.TLSVersionString(tlsVersion), "ipblock-cached")
			}
			if pkt.ver == IPv4 {
				w.sendRSTToClientV4(pkt.raw, pkt.ihl, pkt.src, pkt.dst)
			} else {
				w.sendRSTToClientV6(pkt.raw, pkt.src, pkt.dst)
			}

			m := metrics.GetMetricsCollector()
			m.RecordConnection("TCP", host, pkt.srcStr, pkt.dstStr, true, pkt.srcMac, set.Name, config.TLSVersionString(tlsVersion))
			m.RecordPacket(uint64(len(pkt.raw)))
			vc.drop()
			log.Tracef("IPBlockDetect: dropped packet to %s:%d (cached)", pkt.dstStr, dport)

			return 0
		}
	}

	if !cfg.Queue.IsDiscovery {
		log.LogConnection("TCP", sniTarget, host, pkt.srcStr, sport, ipTarget, pkt.dstStr, dport, pkt.srcMac, config.TLSVersionString(tlsVersion), "")
	}

	{
		m := metrics.GetMetricsCollector()
		setName := ""
		if matched {
			setName = set.Name
		}
		m.RecordConnection("TCP", host, pkt.srcStr, pkt.dstStr, matched, pkt.srcMac, setName, config.TLSVersionString(tlsVersion))
		m.RecordPacket(uint64(len(pkt.raw)))
	}

	if matched && set != nil && set.Routing.Enabled && config.RoutingIsBlock(set.Routing.Mode) {
		if matchedSNI || (matchedIP && !matchedLearned) {
			if config.NormalizeBlockAction(set.Routing.BlockAction) != config.BlockActionDrop {
				if pkt.ver == IPv4 {
					w.sendRSTToClientV4(pkt.raw, pkt.ihl, pkt.src, pkt.dst)
				} else {
					w.sendRSTToClientV6(pkt.raw, pkt.src, pkt.dst)
				}
				log.Tracef("BLACKHOLE: sent RST to %s:%d (set: %s)", pkt.dstStr, dport, set.Name)
			}
			if !cfg.Queue.IsDiscovery {
				log.LogConnection("TCP", sniTarget, host, pkt.srcStr, sport, ipTarget, pkt.dstStr, dport, pkt.srcMac, config.TLSVersionString(tlsVersion), "block")
				blockedTarget := host
				if blockedTarget == "" {
					blockedTarget = pkt.dstStr
				}
				metrics.GetMetricsCollector().RecordBlock(blockedTarget, pkt.srcMac)
			}
			vc.drop()
			return 0
		}
		return vc.accept()
	}

	if matched && set != nil && set.Routing.Enabled && config.RoutingUsesTProxy(set.Routing.Mode) {
		routeSource, routeConfidence, routeAuthorized := tlsObservation.Source, uint8(100), matchedSNI
		if matchedScopedHint {
			routeSource, routeConfidence, routeAuthorized = classifier.EvidenceDNSAnswer, 89, true
		}
		if !w.bindAuthorizedRoute(cfg, pkt, sport, dport, 6, set, host, routeSource, routeConfidence, routeAuthorized) {
			return vc.accept()
		}
		return vc.accept()
	}

	if matched {
		ibdOn := set.TCP.IPBlockDetect.Enabled
		canEscalate := set.Escalate.To != ""
		if isClientHello && !routeTProxy && (ibdOn || canEscalate) && host != "" && cfg.IsTCPPort(dport) {
			ibd := &set.TCP.IPBlockDetect
			ibConnKey := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
			failureKey, scopedKeyOK := scopedFailureKey(cfg, pkt, dport, 6, set, host)

			count, firstSeen := 0, time.Time{}
			if scopedKeyOK && w.scopedFailures != nil {
				count, firstSeen = w.scopedFailures.RecordAttempt(failureKey, time.Now())
			} else if !classifierDecisionEnabled(cfg) {
				count, firstSeen = w.destState.RecordClientHello(ibConnKey, host)
			}
			threshold := ibd.RetransmitThreshold
			if threshold <= 0 {
				threshold = 3
			}
			timeout := time.Duration(ibd.TimeoutMs) * time.Millisecond
			if timeout <= 0 {
				timeout = 3000 * time.Millisecond
			}

			if count >= threshold || (count > 1 && time.Since(firstSeen) > timeout) {
				if canEscalate {
					if next := cfg.GetSetById(set.Escalate.To); next != nil && next.Enabled {
						ttl := time.Duration(set.Escalate.TtlSec) * time.Second
						escalated := false
						if key, ok := scopedEscalationKey(cfg, pkt, set, host); ok && w.scopedFailures != nil {
							escalated = w.scopedFailures.SetEscalation(key, next.Id, ttl, time.Now())
						} else if !classifierDecisionEnabled(cfg) {
							escalated = w.destState.SetEscalation(host, next.Id, ttl)
						}
						if escalated {
							metrics.GetMetricsCollector().RecordEscalation()
							registerEscalatedRoute(cfg, next, pkt.dst)
							if !cfg.Queue.IsDiscovery {
								log.LogConnection("TCP", sniTarget, host, pkt.srcStr, sport, ipTarget, pkt.dstStr, dport, pkt.srcMac, config.TLSVersionString(tlsVersion), "ipblock-escalate->"+next.Name)
							}
							vc.drop()
							return 0
						}
						log.Warnf("escalation hop cap reached for %s (chain stopped at %s)", host, set.Name)
					}
				}
				if ibdOn {
					rstAlreadySent := false
					if flowKeyOK && w.scopedFailures != nil {
						rstAlreadySent = w.scopedFailures.HasRSTSent(flowKey, time.Now())
					} else if !classifierDecisionEnabled(cfg) {
						rstAlreadySent = w.destState.HasRSTSent(ibConnKey)
					}
					if !rstAlreadySent {
						if flowKeyOK && w.scopedFailures != nil {
							w.scopedFailures.MarkRSTSent(flowKey, time.Now())
						} else if !classifierDecisionEnabled(cfg) {
							w.destState.MarkRSTSent(ibConnKey)
						}
						if pkt.ver == IPv4 {
							w.sendRSTToClientV4(pkt.raw, pkt.ihl, pkt.src, pkt.dst)
						} else {
							w.sendRSTToClientV6(pkt.raw, pkt.src, pkt.dst)
						}
						if ibd.CacheBlockedIPs {
							if scopedKeyOK && w.scopedFailures != nil {
								if w.scopedFailures.AddBlocked(failureKey, 5*time.Minute, time.Now()) {
									observability.Default().Metrics.Inc(observability.MetricBlockedCacheWrite, map[string]string{"result": "accepted", "reason": "full_scope"}, 1)
									observability.Default().Trace.Record(observability.TraceEvent{Timestamp: time.Now(), FlowID: fmt.Sprintf("%v", flowKey), Kind: "scoped_failure_state", Fields: map[string]string{"operation": "blocked_cache_write", "scope": "client-domain-set-generation", "result": "accepted", "config_generation": fmt.Sprintf("%d", failureKey.ConfigGen)}})
								} else {
									observability.Default().Metrics.Inc(observability.MetricBlockedCacheWrite, map[string]string{"result": "rejected", "reason": "invalid_scope"}, 1)
								}
							} else if !classifierDecisionEnabled(cfg) {
								w.destState.AddBlocked(fmt.Sprintf("%s:%d", pkt.dstStr, dport))
							} else {
								observability.Default().Metrics.Inc(observability.MetricBlockedCacheWrite, map[string]string{"result": "rejected", "reason": "unknown_or_ambiguous_domain"}, 1)
								if client, ok := dnsClientKey(pkt.src, pkt.srcMac); ok {
									_, _ = diagnostics.Default().Observe(diagnostics.FailureObservation{Signal: diagnostics.SignalBlockedCacheScopeRejected, Client: client, DestinationIP: netIPToAddr(pkt.dst), DestinationPort: dport, Protocol: 6, ObservedAt: time.Now(), Reason: "blocked cache write rejected without full domain scope"})
								}
							}
						}
						if !cfg.Queue.IsDiscovery {
							log.LogConnection("TCP", sniTarget, host, pkt.srcStr, sport, ipTarget, pkt.dstStr, dport, pkt.srcMac, config.TLSVersionString(tlsVersion), "ipblock")
						}
						m := metrics.GetMetricsCollector()
						m.RecordConnection("TCP", host, pkt.srcStr, pkt.dstStr, true, pkt.srcMac, set.Name, config.TLSVersionString(tlsVersion))
					}
					vc.drop()
					return 0
				}
			}
		}

		if set.TCP.Incoming.Mode != config.ConfigOff || set.TCP.RSTProtection.Enabled || set.Escalate.To != "" {
			connKey := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)
			w.connTracker.RegisterOutgoing(connKey, set)
		}

		if routeTProxy || !needsTCPInjection(set) {
			return vc.accept()
		}

		packetCopy := make([]byte, len(pkt.raw))
		copy(packetCopy, pkt.raw)

		if set.TCP.DropSACK {
			if pkt.ver == 4 {
				packetCopy = sock.StripSACKFromTCP(packetCopy)
			} else {
				packetCopy = sock.StripSACKFromTCPv6(packetCopy)
			}
		}

		dstCopy := make(net.IP, len(pkt.dst))
		copy(dstCopy, pkt.dst)
		setCopy := set

		if !vc.drop() {
			return 0
		}

		v := pkt.ver
		w.wg.Add(1)
		go func(s *config.SetConfig, pktData []byte, d net.IP) {
			defer w.wg.Done()
			if v == 4 {
				w.dropAndInjectTCP(s, pktData, d)
			} else {
				w.dropAndInjectTCPv6(s, pktData, d)
			}
		}(setCopy, packetCopy, dstCopy)
		return 0
	}

	return vc.accept()
}

func (w *Worker) submitClientHelloSegment(pkt *pktInfo, sequence uint32, sport, dport uint16, flags byte, payload []byte) {
	sink := w.getClientHelloSink()
	if sink == nil || pkt == nil || dport != 443 {
		return
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return
	}
	_ = sink.Submit(lab.CaptureSegment{
		At:       time.Now(),
		Client:   client,
		SrcIP:    netIPToAddr(pkt.src),
		DstIP:    netIPToAddr(pkt.dst),
		SrcPort:  sport,
		DstPort:  dport,
		Sequence: sequence,
		Flags:    flags,
		Payload:  payload,
	})
}

func (w *Worker) handleUDPPacket(vc *verdictCtx, pkt *pktInfo, cfg *config.Config, matcher *sni.SuffixSet, matched bool, set *config.SetConfig, st *config.SetConfig) int {
	udp := pkt.raw[pkt.ihl:]
	if len(udp) < UDPHeaderLen {
		return vc.accept()
	}

	payload := udp[8:]
	sport := binary.BigEndian.Uint16(udp[0:2])
	dport := binary.BigEndian.Uint16(udp[2:4])
	connKey := fmt.Sprintf(connKeyFormat, pkt.srcStr, sport, pkt.dstStr, dport)

	if sport == 53 || dport == 53 {
		return w.processDnsPacket(vc, pkt.ver, sport, dport, payload, pkt.raw, pkt.srcMac)
	}

	if utils.IsPrivateIP(pkt.dst) {
		return vc.accept()
	}

	matchedIP := st != nil
	matchedQUIC := false
	matchedScopedHint := false
	matchedLearned := false
	isVoiceMedia := false
	host := ""
	ipTarget := ""
	sniTarget := ""

	if matchedIP && !st.MatchesUDPDPort(dport) {
		matchedIP = false
		matched = false
		set = nil
	}

	if matchedIP {
		ipTarget = st.Name
		if !w.allowNFQDomainDecision(cfg, pkt, dport, 17, st, classifier.EvidenceStaticIP, "", false, "static-ip") {
			matchedIP = false
			matched = false
			set = nil
			st = nil
		}
	}

	if !matchedIP && !classifierDecisionEnabled(cfg) {
		if mLearned, learnedSet, learnedDomain := matcher.MatchLearnedIPWithSource(pkt.dst, pkt.srcMac); mLearned && learnedSet.MatchesUDPDPort(dport) {
			matchedIP, matchedLearned, matched, set, host = true, true, true, learnedSet, learnedDomain
			sniTarget, ipTarget = learnedSet.Name, learnedSet.Name
		}
	}

	matchedPort := false
	if !matched {
		if portMatched, portSet := matcher.MatchUDPPort(dport); portMatched {
			if w.allowNFQDomainDecision(cfg, pkt, dport, 17, portSet, classifier.EvidencePortProtocol, "", false, "port-fallback") {
				matchedPort = true
				matched = true
				set = portSet
				ipTarget = portSet.Name
			}
		}
	}
	if !matched {
		if hintSet, ok := w.matchScopedDNSHint(cfg, pkt, sport, dport, 17); ok {
			matched = true
			set = hintSet
			matchedScopedHint = true
			ipTarget = hintSet.Name
		}
	}

	isVoiceMedia = stun.IsSTUNMessage(payload) || discord.IsVoicePacket(payload)

	isQUIC := quic.LooksLikeQUIC(payload)

	if host == "" && isQUIC {
		if h, ok := sni.ParseQUICClientHelloSNI(payload); ok {
			host = h
		}
	}

	quicGate := quicActionGate{}
	if host != "" {
		// QUIC SNI is authoritative positive and negative service evidence.
		provisional := set
		matched, matchedIP, matchedPort, matchedScopedHint = false, false, false, false
		set, st = nil, nil
		eligible := matcher.MatchSNICandidatesWithSourceTLS(host, pkt.srcMac, 0x0304, pkt.ver)
		udpEligible := make([]*config.SetConfig, 0, len(eligible))
		for _, candidateSet := range eligible {
			if candidateSet != nil && candidateSet.MatchesUDPDPort(dport) {
				udpEligible = append(udpEligible, candidateSet)
			}
		}
		if len(udpEligible) == 1 {
			sniSet := udpEligible[0]
			if w.allowNFQDomainDecision(cfg, pkt, dport, 17, sniSet, classifier.EvidenceQUICSNI, host, true, "quic-sni") {
				matchedQUIC, matched, set = true, true, sniSet
				sniTarget = sniSet.Name
				quicGate = newQUICActionGate(cfg, pkt, sport, dport, sniSet, classifier.EvidenceQUICSNI, true, "authoritative QUIC SNI")
				w.observeScopedLearnedObservation(cfg, pkt, dport, 17, host, sniSet, classifier.EvidenceQUICSNI)
				if cfg.System.Classifier.Flags.QUICToTCPHandoffEnabled {
					w.observeQUICHandoff(cfg, pkt, dport, host, sniSet)
				}
			}
		} else {
			reason := "QUIC SNI contradicted provisional service candidate"
			if len(udpEligible) > 1 {
				reason = "QUIC SNI matched multiple service sets"
			}
			quicGate = newQUICActionGate(cfg, pkt, sport, dport, provisional, classifier.EvidenceQUICSNI, false, reason)
		}
	}

	if isQUIC && !quicGate.Authorized && set != nil {
		switch {
		case matchedScopedHint:
			quicGate = newQUICActionGate(cfg, pkt, sport, dport, set, classifier.EvidenceDNSAnswer, true, "fresh scoped hint authorized QUIC flow")
		case quicSetCanUseGlobalFallback(cfg, set) && (matchedIP || matchedPort):
			quicGate = newQUICActionGate(cfg, pkt, sport, dport, set, classifier.EvidenceStaticIP, true, "explicit non-domain global fallback")
		default:
			matched, matchedIP, matchedPort, matchedQUIC = false, false, false, false
			set = nil
			quicGate = newQUICActionGate(cfg, pkt, sport, dport, set, classifier.EvidenceStaticIP, false, "unknown or malformed QUIC without service authorization")
		}
	}

	if isQUIC && quicGate.Authorized && set != nil && set.UDP.FilterQUIC == "all" {
		matchedQUIC = true
	}

	if captureManager := capture.GetManager(cfg); captureManager != nil {
		captureManager.CapturePayload(connKey, host, "quic", payload)
	}

	shouldHandle := set != nil && (matchedIP || matchedQUIC || matchedPort) && (!isQUIC || quicGate.Authorized) && !(isVoiceMedia && set.UDP.FilterSTUN)

	matched = shouldHandle

	udpTLS := ""
	if matchedQUIC || isQUIC {
		udpTLS = "1.3"
	}

	if shouldHandle && set != nil && host != "" {
		if key, ok := scopedEscalationKey(cfg, pkt, set, host); ok && w.scopedFailures != nil {
			if escID, _, found := w.scopedFailures.GetEscalation(key, time.Now()); found {
				if escSet := cfg.GetSetById(escID); escSet != nil && escSet.Enabled {
					set = escSet
					if sniTarget != "" {
						sniTarget = set.Name
					}
					if ipTarget != "" {
						ipTarget = set.Name
					}
				}
			}
		}
	}

	if !cfg.Queue.IsDiscovery {
		log.LogConnection("UDP", sniTarget, host, pkt.srcStr, sport, ipTarget, pkt.dstStr, dport, pkt.srcMac, udpTLS, "")
	}

	if isVoiceMedia && set != nil && set.UDP.FilterSTUN {
		return vc.accept()
	}

	if !shouldHandle {
		m := metrics.GetMetricsCollector()
		m.RecordConnection("UDP", host, pkt.srcStr, pkt.dstStr, false, pkt.srcMac, "", udpTLS)
		m.RecordPacket(uint64(len(pkt.raw)))
		return vc.accept()
	}

	if set != nil && set.Routing.Enabled && set.Targets.DomainOnly {
		confidence := uint8(94)
		if quicGate.Source == classifier.EvidenceDNSAnswer {
			confidence = 89
		}
		if !w.bindAuthorizedRoute(cfg, pkt, sport, dport, 17, set, host, quicGate.Source, confidence, quicGate.Authorized) {
			return vc.accept()
		}
	}

	m := metrics.GetMetricsCollector()
	setName := ""
	if matched {
		setName = set.Name
	}
	m.RecordConnection("UDP", host, pkt.srcStr, pkt.dstStr, matched, pkt.srcMac, setName, udpTLS)
	m.RecordPacket(uint64(len(pkt.raw)))

	if set.Routing.Enabled && config.RoutingIsBlock(set.Routing.Mode) {
		if matchedQUIC || (matchedIP && !matchedLearned) {
			if config.NormalizeBlockAction(set.Routing.BlockAction) != config.BlockActionDrop {
				if pkt.ver == IPv4 {
					if icmp := sock.BuildICMPv4Reject(pkt.raw, pkt.src.To4(), pkt.dst.To4()); icmp != nil {
						_ = w.clientSender().SendIPv4(icmp, pkt.src)
					}
				} else {
					if icmp := sock.BuildICMPv6Reject(pkt.raw, pkt.src.To16(), pkt.dst.To16()); icmp != nil {
						_ = w.clientSender().SendIPv6(icmp, pkt.src)
					}
				}
			}
			if !cfg.Queue.IsDiscovery {
				log.LogConnection("UDP", sniTarget, host, pkt.srcStr, sport, ipTarget, pkt.dstStr, dport, pkt.srcMac, udpTLS, "block")
				blockedTarget := host
				if blockedTarget == "" {
					blockedTarget = pkt.dstStr
				}
				metrics.GetMetricsCollector().RecordBlock(blockedTarget, pkt.srcMac)
			}
			vc.drop()
			return 0
		}
		return vc.accept()
	}

	switch set.UDP.Mode {
	case "drop":
		vc.drop()
		return 0

	case "reject":
		if !vc.drop() {
			return 0
		}
		if pkt.ver == IPv4 {
			if icmp := sock.BuildICMPv4Reject(pkt.raw, pkt.src.To4(), pkt.dst.To4()); icmp != nil {
				_ = w.clientSender().SendIPv4(icmp, pkt.src)
			}
		} else {
			if icmp := sock.BuildICMPv6Reject(pkt.raw, pkt.src.To16(), pkt.dst.To16()); icmp != nil {
				_ = w.clientSender().SendIPv6(icmp, pkt.src)
			}
		}
		return 0

	case "fake":
		packetCopy := make([]byte, len(pkt.raw))
		copy(packetCopy, pkt.raw)
		dstCopy := make(net.IP, len(pkt.dst))
		copy(dstCopy, pkt.dst)
		setCopy := set

		if !vc.drop() {
			return 0
		}

		v := pkt.ver
		w.wg.Add(1)
		go func(s *config.SetConfig, p []byte, d net.IP) {
			defer w.wg.Done()
			if v == IPv4 {
				w.dropAndInjectQUIC(s, p, d)
			} else {
				w.dropAndInjectQUICV6(s, p, d)
			}
		}(setCopy, packetCopy, dstCopy)
		return 0

	default:
		return vc.accept()
	}
}

func (w *Worker) handleNfqError(e error) int {
	if errors.Is(e, syscall.ENOBUFS) {
		now := time.Now().Unix()
		last := atomic.LoadInt64(&w.lastOverflowLog)
		if now-last >= 5 {
			if atomic.CompareAndSwapInt64(&w.lastOverflowLog, last, now) {
				log.Warnf("nfq queue %d overflow - packets dropped", w.qnum)
			}
		}
		return 0
	}
	if w.ctx.Err() != nil {
		return 0
	}
	if errors.Is(e, os.ErrClosed) || errors.Is(e, net.ErrClosed) || errors.Is(e, syscall.EBADF) {
		return 0
	}
	if ne, ok := e.(net.Error); ok && ne.Timeout() {
		return 0
	}
	msg := e.Error()
	if strings.Contains(msg, "use of closed file") || strings.Contains(msg, "file descriptor") {
		return 0
	}
	log.Errorf("nfq: %v", e)
	return 0
}
