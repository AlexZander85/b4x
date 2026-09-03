package nfq

import (
	"net/netip"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
	"github.com/florianl/go-nfqueue"
)

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

// releaseTCPHoldOnFlowTermination immediately releases a held flow when a
// FIN or RST terminates it (ARCH §42-45: a terminated stream must not sit in
// hold until the GC timeout; fail-open release keeps the invariant and the
// explicit abort reason makes the release observable).
func (w *Worker) releaseTCPHoldOnFlowTermination(key classifier.FlowKey, isFin bool) int {
	if w == nil || w.tcpHold == nil {
		return 0
	}
	reason := tcpHoldAbortRST
	if isFin {
		reason = tcpHoldAbortFIN
	}
	return w.tcpHold.Release(key, reason)
}

// maybeHoldTCPPacket is the only active hold entry point. It requires the
// observe-only reassembler to report a bounded, incomplete ClientHello and a
// decision that has not yet reached scoped domain confidence. false,true
// means pressure forced fail-open acceptance of the current packet.
func (w *Worker) maybeHoldTCPPacket(cfg *config.Config, pkt *pktInfo, key classifier.FlowKey, generation uint64, dport uint16, payload []byte, flags byte, tlsMetadata classifier.TLSMetadata, reassembly classifier.TCPReassemblyResult, matchedScopedHint bool, queue *nfqueue.Nfqueue, packetID uint32) (held, failOpen bool) {
	if !ppe.DefaultVisibilityGate().Decision(ppe.VisibilityFeatureHoldReplay).Allowed {
		if w != nil && w.tcpHold != nil {
			w.tcpHold.ReleaseAll(tcpHoldAbortVisibility)
		}
		return false, true
	}
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
