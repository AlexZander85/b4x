package nfq

import (
	"encoding/binary"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/log"
)

// observeTCPReassembly is deliberately observe-only: it copies bounded
// client-to-server payload ranges for metadata and never changes the NFQ
// verdict, delays a packet, or invokes an action executor.
func (w *Worker) observeTCPReassembly(cfg *config.Config, pkt *pktInfo, sequence uint32, sport, dport uint16, flags byte, payload []byte) {
	if cfg == nil || pkt == nil || w.tcpReassembly == nil || cfg.System.Classifier.Flags.TCPReassemblyMode != config.ReassemblyObserve || cfg.IsTCPPort(sport) {
		return
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return
	}
	key := classifier.NewFlowKey(client, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), sport, dport, 6)
	generation := dnsHintConfigGeneration(cfg)
	isSyn := flags&classifier.TCPFlagSYN != 0
	isAck := flags&classifier.TCPFlagACK != 0
	if isSyn && !isAck {
		w.tcpReassembly.Start(key, sequence+1, generation)
		if len(payload) > 0 {
			w.logReassemblyResult(w.tcpReassembly.Observe(key, sequence+1, payload, generation))
		}
	} else if len(payload) > 0 {
		w.logReassemblyResult(w.tcpReassembly.Observe(key, sequence, payload, generation))
	}
	if flags&(classifier.TCPFlagFIN|classifier.TCPFlagRST) != 0 {
		w.logReassemblyResult(w.tcpReassembly.ObserveEvent(key, tcpTerminalEvent(flags), generation))
	}
}

func tcpTerminalEvent(flags byte) classifier.TCPFlowEvent {
	if flags&classifier.TCPFlagRST != 0 {
		return classifier.TCPEventRST
	}
	return classifier.TCPEventFIN
}

func (w *Worker) logReassemblyResult(result classifier.TCPReassemblyResult) {
	if result.Status == classifier.ReassemblyPartial && result.Metadata.ParseError == "" {
		return
	}
	log.Tracef("tcp reassembly status=%s reason=%s segments=%d bytes=%d duplicate=%t sni=%s ech=%t need=%d",
		result.Status, result.Reason, result.SegmentCount, result.BufferedBytes, result.Duplicate, result.Metadata.SNI, result.Metadata.ECHPresent, result.Metadata.NeedBytes)
}

func tcpPacketSequence(tcp []byte) (uint32, bool) {
	if len(tcp) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint32(tcp[4:8]), true
}
