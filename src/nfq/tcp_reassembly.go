package nfq

import (
	"encoding/binary"
	"fmt"

	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/diagnostics"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/sni"
)

// observeTCPReassembly is deliberately observe-only: it copies bounded
// client-to-server payload ranges for metadata and never changes the NFQ
// verdict, delays a packet, or invokes an action executor.
func (w *Worker) observeTCPReassembly(cfg *config.Config, pkt *pktInfo, sequence uint32, sport, dport uint16, flags byte, payload []byte) classifier.TCPReassemblyResult {
	if cfg == nil || pkt == nil || w.tcpReassembly == nil || cfg.System.Classifier.Flags.TCPReassemblyMode != config.ReassemblyObserve || cfg.IsTCPPort(sport) {
		return classifier.TCPReassemblyResult{}
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return classifier.TCPReassemblyResult{}
	}
	key := classifier.NewFlowKey(client, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), sport, dport, 6)
	generation := dnsHintConfigGeneration(cfg)
	isSyn := flags&classifier.TCPFlagSYN != 0
	isAck := flags&classifier.TCPFlagACK != 0
	result := classifier.TCPReassemblyResult{Status: classifier.ReassemblyPartial, Reason: "no payload observed", Key: key}
	if isSyn && !isAck {
		w.tcpReassembly.Start(key, sequence+1, generation)
		observability.Default().Metrics.Inc(observability.MetricTCPReassemblyStarted, map[string]string{"reason": "syn"}, 1)
		result.BaseSequence = sequence + 1
		result.Sequence = sequence + 1
		result.Reason = "SYN sequence base established"
		if len(payload) > 0 {
			result = w.tcpReassembly.Observe(key, sequence+1, payload, generation)
			w.logReassemblyResult(result)
		}
	} else if len(payload) > 0 {
		result = w.tcpReassembly.Observe(key, sequence, payload, generation)
		w.logReassemblyResult(result)
	}
	if flags&(classifier.TCPFlagFIN|classifier.TCPFlagRST) != 0 {
		result = w.tcpReassembly.ObserveEvent(key, tcpTerminalEvent(flags), generation)
		w.logReassemblyResult(result)
	}
	return result
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
	labels := map[string]string{"status": result.Status.String()}
	observability.Default().Metrics.Inc(observability.MetricTCPFlowPhase, labels, 1)
	switch result.Status {
	case classifier.ReassemblyComplete:
		observability.Default().Metrics.Inc(observability.MetricTCPReassemblyCompleted, map[string]string{"reason": "clienthello"}, 1)
	case classifier.ReassemblyAborted:
		observability.Default().Metrics.Inc(observability.MetricTCPReassemblyAborted, map[string]string{"reason": sanitizeReassemblyReason(result.Reason)}, 1)
		destinationIP, destinationPort := result.Key.DstIP, result.Key.DstPort
		if result.Key.Client.SourceIP.IsValid() && result.Key.SrcIP != result.Key.Client.SourceIP {
			destinationIP, destinationPort = result.Key.SrcIP, result.Key.SrcPort
		}
		_, _ = diagnostics.Default().Observe(diagnostics.FailureObservation{
			Signal:          diagnostics.SignalReassemblyAbort,
			Client:          result.Key.Client,
			DestinationIP:   destinationIP,
			DestinationPort: destinationPort,
			Protocol:        6,
			Reason:          result.Reason,
		})
	}
	observability.Default().Trace.Record(observability.TraceEvent{
		ClientID: fmt.Sprintf("%v", result.Key.Client),
		FlowID:   fmt.Sprintf("%v", result.Key),
		Kind:     "tcp_reassembly",
		Fields: map[string]string{
			"status":      result.Status.String(),
			"reason":      sanitizeReassemblyReason(result.Reason),
			"segments":    fmt.Sprintf("%d", result.SegmentCount),
			"buffered":    fmt.Sprintf("%d", result.BufferedBytes),
			"duplicate":   fmt.Sprintf("%t", result.Duplicate),
			"identical":   fmt.Sprintf("%t", result.IdenticalOverlap),
			"conflicting": fmt.Sprintf("%t", result.ConflictingOverlap),
			"sni_hash":    observability.RedactDomain(result.Metadata.SNI),
			"ech":         fmt.Sprintf("%t", result.Metadata.ECHPresent),
			"need_bytes":  fmt.Sprintf("%d", result.Metadata.NeedBytes),
			"clienthello": fmt.Sprintf("%d", result.Metadata.ClientHelloSize),
		},
	})
}

func sanitizeReassemblyReason(reason string) string {
	// Reasons are normally constants from classifier; keep arbitrary parser
	// errors out of metric labels while preserving useful failure classes.
	switch reason {
	case classifier.ReassemblyAbortTimeout, classifier.ReassemblyAbortFIN, classifier.ReassemblyAbortRST,
		classifier.ReassemblyAbortConfigGeneration, classifier.ReassemblyAbortBudget,
		classifier.ReassemblyAbortConflictingOverlap, classifier.ReassemblyAbortMalformed,
		classifier.ReassemblyAbortSequenceBeforeBase, classifier.ReassemblyAbortManual,
		"SYN sequence base established", "clienthello complete":
		return reason
	default:
		return "other"
	}
}

func (w *Worker) tcpTLSDecisionMetadata(cfg *config.Config, pkt *pktInfo, sport, dport uint16, payload []byte) classifier.TLSMetadata {
	metadata := classifier.TLSMetadata{}
	if cfg != nil && pkt != nil && cfg.IsTCPPort(dport) && len(payload) > 0 {
		parsed := sni.ParseTLSClientHelloMetadata(payload)
		metadata = classifier.TLSMetadata{
			Version:         parsed.MaxVersion,
			ECHPresent:      parsed.ECHPresent,
			ClearSNI:        parsed.SNI != "" && !parsed.ECHPresent,
			HandshakeParsed: parsed.Complete,
		}
	}
	if cfg == nil || pkt == nil || w.tcpReassembly == nil || cfg.System.Classifier.Flags.TCPReassemblyMode != config.ReassemblyObserve {
		return metadata
	}
	client, ok := dnsClientKey(pkt.src, pkt.srcMac)
	if !ok {
		return metadata
	}
	key := classifier.NewFlowKey(client, netIPToAddr(pkt.src), netIPToAddr(pkt.dst), sport, dport, 6)
	if result, found := w.tcpReassembly.Lookup(key); found {
		if metadata.Version == 0 {
			metadata.Version = result.Metadata.MaxVersion
		}
		metadata.ECHPresent = metadata.ECHPresent || result.Metadata.ECHPresent
		metadata.ClearSNI = metadata.ClearSNI || (result.Metadata.SNI != "" && !result.Metadata.ECHPresent)
		metadata.HandshakeParsed = metadata.HandshakeParsed || result.Metadata.Complete
	}
	return metadata
}

func tcpPacketSequence(tcp []byte) (uint32, bool) {
	if len(tcp) < 8 {
		return 0, false
	}
	return binary.BigEndian.Uint32(tcp[4:8]), true
}
