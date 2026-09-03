package nfq

import (
	"encoding/binary"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/classifier"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/sni"
)

func (w *Worker) tcpTLSDecisionMetadata(cfg *config.Config, pkt *pktInfo, sport, dport uint16, payload []byte) classifier.TLSMetadata {
	metadata := classifier.TLSMetadata{}
	if cfg != nil && pkt != nil && !pkt.offload.Truncated && cfg.IsTCPPort(dport) && len(payload) > 0 {
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
	if !ppe.DefaultVisibilityGate().Decision(ppe.VisibilityFeatureReassembly).Allowed {
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
