package classifier

import "fmt"

func (p ClassificationPhase) String() string {
	switch p {
	case PhaseInspecting:
		return "inspecting"
	case PhasePartial:
		return "partial"
	case PhaseAmbiguous:
		return "ambiguous"
	case PhaseResolved:
		return "resolved"
	case PhaseFinal:
		return "final"
	default:
		return fmt.Sprintf("phase(%d)", p)
	}
}

func (s EvidenceSource) String() string {
	switch s {
	case EvidencePacketSNI:
		return "packet_sni"
	case EvidenceReassembledSNI:
		return "reassembled_sni"
	case EvidenceQUICSNI:
		return "quic_sni"
	case EvidenceDNSAnswer:
		return "dns_answer"
	case EvidenceDNSHTTPS:
		return "dns_https"
	case EvidenceStaticHost:
		return "static_host"
	case EvidenceStaticIP:
		return "static_ip"
	case EvidenceLegacyLearnedIP:
		return "legacy_learned_ip"
	case EvidencePortProtocol:
		return "port_protocol"
	case EvidenceScopedLearnedObservation:
		return "scoped_learned_observation"
	default:
		return fmt.Sprintf("source(%d)", s)
	}
}

// sourceRank expresses the normative evidence ordering. Higher is stronger.
func sourceRank(s EvidenceSource) int {
	switch s {
	case EvidenceReassembledSNI:
		return 100
	case EvidencePacketSNI:
		return 95
	case EvidenceQUICSNI:
		return 90
	case EvidenceDNSAnswer:
		return 80
	case EvidenceDNSHTTPS:
		return 75
	case EvidenceStaticHost:
		return 65
	case EvidenceScopedLearnedObservation:
		return 50
	case EvidenceStaticIP:
		return 45
	case EvidenceLegacyLearnedIP:
		return 35
	case EvidencePortProtocol:
		return 25
	default:
		return 0
	}
}

func sourceConfidenceCap(s EvidenceSource) uint8 {
	switch s {
	case EvidenceReassembledSNI, EvidencePacketSNI:
		return 100
	case EvidenceQUICSNI:
		return 94
	case EvidenceDNSAnswer:
		return 89
	case EvidenceDNSHTTPS:
		return 84
	case EvidenceStaticHost:
		return 70
	case EvidenceScopedLearnedObservation:
		return 54
	case EvidenceStaticIP:
		return 54
	case EvidenceLegacyLearnedIP:
		return 45
	case EvidencePortProtocol:
		return 34
	default:
		return 0
	}
}

func sourceDefaultConfidence(s EvidenceSource) uint8 {
	return sourceConfidenceCap(s)
}

func isClearSNI(e Evidence) bool {
	return (e.Source == EvidencePacketSNI || e.Source == EvidenceReassembledSNI) && e.Domain != "" && !e.ECHRelated && e.DomainEvidence
}

func isClientScopedSource(s EvidenceSource) bool {
	switch s {
	case EvidencePacketSNI, EvidenceReassembledSNI, EvidenceQUICSNI, EvidenceDNSAnswer, EvidenceDNSHTTPS, EvidenceLegacyLearnedIP, EvidenceScopedLearnedObservation:
		return true
	default:
		return false
	}
}
