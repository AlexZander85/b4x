// Package classifier contains pure, bounded classification types and policy.
// It deliberately does not depend on nfq so packet capture and action
// execution can evolve behind these stable decisions.
package classifier

import (
	"net/netip"
	"time"
)

type ClassificationPhase uint8

const (
	PhaseInspecting ClassificationPhase = iota
	PhasePartial
	PhaseAmbiguous
	PhaseResolved
	PhaseFinal
)

type EvidenceSource uint8

const (
	EvidencePacketSNI EvidenceSource = iota
	EvidenceReassembledSNI
	EvidenceQUICSNI
	EvidenceDNSAnswer
	EvidenceDNSHTTPS
	EvidenceStaticHost
	EvidenceStaticIP
	EvidenceLegacyLearnedIP
	EvidencePortProtocol
)

// ClientKey is the identity available at the capture boundary. A zero MAC is
// valid for temporary IP-only identity; IfIndex and VLAN prevent cross-domain
// merges when the same address is reused.
type ClientKey struct {
	L3Family  uint8
	SourceIP  netip.Addr
	SourceMAC [6]byte
	IfIndex   int
	VLAN      uint16
}

func (k ClientKey) IsZero() bool {
	return k.L3Family == 0 && !k.SourceIP.IsValid() && k.SourceMAC == [6]byte{} && k.IfIndex == 0 && k.VLAN == 0
}

type FlowKey struct {
	Client  ClientKey
	SrcIP   netip.Addr
	DstIP   netip.Addr
	SrcPort uint16
	DstPort uint16
	Proto   uint8
}

type TLSMetadata struct {
	Version         uint16
	ECHPresent      bool
	ClearSNI        bool
	HandshakeParsed bool
}

type Evidence struct {
	Source          EvidenceSource
	Client          ClientKey
	DestinationIP   netip.Addr
	DestinationPort uint16
	L4Proto         uint8
	SourceDevice    string
	Domain          string
	SetID           string
	Confidence      uint8
	DomainEvidence  bool
	ECHRelated      bool
	CreatedAt       time.Time
	ExpiresAt       time.Time
	ConfigGen       uint64
	Reason          string
}

type ClassificationDecision struct {
	Phase       ClassificationPhase
	Selected    *Evidence
	Candidates  []Evidence
	Reason      string
	Confidence  uint8
	ECHPresent  bool
	TLSMetadata TLSMetadata
	FlowKey     FlowKey
	ConfigGen   uint64
	Final       bool
}

type ConfidenceThresholds struct {
	Classify      uint8
	Mutate        uint8
	Destructive   uint8
	ProxyFallback uint8
}

var DefaultConfidenceThresholds = ConfidenceThresholds{
	Classify:      55,
	Mutate:        75,
	Destructive:   85,
	ProxyFallback: 35,
}

type DecisionContext struct {
	Now             time.Time
	Client          ClientKey
	ConfigGen       uint64
	DestinationPort uint16
	L4Proto         uint8
	SourceDevice    string
	FlowKey         FlowKey
	TLSMetadata     TLSMetadata
	InputIncomplete bool
	EvidenceValid   func(Evidence) bool
}
