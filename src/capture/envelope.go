package capture

import (
	"fmt"

	"github.com/daniellavrushin/b4/config"
)

// AddressFamily identifies the IP family carried by a packet observed at the
// capture boundary.
type AddressFamily uint8

const (
	AddressFamilyUnknown AddressFamily = iota
	AddressFamilyIPv4
	AddressFamilyIPv6
)

// Direction is relative to the client protected by b4.
type Direction uint8

const (
	DirectionUnknown Direction = iota
	DirectionOutgoing
	DirectionIncoming
)

// QueueRole keeps production and Discovery queue contracts distinct even when
// the kernel uses the same NFQUEUE mechanism for both.
type QueueRole string

const (
	QueueRoleProduction QueueRole = "production"
	QueueRoleCandidate  QueueRole = "candidate"
)

const (
	ProtocolTCP = 6
	ProtocolUDP = 17

	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagACK = 0x10

	// This bound keeps an invalid or hostile config from turning the capture
	// contract into an unbounded per-flow kernel rule or user-space workload.
	MaxCapturePacketLimit uint32 = 4096
)

// CaptureEnvelope is the bounded kernel/user-space capture contract. Packet
// limits are zero-based packet indexes: PacketIndex 0 is the first packet.
// The struct is intentionally independent of a live queue handle so it can be
// rendered into either nftables or iptables and tested deterministically.
type CaptureEnvelope struct {
	OutgoingPacketLimit uint32    `json:"outgoing_packet_limit"`
	IncomingPacketLimit uint32    `json:"incoming_packet_limit"`
	AlwaysQueueSynAck   bool      `json:"always_queue_syn_ack"`
	AlwaysQueueFin      bool      `json:"always_queue_fin"`
	AlwaysQueueRst      bool      `json:"always_queue_rst"`
	AlwaysQueueQuicInit bool      `json:"always_queue_quic_initial"`
	ProcessedMark       uint32    `json:"processed_mark"`
	ProcessedMarkMask   uint32    `json:"processed_mark_mask"`
	QueueStart          uint16    `json:"queue_start"`
	QueueThreads        uint16    `json:"queue_threads"`
	QueueBypass         bool      `json:"queue_bypass"`
	IPv4Enabled         bool      `json:"ipv4_enabled"`
	IPv6Enabled         bool      `json:"ipv6_enabled"`
	Role                QueueRole `json:"role"`
}

// PacketMeta contains only the fields needed to decide whether the packet is
// inside the envelope. PacketIndex must be the conntrack packet index for the
// selected direction and is not a global process counter.
type PacketMeta struct {
	Family          AddressFamily
	Direction       Direction
	Protocol        uint8
	SourcePort      uint16
	DestinationPort uint16
	TCPFlags        uint8
	PacketIndex     uint32
	IsQUICInitial   bool
	Mark            uint32
}

type CaptureReason string

const (
	CaptureReasonNone        CaptureReason = "none"
	CaptureReasonProcessed   CaptureReason = "processed_mark"
	CaptureReasonFamily      CaptureReason = "family_disabled"
	CaptureReasonDNS         CaptureReason = "dns"
	CaptureReasonFirstN      CaptureReason = "first_n"
	CaptureReasonSynAck      CaptureReason = "syn_ack"
	CaptureReasonFin         CaptureReason = "fin"
	CaptureReasonRst         CaptureReason = "rst"
	CaptureReasonQUICInitial CaptureReason = "quic_initial"
	CaptureReasonUnsupported CaptureReason = "unsupported"
)

type EnvelopeDecision struct {
	Queue  bool
	Reason CaptureReason
}

// NewCaptureEnvelope derives the bounded defaults from the existing queue
// configuration. It does not enable a new classifier feature; it describes
// the contract that the backend must install or diagnose.
//
// When Classifier.Flags.CaptureEnvelopeEnabled is set, the contract is driven
// by System.Classifier.Runtime.Capture (bounded packet limits, always-queue
// lifecycle flags, processed mark and queue bypass); otherwise the legacy
// cfg.Queue-derived defaults are returned so existing deployments keep their
// observed topology unchanged (FB-11).
func NewCaptureEnvelope(cfg *config.Config, role QueueRole) (CaptureEnvelope, error) {
	if cfg == nil {
		return CaptureEnvelope{}, fmt.Errorf("capture envelope: nil config")
	}

	if _, err := boundedPacketLimit(cfg.Queue.UDPConnBytesLimit); err != nil {
		return CaptureEnvelope{}, fmt.Errorf("udp capture limit: %w", err)
	}
	if cfg.Queue.StartNum < 0 || cfg.Queue.StartNum > 65535 || cfg.Queue.Threads < 1 || cfg.Queue.Threads > 65536 {
		return CaptureEnvelope{}, fmt.Errorf("queue start/threads are outside the uint16 range")
	}
	if cfg.Queue.StartNum+cfg.Queue.Threads-1 > 65535 {
		return CaptureEnvelope{}, fmt.Errorf("queue range overflows uint16")
	}

	e := CaptureEnvelope{
		ProcessedMark:     ProcessedMarkFor(cfg.Queue.Mark),
		ProcessedMarkMask: ProcessedMarkMask,
		QueueStart:        uint16(cfg.Queue.StartNum),
		QueueThreads:      uint16(cfg.Queue.Threads),
		QueueBypass:       true,
		IPv4Enabled:       cfg.Queue.IPv4Enabled,
		IPv6Enabled:       cfg.Queue.IPv6Enabled,
		Role:              role,
	}
	if role == "" {
		e.Role = QueueRoleProduction
	}

	if cfg.System.Classifier.Flags.CaptureEnvelopeEnabled {
		rc := cfg.System.Classifier.Runtime.Capture
		e.OutgoingPacketLimit = rc.OutgoingPacketLimit
		e.IncomingPacketLimit = rc.IncomingPacketLimit
		e.AlwaysQueueSynAck = rc.AlwaysQueueSynAck
		e.AlwaysQueueFin = rc.AlwaysQueueFIN
		e.AlwaysQueueRst = rc.AlwaysQueueRST
		e.AlwaysQueueQuicInit = rc.AlwaysQueueQUIC
		e.QueueBypass = rc.QueueBypass
		if rc.ProcessedMark != 0 {
			e.ProcessedMark = rc.ProcessedMark
		}
		if rc.ProcessedMarkMask != 0 {
			e.ProcessedMarkMask = rc.ProcessedMarkMask
		}
	} else {
		tcpLimit, err := boundedPacketLimit(cfg.Queue.TCPConnBytesLimit)
		if err != nil {
			return CaptureEnvelope{}, fmt.Errorf("tcp capture limit: %w", err)
		}
		e.OutgoingPacketLimit = tcpLimit
		e.IncomingPacketLimit = tcpLimit
		e.AlwaysQueueSynAck = true
		e.AlwaysQueueFin = true
		e.AlwaysQueueRst = true
		e.AlwaysQueueQuicInit = true
	}
	return e, e.Validate()
}

func (e CaptureEnvelope) Validate() error {
	if e.OutgoingPacketLimit == 0 || e.IncomingPacketLimit == 0 || e.OutgoingPacketLimit > MaxCapturePacketLimit || e.IncomingPacketLimit > MaxCapturePacketLimit {
		return fmt.Errorf("packet limits must be positive")
	}
	if e.QueueThreads == 0 {
		return fmt.Errorf("queue threads must be positive")
	}
	if e.QueueStart > 65535-(e.QueueThreads-1) {
		return fmt.Errorf("queue range overflows uint16")
	}
	if e.ProcessedMark == 0 || e.ProcessedMarkMask == 0 {
		return fmt.Errorf("processed mark and mask must be non-zero")
	}
	if !e.QueueBypass {
		return fmt.Errorf("queue bypass must be enabled for fail-open capture")
	}
	if e.Role != QueueRoleProduction && e.Role != QueueRoleCandidate {
		return fmt.Errorf("unsupported queue role %q", e.Role)
	}
	if !e.IPv4Enabled && !e.IPv6Enabled {
		return fmt.Errorf("at least one IP family must be enabled")
	}
	return nil
}

func boundedPacketLimit(value int) (uint32, error) {
	if value < 0 || uint64(value)+1 > uint64(MaxCapturePacketLimit) {
		return 0, fmt.Errorf("value %d must produce a packet limit in [1,%d]", value, MaxCapturePacketLimit)
	}
	return uint32(value + 1), nil
}

func (e CaptureEnvelope) familyEnabled(f AddressFamily) bool {
	switch f {
	case AddressFamilyIPv4:
		return e.IPv4Enabled
	case AddressFamilyIPv6:
		return e.IPv6Enabled
	default:
		return false
	}
}

// Decide applies the envelope rules in priority order. Processed packets are
// rejected before any protocol-specific rule, which prevents requeue loops.
func (e CaptureEnvelope) Decide(meta PacketMeta) EnvelopeDecision {
	if MatchesMark(meta.Mark, e.ProcessedMark, e.ProcessedMarkMask) {
		return EnvelopeDecision{Reason: CaptureReasonProcessed}
	}
	if !e.familyEnabled(meta.Family) {
		return EnvelopeDecision{Reason: CaptureReasonFamily}
	}
	if meta.Protocol != ProtocolTCP && meta.Protocol != ProtocolUDP {
		return EnvelopeDecision{Reason: CaptureReasonUnsupported}
	}
	if meta.Protocol == ProtocolUDP && (meta.SourcePort == 53 || meta.DestinationPort == 53) {
		return EnvelopeDecision{Queue: true, Reason: CaptureReasonDNS}
	}
	if meta.Protocol == ProtocolTCP {
		if e.AlwaysQueueSynAck && meta.TCPFlags&(TCPFlagSYN|TCPFlagACK) == (TCPFlagSYN|TCPFlagACK) {
			return EnvelopeDecision{Queue: true, Reason: CaptureReasonSynAck}
		}
		if e.AlwaysQueueFin && meta.TCPFlags&TCPFlagFIN != 0 {
			return EnvelopeDecision{Queue: true, Reason: CaptureReasonFin}
		}
		if e.AlwaysQueueRst && meta.TCPFlags&TCPFlagRST != 0 {
			return EnvelopeDecision{Queue: true, Reason: CaptureReasonRst}
		}
	}
	if meta.Protocol == ProtocolUDP && e.AlwaysQueueQuicInit && meta.IsQUICInitial {
		return EnvelopeDecision{Queue: true, Reason: CaptureReasonQUICInitial}
	}
	if meta.Direction == DirectionOutgoing && meta.PacketIndex < e.OutgoingPacketLimit {
		return EnvelopeDecision{Queue: true, Reason: CaptureReasonFirstN}
	}
	if meta.Direction == DirectionIncoming && meta.PacketIndex < e.IncomingPacketLimit {
		return EnvelopeDecision{Queue: true, Reason: CaptureReasonFirstN}
	}
	return EnvelopeDecision{Reason: CaptureReasonNone}
}
