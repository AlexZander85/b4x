package ppe

import (
	"sync"
	"time"
)

type PassiveDirection string

const (
	PassiveOutgoing PassiveDirection = "outgoing"
	PassiveIncoming PassiveDirection = "incoming"
)

type PassiveState string

const (
	PassiveUnknown        PassiveState = "unknown"
	PassiveOutgoingOnly   PassiveState = "outgoing_only"
	PassiveBidirectional  PassiveState = "bidirectional_observed"
	PassiveSuspectedBlind PassiveState = "suspected_offload_blindness"
)

type PassiveObservation struct {
	FlowID       string
	Family       string
	Protocol     string
	Direction    PassiveDirection
	Sequence     uint32
	HasSequence  bool
	SYN          bool
	ACK          bool
	RST          bool
	PayloadBytes int
	QUIC         bool
	ObservedAt   time.Time
}

type passiveFlow struct {
	updatedAt       time.Time
	lastOutgoingSeq uint32
	hasOutgoingSeq  bool
	incomingSeen    bool
}

type PassiveSnapshot struct {
	CapturedAt             time.Time    `json:"captured_at"`
	State                  PassiveState `json:"state"`
	OutgoingPackets        uint64       `json:"outgoing_packets"`
	IncomingPackets        uint64       `json:"incoming_packets"`
	OutgoingRetransmits    uint64       `json:"outgoing_retransmits"`
	IncomingProgress       uint64       `json:"incoming_progress"`
	IncomingRST            uint64       `json:"incoming_rst"`
	IncomingQUIC           uint64       `json:"incoming_quic"`
	TrackedFlows           int          `json:"tracked_flows"`
	Evictions              uint64       `json:"evictions"`
	FunctionalConfirmation bool         `json:"functional_confirmation"`
	Reasons                []string     `json:"reasons,omitempty"`
}

type PassiveTracker struct {
	mu       sync.Mutex
	flows    map[string]*passiveFlow
	maxFlows int
	ttl      time.Duration

	outgoingPackets     uint64
	incomingPackets     uint64
	outgoingRetransmits uint64
	incomingProgress    uint64
	incomingRST         uint64
	incomingQUIC        uint64
	evictions           uint64
}
