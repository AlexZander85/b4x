package ppe

import "sync"

type evidenceCollector struct {
	mu         sync.Mutex
	phase      SelfTestPhase
	tcpFlowID  string
	quicFlowID string
	evidence   PhaseEvidence
	firstSeq   uint32
	firstLen   uint32
	hasFirst   bool
	ranges     map[[2]uint32]struct{}
}

func newEvidenceCollector(phase SelfTestPhase, tcpFlowID, quicFlowID string) *evidenceCollector {
	return &evidenceCollector{
		phase: phase, tcpFlowID: tcpFlowID, quicFlowID: quicFlowID,
		evidence: PhaseEvidence{Phase: phase}, ranges: make(map[[2]uint32]struct{}),
	}
}

func (c *evidenceCollector) Observe(observation PassiveObservation) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case observation.FlowID == c.tcpFlowID && observation.Protocol == "tcp":
		c.observeTCP(observation)
	case c.quicFlowID != "" && observation.FlowID == c.quicFlowID && observation.Protocol == "udp":
		if observation.Direction == PassiveOutgoing && observation.QUIC && observation.PayloadBytes > 0 {
			c.evidence.QUICInitialSeen = true
		}
		if observation.Direction == PassiveIncoming && observation.QUIC && observation.PayloadBytes > 0 {
			c.evidence.QUICIncomingResponseSeen = true
		}
	}
}

func (c *evidenceCollector) observeTCP(observation PassiveObservation) {
	if observation.Direction == PassiveIncoming {
		if observation.ACK || observation.RST || observation.PayloadBytes > 0 {
			c.evidence.TCPIncomingProgressSeen = true
		}
		return
	}
	if observation.PayloadBytes <= 0 || !observation.HasSequence {
		return
	}
	c.evidence.TCPFirstPayloadSeen = true
	length := uint32(observation.PayloadBytes)
	key := [2]uint32{observation.Sequence, length}
	if _, exists := c.ranges[key]; exists {
		c.evidence.TCPRetransmissionSeen = true
		return
	}
	c.ranges[key] = struct{}{}
	if !c.hasFirst {
		c.hasFirst = true
		c.firstSeq = observation.Sequence
		c.firstLen = length
		return
	}
	if rangesDisjoint(c.firstSeq, c.firstLen, observation.Sequence, length) {
		c.evidence.TCPSecondRangeSeen = true
	}
}

func rangesDisjoint(aStart, aLen, bStart, bLen uint32) bool {
	aEnd := uint64(aStart) + uint64(aLen)
	bEnd := uint64(bStart) + uint64(bLen)
	return aEnd <= uint64(bStart) || bEnd <= uint64(aStart)
}

func (c *evidenceCollector) Snapshot() PhaseEvidence {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.evidence
}
