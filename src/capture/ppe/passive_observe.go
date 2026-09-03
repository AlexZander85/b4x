package ppe

import "time"

func NewPassiveTracker(maxFlows int, ttl time.Duration) *PassiveTracker {
	if maxFlows <= 0 {
		maxFlows = 4096
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &PassiveTracker{flows: make(map[string]*passiveFlow), maxFlows: maxFlows, ttl: ttl}
}

func (t *PassiveTracker) Observe(observation PassiveObservation) {
	if t == nil || observation.FlowID == "" {
		return
	}
	now := observation.ObservedAt
	if now.IsZero() {
		now = time.Now()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked(now)
	flow, ok := t.flows[observation.FlowID]
	if !ok {
		if len(t.flows) >= t.maxFlows {
			t.evictOldestLocked()
		}
		flow = &passiveFlow{}
		t.flows[observation.FlowID] = flow
	}
	flow.updatedAt = now
	if observation.Direction == PassiveIncoming {
		t.incomingPackets++
		flow.incomingSeen = true
		if observation.RST {
			t.incomingRST++
		}
		if observation.QUIC {
			t.incomingQUIC++
		}
		if observation.RST || observation.SYN && observation.ACK || observation.PayloadBytes > 0 || observation.QUIC {
			t.incomingProgress++
		}
		return
	}
	t.outgoingPackets++
	if observation.HasSequence {
		if flow.hasOutgoingSeq && flow.lastOutgoingSeq == observation.Sequence {
			t.outgoingRetransmits++
		}
		flow.lastOutgoingSeq = observation.Sequence
		flow.hasOutgoingSeq = true
	}
}
