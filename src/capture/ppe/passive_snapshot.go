package ppe

import "time"

func (t *PassiveTracker) Snapshot(now time.Time) PassiveSnapshot {
	if now.IsZero() {
		now = time.Now()
	}
	if t == nil {
		return PassiveSnapshot{CapturedAt: now.UTC(), State: PassiveUnknown, Reasons: []string{"passive tracker unavailable"}}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked(now)
	out := PassiveSnapshot{
		CapturedAt: now.UTC(), OutgoingPackets: t.outgoingPackets, IncomingPackets: t.incomingPackets,
		OutgoingRetransmits: t.outgoingRetransmits, IncomingProgress: t.incomingProgress,
		IncomingRST: t.incomingRST, IncomingQUIC: t.incomingQUIC, TrackedFlows: len(t.flows), Evictions: t.evictions,
		FunctionalConfirmation: false,
	}
	switch {
	case out.OutgoingPackets == 0:
		out.State = PassiveUnknown
		out.Reasons = append(out.Reasons, "no scoped outgoing packet observed")
	case out.IncomingProgress > 0:
		out.State = PassiveBidirectional
		out.Reasons = append(out.Reasons, "incoming progress observed passively")
	case out.OutgoingRetransmits > 0:
		out.State = PassiveSuspectedBlind
		out.Reasons = append(out.Reasons, "outgoing retransmission observed without incoming progress")
	default:
		out.State = PassiveOutgoingOnly
		out.Reasons = append(out.Reasons, "outgoing scoped traffic observed without enough incoming evidence")
	}
	return out
}

func (t *PassiveTracker) gcLocked(now time.Time) {
	for key, flow := range t.flows {
		if !flow.updatedAt.IsZero() && now.Sub(flow.updatedAt) > t.ttl {
			delete(t.flows, key)
			t.evictions++
		}
	}
}

func (t *PassiveTracker) evictOldestLocked() {
	var oldestKey string
	var oldest time.Time
	for key, flow := range t.flows {
		if oldestKey == "" || flow.updatedAt.Before(oldest) {
			oldestKey = key
			oldest = flow.updatedAt
		}
	}
	if oldestKey != "" {
		delete(t.flows, oldestKey)
		t.evictions++
	}
}
