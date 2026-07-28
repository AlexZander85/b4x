package ppe

import (
	"testing"
	"time"
)

func TestPassiveTrackerStatesNeverConfirmFunctionally(t *testing.T) {
	tracker := NewPassiveTracker(8, time.Minute)
	now := time.Date(2026, 7, 28, 21, 0, 0, 0, time.UTC)
	unknown := tracker.Snapshot(now)
	if unknown.State != PassiveUnknown || unknown.FunctionalConfirmation {
		t.Fatalf("unknown=%+v", unknown)
	}
	tracker.Observe(PassiveObservation{FlowID: "flow", Direction: PassiveOutgoing, Protocol: "tcp", Sequence: 100, HasSequence: true, ObservedAt: now})
	outgoing := tracker.Snapshot(now)
	if outgoing.State != PassiveOutgoingOnly || outgoing.FunctionalConfirmation {
		t.Fatalf("outgoing=%+v", outgoing)
	}
	tracker.Observe(PassiveObservation{FlowID: "flow", Direction: PassiveOutgoing, Protocol: "tcp", Sequence: 100, HasSequence: true, ObservedAt: now.Add(time.Millisecond)})
	blind := tracker.Snapshot(now.Add(2 * time.Millisecond))
	if blind.State != PassiveSuspectedBlind || blind.OutgoingRetransmits != 1 || blind.FunctionalConfirmation {
		t.Fatalf("blind=%+v", blind)
	}
	tracker.Observe(PassiveObservation{FlowID: "flow", Direction: PassiveIncoming, Protocol: "tcp", ACK: true, PayloadBytes: 64, ObservedAt: now.Add(3 * time.Millisecond)})
	bidirectional := tracker.Snapshot(now.Add(4 * time.Millisecond))
	if bidirectional.State != PassiveBidirectional || bidirectional.IncomingProgress != 1 || bidirectional.FunctionalConfirmation {
		t.Fatalf("bidirectional=%+v", bidirectional)
	}
}

func TestPassiveTrackerBoundedAndExpiresFlows(t *testing.T) {
	tracker := NewPassiveTracker(1, time.Second)
	now := time.Now()
	tracker.Observe(PassiveObservation{FlowID: "one", Direction: PassiveOutgoing, ObservedAt: now})
	tracker.Observe(PassiveObservation{FlowID: "two", Direction: PassiveOutgoing, ObservedAt: now.Add(time.Millisecond)})
	if got := tracker.Snapshot(now.Add(time.Millisecond)); got.TrackedFlows != 1 || got.Evictions != 1 {
		t.Fatalf("bounded=%+v", got)
	}
	if got := tracker.Snapshot(now.Add(2 * time.Second)); got.TrackedFlows != 0 || got.Evictions != 2 {
		t.Fatalf("expired=%+v", got)
	}
}
