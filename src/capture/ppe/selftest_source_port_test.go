package ppe

import "testing"

func TestEvidenceCollectorCorrelatesRealNFQFlowBySourcePort(t *testing.T) {
	collector := newEvidenceCollector(PhaseWithExclusion, "ipv4", "api-run-tcp", "", 41001, 0)
	collector.Observe(PassiveObservation{
		FlowID: "real-five-tuple-hash", Family: "ipv4", Protocol: "tcp",
		Direction: PassiveOutgoing, ClientPort: 41001, ServerPort: 443,
		Sequence: 100, HasSequence: true, PayloadBytes: 64,
	})
	collector.Observe(PassiveObservation{
		FlowID: "real-five-tuple-hash", Family: "ipv4", Protocol: "tcp",
		Direction: PassiveOutgoing, ClientPort: 41001, ServerPort: 443,
		Sequence: 164, HasSequence: true, PayloadBytes: 64,
	})
	collector.Observe(PassiveObservation{
		FlowID: "real-five-tuple-hash", Family: "ipv4", Protocol: "tcp",
		Direction: PassiveOutgoing, ClientPort: 41001, ServerPort: 443,
		Sequence: 164, HasSequence: true, PayloadBytes: 64,
	})
	collector.Observe(PassiveObservation{
		FlowID: "real-five-tuple-hash", Family: "ipv4", Protocol: "tcp",
		Direction: PassiveIncoming, ClientPort: 41001, ServerPort: 443, ACK: true,
	})
	evidence := collector.Snapshot()
	if !evidence.TCPComplete() {
		t.Fatalf("source-port correlated evidence incomplete: %+v", evidence)
	}
}

func TestEvidenceCollectorRejectsOtherSourcePort(t *testing.T) {
	collector := newEvidenceCollector(PhaseWithExclusion, "ipv4", "", "", 41001, 0)
	collector.Observe(PassiveObservation{
		FlowID: "other-flow", Family: "ipv4", Protocol: "tcp",
		Direction: PassiveOutgoing, ClientPort: 41002, ServerPort: 443,
		Sequence: 1, HasSequence: true, PayloadBytes: 32,
	})
	if collector.Snapshot().TCPFirstPayloadSeen {
		t.Fatal("collector accepted traffic from an unrelated source port")
	}
}
