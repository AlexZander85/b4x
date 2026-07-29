package ppe

import (
	"context"
	"errors"
	"testing"
	"time"
)

type testHealth struct{ err error }

func (h testHealth) Check(context.Context, string) error { return h.err }

type testIsolation struct {
	verifyErr  error
	cleanupErr error
}

func (i testIsolation) BeginBypass(context.Context, string, string, uint16, uint16) (func(context.Context) error, error) {
	return func(context.Context) error { return i.cleanupErr }, nil
}
func (i testIsolation) VerifyActive(context.Context, string) error { return i.verifyErr }

type testCounters struct {
	values []map[string]uint64
	index  int
}

func (c *testCounters) RuleCounters(context.Context) (map[string]uint64, error) {
	if len(c.values) == 0 {
		return nil, nil
	}
	index := c.index
	if index >= len(c.values) {
		index = len(c.values) - 1
	}
	c.index++
	return cloneCounters(c.values[index]), nil
}

type scriptedProbe struct {
	bus  *ObservationBus
	mode string
}

func (p scriptedProbe) Run(_ context.Context, request ProbeRequest) (ProbeOutcome, error) {
	if p.mode == "error" {
		return ProbeOutcome{}, errors.New("probe failed")
	}
	emitTCPFirst(p.bus, request.FlowID)
	complete := request.Phase == PhaseWithExclusion || p.mode == "both-complete"
	if complete {
		emitTCPComplete(p.bus, request.FlowID)
	}
	if request.Protocol == "quic" {
		p.bus.Observe(PassiveObservation{FlowID: request.FlowID, Protocol: "udp", Direction: PassiveOutgoing, PayloadBytes: 1200, QUIC: true})
		if complete {
			p.bus.Observe(PassiveObservation{FlowID: request.FlowID, Protocol: "udp", Direction: PassiveIncoming, PayloadBytes: 1200, QUIC: true})
		}
	}
	return ProbeOutcome{Protocol: request.Protocol, ClientEmitted: true}, nil
}

func emitTCPFirst(bus *ObservationBus, flowID string) {
	bus.Observe(PassiveObservation{FlowID: flowID, Protocol: "tcp", Direction: PassiveOutgoing, Sequence: 100, HasSequence: true, PayloadBytes: 40})
}
func emitTCPComplete(bus *ObservationBus, flowID string) {
	bus.Observe(PassiveObservation{FlowID: flowID, Protocol: "tcp", Direction: PassiveOutgoing, Sequence: 140, HasSequence: true, PayloadBytes: 60})
	bus.Observe(PassiveObservation{FlowID: flowID, Protocol: "tcp", Direction: PassiveOutgoing, Sequence: 100, HasSequence: true, PayloadBytes: 40})
	bus.Observe(PassiveObservation{FlowID: flowID, Protocol: "tcp", Direction: PassiveIncoming, ACK: true})
}

func supportedCapability() CapabilityReport {
	return CapabilityReport{State: CapabilitySupported, Supported: true, IPv4: FamilyCapability{State: CapabilitySupported}, IPv6: FamilyCapability{State: CapabilitySupported}}
}

func baseRequest() SelfTestRequest {
	return SelfTestRequest{RunID: "ppe-run-1", Generation: "generation-1", ControlledEndpoint: "https://example.test/health", Family: "ipv4", TCPFlowID: "tcp-flow", TCPSourcePort: 41000, Timeout: time.Second}
}

func TestSelfTestControllerPASSRequiresABContrast(t *testing.T) {
	bus := NewObservationBus()
	store := NewMemorySelfTestStore(8)
	controller := NewSelfTestController(func(context.Context) (CapabilityReport, error) { return supportedCapability(), nil }, func() string { return "exclude" }, testHealth{}, scriptedProbe{bus: bus}, testIsolation{}, &testCounters{values: []map[string]uint64{{"tcp": 1}, {"tcp": 5}}}, bus, store)
	result := controller.Run(context.Background(), baseRequest())
	if result.Verdict != VerdictPASS || !result.ProductionReady || !result.OffloadSuspected {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !result.TCPBidirectionalComplete || !result.OutgoingSecondRangeSeen || !result.OutgoingRetransSeen || !result.IncomingProgressSeen {
		t.Fatalf("missing complete B evidence: %+v", result.PhaseB)
	}
	if stored, ok := store.Get(result.RunID); !ok || stored.Verdict != VerdictPASS {
		t.Fatalf("result not stored: %+v %v", stored, ok)
	}
}

func TestSelfTestControllerNoContrastIsLimited(t *testing.T) {
	bus := NewObservationBus()
	controller := NewSelfTestController(func(context.Context) (CapabilityReport, error) { return supportedCapability(), nil }, nil, testHealth{}, scriptedProbe{bus: bus, mode: "both-complete"}, testIsolation{}, nil, bus, nil)
	result := controller.Run(context.Background(), baseRequest())
	if result.Verdict != VerdictPASSWithLimitations || result.ProductionReady || result.OffloadSuspected {
		t.Fatalf("unexpected result: %+v", result)
	}
}
