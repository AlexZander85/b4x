package ppe

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestSelfTestControllerHealthyButIncompleteBIsFAIL(t *testing.T) {
	bus := NewObservationBus()
	probe := scriptedProbe{bus: bus}
	controller := NewSelfTestController(func(context.Context) (CapabilityReport, error) { return supportedCapability(), nil }, nil, testHealth{}, probe, testIsolation{}, nil, bus, nil)
	request := baseRequest()
	// A regular scripted probe completes B. Replace the flow bus with a probe that emits first only.
	controller.probe = firstOnlyProbe{bus: bus}
	result := controller.Run(context.Background(), request)
	if result.Verdict != VerdictFAIL || result.FailureStage != "phase_b_visibility" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

type firstOnlyProbe struct{ bus *ObservationBus }

func (p firstOnlyProbe) Run(_ context.Context, request ProbeRequest) (ProbeOutcome, error) {
	emitTCPFirst(p.bus, request.Family, request.FlowID)
	return ProbeOutcome{Protocol: request.Protocol, ClientEmitted: true}, nil
}

func TestSelfTestControllerHealthFailureIsInconclusive(t *testing.T) {
	bus := NewObservationBus()
	controller := NewSelfTestController(func(context.Context) (CapabilityReport, error) { return supportedCapability(), nil }, nil, testHealth{err: errors.New("offline")}, scriptedProbe{bus: bus}, testIsolation{}, nil, bus, nil)
	result := controller.Run(context.Background(), baseRequest())
	if result.Verdict != VerdictINCONCLUSIVE || result.FailureStage != "endpoint_health" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestSelfTestControllerUnsupported(t *testing.T) {
	bus := NewObservationBus()
	controller := NewSelfTestController(func(context.Context) (CapabilityReport, error) {
		return CapabilityReport{State: CapabilityUnsupported}, nil
	}, nil, testHealth{}, scriptedProbe{bus: bus}, testIsolation{}, nil, bus, nil)
	result := controller.Run(context.Background(), baseRequest())
	if result.Verdict != VerdictUNSUPPORTED {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestObservationBusUnsubscribe(t *testing.T) {
	bus := NewObservationBus()
	sink := &countingSink{}
	unsubscribe := bus.Subscribe(sink)
	bus.Observe(PassiveObservation{})
	unsubscribe()
	bus.Observe(PassiveObservation{})
	if sink.Count() != 1 {
		t.Fatalf("count=%d", sink.Count())
	}
}

type countingSink struct {
	mu    sync.Mutex
	count int
}

func (s *countingSink) Observe(PassiveObservation) { s.mu.Lock(); s.count++; s.mu.Unlock() }
func (s *countingSink) Count() int                 { s.mu.Lock(); defer s.mu.Unlock(); return s.count }
