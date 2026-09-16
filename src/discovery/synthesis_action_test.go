package discovery

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
)

func TestCompileSynthesizedCandidateCombinesExistingSplitPrimitives(t *testing.T) {
	now := time.Unix(32000, 0)
	req, _ := synthesisPlannerTestInput(now)
	operations := []CandidateOperation{
		{Family: detector.OperatorTCPSplit, Params: map[string]string{"marker": string(action.MarkerHostStart)}},
		{Family: detector.OperatorTLSRecordSplit, Params: map[string]string{"marker": string(action.MarkerHostEnd)}},
		{Family: detector.OperatorBoundedDisorder, Params: map[string]string{"marker": string(action.MarkerSNIExtensionStart), "pattern": "swap-adjacent-once"}},
		{Family: detector.OperatorPerFlowJitter, Params: map[string]string{"jitter_ms": "1"}},
	}
	candidate, err := newSynthesizedCandidate(
		req,
		1,
		[]string{"parent-a"},
		CandidateTrigger{Phase: "complete-reassembled-clienthello", Marker: "host-start"},
		operations,
		action.RepresentationNormalTCP,
		[]string{"current-action-authorization", "complete-clienthello"},
		CandidateCost{},
		CandidateRisk{},
		[]string{"test-combination"},
		now,
	)
	if err != nil {
		t.Fatalf("candidate: %v", err)
	}
	if reason := candidateActionBridgeShape(candidate.Operations); reason != "" {
		t.Fatalf("static bridge rejected compatible combination: %s", reason)
	}

	// Minimal structurally valid TLS handshake record for the existing
	// PlanTLSRecordSplit parser: one ClientHello handshake with a four-byte
	// body. Marker offsets are supplied by the same semantic marker envelope
	// that ActionPlanner normally receives from reassembly.
	payload := []byte{
		0x16, 0x03, 0x03, 0x00, 0x08,
		0x01, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00,
	}
	markers := action.MarkerSet{
		Host:     "example.com",
		Complete: true,
		Markers: []action.LogicalMarker{
			{Kind: action.MarkerClientHelloStart, Offset: 0, Available: true},
			{Kind: action.MarkerClientHelloEnd, Offset: uint64(len(payload)), Available: true},
			{Kind: action.MarkerSNIExtensionStart, Offset: 7, Available: true},
			{Kind: action.MarkerHostStart, Offset: 9, Available: true},
			{Kind: action.MarkerHostEnd, Offset: 11, Available: true},
		},
	}
	input := action.PlanInput{
		BaseSequence:  1000,
		Payload:       payload,
		Markers:       markers,
		MTU:           1500,
		IPHeaderLen:   20,
		TCPHeaderLen:  20,
		ProcessedMark: 1,
		MaxWrites:     16,
		MaxBytes:      64 * 1024,
		DryRun:        true,
		ConfigGen:     req.ConfigGeneration,
	}
	compiled, err := CompileSynthesizedCandidate(candidate, SynthesisActionContext{
		Input:               input,
		Confidence:          90,
		TCPPhase:            "first-flight",
		CompleteClientHello: true,
		ConfigGen:           req.ConfigGeneration,
		Budgets:             action.DefaultActionBudgets(),
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if compiled.ActionPlan == nil || !compiled.ActionPlan.Valid {
		t.Fatalf("compiled plan invalid: %+v", compiled)
	}
	if compiled.ActionPlan.StrategyID != candidate.CandidateID {
		t.Fatalf("strategy ID = %q, want candidate ID", compiled.ActionPlan.StrategyID)
	}
	if len(compiled.ActionPlan.Writes) < 4 {
		t.Fatalf("expected multi-boundary ActionPlan, got %d writes", len(compiled.ActionPlan.Writes))
	}
	for _, write := range compiled.ActionPlan.Writes {
		if write.Delay < time.Millisecond {
			t.Fatalf("jitter transform missing from write: %+v", write)
		}
	}
}

func TestCandidateActionBridgeRejectsDuplicateStructuralBoundary(t *testing.T) {
	operations := []CandidateOperation{
		{Family: detector.OperatorTCPSplit, Params: map[string]string{"marker": "host-start"}},
		{Family: detector.OperatorTLSRecordSplit, Params: map[string]string{"marker": "host-start"}},
	}
	if reason := candidateActionBridgeShape(operations); reason == "" {
		t.Fatal("duplicate semantic split boundary accepted")
	}
}
