package discovery

import (
	"bytes"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/fixtures"
)

func TestCompileSynthesizedTLSRecordSplitWithPrePadding(t *testing.T) {
	now := time.Unix(33000, 0)
	req, prior := synthesisPlannerTestInput(now)
	operations := []CandidateOperation{
		{Family: detector.OperatorTLSRecordSplit, Params: map[string]string{"marker": string(action.MarkerHostStart)}},
		{Family: detector.OperatorPrePadding, Params: map[string]string{"padding_bytes": "8"}},
	}
	candidate, err := newSynthesizedCandidate(
		req,
		1,
		[]string{"parent-padding"},
		CandidateTrigger{Phase: "complete-reassembled-clienthello", Marker: "host-start"},
		operations,
		action.RepresentationNormalTCP,
		[]string{"current-action-authorization", "complete-clienthello"},
		CandidateCost{},
		CandidateRisk{},
		[]string{"test-tls-split-padding"},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	validation := NewSynthesisPlanner().ValidateCandidate(req, prior, candidate)
	if !validation.Valid {
		t.Fatalf("static validation rejected padding candidate: %s", validation.Reason)
	}

	payload := fixtures.BuildTLSClientHello("api.youtube.com", 0x0304, false, 0)
	input := action.PlanInput{
		BaseSequence:  4000,
		Payload:       payload,
		Markers:       action.DiscoverTLSMarkers(payload),
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
		TCPPhase:            "clienthello",
		CompleteClientHello: true,
		ConfigGen:           req.ConfigGeneration,
		Budgets: action.ActionBudgets{
			MaxWritesPerHello: 16,
			MaxFakeBytes:      64,
			MaxAmplification:  1.5,
		},
	})
	if err != nil {
		t.Fatalf("compile padding candidate: %v", err)
	}
	if compiled.ActionPlan == nil || !compiled.ActionPlan.Valid {
		t.Fatalf("invalid compiled padding plan: %+v", compiled)
	}
	plan := compiled.ActionPlan
	if plan.TotalBytes != len(payload)+8 {
		t.Fatalf("total bytes=%d want=%d", plan.TotalBytes, len(payload)+8)
	}
	if len(plan.Writes) < 3 {
		t.Fatalf("expected padding plus TLS split writes, got %d", len(plan.Writes))
	}
	padding := plan.Writes[0]
	if padding.Sequence != input.BaseSequence || padding.StreamStart != 0 || padding.StreamEnd != 8 || !bytes.Equal(padding.Payload, payload[:8]) {
		t.Fatalf("unexpected pre-padding write: %+v", padding)
	}
}

func TestAutomaticGrammarRegistersPaddingAsBoundedSafeOperators(t *testing.T) {
	grammar := AutomaticStrategyGrammarV1()
	for _, family := range []detector.StrategyOperatorFamily{detector.OperatorPrePadding, detector.OperatorPostPadding} {
		definition, ok := grammar.Operator(family)
		if !ok || !definition.AutomaticSafe || definition.Compiler != "action_plan_clienthello_padding" {
			t.Fatalf("padding operator %s not automatic-safe: %+v", family, definition)
		}
		want := []string{"1", "4", "8", "16", "32"}
		got := definition.ParameterDomain["padding_bytes"]
		if len(got) != len(want) {
			t.Fatalf("padding domain=%v", got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("padding domain=%v want=%v", got, want)
			}
		}
	}
}
