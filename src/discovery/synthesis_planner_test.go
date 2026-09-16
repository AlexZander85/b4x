package discovery

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

func synthesisPlannerTestInput(now time.Time) (SynthesisRequest, detector.DiscoverySearchPrior) {
	scope := monitor.MonitorScopeKey{
		ClientScope:      monitor.ClientScopeKey{ID: "client-a", Role: "forwarded"},
		ServiceProfileID: "service-a",
		ComponentID:      "tls",
		TargetRole:       "target",
		IPFamily:         "ipv4",
		NetworkContextID: "network-a",
		ConfigGeneration: 7,
	}
	req := SynthesisRequest{
		RequestID:             "synthesis-a",
		Scope:                 scope,
		ConfigGeneration:      scope.ConfigGeneration,
		BlockingProfileID:     "bp-a",
		BehavioralEvidenceID:  "be-a",
		BaselineCandidateIDs:  []string{"baseline-none", "baseline-production"},
		AllowedGrammarVersion: SynthesisGrammarV1,
		Limits:                DefaultSynthesisLimits(),
		RequestedAt:           now,
		ExpiresAt:             now.Add(time.Minute),
		DeterministicSeed:     42,
	}
	prior := detector.DiscoverySearchPrior{
		Scope:                scope,
		ProfileID:            req.BlockingProfileID,
		BehavioralEvidenceID: req.BehavioralEvidenceID,
		SupportedOperators: []detector.StrategyOperatorFamily{
			detector.OperatorTCPSplit,
			detector.OperatorPerFlowJitter,
		},
		CoverageDenominator: 1,
		MandatoryBaselines:  append([]string(nil), req.BaselineCandidateIDs...),
		Applied:             true,
	}
	return req, prior
}

func TestSynthesisPlannerDeterministicAndBounded(t *testing.T) {
	now := time.Unix(29000, 0)
	req, prior := synthesisPlannerTestInput(now)
	planner := NewSynthesisPlanner()

	first, err := planner.Plan(req, prior, nil)
	if err != nil {
		t.Fatalf("first plan: %v", err)
	}
	second, err := planner.Plan(req, prior, nil)
	if err != nil {
		t.Fatalf("second plan: %v", err)
	}
	ids := func(result SynthesisPlanResult) []string {
		out := make([]string, len(result.Candidates))
		for i, candidate := range result.Candidates {
			out[i] = candidate.CandidateID
		}
		return out
	}
	if !reflect.DeepEqual(ids(first), ids(second)) {
		t.Fatalf("same request/seed generated different candidate order\nfirst=%v\nsecond=%v", ids(first), ids(second))
	}
	if len(first.Candidates) == 0 || len(first.Candidates) > int(req.Limits.MaxCandidates) {
		t.Fatalf("candidate bound violated: %d", len(first.Candidates))
	}
	perGeneration := map[uint8]int{}
	for _, candidate := range first.Candidates {
		if !candidate.ValidIdentity() {
			t.Fatalf("invalid canonical identity: %s", candidate.CandidateID)
		}
		if candidate.Generation >= req.Limits.MaxGenerations {
			t.Fatalf("generation %d exceeds max %d", candidate.Generation, req.Limits.MaxGenerations)
		}
		perGeneration[candidate.Generation]++
	}
	for generation, count := range perGeneration {
		if generation > 0 && count > maxSynthesisCandidatesPerGeneration {
			t.Fatalf("generation %d produced %d candidates", generation, count)
		}
	}
}

func TestSynthesisPlannerProducesNovelCombinationAndFiniteParameterMutation(t *testing.T) {
	now := time.Unix(30000, 0)
	req, prior := synthesisPlannerTestInput(now)
	result, err := NewSynthesisPlanner().Plan(req, prior, nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var multiOperator, parameterMutation bool
	for _, candidate := range result.Candidates {
		if len(candidate.Operations) > 1 {
			multiOperator = true
		}
		for _, trace := range candidate.Provenance.MutationTrace {
			if strings.Contains(trace, ":param:") {
				parameterMutation = true
			}
		}
	}
	if !multiOperator {
		t.Fatal("bounded evolution produced no novel multi-operator combination")
	}
	if !parameterMutation {
		t.Fatal("bounded evolution produced no finite parameter/marker mutation")
	}
}

func TestSynthesisPlannerHonorsBehavioralExclusionDuringEvolution(t *testing.T) {
	now := time.Unix(31000, 0)
	req, prior := synthesisPlannerTestInput(now)
	prior.ExcludedOperators = []detector.StrategyOperatorFamily{detector.OperatorBoundedDisorder}
	result, err := NewSynthesisPlanner().Plan(req, prior, nil)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	for _, candidate := range result.Candidates {
		for _, operation := range candidate.Operations {
			if operation.Family == detector.OperatorBoundedDisorder {
				t.Fatalf("behaviorally excluded operator escaped into candidate %s", candidate.CandidateID)
			}
		}
	}
}
