package discovery

import (
	"testing"
	"time"

	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/observability"
)

func synthesisCounterValue(name string) uint64 {
	snapshot := observability.Default().Metrics.Snapshot(time.Now())
	for _, sample := range snapshot.Counters {
		if sample.Name == name {
			return sample.Value
		}
	}
	return 0
}

func requireSynthesisCounter(t *testing.T, name string) {
	t.Helper()
	if got := synthesisCounterValue(name); got == 0 {
		t.Fatalf("zero-tolerance counter %q was not raised", name)
	}
}

func TestSynthesisPreflightZeroToleranceCounters(t *testing.T) {
	now := time.Unix(32000, 0)
	tests := []struct {
		name   string
		metric string
		mutate func(*SynthesisGateInput)
	}{
		{"without-opt-in", observability.MetricSynthesisWithoutUserOptIn, func(in *SynthesisGateInput) { in.UserOptIn = false }},
		{"without-persistent-regression", observability.MetricSynthesisWithoutPersistentRegression, func(in *SynthesisGateInput) { in.PersistentRegressionQualified = false }},
		{"without-fresh-profile", observability.MetricSynthesisWithoutFreshProfile, func(in *SynthesisGateInput) { in.Assessment.ExpiresAt = now }},
		{"stale-generation", observability.MetricSynthesisStaleGenerationUsed, func(in *SynthesisGateInput) { in.CurrentConfigGeneration++ }},
		{"scope-escape", observability.MetricSynthesisScopeEscape, func(in *SynthesisGateInput) { in.Profile.Scope.ComponentID = "" }},
		{"cleanup-incomplete", observability.MetricSynthesisCleanupIncomplete, func(in *SynthesisGateInput) { in.CleanupComplete = false }},
		{"foreign-resource-mutation", observability.MetricSynthesisForeignResourceMutation, func(in *SynthesisGateInput) { in.ResourceOwnershipReady = false }},
		{"unbounded-execution", observability.MetricSynthesisUnboundedExecution, func(in *SynthesisGateInput) { in.ResourceBudgetAvailable = false }},
		{"missing-control", observability.MetricSynthesisMissingMandatoryControl, func(in *SynthesisGateInput) { in.MandatoryControlsReady = false }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			observability.Default().Metrics.Reset()
			in := validSynthesisGateInput(t, now)
			tc.mutate(&in)
			if err := CheckAutomaticSynthesisGate(in); err == nil {
				t.Fatal("fault injection was accepted")
			}
			requireSynthesisCounter(t, tc.metric)
		})
	}
}

func TestSynthesizedEmissionZeroToleranceCounters(t *testing.T) {
	now := time.Unix(33000, 0)
	req, prior := synthesisPlannerTestInput(now)
	planned, err := NewSynthesisPlanner().Plan(req, prior, nil)
	if err != nil || len(planned.Candidates) == 0 {
		t.Fatalf("seed candidate: result=%+v err=%v", planned, err)
	}
	valid := planned.Candidates[0]

	t.Run("grammar-escape", func(t *testing.T) {
		observability.Default().Metrics.Reset()
		candidate := valid
		candidate.Operations = cloneCandidateOperations(valid.Operations)
		candidate.Operations[0].Family = detector.StrategyOperatorFamily("unregistered_escape")
		if err := CheckSynthesizedEmission(candidate); err == nil {
			t.Fatal("unregistered operator escaped emission guard")
		}
		requireSynthesisCounter(t, observability.MetricSynthesisGrammarEscape)
	})

	t.Run("unsafe-operator", func(t *testing.T) {
		observability.Default().Metrics.Reset()
		grammar := AutomaticStrategyGrammarV1()
		family := valid.Operations[0].Family
		found := false
		for i := range grammar.Operators {
			if grammar.Operators[i].Family == family {
				grammar.Operators[i].AutomaticSafe = false
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("seed operator %q missing from grammar", family)
		}
		if err := checkSynthesizedEmission(valid, grammar); err == nil {
			t.Fatal("unsafe automatic operator escaped emission guard")
		}
		requireSynthesisCounter(t, observability.MetricSynthesisUnsafeOperatorEmitted)
	})

	t.Run("direct-apply", func(t *testing.T) {
		observability.Default().Metrics.Reset()
		if err := RejectSynthesizedDirectApply(AdaptiveRunResult{Applied: true}); err == nil {
			t.Fatal("direct synthesized apply was accepted")
		}
		requireSynthesisCounter(t, observability.MetricSynthesisCandidateDirectApply)
	})

	t.Run("identity-collision", func(t *testing.T) {
		observability.Default().Metrics.Reset()
		store := NewSynthesisRunStore(req.RequestID, 2)
		store.plans[valid.CandidateID] = SynthesizedCandidatePlan{CandidateID: valid.CandidateID, CanonicalHash: "fault-injected-different-hash"}
		if err := store.Put(valid); err == nil {
			t.Fatal("fault-injected candidate identity collision was accepted")
		}
		requireSynthesisCounter(t, observability.MetricSynthesisCandidateIdentityCollision)
	})
}
