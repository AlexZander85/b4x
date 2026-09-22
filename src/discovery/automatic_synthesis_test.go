package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/detector"
)

// TestRunAutomaticSynthesisChainsPanelGateAndSearch proves the single automatic
// AFS entry point runs the behavioral panel, attaches the fresh evidence, passes
// the canonical preflight, and executes the bounded search without ever
// applying a winner.
func TestRunAutomaticSynthesisChainsPanelGateAndSearch(t *testing.T) {
	now := time.Now()
	scope := gateTestScope()
	blocking := gateTestBlocking(now)

	cfg := config.NewConfig()
	cfg.Automation.AdaptiveStrategySynthesis.Enabled = true
	cfg.Automation.AdaptiveStrategySynthesis.RunTimeout = time.Minute
	cfg.System.Classifier.Runtime.Discovery.MaxProbes = 32
	cfg.System.Classifier.Runtime.Discovery.SamplesPerVariant = 1
	cfg.System.Classifier.Runtime.Discovery.StableSuccesses = 2
	cfg.System.Classifier.Runtime.Discovery.MaxConcurrency = 1

	in := AutomaticSynthesisInput{
		Gate: SynthesisGateContext{
			Assessment:                    gateTestAssessment(scope, now),
			Blocking:                      blocking,
			CurrentConfigGeneration:       scope.ConfigGeneration,
			CandidateCoverage:             []detector.CandidateCoverageVector{{TargetID: "t1", Covered: true}},
			UserOptIn:                     true,
			PersistentRegressionQualified: true,
			RolloutIdle:                   true,
			NoConflictingRun:              true,
			VisibilityReady:               true,
			MandatoryControlsReady:        true,
			TargetPlanComplete:            true,
			ActiveTestAuthorized:          true,
			ResourceBudgetAvailable:       true,
			ResourceOwnershipReady:        true,
			CleanupComplete:               true,
			CatalogEscalationSatisfied:    true,
		},
		MutationCatalog: []detector.BehavioralProbeMutation{
			{ProbeID: "probe-a", Family: detector.OperatorTCPSplit, Params: map[string]string{"marker": "host-start"}},
		},
		BehavioralPolicy: config.BehavioralFingerprintingConfig{
			MaxProbes: 4, AttemptsPerProbe: 1, Concurrency: 1,
			MaxDuration: 10 * time.Second, MaxInconclusiveRatio: 0.25,
		},
		BehavioralCatalog:    "afs-behavior-catalog-v1",
		BehavioralValidUntil: now.Add(time.Minute),
		Targets:              []string{"target"},
		SameServiceControls:  []string{"same-control"},
		UnrelatedControls:    []string{"unrelated-control"},
		FailureFamily:        "tls_fingerprint_specific",
		Authority:            "authoritative-abd",
		BaselineStrategyID:   "baseline-production",
		ActionContext: SynthesisActionContext{
			Confidence: 90, TCPPhase: "first-flight", CompleteClientHello: true,
			ConfigGen: scope.ConfigGeneration, Budgets: action.DefaultActionBudgets(),
		},
		Now: now,
	}

	behavioral := func(_ context.Context, c detector.BehavioralProbeCase) (detector.BehavioralProbeResult, error) {
		outcome := detector.BehaviorOutcomeOK
		if c.Role == "target" && !c.Mutated {
			outcome = detector.BehaviorOutcomeFail
		}
		return detector.BehavioralProbeResult{Outcome: outcome, EvidenceRef: "behavioral/ref", ObservedAt: now}, nil
	}
	baseline := func(_ context.Context, v DiscoveryVariant) ProbeOutcome {
		return synthesisSearchAvailable(v.TargetProfile)
	}
	synthesized := func(_ context.Context, v DiscoveryVariant, _ SynthesizedCandidatePlan, _ CompiledSynthesizedAction) ProbeOutcome {
		return synthesisSearchAvailable(v.TargetProfile)
	}

	res, err := RunAutomaticSynthesis(context.Background(), &cfg, in, baseline, synthesized, behavioral)
	if err != nil {
		t.Fatalf("run automatic synthesis: %v", err)
	}
	if res.Evidence.EvidenceID == "" {
		t.Fatal("behavioral evidence not produced")
	}
	if res.Result.Applied {
		t.Fatal("automatic synthesis must never apply a winner")
	}
	if !res.Gate.Prior.Valid() {
		t.Fatalf("gate prior invalid: %+v", res.Gate.Prior)
	}
	if res.Gate.Prior.BehavioralEvidenceID != res.Evidence.EvidenceID {
		t.Fatal("prior behavioral evidence not wired from the panel")
	}
}

// TestRunAutomaticSynthesisFailsClosedWithoutBehavioralRunner proves the entry
// point never fabricates a run when a required runner is missing.
func TestRunAutomaticSynthesisFailsClosedWithoutBehavioralRunner(t *testing.T) {
	cfg := config.NewConfig()
	baseline := func(_ context.Context, v DiscoveryVariant) ProbeOutcome {
		return synthesisSearchAvailable(v.TargetProfile)
	}
	synthesized := func(_ context.Context, v DiscoveryVariant, _ SynthesizedCandidatePlan, _ CompiledSynthesizedAction) ProbeOutcome {
		return synthesisSearchAvailable(v.TargetProfile)
	}
	if _, err := RunAutomaticSynthesis(context.Background(), &cfg, AutomaticSynthesisInput{}, baseline, synthesized, nil); err == nil {
		t.Fatal("missing behavioral runner must fail closed")
	}
}
