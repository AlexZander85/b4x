package discovery

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
)

// AutomaticSynthesisInput is the fully-projected input for one bounded
// automatic synthesis run. Every field is supplied by an existing owner
// (monitoring/ABD/Discovery/config); the orchestrator fabricates nothing.
type AutomaticSynthesisInput struct {
	Gate                 SynthesisGateContext
	MutationCatalog      []detector.BehavioralProbeMutation
	BehavioralPolicy     config.BehavioralFingerprintingConfig
	BehavioralCatalog    string
	BehavioralValidUntil time.Time

	RequestID               string
	Targets                 []string
	SameServiceControls     []string
	UnrelatedControls       []string
	FailureFamily           string
	Authority               string
	BaselineStrategyID      string
	Baseline                []string
	CandidateCoverage       []detector.CandidateCoverageVector
	ActionContext           SynthesisActionContext
	ExistingCanonicalHashes map[string]struct{}
	StoreMaxEntries         int
	Now                     time.Time
}

// AutomaticSynthesisResult carries the behavioral evidence produced by the
// panel and the bounded search outcome. Applied is always false: promotion
// stays with the existing transactional runtime.
type AutomaticSynthesisResult struct {
	Evidence detector.BehavioralFingerprintEvidence
	Gate     SynthesisGateInput
	Result   BoundedSynthesisSearchResult
}

// RunAutomaticSynthesis is the single automatic AFS entry point: it runs the
// bounded behavioral panel, attaches the fresh evidence to the retained ABD
// blocking profile, evaluates the canonical preflight, and — only if the gate
// passes — runs the bounded synthesized Discovery search through the injected
// probe runners. It never applies or promotes a winner.
func RunAutomaticSynthesis(
	ctx context.Context,
	cfg *config.Config,
	in AutomaticSynthesisInput,
	baselineRunner ProbeRunner,
	synthesizedRunner SynthesizedProbeRunner,
	behavioralRunner detector.BehavioralProbeRunner,
) (AutomaticSynthesisResult, error) {
	var out AutomaticSynthesisResult
	if ctx == nil || cfg == nil {
		return out, errors.New("automatic synthesis requires context and config")
	}
	if baselineRunner == nil || synthesizedRunner == nil || behavioralRunner == nil {
		return out, errors.New("automatic synthesis requires probe runners")
	}
	now := in.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	scope := in.Gate.Blocking.Scope
	validUntil := in.BehavioralValidUntil
	if validUntil.IsZero() {
		validUntil = now.Add(SynthesisProfileTTL)
	}
	evidence, err := detector.RunBehavioralPanel(ctx, scope, in.BehavioralCatalog, in.MutationCatalog, in.BehavioralPolicy, validUntil, now, behavioralRunner)
	if err != nil {
		return out, err
	}
	out.Evidence = evidence

	gateContext := in.Gate
	blocking := gateContext.Blocking
	blocking.Behavioral = &evidence
	gateContext.Blocking = blocking
	gateContext.Now = now

	gate, err := BuildSynthesisGateInput(gateContext)
	if err != nil {
		return out, err
	}
	out.Gate = gate
	if err := CheckAutomaticSynthesisGate(gate); err != nil {
		return out, err
	}

	requestID := in.RequestID
	if requestID == "" {
		requestID = "afs/" + gate.Profile.ProfileID
	}
	synthesis := SynthesisRequest{
		RequestID:             requestID,
		Scope:                 gate.Profile.Scope,
		ConfigGeneration:      gate.CurrentConfigGeneration,
		BlockingProfileID:     gate.Profile.Blocking.ProfileID,
		BehavioralEvidenceID:  evidence.EvidenceID,
		AllowedGrammarVersion: SynthesisGrammarV1,
		Limits:                DefaultSynthesisLimits(),
		RequestedAt:           now,
		ExpiresAt:             now.Add(SynthesisProfileTTL),
	}
	maxEntries := in.StoreMaxEntries
	if maxEntries <= 0 {
		maxEntries = int(cfg.Automation.AdaptiveStrategySynthesis.MaxCandidates)
	}
	store := NewSynthesisRunStore(requestID, maxEntries)
	defer store.Close()
	req := BoundedSynthesisSearchRequest{
		Gate:                    gate,
		Synthesis:               synthesis,
		Store:                   store,
		ActionContext:           in.ActionContext,
		Targets:                 append([]string(nil), in.Targets...),
		SameServiceControls:     append([]string(nil), in.SameServiceControls...),
		UnrelatedControls:       append([]string(nil), in.UnrelatedControls...),
		FailureFamily:           in.FailureFamily,
		Authority:               in.Authority,
		BaselineStrategyID:      in.BaselineStrategyID,
		ExistingCanonicalHashes: in.ExistingCanonicalHashes,
	}
	result, err := NewRuntime().RunBoundedSynthesisSearch(ctx, cfg, req, baselineRunner, synthesizedRunner)
	if err != nil {
		return out, err
	}
	out.Result = result
	return out, nil
}

// AutomaticBehavioralMutations derives the bounded behavioral probe catalog
// from the automatic-safe grammar-v1 operators. Each operator yields one
// mutation using its first registered finite parameter value; external-param
// operators (safe fake) still probe their finite mode domain.
func AutomaticBehavioralMutations() []detector.BehavioralProbeMutation {
	grammar := AutomaticStrategyGrammarV1()
	mutations := make([]detector.BehavioralProbeMutation, 0, len(grammar.Operators))
	for _, op := range grammar.Operators {
		if !op.AutomaticSafe || len(op.ParameterDomain) == 0 {
			continue
		}
		params := make(map[string]string, len(op.ParameterDomain))
		for name, domain := range op.ParameterDomain {
			if len(domain) == 0 {
				continue
			}
			params[name] = domain[0]
		}
		mutations = append(mutations, detector.BehavioralProbeMutation{
			ProbeID: string(op.Family),
			Family:  op.Family,
			Params:  params,
		})
	}
	sort.SliceStable(mutations, func(i, j int) bool { return mutations[i].ProbeID < mutations[j].ProbeID })
	return mutations
}

// AutomaticSynthesisActionContext builds the base action context for automatic
// synthesis. No payload is required: the synthesized/behavioral plan compiler
// replaces Input with the real packet observed on the nfq path.
func AutomaticSynthesisActionContext(scope monitor.MonitorScopeKey) SynthesisActionContext {
	return SynthesisActionContext{
		Confidence:          80,
		TCPPhase:            "complete-reassembled-clienthello",
		CompleteClientHello: true,
		ConfigGen:           scope.ConfigGeneration,
		Budgets:             action.DefaultActionBudgets(),
	}
}
