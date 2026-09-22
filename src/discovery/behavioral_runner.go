package discovery

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/monitor"
	"github.com/daniellavrushin/b4/nfq"
)

// BehavioralProbeTargets resolves the reference and target legs of the AFS
// four-way behavioral panel. Both must be reachable through the existing packet
// path; the runner never sends packets itself.
type BehavioralProbeTargets struct {
	Reference SynthesisProbeTarget
	Target    SynthesisProbeTarget
}

// BehavioralMutationBase carries the synthesis action context used to compile
// the mutated legs (R3/R4) into an existing ActionPlan. Identity is derived per
// case from the mutation family/params.
type BehavioralMutationBase struct {
	Scope                monitor.MonitorScopeKey
	ConfigGeneration     uint64
	BlockingProfileID    string
	BehavioralEvidenceID string
	GrammarVersion       string
	ActionContext        SynthesisActionContext
}

// ProductionBehavioralRunner builds the production detector.BehavioralProbeRunner
// for RunBehavioralPanel. Baseline legs run a bounded probe unchanged; mutated
// legs arm the existing nfq synthesized-plan override for the destination so
// the centralized action executor applies the mutation. It is default-off (only
// invoked from an AFS run) and returns an inconclusive outcome, never a
// fabricated success, when a mutation cannot be compiled.
func ProductionBehavioralRunner(targets BehavioralProbeTargets, base BehavioralMutationBase, cfg SynthesisProbeConfig) detector.BehavioralProbeRunner {
	if cfg.OverrideTTL <= 0 {
		cfg.OverrideTTL = 30 * time.Second
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 15 * time.Second
	}
	client := SynthesisProbeClient(cfg.ProbeTimeout)

	return func(ctx context.Context, probe detector.BehavioralProbeCase) (detector.BehavioralProbeResult, error) {
		target := targets.Target
		if probe.Role == "reference" {
			target = targets.Reference
		}
		evidenceRef := behavioralEvidenceRef(probe)
		if target.URL == "" {
			return detector.BehavioralProbeResult{Outcome: detector.BehaviorOutcomeInconclusive, EvidenceRef: evidenceRef, ObservedAt: time.Now().UTC()}, nil
		}
		if probe.Mutated {
			compiler, err := behavioralMutationCompiler(probe, base)
			if err != nil {
				return detector.BehavioralProbeResult{Outcome: detector.BehaviorOutcomeInconclusive, EvidenceRef: evidenceRef, ObservedAt: time.Now().UTC()}, nil
			}
			release := nfq.ArmSynthesisOverride(target.IP, compiler, cfg.OverrideTTL)
			defer release()
		}
		outcome := RunHTTPProbe(ctx, HTTPProbeRequest{URL: target.URL, Client: client, Policy: cfg.Policy})
		return detector.BehavioralProbeResult{
			Outcome:     behaviorOutcomeFromProbe(outcome),
			EvidenceRef: evidenceRef,
			ObservedAt:  time.Now().UTC(),
		}, nil
	}
}

// behavioralMutationCompiler compiles one mutation family/params into an
// existing ActionPlan through the same canonical candidate path used by
// synthesis (no second executor, no raw bytes).
func behavioralMutationCompiler(probe detector.BehavioralProbeCase, base BehavioralMutationBase) (nfq.SynthesisPlanCompiler, error) {
	if base.GrammarVersion == "" {
		return nil, errors.New("behavioral mutation grammar version required")
	}
	req := SynthesisRequest{
		Scope:                 base.Scope,
		ConfigGeneration:      base.ConfigGeneration,
		BlockingProfileID:     base.BlockingProfileID,
		BehavioralEvidenceID:  base.BehavioralEvidenceID,
		AllowedGrammarVersion: base.GrammarVersion,
	}
	candidate, err := newSynthesizedCandidate(
		req,
		0,
		nil,
		CandidateTrigger{Phase: "complete-reassembled-clienthello", Marker: "host-start"},
		[]CandidateOperation{{Family: probe.Family, Params: cloneBehaviorParams(probe.Params)}},
		action.RepresentationNormalTCP,
		[]string{"current-action-authorization"},
		CandidateCost{Actions: 1, EstimatedPackets: 1, Amplification: 1},
		CandidateRisk{Tier: "endpoint-safe", AutomaticOK: true},
		[]string{"behavioral-mutation"},
		time.Now().UTC(),
	)
	if err != nil {
		return nil, err
	}
	return SynthesisCandidateCompiler(candidate, base.ActionContext), nil
}

func cloneBehaviorParams(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func behavioralEvidenceRef(probe detector.BehavioralProbeCase) string {
	mutated := "baseline"
	if probe.Mutated {
		mutated = "mutated"
	}
	return fmt.Sprintf("behavioral/%s/%d/%s/%s", probe.ProbeID, probe.Attempt, probe.Role, mutated)
}

// behaviorOutcomeFromProbe maps an existing probe verdict onto the behavioral
// panel vocabulary. Capture-incomplete/classifier-unresolved never count as a
// success.
func behaviorOutcomeFromProbe(out ProbeOutcome) detector.BehaviorOutcome {
	switch out.Verdict {
	case DiagnosticAvailable:
		return detector.BehaviorOutcomeOK
	case DiagnosticDPIRest, DiagnosticMidstreamReset:
		return detector.BehaviorOutcomeReset
	case DiagnosticThrottled, DiagnosticBodyTruncated:
		return detector.BehaviorOutcomeStall
	case DiagnosticCaptureIncomplete, DiagnosticClassifierUnresolved:
		return detector.BehaviorOutcomeInconclusive
	}
	if out.TCPReset {
		return detector.BehaviorOutcomeReset
	}
	if out.TimedOut {
		return detector.BehaviorOutcomeStall
	}
	return detector.BehaviorOutcomeFail
}
