package discovery

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/daniellavrushin/b4/action"
	"github.com/daniellavrushin/b4/nfq"
)

// SynthesisProbeTarget is one bounded probe destination for an AFS run. IP is
// the WAN-facing address the candidate override is bound to (the existing
// centralized action executor keys on destination IP).
type SynthesisProbeTarget struct {
	URL string
	IP  net.IP
}

// SynthesisProbeConfig tunes the production probe runner. A zero Policy is
// normalized by the probe tracker.
type SynthesisProbeConfig struct {
	Policy       ProbePolicy
	OverrideTTL  time.Duration
	ProbeTimeout time.Duration
}

// SynthesisCandidateCompiler builds the nfq plan compiler for one candidate.
// The candidate is compiled against the real payload/sequence at probe time,
// because CompileSynthesizedCandidate requires a concrete PlanInput (the engine
// only holds a dry-run compilation).
func SynthesisCandidateCompiler(candidate SynthesizedCandidatePlan, base SynthesisActionContext) nfq.SynthesisPlanCompiler {
	return func(input action.PlanInput) (action.ActionPlan, error) {
		ctx := base
		if input.ConfigGen == 0 {
			input.ConfigGen = base.ConfigGen
		}
		ctx.Input = input
		compiled, err := CompileSynthesizedCandidate(candidate, ctx)
		if err != nil {
			return action.ActionPlan{}, err
		}
		if compiled.ActionPlan != nil {
			return *compiled.ActionPlan, nil
		}
		if compiled.FakeMixPlan != nil {
			if plan, ok := action.PlanFromFakeMix(*compiled.FakeMixPlan); ok {
				return plan, nil
			}
		}
		return action.ActionPlan{}, errors.New("candidate compiled no executable plan")
	}
}

// SynthesisProbeClient returns the bounded HTTP client used for probes. Keep
// alives are disabled so every probe opens a fresh flow (and therefore a fresh
// ClientHello) that the armed override can act on.
func SynthesisProbeClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives:   true,
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        0,
			TLSHandshakeTimeout: timeout,
		},
	}
}

// ProductionSynthesisRunners builds the ProbeRunner/SynthesizedProbeRunner pair
// used by a bounded AFS run. It never sends packets itself: the synthesized
// runner arms an nfq plan override for the probe destination and drives one
// bounded HTTP probe, so the existing centralized action executor applies the
// candidate. Targets are keyed by the Discovery target profile. The runners are
// only exercised when the global opt-in is on (enforced upstream).
func ProductionSynthesisRunners(targets map[string]SynthesisProbeTarget, base SynthesisActionContext, cfg SynthesisProbeConfig) (ProbeRunner, SynthesizedProbeRunner) {
	if cfg.OverrideTTL <= 0 {
		cfg.OverrideTTL = 30 * time.Second
	}
	if cfg.ProbeTimeout <= 0 {
		cfg.ProbeTimeout = 15 * time.Second
	}
	client := SynthesisProbeClient(cfg.ProbeTimeout)

	probe := func(ctx context.Context, target SynthesisProbeTarget) ProbeOutcome {
		return RunHTTPProbe(ctx, HTTPProbeRequest{URL: target.URL, Client: client, Policy: cfg.Policy})
	}
	baseline := func(ctx context.Context, variant DiscoveryVariant) ProbeOutcome {
		target, ok := targets[variant.TargetProfile]
		if !ok {
			return NewProbeTracker(cfg.Policy).Finish()
		}
		return probe(ctx, target)
	}
	synthesized := func(ctx context.Context, variant DiscoveryVariant, candidate SynthesizedCandidatePlan, _ CompiledSynthesizedAction) ProbeOutcome {
		target, ok := targets[variant.TargetProfile]
		if !ok {
			return NewProbeTracker(cfg.Policy).Finish()
		}
		release := nfq.ArmSynthesisOverride(target.IP, SynthesisCandidateCompiler(candidate, base), cfg.OverrideTTL)
		defer release()
		return probe(ctx, target)
	}
	return baseline, synthesized
}
