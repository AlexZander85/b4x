package handler

import (
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/capture/ppe"
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/discovery"
	"github.com/daniellavrushin/b4/monitor"
)

// automaticSynthesisRunners bundles the three production runners a bounded AFS
// run needs. They are constructed here so the orchestrator stays transport
// agnostic.
type automaticSynthesisRunners struct {
	baseline    discovery.ProbeRunner
	synthesized discovery.SynthesizedProbeRunner
	behavioral  detector.BehavioralProbeRunner
}

const (
	afsTargetProfile     = "target"
	afsSameServiceCtl    = "same-service-control"
	afsUnrelatedCtl      = "unrelated-control"
	afsDefaultFamily     = "tls_fingerprint_specific"
	afsDefaultAuthority  = "authoritative-abd"
	afsDefaultBaselineID = "baseline-production"
)

// buildAutomaticSynthesis projects the existing owners (monitoring ABD inputs,
// ppe visibility gate, runtimecontrol pending state, Discovery activity, config
// budget) into one bounded run. The operator supplies the probe targets and an
// explicit authorization; nothing else is fabricated.
func (api *API) buildAutomaticSynthesis(scope monitor.MonitorScopeKey, asr *DiscoveryAdaptiveSynthesisRequest, cfg *config.Config) (discovery.AutomaticSynthesisInput, automaticSynthesisRunners, error) {
	var in discovery.AutomaticSynthesisInput
	var runners automaticSynthesisRunners
	if cfg == nil {
		return in, runners, errors.New("active config is unavailable")
	}
	if asr == nil || !asr.Authorized {
		return in, runners, errors.New("operator authorization is required for a bounded active test")
	}
	if globalMonitoring == nil {
		return in, runners, errors.New("monitoring runtime is unavailable")
	}
	retained, ok := globalMonitoring.SynthesisInputs(scope)
	if !ok {
		return in, runners, errors.New("no retained ABD inputs for the requested scope")
	}
	referenceURL := strings.TrimSpace(asr.ReferenceURL)
	targetURL := strings.TrimSpace(asr.TargetURL)
	sameURL := strings.TrimSpace(asr.SameServiceControlURL)
	unrelatedURL := strings.TrimSpace(asr.UnrelatedControlURL)
	if referenceURL == "" || targetURL == "" || sameURL == "" || unrelatedURL == "" {
		return in, runners, errors.New("reference, target, same-service control and unrelated control URLs are required")
	}
	referenceIP, err := resolveProbeIP(referenceURL)
	if err != nil {
		return in, runners, err
	}
	targetIP, err := resolveProbeIP(targetURL)
	if err != nil {
		return in, runners, err
	}
	sameIP, err := resolveProbeIP(sameURL)
	if err != nil {
		return in, runners, err
	}
	unrelatedIP, err := resolveProbeIP(unrelatedURL)
	if err != nil {
		return in, runners, err
	}

	actionContext := discovery.AutomaticSynthesisActionContext(scope)
	targetMap := map[string]discovery.SynthesisProbeTarget{
		afsTargetProfile:  {URL: targetURL, IP: targetIP},
		afsSameServiceCtl: {URL: sameURL, IP: sameIP},
		afsUnrelatedCtl:   {URL: unrelatedURL, IP: unrelatedIP},
	}
	probeCfg := discovery.SynthesisProbeConfig{}
	baseline, synthesized := discovery.ProductionSynthesisRunners(targetMap, actionContext, probeCfg)
	behavioral := discovery.ProductionBehavioralRunner(
		discovery.BehavioralProbeTargets{
			Reference: discovery.SynthesisProbeTarget{URL: referenceURL, IP: referenceIP},
			Target:    discovery.SynthesisProbeTarget{URL: targetURL, IP: targetIP},
		},
		discovery.BehavioralMutationBase{
			Scope:             scope,
			ConfigGeneration:  scope.ConfigGeneration,
			BlockingProfileID: retained.Profile.ProfileID,
			GrammarVersion:    discovery.SynthesisGrammarV1,
			ActionContext:     actionContext,
		},
		probeCfg,
	)
	runners = automaticSynthesisRunners{baseline: baseline, synthesized: synthesized, behavioral: behavioral}

	now := time.Now().UTC()
	visibility := ppe.DefaultVisibilityGate().Decision(ppe.VisibilityFeatureAutomaticDiscovery)
	rolloutIdle := true
	if manager := api.getRuntimeControlManager(); manager != nil {
		if _, pending := manager.Pending(); pending {
			rolloutIdle = false
		}
	}
	noConflictingRun := discoveryRuntime == nil || !discoveryRuntime.IsActive()
	failureFamily := strings.TrimSpace(asr.Trigger)
	if failureFamily == "" {
		failureFamily = afsDefaultFamily
	}

	blocking := retained.Profile
	blocking.Behavioral = nil // fresh evidence is attached by the panel run
	in = discovery.AutomaticSynthesisInput{
		Gate: discovery.SynthesisGateContext{
			Assessment:                    retained.Assessment,
			Blocking:                      blocking,
			CurrentConfigGeneration:       scope.ConfigGeneration,
			CandidateCoverage:             []detector.CandidateCoverageVector{{TargetID: afsTargetProfile, Covered: true}, {TargetID: afsSameServiceCtl, Covered: true}, {TargetID: afsUnrelatedCtl, Covered: true}},
			UserOptIn:                     true,
			PersistentRegressionQualified: globalMonitoring.PersistentRegressionQualified(scope),
			RolloutIdle:                   rolloutIdle,
			NoConflictingRun:              noConflictingRun,
			VisibilityReady:               visibility.Allowed,
			MandatoryControlsReady:        true,
			TargetPlanComplete:            true,
			ActiveTestAuthorized:          asr.Authorized,
			ResourceBudgetAvailable:       cfg.System.Classifier.Runtime.Discovery.MaxProbes > 0,
			ResourceOwnershipReady:        true,
			CleanupComplete:               true,
			CatalogEscalationSatisfied:    asr.Authorized,
			Now:                           now,
		},
		MutationCatalog:      discovery.AutomaticBehavioralMutations(),
		BehavioralPolicy:     cfg.Automation.AdaptiveStrategySynthesis.Fingerprinting,
		BehavioralCatalog:    discovery.AutomaticStrategyGrammarV1().Version,
		BehavioralValidUntil: now.Add(discovery.SynthesisProfileTTL),
		Targets:              []string{afsTargetProfile},
		SameServiceControls:  []string{afsSameServiceCtl},
		UnrelatedControls:    []string{afsUnrelatedCtl},
		FailureFamily:        failureFamily,
		Authority:            afsDefaultAuthority,
		BaselineStrategyID:   afsDefaultBaselineID,
		ActionContext:        actionContext,
		Now:                  now,
	}
	return in, runners, nil
}

// resolveProbeIP resolves a probe URL to the WAN-facing destination the nfq
// plan override is bound to.
func resolveProbeIP(rawURL string) (net.IP, error) {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || parsed.Host == "" {
		return nil, errors.New("invalid probe url: " + rawURL)
	}
	host := parsed.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, errors.New("probe host did not resolve: " + host)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4, nil
		}
	}
	if len(ips) > 0 {
		return ips[0], nil
	}
	return nil, errors.New("probe host has no address: " + host)
}
