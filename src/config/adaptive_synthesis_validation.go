package config

import (
	"fmt"
	"time"
)

func (c *Config) validateAdaptiveStrategySynthesis(v *validator) {
	if c == nil || v == nil {
		return
	}
	p := &c.Automation.AdaptiveStrategySynthesis
	d := DefaultAdaptiveStrategySynthesisConfig

	if p.MaxCandidates == 0 {
		p.MaxCandidates = d.MaxCandidates
	}
	if p.MaxGenerations == 0 {
		p.MaxGenerations = d.MaxGenerations
	}
	if p.MaxActions == 0 {
		p.MaxActions = d.MaxActions
	}
	if p.MaxBranches == 0 {
		p.MaxBranches = d.MaxBranches
	}
	if p.MaxAmplification == 0 {
		p.MaxAmplification = d.MaxAmplification
	}
	if p.RunTimeout == 0 {
		p.RunTimeout = d.RunTimeout
	}
	if p.Cooldown == 0 {
		p.Cooldown = d.Cooldown
	}
	if p.FailedSearchCooldown == 0 {
		p.FailedSearchCooldown = d.FailedSearchCooldown
	}

	f := &p.Fingerprinting
	fd := d.Fingerprinting
	if f.MaxProbes == 0 {
		f.MaxProbes = fd.MaxProbes
	}
	if f.AttemptsPerProbe == 0 {
		f.AttemptsPerProbe = fd.AttemptsPerProbe
	}
	if f.Concurrency == 0 {
		f.Concurrency = fd.Concurrency
	}
	if f.MaxDuration == 0 {
		f.MaxDuration = fd.MaxDuration
	}
	if f.InterProbeDelay == 0 {
		f.InterProbeDelay = fd.InterProbeDelay
	}
	if f.MaxInconclusiveRatio == 0 {
		f.MaxInconclusiveRatio = fd.MaxInconclusiveRatio
	}

	if p.MaxCandidates < 1 || p.MaxCandidates > 64 {
		v.add("automation.adaptive_strategy_synthesis.max_candidates", "out_of_range", "max_candidates must be in [1,64]", nil)
	}
	if p.MaxGenerations < 1 || p.MaxGenerations > 8 {
		v.add("automation.adaptive_strategy_synthesis.max_generations", "out_of_range", "max_generations must be in [1,8]", nil)
	}
	if p.MaxActions < 1 || p.MaxActions > 8 {
		v.add("automation.adaptive_strategy_synthesis.max_actions", "out_of_range", "max_actions must be in [1,8]", nil)
	}
	if p.MaxBranches > 2 {
		v.add("automation.adaptive_strategy_synthesis.max_branches", "out_of_range", "max_branches must be in [0,2]", nil)
	}
	if p.MaxAmplification < 1 || p.MaxAmplification > 4 {
		v.add("automation.adaptive_strategy_synthesis.max_amplification", "out_of_range", "max_amplification must be in [1,4]", nil)
	}
	if actionMax := c.System.Classifier.Runtime.Actions.MaxAmplification; actionMax > 0 && p.MaxAmplification > actionMax {
		v.add("automation.adaptive_strategy_synthesis.max_amplification", "exceeds_action_budget", "synthesis amplification must not exceed the existing Action budget", map[string]any{"action_max_amplification": actionMax})
	}
	if p.RunTimeout <= 0 || p.RunTimeout > 10*time.Minute {
		v.add("automation.adaptive_strategy_synthesis.run_timeout", "out_of_range", "run_timeout must be in (0,10m]", nil)
	}
	if p.Cooldown <= 0 || p.Cooldown > 24*time.Hour {
		v.add("automation.adaptive_strategy_synthesis.cooldown", "out_of_range", "cooldown must be in (0,24h]", nil)
	}
	if p.FailedSearchCooldown <= 0 || p.FailedSearchCooldown > 7*24*time.Hour {
		v.add("automation.adaptive_strategy_synthesis.failed_search_cooldown", "out_of_range", "failed_search_cooldown must be in (0,168h]", nil)
	}

	if f.MaxProbes < 1 || f.MaxProbes > 16 {
		v.add("automation.adaptive_strategy_synthesis.fingerprinting.max_probes", "out_of_range", "max_probes must be in [1,16]", nil)
	}
	if f.AttemptsPerProbe < 1 || f.AttemptsPerProbe > 5 {
		v.add("automation.adaptive_strategy_synthesis.fingerprinting.attempts_per_probe", "out_of_range", "attempts_per_probe must be in [1,5]", nil)
	}
	if f.Concurrency != 1 {
		v.add("automation.adaptive_strategy_synthesis.fingerprinting.concurrency", "automatic_concurrency_one", "automatic behavioral fingerprinting is concurrency=1", nil)
	}
	if f.MaxDuration <= 0 || f.MaxDuration > 2*time.Minute {
		v.add("automation.adaptive_strategy_synthesis.fingerprinting.max_duration", "out_of_range", "max_duration must be in (0,2m]", nil)
	}
	if f.InterProbeDelay < 0 || f.InterProbeDelay > 10*time.Second {
		v.add("automation.adaptive_strategy_synthesis.fingerprinting.inter_probe_delay", "out_of_range", "inter_probe_delay must be in [0,10s]", nil)
	}
	if f.MaxInconclusiveRatio <= 0 || f.MaxInconclusiveRatio > 0.5 {
		v.add("automation.adaptive_strategy_synthesis.fingerprinting.max_inconclusive_ratio", "out_of_range", "max_inconclusive_ratio must be in (0,0.5]", nil)
	}

	// The service-profile catalog is owned by serviceprofile, not config. AFS
	// stores only a narrowing policy keyed by the existing ProfileID carried at
	// runtime; duplicating catalog membership here would create a second source
	// of truth. Unknown/non-loaded IDs are harmless because they can never match
	// a runtime scope and therefore cannot widen global permission.
	for profileID, policy := range p.ServiceProfilePolicy {
		path := fmt.Sprintf("automation.adaptive_strategy_synthesis.service_profile_policy[%q]", profileID)
		if profileID == "" {
			v.add(path, "empty_profile_id", "service profile policy key must be a non-empty service profile ID", nil)
			continue
		}
		switch policy {
		case "", AdaptiveSynthesisProfileInherit, AdaptiveSynthesisProfileDisabled:
		default:
			v.add(path, "unsupported_policy", "service profile policy must be inherit or disabled", nil)
		}
	}
}
