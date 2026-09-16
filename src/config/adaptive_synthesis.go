package config

import "time"

const (
	AdaptiveSynthesisProfileInherit  = "inherit"
	AdaptiveSynthesisProfileDisabled = "disabled"
)

// AutomationConfig is the persisted automation policy surface. It deliberately
// contains policy only: packet/action/discovery execution remains owned by the
// existing classifier, Discovery and runtimecontrol subsystems.
type AutomationConfig struct {
	AdaptiveStrategySynthesis AdaptiveStrategySynthesisConfig `json:"adaptive_strategy_synthesis"`
}

// AdaptiveStrategySynthesisConfig is the user opt-in and bounded search policy
// from the post-v2.3 AFS addendum. Discovery/Action/Rollout keep their existing
// budgets and ownership; these values are additional upper bounds only.
type AdaptiveStrategySynthesisConfig struct {
	Enabled              bool          `json:"enabled"`
	MaxCandidates        uint16        `json:"max_candidates"`
	MaxGenerations       uint8         `json:"max_generations"`
	MaxActions           uint8         `json:"max_actions"`
	MaxBranches          uint8         `json:"max_branches"`
	MaxAmplification     float64       `json:"max_amplification"`
	RunTimeout           time.Duration `json:"run_timeout"`
	Cooldown             time.Duration `json:"cooldown"`
	FailedSearchCooldown time.Duration `json:"failed_search_cooldown"`

	AllowSafeFake        bool `json:"allow_safe_fake"`
	AllowBoundedDisorder bool `json:"allow_bounded_disorder"`
	AllowJitter          bool `json:"allow_jitter"`

	Fingerprinting BehavioralFingerprintingConfig `json:"fingerprinting"`

	// ServiceProfilePolicy is keyed by the existing serviceprofile ProfileID
	// carried by MonitorScopeKey / synthesis scope. The config layer does not
	// create or mirror the service-profile catalog; missing/"inherit" keeps the
	// global decision and "disabled" can only narrow global permission.
	ServiceProfilePolicy map[string]string `json:"service_profile_policy,omitempty"`
}

// BehavioralFingerprintingConfig bounds the optional AFS behavioral panel.
// Concurrency defaults to one as required by the automatic-mode contract.
type BehavioralFingerprintingConfig struct {
	MaxProbes            uint8         `json:"max_probes"`
	AttemptsPerProbe     uint8         `json:"attempts_per_probe"`
	Concurrency          uint8         `json:"concurrency"`
	MaxDuration          time.Duration `json:"max_duration"`
	InterProbeDelay      time.Duration `json:"inter_probe_delay"`
	MaxInconclusiveRatio float64       `json:"max_inconclusive_ratio"`
}

var DefaultAdaptiveStrategySynthesisConfig = AdaptiveStrategySynthesisConfig{
	Enabled:              false,
	MaxCandidates:        24,
	MaxGenerations:       3,
	MaxActions:           4,
	MaxBranches:          1,
	MaxAmplification:     1.5,
	RunTimeout:           180 * time.Second,
	Cooldown:             5 * time.Minute,
	FailedSearchCooldown: 15 * time.Minute,
	AllowSafeFake:        false,
	AllowBoundedDisorder: true,
	AllowJitter:          true,
	Fingerprinting: BehavioralFingerprintingConfig{
		MaxProbes:            8,
		AttemptsPerProbe:     2,
		Concurrency:          1,
		MaxDuration:          60 * time.Second,
		InterProbeDelay:      500 * time.Millisecond,
		MaxInconclusiveRatio: 0.25,
	},
}

var DefaultAutomationConfig = AutomationConfig{
	AdaptiveStrategySynthesis: DefaultAdaptiveStrategySynthesisConfig,
}

// AdaptiveSynthesisAllowed applies the addendum's global-upper-bound rule to
// the existing service-profile identity. A profile can disable AFS, but can
// never enable it while the global setting is off.
func (c *Config) AdaptiveSynthesisAllowed(serviceProfileID string) bool {
	if c == nil || !c.Automation.AdaptiveStrategySynthesis.Enabled {
		return false
	}
	policy := c.Automation.AdaptiveStrategySynthesis.ServiceProfilePolicy[serviceProfileID]
	return policy != AdaptiveSynthesisProfileDisabled
}
