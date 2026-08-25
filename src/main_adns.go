package main

import (
	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/http/handler"
	"github.com/daniellavrushin/b4/log"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// initAdaptiveDNS wires the global adaptive DNS control plane (addendum
// §19/§88). Default mode is "current": the manager exists for observability
// but adaptive selection never runs implicitly on existing installs.
func initAdaptiveDNS(cfg *config.Config) {
	mode := dnspath.DNSOperatingMode(cfg.DNSMode)
	if mode == "" {
		mode = dnspath.DNSModeCurrent
	}
	policy := adaptivePolicyFromConfig(cfg.DNSAdaptive)
	manager := dnspath.NewManager(mode, policy, 1, "boot", "wan-unknown")
	handler.SetDNSPathManager(manager)
	log.Infof("adaptive dns: mode=%s adaptive=%v", mode, policy.Enabled)
}

// adaptivePolicyFromConfig converts the config-schema mirror into the
// runtime policy. Nil config yields the default-safe policy (§88).
func adaptivePolicyFromConfig(c *config.DNSAdaptiveConfig) dnspath.AdaptivePolicy {
	if c == nil {
		return dnspath.DefaultAdaptivePolicy()
	}
	return dnspath.AdaptivePolicy{
		Enabled:                 c.Enabled,
		AllowNativeClassic:      c.AllowNativeClassic,
		AllowNativeEncrypted:    c.AllowNativeEncrypted,
		AllowManagedDNSCrypt:    c.AllowManagedDNSCrypt,
		AllowAnonymizedDNSCrypt: c.AllowAnonymizedDNSCrypt,
		AllowODoH:               c.AllowODoH,
		AllowPQDNSCrypt:         c.AllowPQDNSCrypt,
		Preference:              dnspath.Preference(c.Preference),
		RequireDNSSECCapable:    c.RequireDNSSECCapable,
		RequireNoLogClaim:       c.RequireNoLogClaim,
		RequireNoFilterClaim:    c.RequireNoFilterClaim,
		MaxQuickCandidates:      c.MaxQuickCandidates,
		MaxDeepCandidates:       c.MaxDeepCandidates,
		MaxParallelProbes:       c.MaxParallelProbes,
		Cooldown:                c.Cooldown,
		FailedSearchCooldown:    c.FailedSearchCooldown,
		RecoveryHysteresis:      c.RecoveryHysteresis,
		ProfileTTL:              c.ProfileTTL,
		ManualExclusions:        c.ManualExclusions,
		PinnedPrimary:           c.PinnedPrimary,
		PinnedFallbacks:         c.PinnedFallbacks,
	}
}
