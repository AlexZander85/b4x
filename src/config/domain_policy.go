package config

import (
	"fmt"
	"strings"
)

const UnsafeLegacyDomainScopeReason = "unsafe_legacy_domain_scope"

// NormalizeDomainPolicy validates the explicit per-set vocabulary. Empty is
// compatibility-equivalent to inherit and is intentionally preserved on disk.
func NormalizeDomainPolicy(policy DomainPolicy) DomainPolicy {
	switch DomainPolicy(strings.TrimSpace(string(policy))) {
	case "", DomainPolicyInherit:
		return DomainPolicyInherit
	case DomainPolicyStrict:
		return DomainPolicyStrict
	case DomainPolicyScopedHints:
		return DomainPolicyScopedHints
	case DomainPolicyLegacy:
		return DomainPolicyLegacy
	case DomainPolicyDisabled:
		return DomainPolicyDisabled
	default:
		return policy
	}
}

func GlobalDomainPolicy(mode string) DomainPolicy {
	switch strings.TrimSpace(mode) {
	case DomainStrict:
		return DomainPolicyStrict
	case DomainScopedHints:
		return DomainPolicyScopedHints
	case DomainDisabled:
		return DomainPolicyDisabled
	default:
		return DomainPolicyLegacy
	}
}

// EffectiveDomainPolicy resolves explicit set policy first, then the global
// compatibility mode. DomainOnly=false has disabled semantics regardless of a
// stale policy field.
func EffectiveDomainPolicy(globalMode string, set *SetConfig) DomainPolicy {
	if set == nil || !set.Targets.DomainOnly {
		return DomainPolicyDisabled
	}
	policy := NormalizeDomainPolicy(set.Targets.DomainPolicy)
	if policy == DomainPolicyInherit {
		return GlobalDomainPolicy(globalMode)
	}
	return policy
}

func (c *Config) EffectiveDomainPolicy(set *SetConfig) DomainPolicy {
	if c == nil {
		return EffectiveDomainPolicy(DomainLegacy, set)
	}
	return EffectiveDomainPolicy(c.System.Classifier.DomainOnlyMode, set)
}

func setHasScopeFallback(set *SetConfig) bool {
	if set == nil {
		return false
	}
	return len(set.Targets.IPs) > 0 || len(set.Targets.GeoIpCategories) > 0 ||
		len(set.Targets.GeoSiteCategories) > 0 || strings.TrimSpace(set.TCP.DPortFilter) != "" ||
		strings.TrimSpace(set.UDP.DPortFilter) != ""
}

func setHasDestructiveAction(set *SetConfig) bool {
	if set == nil {
		return false
	}
	if set.Routing.Enabled || set.TCP.Duplicate.Enabled || set.TCP.DropSACK || set.TCP.SynFake ||
		set.TCP.IPBlockDetect.Enabled || set.TCP.Desync.PostDesync || set.Faking.SNI || set.Faking.TCPMD5 {
		return true
	}
	if set.TCP.Desync.Mode != "" && set.TCP.Desync.Mode != ConfigOff ||
		set.TCP.Win.Mode != "" && set.TCP.Win.Mode != ConfigOff ||
		set.Fragmentation.Strategy != "" && set.Fragmentation.Strategy != ConfigNone ||
		len(set.Fragmentation.StrategyPool) > 0 ||
		set.Faking.SNIMutation.Mode != "" && set.Faking.SNIMutation.Mode != ConfigOff {
		return true
	}
	switch strings.TrimSpace(set.UDP.Mode) {
	case "drop", "reject", "fake":
		return true
	}
	return false
}

func UnsafeLegacyDomainScope(c *Config, set *SetConfig) bool {
	return set != nil && set.Targets.DomainOnly && c.EffectiveDomainPolicy(set) == DomainPolicyLegacy &&
		setHasScopeFallback(set) && setHasDestructiveAction(set)
}

type DomainPolicyMigrationPreview struct {
	SetID      string       `json:"set_id"`
	SetName    string       `json:"set_name"`
	From       DomainPolicy `json:"from"`
	To         DomainPolicy `json:"to"`
	Required   bool         `json:"required"`
	ReasonCode string       `json:"reason_code,omitempty"`
}

func (c *Config) PreviewDomainPolicyMigration() []DomainPolicyMigrationPreview {
	if c == nil {
		return nil
	}
	out := make([]DomainPolicyMigrationPreview, 0)
	for _, set := range c.Sets {
		if set == nil || !set.Targets.DomainOnly {
			continue
		}
		from := c.EffectiveDomainPolicy(set)
		if from != DomainPolicyLegacy {
			continue
		}
		preview := DomainPolicyMigrationPreview{SetID: set.Id, SetName: set.Name, From: from, To: DomainPolicyScopedHints}
		if UnsafeLegacyDomainScope(c, set) {
			preview.Required = true
			preview.ReasonCode = UnsafeLegacyDomainScopeReason
		}
		out = append(out, preview)
	}
	return out
}

// PrepareGeneratedSetDomainPolicy is the shared compiler/Discovery guard. New
// managed domain-only sets get scoped-hints; generators are never allowed to
// emit the unsafe compatibility policy.
func PrepareGeneratedSetDomainPolicy(set *SetConfig) error {
	if set == nil || !set.Targets.DomainOnly {
		return nil
	}
	policy := NormalizeDomainPolicy(set.Targets.DomainPolicy)
	if policy == DomainPolicyLegacy {
		return fmt.Errorf("%s: generated profiles cannot use legacy domain policy", UnsafeLegacyDomainScopeReason)
	}
	if policy == DomainPolicyInherit {
		set.Targets.DomainPolicy = DomainPolicyScopedHints
	}
	return nil
}
