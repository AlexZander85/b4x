package dnspath

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// Preference is the policy profile (addendum §22). No preference may lower
// correctness, controls, certificate validation or generation freshness.
type Preference string

const (
	PreferenceLowestLatency     Preference = "lowest-latency"
	PreferenceBalanced          Preference = "balanced"
	PreferencePrivacy           Preference = "privacy"
	PreferenceMinimumDependency Preference = "minimum-dependency"
)

func (p Preference) Valid() bool {
	switch p {
	case PreferenceLowestLatency, PreferenceBalanced, PreferencePrivacy, PreferenceMinimumDependency:
		return true
	}
	return false
}

// AdaptivePolicy is the advanced policy model (addendum §21).
type AdaptivePolicy struct {
	Enabled                 bool          `json:"enabled"`
	AllowNativeClassic      bool          `json:"allow_native_classic"`
	AllowNativeEncrypted    bool          `json:"allow_native_encrypted"`
	AllowManagedDNSCrypt    bool          `json:"allow_managed_dnscrypt_backend"`
	AllowAnonymizedDNSCrypt bool          `json:"allow_anonymized_dnscrypt"`
	AllowODoH               bool          `json:"allow_odoh"`
	AllowPQDNSCrypt         bool          `json:"allow_pqdnscrypt"`
	Preference              Preference    `json:"preference"`
	RequireDNSSECCapable    bool          `json:"require_dnssec_capable"`
	RequireNoLogClaim       bool          `json:"require_nolog_claim"`
	RequireNoFilterClaim    bool          `json:"require_nofilter_claim"`
	MaxQuickCandidates      int           `json:"max_quick_candidates"`
	MaxDeepCandidates       int           `json:"max_deep_candidates"`
	MaxParallelProbes       int           `json:"max_parallel_probes"`
	Cooldown                time.Duration `json:"cooldown"`
	FailedSearchCooldown    time.Duration `json:"failed_search_cooldown"`
	RecoveryHysteresis      time.Duration `json:"recovery_hysteresis"`
	ProfileTTL              time.Duration `json:"profile_ttl"`
	ManualExclusions        []string      `json:"manual_exclusions"` // canonical path hashes
	PinnedPrimary           string        `json:"pinned_primary"`    // canonical path hash, manual mode
	PinnedFallbacks         []string      `json:"pinned_fallbacks"`
}

// DefaultAdaptivePolicy returns the default-safe policy: adaptive disabled,
// conservative bounds for constrained routers (addendum §51).
func DefaultAdaptivePolicy() AdaptivePolicy {
	return AdaptivePolicy{
		Enabled:                 false,
		AllowNativeClassic:      true,
		AllowNativeEncrypted:    true,
		AllowManagedDNSCrypt:    false,
		AllowAnonymizedDNSCrypt: false,
		AllowODoH:               false,
		AllowPQDNSCrypt:         false,
		Preference:              PreferenceBalanced,
		RequireNoLogClaim:       true,
		RequireNoFilterClaim:    true,
		MaxQuickCandidates:      8,
		MaxDeepCandidates:       24,
		MaxParallelProbes:       1,
		Cooldown:                10 * time.Minute,
		FailedSearchCooldown:    time.Hour,
		RecoveryHysteresis:      30 * time.Minute,
		ProfileTTL:              24 * time.Hour,
	}
}

// Digest returns the stable policy digest stored in profiles.
func (p AdaptivePolicy) Digest() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:16])
}

// AllowsFamily reports whether the policy permits a path family.
func (p AdaptivePolicy) AllowsFamily(f DNSPathFamily) bool {
	switch f {
	case DNSPathSystemForward, DNSPathUDP, DNSPathTCP, DNSPathTCPSegmented:
		return p.AllowNativeClassic
	case DNSPathDoT, DNSPathDoH, DNSPathDoH3, DNSPathDoQ:
		return p.AllowNativeEncrypted
	case DNSPathDNSCrypt:
		return p.AllowManagedDNSCrypt
	case DNSPathPQDNSCrypt:
		return p.AllowManagedDNSCrypt && p.AllowPQDNSCrypt
	case DNSPathAnonymizedDNSCrypt:
		return p.AllowManagedDNSCrypt && p.AllowAnonymizedDNSCrypt
	case DNSPathODoH:
		return p.AllowManagedDNSCrypt && p.AllowODoH
	}
	return false
}

// ManuallyExcluded reports whether a path hash is in the manual exclusion list.
func (p AdaptivePolicy) ManuallyExcluded(pathHash string) bool {
	for _, ex := range p.ManualExclusions {
		if ex == pathHash {
			return true
		}
	}
	return false
}
