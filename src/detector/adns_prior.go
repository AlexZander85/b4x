package detector

import (
	"errors"
	"time"

	"github.com/daniellavrushin/b4/monitor"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
)

// BuildDNSDiscoveryPrior converts a fresh DNSPathProfile into the existing
// DiscoverySearchPrior contract (addendum §69/§70). The profile is used only
// for ordering, budget and exclusions; mandatory baselines, controls and the
// full bounded fallback stay intact. A DNSPathProfile is never a
// TransportAuthorization.
func BuildDNSDiscoveryPrior(profile *dnspath.DNSPathProfile, scope monitor.MonitorScopeKey, currentBaseline []string, now time.Time) (DiscoverySearchPrior, error) {
	if profile == nil {
		return DiscoverySearchPrior{}, errors.New("dns path profile required")
	}
	if err := profile.Valid(now); err != nil {
		return DiscoverySearchPrior{}, err
	}
	if len(currentBaseline) == 0 {
		return DiscoverySearchPrior{}, errors.New("current baseline mandatory")
	}
	p := DiscoverySearchPrior{
		Scope:               scope,
		ProfileID:           profile.ProfileID,
		CoverageDenominator: len(profile.CandidateOutcomes),
		MandatoryBaselines:  append([]string(nil), currentBaseline...),
		Applied:             true,
		Explanation:         "DNSPathProfile orders bounded DNS candidate search; baselines/controls/full fallback remain mandatory",
	}
	if p.CoverageDenominator == 0 {
		p.CoverageDenominator = 1
	}
	var hypotheses []string
	if profile.PoisoningDetected {
		hypotheses = append(hypotheses, "dns_poisoning")
	}
	if profile.InjectionDetected {
		hypotheses = append(hypotheses, "dns_early_injection")
	}
	if profile.UDPDropDetected {
		hypotheses = append(hypotheses, "dns_udp_drop")
	}
	if profile.Port53Blocked {
		hypotheses = append(hypotheses, "dns_port53_blocked")
	}
	if profile.EncryptedPathBlocked {
		hypotheses = append(hypotheses, "dns_encrypted_path_blocked")
	}
	p.Hypotheses = hypotheses
	// deterministic candidate order: primary, then fallbacks
	p.TargetOrder = append(p.TargetOrder, profile.Primary.Hash())
	for _, fb := range profile.Fallbacks {
		p.TargetOrder = append(p.TargetOrder, fb.Hash())
	}
	for _, ex := range profile.Excluded {
		p.ExcludedTargets = append(p.ExcludedTargets, ex.Path.Hash())
	}
	return p, nil
}
