package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/detector"
	"github.com/daniellavrushin/b4/http/handler"
	"github.com/daniellavrushin/b4/log"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/providers"
)

const (
	adnsRuntimeEpoch       = "boot"
	adnsNetworkContext     = "wan-unknown"
	adnsReferenceCatalog   = "runtime-reference-dns-v1"
	adnsUnrelatedControl   = "example.com"
	adnsUnrelatedControl2  = "example.net"
)

// initAdaptiveDNS wires the global adaptive DNS control plane (addendum
// §19/§88). Default mode is "current": the manager exists for observability
// but adaptive selection never runs implicitly on existing installs.
//
// The diagnosis provider set is derived only from the already-existing
// system.checker.reference_dns list. No new public resolvers are injected by
// ADNS. Diagnosis remains evidence-only: this closure never adopts/promotes
// the compiled profile.
func initAdaptiveDNS(cfg *config.Config) {
	mode := dnspath.DNSOperatingMode(cfg.DNSMode)
	if mode == "" {
		mode = dnspath.DNSModeCurrent
	}
	policy := adaptivePolicyFromConfig(cfg.DNSAdaptive)
	manager := dnspath.NewManager(mode, policy, 1, adnsRuntimeEpoch, adnsNetworkContext)

	diagnosisProviders := buildADNSReferenceProviders(cfg)
	for _, provider := range diagnosisProviders {
		// Native UDP/TCP Prepare is side-effect free (no query is sent). Keep
		// the handles ready so a later explicit transaction can use a profile
		// without silently creating a new, untracked provider identity.
		if err := manager.PreparePath(context.Background(), provider, false); err != nil {
			log.Warnf("adaptive dns: provider %s prepare failed: %v", provider.ID().Family, err)
			continue
		}
		manager.MarkPathHealth(provider.ID(), dnspath.DNSPathHealth{State: dnspath.CapAvailable})
	}

	handler.SetDNSPathManager(manager)
	handler.SetDNSDiagnoser(func(ctx context.Context) (*handler.DNSDiagnoseResult, error) {
		target := strings.TrimSpace(cfg.System.Checker.ReferenceDomain)
		if target == "" {
			return nil, fmt.Errorf("adaptive dns diagnosis requires system.checker.reference_domain")
		}
		if independentResolverCount(diagnosisProviders) < 2 {
			return nil, fmt.Errorf("adaptive dns diagnosis requires at least two independent configured reference DNS resolvers")
		}
		control := adnsUnrelatedControl
		if sameDNSName(target, control) {
			control = adnsUnrelatedControl2
		}
		livePolicy := manager.Policy()
		diag, err := detector.RunADNSDiagnosis(ctx, detector.ADNSDiagnosisInput{
			Providers:      diagnosisProviders,
			Policy:         livePolicy,
			Suite:          detector.CanonicalSuite(target, control),
			AttemptsQuick:  2,
			AttemptsValid:  5,
			NetworkContext: manager.NetworkContext(),
			Generation:     manager.Generation(),
			RuntimeEpoch:   adnsRuntimeEpoch,
			CatalogVersion: adnsReferenceCatalog,
			PolicyDigest:   livePolicy.Digest(),
			TTL:            livePolicy.ProfileTTL,
		})
		if err != nil {
			return nil, err
		}
		result := &handler.DNSDiagnoseResult{
			PoisoningDetected: diag.PoisoningDetected,
			InjectionDetected: diag.InjectionDetected,
			UDPDropDetected:   diag.UDPDropDetected,
		}
		if diag.Profile != nil {
			result.ProfileID = diag.Profile.ProfileID
			result.Confidence = diag.Profile.Confidence.Score
			if diag.Profile.Status == dnspath.ProfileStatusReady {
				result.PrimaryFamily = string(diag.Profile.Primary.Family)
				for _, fb := range diag.Profile.Fallbacks {
					result.FallbackFamilies = append(result.FallbackFamilies, string(fb.Family))
				}
			} else {
				result.Explanation = append(result.Explanation, "no path satisfied correctness, control and active policy gates")
			}
		}
		if diag.InjectionDetected {
			result.Explanation = append(result.Explanation, "conflicting early DNS responses observed")
		}
		if diag.PoisoningDetected {
			result.Explanation = append(result.Explanation, "answer conflict reached differential poisoning threshold")
		}
		if diag.UDPDropDetected {
			result.Explanation = append(result.Explanation, "repeated UDP DNS timeout observed")
		}
		if diag.Port53Blocked {
			result.Explanation = append(result.Explanation, "classic port-53 transport failure corroborated by an encrypted path")
		}
		return result, nil
	})
	log.Infof("adaptive dns: mode=%s adaptive=%v reference_resolvers=%d", mode, policy.Enabled, independentResolverCount(diagnosisProviders))
}

func buildADNSReferenceProviders(cfg *config.Config) []dnspath.DNSPathProvider {
	seen := map[netip.Addr]bool{}
	out := make([]dnspath.DNSPathProvider, 0, len(cfg.System.Checker.ReferenceDNS)*2)
	mark := int(cfg.Queue.Mark)
	for _, raw := range cfg.System.Checker.ReferenceDNS {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || !addr.IsValid() || seen[addr] {
			continue
		}
		seen[addr] = true
		out = append(out,
			providers.NewUDPProvider(addr, 53, mark, adnsReferenceCatalog),
			providers.NewTCPProvider(addr, 53, mark, adnsReferenceCatalog),
		)
	}
	return out
}

func independentResolverCount(items []dnspath.DNSPathProvider) int {
	seen := map[string]bool{}
	for _, provider := range items {
		if id := provider.ID().ResolverID; id != "" {
			seen[id] = true
		}
	}
	return len(seen)
}

func sameDNSName(a, b string) bool {
	norm := func(v string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v)), ".") }
	return norm(a) == norm(b)
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
