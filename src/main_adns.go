package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/detector"
	b4dns "github.com/daniellavrushin/b4/dns"
	"github.com/daniellavrushin/b4/http/handler"
	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/nfq"
	dnspath "github.com/daniellavrushin/b4/transport/dns"
	"github.com/daniellavrushin/b4/transport/dns/providers"
)

const (
	adnsRuntimeEpoch      = "boot"
	adnsNetworkContext    = "wan-unknown"
	adnsReferenceCatalog  = "runtime-reference-dns-v1"
	adnsUnrelatedControl  = "example.com"
	adnsUnrelatedControl2 = "example.net"
)

// initAdaptiveDNS wires the global adaptive DNS control plane (addendum
// §19/§88). Default mode is "current": the manager exists for observability
// but adaptive selection never runs implicitly on existing installs.
//
// The diagnosis provider set is derived from the current system resolver,
// already-existing system.checker.reference_dns entries and, when explicitly
// provisioned, verified managed dnscrypt-proxy catalog entries. Runtime
// download is never performed. Diagnosis/adoption alone never changes LAN
// DNS: selected paths are prepared, then a real source-scoped LAN canary and
// Transaction.Run are required before the NFQ dataplane sees the new binding.
func initAdaptiveDNS(cfg *config.Config) {
	mode := dnspath.DNSOperatingMode(cfg.DNSMode)
	if mode == "" {
		mode = dnspath.DNSModeCurrent
	}
	policy := adaptivePolicyFromConfig(cfg.DNSAdaptive)
	manager := dnspath.NewManager(mode, policy, 1, adnsRuntimeEpoch, adnsNetworkContext)

	// The built-in reference list is a local config source with a stable
	// version. If a verified managed catalog is loaded it adds its own version
	// to the same allowlist.
	dnspath.KnownCatalogVersions[adnsReferenceCatalog] = true
	diagnosisProviders := buildADNSReferenceProviders(cfg, policy)
	for _, provider := range diagnosisProviders {
		manager.RegisterProvider(provider)
		manager.MarkPathHealth(provider.ID(), dnspath.DNSPathHealth{State: provider.Capabilities().State})
	}

	// The globally promoted path is consumed by NFQ only after a transaction
	// installs an active binding. Current/diagnostic modes remain untouched.
	nfq.ConfigureAdaptiveDNSRuntime(func() bool {
		mode := manager.Mode()
		if mode != dnspath.DNSModeAdaptive && mode != dnspath.DNSModeManual {
			return false
		}
		return manager.ActiveBinding() != nil
	}, func(ctx context.Context, raw []byte) ([]byte, error) {
		q, err := adaptiveDNSQueryFromWire(raw)
		if err != nil {
			return nil, err
		}
		resp, err := manager.Resolve(ctx, q)
		if err != nil {
			return nil, err
		}
		return resp.Payload, nil
	})

	handler.SetDNSPathManager(manager)
	handler.SetDNSDiagnoser(func(ctx context.Context) (*handler.DNSDiagnoseResult, error) {
		target := strings.TrimSpace(cfg.System.Checker.ReferenceDomain)
		if target == "" {
			return nil, fmt.Errorf("adaptive dns diagnosis requires system.checker.reference_domain")
		}
		if independentResolverCount(diagnosisProviders) < 2 {
			return nil, fmt.Errorf("adaptive dns diagnosis requires at least two independent configured/effective DNS resolver identities")
		}
		unrelated := adnsUnrelatedControl
		if sameDNSName(target, unrelated) {
			unrelated = adnsUnrelatedControl2
		}
		livePolicy := manager.Policy()
		attemptsValid := cfg.System.Checker.ValidationTries
		if attemptsValid < 2 {
			attemptsValid = 5
		}
		if attemptsValid > 10 {
			attemptsValid = 10
		}
		diag, err := detector.RunADNSDiagnosis(ctx, detector.ADNSDiagnosisInput{
			Providers:      diagnosisProviders,
			Policy:         livePolicy,
			Suite:          detector.CanonicalSuiteWithControls(target, "", unrelated),
			Deep:           true,
			AttemptsQuick:  2,
			AttemptsValid:  attemptsValid,
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
				// Diagnostic handles are retired by the detector. Re-prepare only
				// selected primary/fallback paths as production handles before the
				// profile becomes eligible for a LAN canary.
				if err := manager.PrepareProfilePaths(ctx, diag.Profile); err != nil {
					return nil, fmt.Errorf("prepare validated DNS profile: %w", err)
				}
				if err := manager.AdoptProfile(diag.Profile); err != nil {
					return nil, fmt.Errorf("adopt validated DNS profile: %w", err)
				}
				result.PrimaryFamily = string(diag.Profile.Primary.Family)
				for _, fb := range diag.Profile.Fallbacks {
					result.FallbackFamilies = append(result.FallbackFamilies, string(fb.Family))
				}
				result.Explanation = append(result.Explanation, "profile prepared; source-scoped LAN canary is required before promotion")
			} else {
				result.Explanation = append(result.Explanation, "no path satisfied correctness, control and active policy gates")
			}
		}
		if diag.InjectionDetected {
			result.Explanation = append(result.Explanation, "conflicting early DNS responses observed")
		}
		if diag.PoisoningDetected {
			result.Explanation = append(result.Explanation, "UDP/TCP or independent answer conflict reached poisoning evidence threshold")
		}
		if diag.UDPDropDetected {
			result.Explanation = append(result.Explanation, "UDP failure corroborated by working TCP to the same apparent resolver")
		}
		if diag.Port53Blocked {
			result.Explanation = append(result.Explanation, "classic port-53 failure corroborated by an independently validated encrypted path")
		}
		return result, nil
	})

	handler.SetDNSCanaryRunner(func(ctx context.Context, req handler.DNSCanaryRequest) (*handler.DNSCanaryResult, error) {
		if manager.Mode() != dnspath.DNSModeAdaptive {
			return nil, fmt.Errorf("automatic DNS canary/promotion requires dns_mode=adaptive")
		}
		if !manager.Policy().Enabled {
			return nil, fmt.Errorf("adaptive DNS policy is disabled")
		}
		profile := manager.Profile()
		if profile == nil {
			return nil, fmt.Errorf("no adopted profile; diagnose first")
		}
		if err := profile.Validated(time.Now()); err != nil {
			return nil, fmt.Errorf("profile not fresh/proven: %w", err)
		}
		// Refresh production readiness immediately before canary.
		if err := manager.PrepareProfilePaths(ctx, profile); err != nil {
			return nil, err
		}
		bindingTTL := time.Until(profile.ValidUntil)
		if bindingTTL <= 0 {
			return nil, fmt.Errorf("profile expired before canary")
		}
		binding, err := manager.NewBinding("lan-canary", bindingTTL)
		if err != nil {
			return nil, err
		}
		lastGood := manager.ActiveBinding()
		tx := &dnspath.Transaction{
			Profile: profile, Candidate: binding, LastGood: lastGood,
		}
		var canary nfq.DNSCanaryResult
		tx.Canary = func(canaryCtx context.Context, candidate *dnspath.DNSPathBinding) error {
			res, runErr := nfq.RunAdaptiveDNSCanary(
				canaryCtx,
				req.ClientMAC,
				req.MinimumQueries,
				time.Duration(req.WindowSeconds)*time.Second,
				func(resolveCtx context.Context, raw []byte) ([]byte, error) {
					q, qErr := adaptiveDNSQueryFromWire(raw)
					if qErr != nil {
						return nil, qErr
					}
					resp, qErr := manager.ResolveCandidate(resolveCtx, candidate, q)
					if qErr != nil {
						return nil, qErr
					}
					return resp.Payload, nil
				},
			)
			canary = res
			return runErr
		}
		if err := tx.Run(ctx, manager); err != nil {
			result := &handler.DNSCanaryResult{
				Promoted: false, ProfileID: profile.ProfileID,
				PrimaryFamily: string(profile.Primary.Family),
				Successes: canary.Successes, Failures: canary.Failures,
				Reason: tx.Reason,
			}
			return result, fmt.Errorf("DNS canary/promotion aborted: %s", tx.Reason)
		}
		return &handler.DNSCanaryResult{
			Promoted: true, ProfileID: profile.ProfileID,
			PrimaryFamily: string(profile.Primary.Family),
			Successes: canary.Successes, Failures: canary.Failures,
		}, nil
	})

	log.Infof("adaptive dns: mode=%s adaptive=%v resolver_identities=%d providers=%d", mode, policy.Enabled, independentResolverCount(diagnosisProviders), len(diagnosisProviders))
}

func adaptiveDNSQueryFromWire(raw []byte) (dnspath.DNSQuery, error) {
	name, qtype, txid, ok := b4dns.ParseQuestion(raw)
	if !ok {
		return dnspath.DNSQuery{}, fmt.Errorf("unsupported or malformed client DNS question")
	}
	return dnspath.DNSQuery{
		Name: name, NameHash: dnspath.HashQName(name), QType: qtype, TxID: txid,
		Payload: append([]byte(nil), raw...),
	}, nil
}

func buildADNSReferenceProviders(cfg *config.Config, policy dnspath.AdaptivePolicy) []dnspath.DNSPathProvider {
	seen := map[netip.Addr]bool{}
	out := make([]dnspath.DNSPathProvider, 0, 1+len(cfg.System.Checker.ReferenceDNS)*2+managedDNSMaxCandidates)
	// Use the dedicated discovery mark for system/UDP/TCP so a transport
	// differential changes transport, not policy-routing identity.
	mark := int(cfg.System.Checker.DiscoveryFlowMark)
	out = append(out, providers.NewSystemForwardProvider("/etc/resolv.conf", nil, mark))
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
	out = append(out, buildADNSManagedProviders(policy, cfg.System.Checker.ReferenceDomain)...)
	return out
}

func independentResolverCount(items []dnspath.DNSPathProvider) int {
	seen := map[string]bool{}
	for _, provider := range items {
		caps := provider.Capabilities()
		if caps.State != dnspath.CapAvailable && caps.State != dnspath.CapReady && caps.State != dnspath.CapDegraded {
			continue
		}
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
// runtime policy. Nil config yields the addendum defaults; existing installs
// remain unaffected because DNS mode itself defaults to "current".
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
