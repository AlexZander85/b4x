package watchdog

import (
	"strings"

	"github.com/daniellavrushin/b4/config"
)

// normalizeDomain lower-cases and trims a domain for matching.
func normalizeDomain(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// setContainsAnyDomain reports whether any target of the (read-only) set
// matches one of the supplied domains. Kept after the FB-28 cutover as a pure
// read helper for status projection (GetState); it never mutates configuration.
func setContainsAnyDomain(set *config.SetConfig, domains []string) bool {
	matchList := set.Targets.DomainsToMatch
	if len(matchList) == 0 {
		matchList = set.Targets.SNIDomains
	}
	for _, rawTarget := range matchList {
		target := normalizeDomain(rawTarget)
		if target == "" {
			continue
		}
		for _, rawDomain := range domains {
			domain := normalizeDomain(rawDomain)
			if domain == "" {
				continue
			}
			if target == domain || domainMatchesSuffix(domain, target) {
				return true
			}
		}
	}
	return false
}

// domainMatchesSuffix reports whether one domain is a strict suffix of the
// other (same registered name, subdomain relationship), never a bare partial
// substring ("cord.com" is not a match for "discord.com").
func domainMatchesSuffix(domain, target string) bool {
	if len(domain) > len(target) && strings.HasSuffix(domain, "."+target) {
		return true
	}
	if len(target) > len(domain) && strings.HasSuffix(target, "."+domain) {
		return true
	}
	return false
}