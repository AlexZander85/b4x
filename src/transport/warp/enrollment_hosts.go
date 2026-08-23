// Enrollment/control hostlist contract (design §5 transport ladder step 1
// and §8 "enrollment наоборот"; z2k lesson #16: without the enrollment API
// hostname in the fork's bypass-hostlist strategies, enrollment falls into
// TLS timeouts on hostile networks because nothing covers it).
//
// The engine stays dependency-free: these are the CANONICAL names plus pure
// merge/check helpers. Binding them into the live strategy catalog is the
// E7/E8 wiring's job — the checker makes a missing entry a LOUD structural
// failure instead of the silent field outage z2k hit.
package transportwarp

import (
	"sort"
	"strings"
)

// Canonical control-plane hostnames (usque/z2k/warp-socks patterns):
const (
	// EnrollHostAPI is the registration API host (z2k #16 bypass-hostlist).
	EnrollHostAPI = "api.cloudflareclient.com"
	// ConnectAuthorityHost is the CONNECT-IP URI template authority.
	ConnectAuthorityHost = "cloudflareaccess.com"
	// MasqueSNIConsumer is the default MASQUE cover SNI (= DefaultSNI).
	MasqueSNIConsumer = "consumer-masque.cloudflareclient.com"
	// MasqueSNIProxyL4 is the L4-proxy SNI variant (warp-socks).
	MasqueSNIProxyL4 = "consumer-masque-proxy.cloudflareclient.com"
	// MasqueSNIZT is the Zero Trust variant.
	MasqueSNIZT = "zt-masque.cloudflareclient.com"
	// DoHSNI is the in-tunnel DoH resolver name (warp-socks dns.rs).
	DoHSNI = "cloudflare-dns.com"
)

// WarpControlDomains returns the canonical control-plane domains, sorted,
// deduplicated.
func WarpControlDomains() []string {
	out := []string{
		EnrollHostAPI,
		ConnectAuthorityHost,
		MasqueSNIConsumer,
		MasqueSNIProxyL4,
		MasqueSNIZT,
		DoHSNI,
	}
	sort.Strings(out)
	return out
}

// covered reports whether have covers name exactly or as a suffix domain
// ("x.api.cloudflareclient.com" covers "api.cloudflareclient.com" only in
// the reverse direction; strategy lists usually carry the parent, so we
// check: exact match, OR have IS the parent of name via dot-suffix, OR name
// is a subdomain of have).
func domainCovered(have, name string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(have), "."))
	n := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if h == "" || n == "" {
		return false
	}
	if h == n {
		return true
	}
	return strings.HasSuffix(n, "."+h) || strings.HasSuffix(h, "."+n)
}

// MissingWarpControlDomains returns the canonical domains not covered by
// the given strategy hostlist. Empty result = the catalog can carry WARP
// control traffic through the fork's desync.
func MissingWarpControlDomains(have []string) []string {
	var missing []string
	for _, canon := range WarpControlDomains() {
		found := false
		for _, h := range have {
			if domainCovered(h, canon) {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, canon)
		}
	}
	return missing
}

// MergeWarpControlDomains returns have + any missing canonical domains
// (stable order: preserved entries first, then missing sorted). Pure.
func MergeWarpControlDomains(have []string) []string {
	missing := MissingWarpControlDomains(have)
	out := append([]string(nil), have...)
	out = append(out, missing...)
	return out
}
