// Geo classify oracle: the E7 production wiring of WhoamiDNSProvider's
// classify seam (transport/warp ships the engine with the oracle injected —
// "production wiring supplies the oracle (E7)"). The oracle maps an observed
// egress IPv4 to an ISO-3166 alpha-2 country via the daemon's geoip.dat
// (geodat.LoadCountryPrefixes), independent of Cloudflare's own view: the
// CF-trace provider corroborates with CF's loc=, the whoami pair votes on
// THIS oracle — two independent classification sources, never one.
//
// Failure posture is fail-closed honesty: an absent/unreadable geoip index
// yields an oracle that classifies EVERY address as unknown ("") — the
// quorum can never form, the gate stays closed, and the runtime surfaces
// OracleLoaded=false in its status. A mis-classified country is the data's
// verdict, not the daemon's: the gate reports what the oracle said.
package nonruservice

import (
	"net/netip"
	"sort"

	"github.com/daniellavrushin/b4/geodat"
)

// oracleEntry is one indexed prefix with its country tag.
type oracleEntry struct {
	net      netip.Prefix
	country  string
	isPseudo bool // non-country pseudo-tag (private, "1"/cloudflare, ...)
}

// isPseudoCountry reports tags that must never classify an egress: a hit on
// these is an honest "unknown", not a country (geoip.dat ships
// private/cloudflare ranges as their own categories).
func isPseudoCountry(tag string) bool {
	switch tag {
	case "private", "1", "":
		return true
	}
	return false
}

// geoOracle is the immutable country index (load once, read-only after).
type geoOracle struct {
	entries []oracleEntry // sorted by network address
}

// loadGeoOracle builds the country index from a geoip.dat.
func loadGeoOracle(geoipPath string) (*geoOracle, error) {
	byCountry, err := geodat.LoadCountryPrefixes(geoipPath)
	if err != nil {
		return nil, err
	}
	total := 0
	for _, pfxs := range byCountry {
		total += len(pfxs)
	}
	o := &geoOracle{entries: make([]oracleEntry, 0, total)}
	for country, pfxs := range byCountry {
		pseudo := isPseudoCountry(country)
		for _, p := range pfxs {
			o.entries = append(o.entries, oracleEntry{net: p, country: country, isPseudo: pseudo})
		}
	}
	sort.Slice(o.entries, func(i, j int) bool {
		a, b := o.entries[i], o.entries[j]
		if c := a.net.Addr().Compare(b.net.Addr()); c != 0 {
			return c < 0
		}
		// Equal network addresses (nested prefixes from overlapping tags):
		// the WIDER prefix sorts LAST — the backward scan meets it first and
		// classifies by the coarsest containing network, deterministically.
		return a.net.Bits() > b.net.Bits()
	})
	return o, nil
}

// Classify returns the ISO-3166 alpha-2 country of an IPv4 address (""
// when unmatched or matched only by a pseudo-tag). The search is a binary
// descent over the sorted network addresses with a bounded backward scan —
// geoip.dat prefixes are disjoint in practice, but an overlap across tags
// is tolerated deterministically: among equal network addresses the WIDER
// prefix wins (the coarsest containing classification).
func (o *geoOracle) Classify(ip netip.Addr) string {
	if o == nil || !ip.Is4() {
		return ""
	}
	i := sort.Search(len(o.entries), func(i int) bool {
		return o.entries[i].net.Addr().Compare(ip) > 0
	})
	// Candidates start at i-1 and walk back while the network address
	// could still contain ip (nesting); a small bound keeps worst cases
	// honest without a full linear scan.
	for j := i - 1; j >= 0 && i-j <= 16; j-- {
		e := o.entries[j]
		if e.net.Contains(ip) && !e.isPseudo {
			return e.country
		}
	}
	return ""
}
