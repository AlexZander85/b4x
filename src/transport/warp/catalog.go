// Versioned MASQUE endpoint catalog (addendum v1.2 §34: "Candidate catalog
// MUST be versioned and tested. Random Cloudflare IP scanning is forbidden").
//
// The ranges below are the measured Cloudflare MASQUE gateway map compiled in
// .ag/research/warp-dataplane-research.md from three independent field tools:
//   - warpscout masque.go:50-91: QUIC-MASQUE answers only at 162.159.198.1/.2
//     (+ v6 2606:4700:103::/104:: .1/.2); TCP-MASQUE (h2) answers across the
//     whole 162.159.198.0/24 + 162.159.199.0/24 and the 2606:4700:103::/48 +
//     104::/48 blocks; ports {443,500,1701,4500,4443,8443,8095};
//   - Nova strat/warp.json: same endpoint/port matrix for masque-* profiles;
//   - MSN-GUARD core prober.rs: same measured map.
//
// Discovery may probe ONLY addresses inside these ranges; anything else must
// be rejected as an out-of-catalog endpoint (addendum Appendix C forbids
// arbitrary endpoint scans). The catalog is re-verified by unit test against
// its own invariants so a stale range cannot silently ship.
package transportwarp

import "net/netip"

// CatalogVersion increments on any change to the ranges below. Validation
// reports and trace exports carry this number so a field failure can be
// correlated with the exact map revision it ran against.
const CatalogVersion = 1

// EndpointKind selects the catalog family.
type EndpointKind string

const (
	// KindMasqueH2 is CONNECT-IP over TCP+TLS (HTTP/2), the production
	// default transport of this engine.
	KindMasqueH2 EndpointKind = "masque-h2"
	// KindMasqueQUIC is CONNECT-IP over QUIC/HTTP-3. Reserved for the future
	// H3 capability; listed here because the gateway set is distinct.
	KindMasqueQUIC EndpointKind = "masque-quic"
)

// h2GatewayCIDRs are the IPv4/IPv6 prefixes whose every address terminates
// TCP MASQUE (CONNECT-IP over HTTP/2).
var h2GatewayCIDRs = []netip.Prefix{
	netip.MustParsePrefix("162.159.198.0/24"),
	netip.MustParsePrefix("162.159.199.0/24"),
	netip.MustParsePrefix("2606:4700:103::/48"),
	netip.MustParsePrefix("2606:4700:104::/48"),
}

// quicGatewayAddrs are the only addresses that terminate QUIC MASQUE today;
// other addresses of the /24 answer QUIC but reject the TLS handshake.
var quicGatewayAddrs = []netip.Addr{
	netip.MustParseAddr("162.159.198.1"),
	netip.MustParseAddr("162.159.198.2"),
	netip.MustParseAddr("2606:4700:103::1"),
	netip.MustParseAddr("2606:4700:103::2"),
	netip.MustParseAddr("2606:4700:104::1"),
	netip.MustParseAddr("2606:4700:104::2"),
}

// Ports is the fixed MASQUE port set reported by registration responses and
// confirmed identical across all measured gateways.
var Ports = []uint16{443, 500, 1701, 4500, 4443, 8443, 8095}

// DefaultH2Endpoint mirrors usque's DefaultEndpointH2V4 with the primary
// port; it is the bootstrap endpoint before discovery runs.
func DefaultH2Endpoint() netip.AddrPort {
	return netip.MustParseAddrPort("162.159.198.2:443")
}

// SeedEndpoints returns a small ordered candidate list for kind: known-live
// anycast seeds first, then the remaining ports on the default address. It is
// the starting input of bounded verification, not a scan target list.
func SeedEndpoints(kind EndpointKind) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(Ports))
	switch kind {
	case KindMasqueQUIC:
		for _, a := range quicGatewayAddrs {
			if a.Is4() {
				out = append(out, netip.AddrPortFrom(a, 443))
			}
		}
	default:
		def := DefaultH2Endpoint()
		out = append(out, def)
		for _, p := range Ports {
			if p == 443 {
				continue
			}
			out = append(out, netip.AddrPortFrom(def.Addr(), p))
		}
	}
	return out
}

// InCatalog reports whether addr belongs to the versioned gateway map for
// kind. Configured endpoints outside the catalog are legal only through the
// explicit user-override path and are flagged in diagnostics.
func InCatalog(kind EndpointKind, ip netip.Addr) bool {
	switch kind {
	case KindMasqueQUIC:
		for _, a := range quicGatewayAddrs {
			if a == ip.Unmap() {
				return true
			}
		}
		return false
	default:
		ip = ip.Unmap()
		for _, p := range h2GatewayCIDRs {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
}

// KnownPort reports whether port belongs to the fixed MASQUE port set.
func KnownPort(port uint16) bool {
	for _, p := range Ports {
		if p == port {
			return true
		}
	}
	return false
}
