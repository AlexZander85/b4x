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

// QuicCatalogCandidates builds the bounded QUIC-branch candidate list for
// the H3-enabled discovery scan (E-H3 continuation, EH3): every catalog
// QUIC gateway address × the full known port set, v4 anycast pair first,
// then the v6 pairs — all inside the SAME versioned map (no new ranges,
// CatalogVersion unchanged; §34 gate holds because both factors of the
// product are catalog-listed). Turbo stays a single bootstrap seed.
// The two-address :443 SeedEndpoints(KindMasqueQUIC) list remains the
// registration/bootstrap seed and is untouched (its shape is pinned by test).
func QuicCatalogCandidates(s ScanStrategy) []netip.AddrPort {
	if s == StrategyTurbo {
		return []netip.AddrPort{netip.AddrPortFrom(quicGatewayAddrs[0], Ports[0])}
	}
	out := make([]netip.AddrPort, 0, len(quicGatewayAddrs)*len(Ports))
	for _, a := range quicGatewayAddrs {
		for _, p := range Ports {
			out = append(out, netip.AddrPortFrom(a, p))
		}
	}
	return out
}

// CatalogCandidates builds the bounded candidate list for a scan strategy
// from the versioned map ONLY (addendum §34: discovery may test catalog
// entries, never arbitrary internet addresses). H2 scanning stays
// IPv4-first: usque ships h2_v6 intentionally empty, and the v6 blocks are
// exercised through the QUIC anycast seeds instead.
func CatalogCandidates(kind EndpointKind, s ScanStrategy) []netip.AddrPort {
	if kind == KindMasqueQUIC {
		return SeedEndpoints(kind)
	}
	def := DefaultH2Endpoint()
	switch s {
	case StrategyTurbo:
		// "1 target, early-exit": the bootstrap default only.
		return []netip.AddrPort{def}
	case StrategyThorough:
		// Full product of both measured H2 /24s x the port set.
		out := make([]netip.AddrPort, 0, 512*len(Ports))
		for _, cidr := range h2GatewayCIDRs {
			if !cidr.Addr().Is4() {
				continue
			}
			base := cidr.Masked().Addr()
			for i := 0; i < 256; i++ {
				for _, p := range Ports {
					out = append(out, netip.AddrPortFrom(base, p))
				}
				base = base.Next()
			}
		}
		return out
	default: // balanced: seeds plus a deterministic edge sample per /24
		out := SeedEndpoints(KindMasqueH2)
		for _, cidr := range h2GatewayCIDRs {
			if !cidr.Addr().Is4() {
				continue
			}
			base := cidr.Masked().Addr()
			first := base.Next() // x.x.x.1
			out = append(out, netip.AddrPortFrom(first, 443))
			last := base
			for i := 0; i < 254; i++ {
				last = last.Next() // x.x.x.254
			}
			out = append(out, netip.AddrPortFrom(last, 443))
		}
		return out
	}
}
