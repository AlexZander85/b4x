// Versioned WG/AWG endpoint catalog (design §6). It is deliberately
// SEPARATE from both the MASQUE endpoint catalog (transportwarp — its
// invariant test pins these very ranges OUT of the MASQUE map) and the
// obfuscation-profile catalog (profiles.go).
//
// Every range and port below is a MEASURED value; provenance is recorded at
// the declaration site, not folklore:
//
//   - ZeroTrust v4/v6 prefixes: Aether wireguard.rs:699-701
//     (WG_ZT_PREFIXES_V4 = 162.159.193.0/24, WG_ZT_PREFIXES_V6 =
//     2606:4700:100::/48);
//   - core ports {2408,500,1701,4500}: warpscout warp.go:81 primaryWarpPorts,
//     head of the Aether WG_PORTS list;
//   - extended port set (50 ports): Aether wireguard.rs:703-708 ==
//     warpscout warp.go:82-88 — two independent local copies of the
//     CloudflareWarpSpeedTest lineage agree byte-for-byte ("measured
//     community list", NOT synthetic sampling);
//   - regional family 188.114.96-99: Aether wireguard.rs:686-689;
//   - 8.x host routes: Nova battle profiles (wireguard/Nova/awg, Endpoint=
//     lines) — declared as /32s because only individual hosts are measured,
//     never inferred ranges; all 38 distinct Nova ports are a subset of
//     core ∪ extended (verified against the profiles directly);
//   - anycast alternates 162.159.192/195: Aether wireguard.rs:684-685 —
//     same official WARP anycast space, geo-uncontrollable, so they ride
//     the verify-then-flip pool lifecycle below (in the GATE since WG5,
//     never in default sourcing — §7.5 policy: unverified entries stay out
//     of the tree until field evidence);
//   - builtin seed pool: warp-socks src/endpoint/source.rs:12-21 verbatim
//     (its own comment: cover primary AND fallback ports so candidates do
//     not all traverse the same :2408 network path).
//
// Red line (design §11.5 through MASQUE addendum §34): candidate sourcing
// may emit ONLY addresses inside these ranges on known ports.
// InWGCatalog/KnownWGPort are the gate; the Seeker enforces it by default
// (AllowOutOfCatalog is a tests-only escape for loopback fake edges,
// mirroring the transportwarp AllowUnconstrainedInner discipline).
package transportwg

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// EndpointCatalogVersion increments on any change to ranges/ports below.
// Trace exports and seek reports carry it for field correlation; it is
// independent of the profile-catalog CatalogVersion.
const EndpointCatalogVersion = 1

// EdgeHostname is the official WARP bootstrap hostname; its A/AAAA records
// resolve into catalog ranges only (enforced by ResolveEdgeEndpoints).
const EdgeHostname = "engage.cloudflareclient.com"

// CorePorts is the verified primary port set (warp-socks primaryWarpPorts).
var CorePorts = []uint16{2408, 500, 1701, 4500}

// ExtendedPorts is the measured alternate-port set (CloudflareWarpSpeedTest
// lineage via Aether == warpscout; order preserved from the sources).
var ExtendedPorts = []uint16{
	854, 859, 864, 878, 880, 890, 891, 894, 903, 908,
	928, 934, 939, 942, 943, 945, 946, 955, 968, 987,
	988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843,
	2371, 2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279,
	5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886,
}

// AllPorts returns core ++ extended as a fresh slice.
func AllPorts() []uint16 {
	out := make([]uint16, 0, len(CorePorts)+len(ExtendedPorts))
	out = append(out, CorePorts...)
	out = append(out, ExtendedPorts...)
	return out
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }

// Catalog ranges (all measured, see package doc for provenance).
var (
	ztZeroTrustV4   = []netip.Prefix{mustPrefix("162.159.193.0/24")}
	ztZeroTrustV6   = []netip.Prefix{mustPrefix("2606:4700:100::/48")}
	regional188V4   = []netip.Prefix{mustPrefix("188.114.96.0/24"), mustPrefix("188.114.97.0/24"), mustPrefix("188.114.98.0/24"), mustPrefix("188.114.99.0/24")}
	regionalV6      = []netip.Prefix{mustPrefix("2606:4700:d0::/64"), mustPrefix("2606:4700:d1::/64")}
	regionalNovaV4  = novaHostRoutes()
	anycast192V4    = []netip.Prefix{mustPrefix("162.159.192.0/24")}
	anycast195V4    = []netip.Prefix{mustPrefix("162.159.195.0/24")}
	builtinSeedPool = []netip.AddrPort{
		netip.MustParseAddrPort("162.159.193.5:2408"),
		netip.MustParseAddrPort("162.159.193.9:500"),
		netip.MustParseAddrPort("162.159.193.8:1701"),
		netip.MustParseAddrPort("162.159.193.3:4500"),
		netip.MustParseAddrPort("162.159.193.7:2408"),
		netip.MustParseAddrPort("162.159.193.47:500"),
		netip.MustParseAddrPort("162.159.193.10:1701"),
		netip.MustParseAddrPort("162.159.193.11:4500"),
	}
)

// novaHostRoutes renders the Nova battle-measured hosts as /32s. Only
// individually observed hosts are listed; no range is inferred.
func novaHostRoutes() []netip.Prefix {
	hosts := []string{
		"8.34.70.4", "8.34.146.3", "8.34.146.7",
		"8.35.211.1", "8.35.211.5",
		"8.39.125.2", "8.39.125.3", "8.39.125.4", "8.39.125.9", "8.39.125.10",
		"8.39.204.9",
		"8.39.214.1", "8.39.214.4", "8.39.214.7", "8.39.214.8", "8.39.214.9", "8.39.214.10",
		"8.47.69.5", "8.47.69.8",
		"8.6.112.2", "8.6.112.6", "8.6.112.8",
	}
	out := make([]netip.Prefix, 0, len(hosts))
	for _, h := range hosts {
		out = append(out, netip.PrefixFrom(netip.MustParseAddr(h), 32))
	}
	return out
}

// RegionPool is one alternate WG pool beyond the ZeroTrust default (design
// §6 R2 role): plan-Б regional families AND the anycast alternates, which
// share the same verify-then-flip lifecycle. Pools ship UNVERIFIED: the
// region tag is filled by the FIELD2 Phase E field session using the
// warpscout SEEN AS methodology THROUGH a tunnel (loc= evidence), never by
// guessing. Unverified pools are excluded from default candidate sourcing;
// using them requires an explicit opt-in via PoolCandidates.
type RegionPool struct {
	Tag        string         // routing label until FIELD2 assigns final ones
	Prefixes   []netip.Prefix // v4 /24s or /32 host routes
	Verified   bool           // false until loc= verification through a tunnel
	Source     string         // PRE-field provenance of the entry itself (who measured these ranges/hosts)
	VerifyMeta string         // field evidence ONLY: "<date> <method> <result>", e.g. "2026-09-01 warpscout-seen-as loc=hh1"
}

// RegionalPools is the alternate-pool registry. Entries stay Verified=false
// until real field evidence exists; nothing here may enter the default
// ladder before that.
//
// Enabling an entry after verification must be a DATA flip (Verified=true +
// VerifyMeta filled at the declaration site), never a logic change. Point
// extensions are coordinated against the field2-report endpoint list.
var RegionalPools = []RegionPool{
	{
		Tag:      "unassigned",
		Source:   "aether-prefixes", // wireguard.rs:686-689
		Prefixes: append([]netip.Prefix{}, regional188V4...),
	},
	{
		Tag:      "unassigned",
		Source:   "nova-measured", // battle profiles; /32s because only individual hosts are measured
		Prefixes: append([]netip.Prefix{}, regionalNovaV4...),
	},
	{
		// Anycast alternates (owner decision 24.08): in the gate since WG5,
		// never in default generation. Precedent base: Nova profiles ran
		// MEASURED 7 (.192) + 12 (.195) live (addr,port) pairs through the
		// full cycle — flip to verified only from field2-report loc= data.
		Tag:      "cf-anycast-192",
		Source:   "nova-measured",
		Prefixes: append([]netip.Prefix{}, anycast192V4...),
	},
	{
		Tag:      "cf-anycast-195",
		Source:   "nova-measured",
		Prefixes: append([]netip.Prefix{}, anycast195V4...),
	},
}

// InWGCatalog reports whether ip belongs to any measured WG range. This is
// the §34-analog gate: configured/resolved/last-good endpoints outside the
// catalog are rejected by default.
func InWGCatalog(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range ztZeroTrustV4 {
		if p.Contains(ip) {
			return true
		}
	}
	for _, p := range ztZeroTrustV6 {
		if p.Contains(ip) {
			return true
		}
	}
	for _, pool := range RegionalPools {
		for _, p := range pool.Prefixes {
			if p.Contains(ip) {
				return true
			}
		}
	}
	for _, p := range regionalV6 {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// KnownWGPort reports whether port belongs to the measured port sets
// (core ∪ extended).
func KnownWGPort(port uint16) bool {
	for _, p := range CorePorts {
		if p == port {
			return true
		}
	}
	for _, p := range ExtendedPorts {
		if p == port {
			return true
		}
	}
	return false
}

// endpointInCatalog is the full AddrPort-level gate.
func endpointInCatalog(ap netip.AddrPort) bool {
	return ap.IsValid() && InWGCatalog(ap.Addr()) && KnownWGPort(ap.Port())
}

// FilterInCatalog keeps only in-catalog endpoints (order preserved).
func FilterInCatalog(list []netip.AddrPort) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(list))
	for _, ap := range list {
		if endpointInCatalog(ap) {
			out = append(out, ap)
		}
	}
	return out
}

// ScanStrategy selects the bounded candidate shape (semantics mirror the
// MASQUE discovery tiers, scaled to per-attempt session costs).
type ScanStrategy string

const (
	// StrategyTurbo: minimal bootstrap start — the builtin seed pool only.
	StrategyTurbo ScanStrategy = "turbo"
	// StrategyBalanced: full builtin seed pool expanded over the core port
	// set (warp-socks diversification posture).
	StrategyBalanced ScanStrategy = "balanced"
	// StrategyThorough: builtin pool × every measured port plus a fixed
	// interior sample of the ZeroTrust /24 on core ports. Bounded ≤512.
	StrategyThorough ScanStrategy = "thorough"
)

// Candidate budget caps asserted by tests (scan-budget discipline).
const (
	CapCandidatesTurbo    = 16
	CapCandidatesBalanced = 64
	CapCandidatesThorough = 512
)

// CatalogCandidates builds the bounded, deterministic candidate list for a
// strategy from THIS catalog only. Default output is IPv4 ZeroTrust —
// design §6 scopes the default ladder to the official ZT range; regional
// pools ride the explicit PoolCandidates path until verified.
func CatalogCandidates(s ScanStrategy) []netip.AddrPort {
	switch s {
	case StrategyTurbo:
		return append([]netip.AddrPort{}, builtinSeedPool...)
	case StrategyBalanced:
		var out []netip.AddrPort
		for _, ap := range builtinSeedPool {
			for _, p := range CorePorts {
				out = append(out, netip.AddrPortFrom(ap.Addr(), p))
			}
		}
		return out
	default: // thorough
		seen := map[netip.AddrPort]bool{}
		out := make([]netip.AddrPort, 0, CapCandidatesThorough)
		push := func(ap netip.AddrPort) {
			if !seen[ap] {
				seen[ap] = true
				out = append(out, ap)
			}
		}
		for _, ap := range builtinSeedPool {
			for _, p := range AllPorts() {
				push(netip.AddrPortFrom(ap.Addr(), p))
			}
		}
		// Fixed interior sample of the official ZT /24 (x.{1,33,...,225}):
		// the RANGE is the published fact, the grid is deterministic.
		for i := 1; i < 256; i += 32 {
			addr := netip.AddrFrom4([4]byte{162, 159, 193, byte(i)})
			for _, p := range CorePorts {
				push(netip.AddrPortFrom(addr, p))
			}
		}
		return out
	}
}

// SeedEndpoints returns the builtin seed pool verbatim (warp-socks
// source.rs:12-21): eight ZeroTrust addresses covering primary and fallback
// ports so candidates do not share a single :2408 path.
func SeedEndpoints() []netip.AddrPort {
	return append([]netip.AddrPort{}, builtinSeedPool...)
}

// SeedEndpointsV6 returns the measured v6 seeds (Aether wireguard.rs:718)
// on the head port. The default ladder stays IPv4-first (same posture as
// the MASQUE engine); this feeds Happy-Eyeballs wiring once v6 dial paths
// are exercised in the field.
func SeedEndpointsV6() []netip.AddrPort {
	seeds := []string{
		"2606:4700:d0::a29f:c001",
		"2606:4700:d1::a29f:c001",
		"2606:4700:d0::a29f:c301",
		"2606:4700:d0::bc72:6001",
	}
	out := make([]netip.AddrPort, 0, len(seeds))
	for _, s := range seeds {
		out = append(out, netip.AddrPortFrom(netip.MustParseAddr(s), CorePorts[0]))
	}
	return out
}

// PoolCandidates expands one pool into candidates on core ports. Explicit
// opt-in: unverified pools are returned with their tag so callers can label
// traces, but they NEVER mix into the default ladder. A v4 range shorter
// than /32 expands from its FIRST HOST (x.x.x.1), never the network
// address; /32 entries stay exact.
func PoolCandidates(tag string) ([]netip.AddrPort, error) {
	for _, pool := range RegionalPools {
		if pool.Tag != tag {
			continue
		}
		var out []netip.AddrPort
		for _, pfx := range pool.Prefixes {
			addr := pfx.Addr()
			if addr.Is4() && pfx.Bits() < 32 {
				if a4 := addr.As4(); a4[3] == 0 {
					addr = addr.Next()
				}
			}
			if addr.Is4() {
				for _, p := range CorePorts {
					out = append(out, netip.AddrPortFrom(addr, p))
				}
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("transportwg: unknown regional pool %q", tag)
}

// InterleaveV4V6 weaves two address families preserving relative order
// within each family, v4 first (warp-socks Happy-Eyeballs pattern). Pure
// helper; the result length equals the input length.
func InterleaveV4V6(cands []netip.AddrPort) []netip.AddrPort {
	var v4, v6 []netip.AddrPort
	for _, ap := range cands {
		if ap.Addr().Is4() {
			v4 = append(v4, ap)
		} else {
			v6 = append(v6, ap)
		}
	}
	out := make([]netip.AddrPort, 0, len(cands))
	for i := 0; i < len(v4) || i < len(v6); i++ {
		if i < len(v4) {
			out = append(out, v4[i])
		}
		if i < len(v6) {
			out = append(out, v6[i])
		}
	}
	return out
}

// HostResolver is the hostname seam (production: *net.Resolver; tests:
// fakes). Results are ALWAYS filtered through InWGCatalog so a hostile or
// stale DNS answer cannot smuggle an arbitrary endpoint past the §34 gate.
type HostResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// ResolveEdgeEndpoints resolves EdgeHostname and expands it over ports,
// keeping only in-catalog products. Fail-closed: an answer with zero
// catalog members is an error, not an empty list.
func ResolveEdgeEndpoints(ctx context.Context, r HostResolver, ports []uint16) ([]netip.AddrPort, error) {
	addrs, err := r.LookupNetIP(ctx, "ip", EdgeHostname)
	if err != nil {
		return nil, fmt.Errorf("transportwg: resolve %s: %w", EdgeHostname, err)
	}
	var out []netip.AddrPort
	seen := map[netip.AddrPort]bool{}
	for _, a := range addrs {
		a = a.Unmap()
		if !InWGCatalog(a) {
			continue
		}
		for _, p := range ports {
			if !KnownWGPort(p) {
				continue
			}
			ap := netip.AddrPortFrom(a, p)
			if !seen[ap] {
				seen[ap] = true
				out = append(out, ap)
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("transportwg: %s resolved to no in-catalog endpoint", EdgeHostname)
	}
	return out, nil
}

// DefaultHostResolver adapts the stdlib resolver to the seam.
func DefaultHostResolver() HostResolver { return net.DefaultResolver }
