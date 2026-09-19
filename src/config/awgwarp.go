// AWG-WARP and nested-chain config schemas (tunnels panel stage 2,
// TUNNELS_PANEL_DESIGN.md §6): the system.warp section grows two shapes —
// the AWG branch (one AmneziaWG session over the CF WARP WG edge) and the
// chains list (nested compositions from transport/nested). Both default to
// DISABLED; the effective endpoints/profiles resolve against the same
// versioned catalogs the engines enforce (no arbitrary internet scanning,
// addendum §34).
package config

import (
	"fmt"
	"net/netip"
	"strings"

	twarp "github.com/daniellavrushin/b4/transport/warp"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// DefaultWarpAWGIdentityPath is the AWG-WARP identity slot. A SEPARATE file
// from the MASQUE identity on purpose: one CF device per transport (red
// line §3 of the nested design — sharing a device between planes is
// forbidden), so AWG-WARP owns its own registration.
const DefaultWarpAWGIdentityPath = "/opt/etc/b4/warp/awg-identity.json"

// Chain kinds (closed set): the four nested compositions the engines ship.
// masque+awg / awg+masque / masque+masque ride transport/nested; awg+awg (W+W)
// rides transport/wg.NestedWgRuntime (design §7 R3 gool pattern). "nonru" is
// a geo-gated policy, not a pair — not accepted by this schema.
const (
	ChainKindMasqueAwg    = "masque+awg"    // MASQUE-H2 outer, AWG inner (M+W)
	ChainKindAwgMasque    = "awg+masque"    // AWG outer, MASQUE-H2 inner (W+M)
	ChainKindAwgAwg       = "awg+awg"       // AWG outer, AWG inner (W+W)
	ChainKindMasqueMasque = "masque+masque" // MASQUE-H2 outer, MASQUE-H2 inner (M+M)
)

// WarpChainKinds is the closed chain-kind set (validation + UI catalogs).
var WarpChainKinds = []string{ChainKindMasqueAwg, ChainKindAwgMasque, ChainKindAwgAwg, ChainKindMasqueMasque}

// IsWarpChainKind reports kind membership in the chain set.
func IsWarpChainKind(kind string) bool {
	return kind == ChainKindMasqueAwg || kind == ChainKindAwgMasque ||
		kind == ChainKindAwgAwg || kind == ChainKindMasqueMasque
}

// Data-plane modes of the AWG-WARP transport.
const (
	// WarpAWGModeNetstack is the userspace gVisor data plane: the session's
	// netstack serves the reserve carrier (TCP streams + UDP full-scope) —
	// the per-domain tproxy routing path.
	WarpAWGModeNetstack = "netstack"
	// WarpAWGModeKernel is the kernel /dev/net/tun data plane with scoped
	// PBR (the field layer, design §7 "kernel-TUN PBR — основной путь
	// роутера"): the FROM-CIDR selectors route selected LAN sources through
	// the TUN; there is NO userspace carrier in this mode (honest refusal).
	WarpAWGModeKernel = "kernel"
)

// Kernel-TUN PBR defaults (the wg-quick canon where it applies).
const (
	// DefaultWarpAWGKernelInterface is the kernel device name hint. A fixed
	// name keeps the PBR plane stable across reboots; the kernel may still
	// diverge and the session passes the ACTUAL name to the KernelUp hook.
	DefaultWarpAWGKernelInterface = "awgwarp0"
	// DefaultWarpAWGPBRTable is the dedicated routing table. It is
	// deliberately small: the field routers run BusyBox `ip`, whose table
	// identifiers are 8-bit (a numeric table >255 is rejected with
	// "invalid argument ... to 'table'"). wg-quick's 51820 cannot be
	// expressed there, so the kernel-TUN default uses 200 (unused on the
	// field router; collides with no Keenetic table).
	DefaultWarpAWGPBRTable = 200
	// DefaultWarpAWGRulePriority sits below the main table (32766) so the
	// policy selectors are consulted first without shadowing the kernel's
	// own default rules.
	DefaultWarpAWGRulePriority = 30000
	// DefaultWarpAWGFwMark marks the session's own UDP socket so the policy
	// rule never loops the tunnel's egress back into the TUN.
	DefaultWarpAWGFwMark = 51820
)

// WarpAWGConfig enables the AWG-WARP transport (kind "warp"): one
// AmneziaWG session over the CF WARP WG edge. Mode selects the data plane:
// netstack (default) serves the userspace reserve carrier; kernel arms the
// scoped-PBR field layer through /dev/net/tun (linux + CAP_NET_ADMIN
// required — the session's kernel hooks own the wiring, no half-states).
type WarpAWGConfig struct {
	Enabled bool `json:"enabled"`
	// Mode selects the data plane: "" | "netstack" (userspace carrier) or
	// "kernel" (kernel-TUN + PBR). Empty -> netstack.
	Mode string `json:"mode"`
	// IdentityPath is the wg IdentityStore slot. Empty -> EffectiveIdentityPath.
	IdentityPath string `json:"identity_path"`
	// Endpoint overrides the catalog default ("ip:port"). Empty -> the first
	// builtin WG seed. Explicit values must pass the InWGCatalog + KnownWGPort
	// gates (addendum §34).
	Endpoint string `json:"endpoint"`
	// Profile selects the AWG obfuscation profile id from the versioned
	// catalog (vanilla-safe cf-warp family only). Empty -> the ladder head.
	Profile string `json:"profile"`
	// MTU is the session MTU. 0 -> transportwg.DefaultMTU (1280).
	MTU int `json:"mtu"`
	// MaxRestartsPerHour caps the service-level session rebuilds. 0 -> 6
	// (proton canon).
	MaxRestartsPerHour int `json:"max_restarts_per_hour"`
	// Kernel carries the scoped-PBR field for mode=kernel (ignored in
	// netstack mode; validated in both so a typo cannot hide until the
	// switch day).
	Kernel WarpAWGKernelConfig `json:"kernel"`
}

// WarpAWGKernelConfig is the kernel-TUN PBR field layer (design §7). The
// wiring plan: assign the WG /32 on the device, default route in a DEDICATED
// table, and one policy rule per source selector — "not fwmark <mark>
// from <cidr> lookup <table>" — so the session's own marked UDP egress
// never loops back into the tunnel.
type WarpAWGKernelConfig struct {
	// Interface is the kernel device name hint (<= 15 chars). Empty ->
	// DefaultWarpAWGKernelInterface. The ACTUAL name reaches the PBR hooks
	// from the session (the kernel may diverge from the hint).
	Interface string `json:"interface"`
	// Table is the dedicated routing table number. 0 -> 51820.
	Table int `json:"table"`
	// RulePriority is the policy-rule priority (1..32765, below the main
	// table's 32766). 0 -> 30000.
	RulePriority int `json:"rule_priority"`
	// FwMark marks the session's own UDP socket (the anti-loop guard). 0 ->
	// 51820.
	FwMark uint32 `json:"fwmark"`
	// FromCIDRs are the IPv4 source selectors routed through the tunnel
	// (LAN subnets of the field deployment). REQUIRED in kernel mode — a
	// kernel TUN without selectors is a half-state and never ships.
	FromCIDRs []string `json:"from_cidrs"`
	// BypassCIDRs are DESTINATION prefixes that must keep consulting the
	// main table before the tunnel selector (local/LAN reachability: a
	// selector for a device would otherwise also swallow its traffic to the
	// router itself into the TUN — including the SSH control channel). One
	// higher-priority "to <prefix> lookup main" rule per entry.
	BypassCIDRs []string `json:"bypass_cidrs"`
	// SNAT masquerades the selector traffic leaving the tunnel device. A
	// router MUST rewrite LAN sources to the tunnel address: the CF WARP WG
	// edge accepts only the peer's assigned /32 as inner source (the same
	// role as amnezia-wg-proxy's "iptables -t nat -A POSTROUTING -o
	// amnezia -j MASQUERADE"). nil -> true (the router-correct default);
	// set false only for diagnostics.
	SNAT *bool `json:"snat"`
}

// EffectiveMode normalizes the data-plane mode ("" -> netstack).
func (c *WarpAWGConfig) EffectiveMode() string {
	if m := strings.ToLower(strings.TrimSpace(c.Mode)); m != "" {
		return m
	}
	return WarpAWGModeNetstack
}

// KernelMode reports whether the kernel-TUN PBR data plane is armed.
func (c *WarpAWGConfig) KernelMode() bool {
	return c.EffectiveMode() == WarpAWGModeKernel
}

// EffectiveInterface fills the kernel device name default.
func (k *WarpAWGKernelConfig) EffectiveInterface() string {
	if k.Interface == "" {
		return DefaultWarpAWGKernelInterface
	}
	return k.Interface
}

// EffectiveTable fills the routing-table default (200 — the BusyBox-safe
// dedicated table; see DefaultWarpAWGPBRTable).
func (k *WarpAWGKernelConfig) EffectiveTable() int {
	if k.Table <= 0 {
		return DefaultWarpAWGPBRTable
	}
	return k.Table
}

// EffectiveSNAT reports whether selector traffic leaving the tunnel is
// masqueraded. Unset -> true: the router-correct behavior (the WARP edge
// binds the inner source to the assigned /32).
func (k *WarpAWGKernelConfig) EffectiveSNAT() bool {
	if k.SNAT == nil {
		return true
	}
	return *k.SNAT
}

// EffectiveRulePriority fills the policy-rule priority default (30000 —
// below the main table's 32766).
func (k *WarpAWGKernelConfig) EffectiveRulePriority() int {
	if k.RulePriority <= 0 {
		return DefaultWarpAWGRulePriority
	}
	return k.RulePriority
}

// EffectiveFwMark fills the anti-loop mark default (51820).
func (k *WarpAWGKernelConfig) EffectiveFwMark() uint32 {
	if k.FwMark == 0 {
		return DefaultWarpAWGFwMark
	}
	return k.FwMark
}

// EffectiveIdentityPath fills the default slot path.
func (c *WarpAWGConfig) EffectiveIdentityPath() string {
	if c.IdentityPath == "" {
		return DefaultWarpAWGIdentityPath
	}
	return c.IdentityPath
}

// EffectiveEndpoint resolves the WG endpoint: "" -> the first builtin seed
// (162.159.193.5:2408), explicit -> catalog-gated.
func (c *WarpAWGConfig) EffectiveEndpoint() (netip.AddrPort, error) {
	if c.Endpoint == "" {
		// bd b4x-wh6: prefer the FIELD-VERIFIED endpoints — the historical
		// ZeroTrust seeds answer 0 IN from the field network while these
		// complete the WG handshake with the stock engine.
		if fv := twg.FieldVerifiedEndpoints(); len(fv) > 0 {
			return fv[0], nil
		}
		seeds := twg.SeedEndpoints()
		if len(seeds) == 0 {
			return netip.AddrPort{}, fmt.Errorf("system.warp.awg.endpoint: builtin seed pool empty")
		}
		return seeds[0], nil
	}
	ap, err := netip.ParseAddrPort(c.Endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("system.warp.awg.endpoint %q: %v", c.Endpoint, err)
	}
	if !twg.InWGCatalog(ap.Addr()) {
		return ap, fmt.Errorf("system.warp.awg.endpoint %q: address outside the versioned WG catalog (addendum §34)", c.Endpoint)
	}
	if !twg.KnownWGPort(ap.Port()) {
		return ap, fmt.Errorf("system.warp.awg.endpoint %q: port outside the catalog port set", c.Endpoint)
	}
	return ap, nil
}

// EffectiveProfile resolves the AWG profile: "" -> the ladder head for the
// cf-warp target; explicit -> the catalog entry, which must be cf-warp
// target (vanilla-safe family — S/H obfuscation never ships against the CF
// edge).
func (c *WarpAWGConfig) EffectiveProfile() (twg.Profile, error) {
	return resolveCfWarpProfile("system.warp.awg.profile", c.Profile)
}

// EffectiveMTU fills the session MTU default.
func (c *WarpAWGConfig) EffectiveMTU() int {
	if c.MTU <= 0 {
		return twg.DefaultMTU
	}
	return c.MTU
}

// EffectiveMaxRestarts fills the restart cap default (proton canon: 6).
func (c *WarpAWGConfig) EffectiveMaxRestarts() int {
	if c.MaxRestartsPerHour <= 0 {
		return 6
	}
	return c.MaxRestartsPerHour
}

// DefaultMasqueInnerEndpoint is the M+M inner default: the OTHER measured
// anycast gateway (162.159.198.1 — TCP MASQUE answers across the whole
// catalog /24), distinct from the outer default 162.159.198.2 (gool hard
// rule at defaults).
func defaultMasqueInnerEndpoint(avoid netip.Addr) netip.AddrPort {
	def := twarp.DefaultH2Endpoint()
	if avoid.IsValid() && def.Addr() == avoid {
		return netip.MustParseAddrPort("162.159.198.1:443")
	}
	return def
}

// resolveCfWarpProfile resolves a cf-warp vanilla-safe profile id.
func resolveCfWarpProfile(field, id string) (twg.Profile, error) {
	if id == "" {
		ladder, err := twg.LadderFor(twg.TargetCfWarp, "")
		if err != nil {
			return twg.Profile{}, fmt.Errorf("%s: ladder: %w", field, err)
		}
		if len(ladder) == 0 {
			return twg.Profile{}, fmt.Errorf("%s: cf-warp ladder empty", field)
		}
		return ladder[0].Build()
	}
	tpl, err := twg.LookupProfile(id)
	if err != nil {
		return twg.Profile{}, fmt.Errorf("%s: %w", field, err)
	}
	if tpl.Target != twg.TargetCfWarp {
		return twg.Profile{}, fmt.Errorf("%s %q: profile target %q is not cf-warp (vanilla-safe family only)", field, id, tpl.Target)
	}
	return tpl.Build()
}

// EffectiveAWGProfile resolves the AWG layer profile of a chain and its
// resolved id. An explicit id resolves by catalog; "" uses the ladder
// default — the first JUNK-ACTIVE cf-warp profile for awg+awg (the W+W outer
// layer requires junk, ErrOuterObfRequired), otherwise the ladder head.
// FIELD 2026-09-18: the plain cf-warp ladder leads with vanilla-off (junk
// breaks the WARP data path here), so the nested case needs its own default.
func (c *WarpChainConfig) EffectiveAWGProfile() (twg.Profile, string, error) {
	field := "system.warp.chains[" + c.Kind + "].awg_profile"
	if c.AWGProfile != "" {
		p, err := resolveCfWarpProfile(field, c.AWGProfile)
		return p, c.AWGProfile, err
	}
	if c.Kind == ChainKindAwgAwg {
		// b4x-mrl: the field-proven cover (cf-field-i1 blob) plus a minimal
		// Jc=4 junk family carries data where the plain junk profiles do not
		// (see the FIELD note above: junk breaks the WARP data path here).
		// Prefer it; fall back to any junk-active profile.
		if p, err := resolveCfWarpProfile(field, "cf-field-i1-j4"); err == nil && p.JunkCount > 0 {
			return p, "cf-field-i1-j4", nil
		}
		p, id, err := twg.DefaultJunkActiveCfWarp()
		return p, id, err
	}
	p, err := resolveCfWarpProfile(field, "")
	return p, "", err
}

// DefaultWarpNonRUIdentityPath is the nested НЕ РФ inner warp slot. A
// SEPARATE file from the base warp identity on purpose (ADR-WARP-6 + nested
// red line #3: the nested session is a SECOND CF device — the base warp
// slot serves the outer layer only).
const DefaultWarpNonRUIdentityPath = "/opt/etc/b4/warp/nonru-identity.json"

// WarpNonRUConfig arms the experimental НЕ РФ (non-RU) mode (addendum §3.2,
// ADR-WARP-6): a SECOND isolated WARP session whose control TCP is forced
// through the verified BASE warp (system.warp), promoted as a routable
// carrier ONLY while a fresh multi-provider non-RU geo attestation holds
// (transport/warp NonRUGate). The base warp stays the prerequisite — this
// section is rejected by validation when system.warp.enabled is false.
type WarpNonRUConfig struct {
	Enabled bool `json:"enabled"`
	// IdentityPath is the INNER warp identity slot (a second CF device).
	// Empty -> EffectiveIdentityPath.
	IdentityPath string `json:"identity_path"`
	// Endpoint overrides the INNER layer's catalog default ("ip:port").
	// Empty -> the MASQUE-H2 default avoiding the BASE warp's edge IP (the
	// gool different-edge rule at defaults); explicit values must pass the
	// catalog gates and differ from the base endpoint IP.
	Endpoint string `json:"endpoint"`
	// Fingerprint is the INNER layer's uTLS ClientHello ("", "chrome120",
	// "firefox" — the system.warp.masquerade canon).
	Fingerprint string `json:"fingerprint"`
	// InnerMTU caps the inner layer MTU. 0 -> the nested engine's
	// MaxInnerMTU (1200).
	InnerMTU int `json:"inner_mtu"`
	// AttestationTTLSeconds bounds how long a geo attestation may serve the
	// open route. 0 -> 120 (addendum §45 ttl).
	AttestationTTLSeconds int `json:"attestation_ttl_seconds"`
	// RefreshIntervalSeconds is the probe round period. 0 -> 60 (addendum
	// §45 refresh_interval). Must stay <= TTL/2 so a route never rides a
	// stale attestation by scheduling alone.
	RefreshIntervalSeconds int `json:"refresh_interval_seconds"`
	// RUCountries lists ISO-3166 alpha-2 codes classified RU (default RU).
	RUCountries []string `json:"ru_countries"`
	// FallbackToBase enables the §47 advanced-policy event emission on
	// fail-closed revocations (fail_closed + fallback_to_base events; the
	// actual base-fallback routing is the operator's explicit choice, never
	// automatic).
	FallbackToBase bool `json:"fallback_to_base"`
}

// EffectiveIdentityPath fills the inner slot default.
func (c *WarpNonRUConfig) EffectiveIdentityPath() string {
	if c.IdentityPath == "" {
		return DefaultWarpNonRUIdentityPath
	}
	return c.IdentityPath
}

// EffectiveEndpoint resolves the INNER layer endpoint against the MASQUE-H2
// catalog. The default avoids the base warp's edge IP (gool rule at
// defaults); explicit endpoints are collision-checked against the base by
// validation.
func (c *WarpNonRUConfig) EffectiveEndpoint(avoid netip.Addr) (netip.AddrPort, error) {
	if c.Endpoint == "" {
		if avoid.IsValid() {
			return defaultMasqueInnerEndpoint(avoid), nil
		}
		return twarp.DefaultH2Endpoint(), nil
	}
	ap, err := netip.ParseAddrPort(c.Endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("system.warp.nonru.endpoint %q: %v", c.Endpoint, err)
	}
	if !twarp.InCatalog(twarp.KindMasqueH2, ap.Addr()) {
		return ap, fmt.Errorf("system.warp.nonru.endpoint %q: address outside the versioned MASQUE-H2 catalog (addendum §34)", c.Endpoint)
	}
	if !twarp.KnownPort(ap.Port()) {
		return ap, fmt.Errorf("system.warp.nonru.endpoint %q: port outside the catalog port set", c.Endpoint)
	}
	return ap, nil
}

// EffectiveAttestationTTL fills the attestation TTL default (120s).
func (c *WarpNonRUConfig) EffectiveAttestationTTL() int {
	if c.AttestationTTLSeconds <= 0 {
		return 120
	}
	return c.AttestationTTLSeconds
}

// EffectiveRefreshInterval fills the refresh default (60s).
func (c *WarpNonRUConfig) EffectiveRefreshInterval() int {
	if c.RefreshIntervalSeconds <= 0 {
		return 60
	}
	return c.RefreshIntervalSeconds
}

// EffectiveRUCountries fills the RU-country set (default {"RU"}).
func (c *WarpNonRUConfig) EffectiveRUCountries() map[string]bool {
	out := make(map[string]bool, len(c.RUCountries))
	for _, cc := range c.RUCountries {
		if cc = strings.ToUpper(strings.TrimSpace(cc)); cc != "" {
			out[cc] = true
		}
	}
	if len(out) == 0 {
		out["RU"] = true
	}
	return out
}

// WarpChainConfig declares one nested chain. Each layer owns a DISTINCT
// identity slot (one CF device per layer, nested red line #3): the outer
// identity of masque+awg never serves the inner AWG layer and vice versa;
// awg+awg owns TWO wg devices (one per layer). Defaults park the slot paths
// next to the MASQUE identity under
// /opt/etc/b4/warp/chain-<kind>-{outer,inner}.json.
type WarpChainConfig struct {
	// Kind selects the composition: "masque+awg" (M+W), "awg+masque" (W+M)
	// or "awg+awg" (W+W — the transport/wg nested runtime).
	Kind string `json:"kind"`
	// Enabled arms the daemon assembly for this chain.
	Enabled bool `json:"enabled"`
	// OuterIdentityPath / InnerIdentityPath are the per-layer identity slots.
	// Empty -> Effective{Outer,Inner}IdentityPath defaults.
	OuterIdentityPath string `json:"outer_identity_path"`
	InnerIdentityPath string `json:"inner_identity_path"`
	// OuterEndpoint / InnerEndpoint override the per-layer catalog defaults:
	// an awg layer resolves against the WG catalog, a masque layer against
	// the MASQUE-H2 catalog. Empty -> the layer default. The two layers must
	// terminate on DIFFERENT edge IPs (gool hard rule — validated here so a
	// self-nesting config cannot pass silently).
	OuterEndpoint string `json:"outer_endpoint"`
	InnerEndpoint string `json:"inner_endpoint"`
	// AWGProfile selects the AWG layer's obfuscation profile (vanilla-safe
	// cf-warp family). Empty -> the ladder head.
	AWGProfile string `json:"awg_profile"`
	// Fingerprint configures the masque layer's uTLS ClientHello ("",
	// "chrome120", "firefox" — the system.warp.masquerade canon).
	Fingerprint string `json:"fingerprint"`
	// InnerMTU caps the inner layer MTU. 0 -> the nested engine's
	// MaxInnerMTU (1200); values above it are rejected (encapsulation
	// headroom invariant).
	InnerMTU int `json:"inner_mtu"`
	// MaxRestartsPerHour caps the service-level chain rebuilds. 0 -> 6.
	MaxRestartsPerHour int `json:"max_restarts_per_hour"`
}

// EffectiveOuterIdentityPath fills the outer slot default.
func (c *WarpChainConfig) EffectiveOuterIdentityPath() string {
	if c.OuterIdentityPath == "" {
		return "/opt/etc/b4/warp/chain-" + c.Kind + "-outer.json"
	}
	return c.OuterIdentityPath
}

// EffectiveInnerIdentityPath fills the inner slot default.
func (c *WarpChainConfig) EffectiveInnerIdentityPath() string {
	if c.InnerIdentityPath == "" {
		return "/opt/etc/b4/warp/chain-" + c.Kind + "-inner.json"
	}
	return c.InnerIdentityPath
}

// EffectiveMaxRestarts fills the rebuild cap default (proton canon: 6).
func (c *WarpChainConfig) EffectiveMaxRestarts() int {
	if c.MaxRestartsPerHour <= 0 {
		return 6
	}
	return c.MaxRestartsPerHour
}

// ResolveEndpoints resolves both layer endpoints against their catalogs
// (awg layer -> WG catalog, masque layer -> MASQUE-H2 catalog) and enforces
// the different-edge rule. Used by validation and the daemon assembly
// (warpchainservice).
func (c *WarpChainConfig) ResolveEndpoints() (outer, inner netip.AddrPort, err error) {
	return c.resolveChainEndpoints()
}

// resolveChainEndpoints is the internal implementation.
func (c *WarpChainConfig) resolveChainEndpoints() (outer, inner netip.AddrPort, err error) {
	awgEp := func(field, raw string, avoid netip.Addr) (netip.AddrPort, error) {
		if raw == "" {
			// bd b4x-wh6: prefer the FIELD-VERIFIED endpoints — the historical
			// ZeroTrust seeds answer 0 IN from the field network (the default
			// single-AWG transport uses the same list). A field-verified entry
			// is preferred for EVERY layer selector.
			seeds := append(twg.FieldVerifiedEndpoints(), twg.SeedEndpoints()...)
			if len(seeds) == 0 {
				return netip.AddrPort{}, fmt.Errorf("%s: builtin WG seed pool empty", field)
			}
			// awg+awg: the default inner edge must differ from the outer's IP
			// (gool hard rule — distinct_by_ip); a single-seed pool cannot
			// express the pair and fails honestly.
			if avoid.IsValid() {
				for _, s := range seeds {
					if s.Addr() != avoid {
						return s, nil
					}
				}
				return netip.AddrPort{}, fmt.Errorf("%s: no builtin WG seed with an IP distinct from %s (gool hard rule)", field, avoid)
			}
			return seeds[0], nil
		}
		ap, perr := netip.ParseAddrPort(raw)
		if perr != nil {
			return netip.AddrPort{}, fmt.Errorf("%s %q: %v", field, raw, perr)
		}
		if !twg.InWGCatalog(ap.Addr()) {
			return ap, fmt.Errorf("%s %q: address outside the versioned WG catalog (addendum §34)", field, raw)
		}
		if !twg.KnownWGPort(ap.Port()) {
			return ap, fmt.Errorf("%s %q: port outside the catalog port set", field, raw)
		}
		return ap, nil
	}
	masqueEp := func(field, raw string, avoid netip.Addr) (netip.AddrPort, error) {
		if raw == "" {
			// M+M: the default inner edge must differ from the outer's IP
			// (gool hard rule at defaults); explicit values still collide-check
			// below.
			if avoid.IsValid() {
				return defaultMasqueInnerEndpoint(avoid), nil
			}
			return twarp.DefaultH2Endpoint(), nil
		}
		ap, perr := netip.ParseAddrPort(raw)
		if perr != nil {
			return netip.AddrPort{}, fmt.Errorf("%s %q: %v", field, raw, perr)
		}
		if !twarp.InCatalog(twarp.KindMasqueH2, ap.Addr()) {
			return ap, fmt.Errorf("%s %q: address outside the versioned MASQUE-H2 catalog (addendum §34)", field, raw)
		}
		if !twarp.KnownPort(ap.Port()) {
			return ap, fmt.Errorf("%s %q: port outside the catalog port set", field, raw)
		}
		return ap, nil
	}

	switch c.Kind {
	case ChainKindMasqueAwg:
		outer, err = masqueEp("system.warp.chains[masque+awg].outer_endpoint", c.OuterEndpoint, netip.AddrPort{}.Addr())
		if err != nil {
			return
		}
		inner, err = awgEp("system.warp.chains[masque+awg].inner_endpoint", c.InnerEndpoint, netip.AddrPort{}.Addr())
	case ChainKindAwgMasque:
		outer, err = awgEp("system.warp.chains[awg+masque].outer_endpoint", c.OuterEndpoint, netip.AddrPort{}.Addr())
		if err != nil {
			return
		}
		inner, err = masqueEp("system.warp.chains[awg+masque].inner_endpoint", c.InnerEndpoint, netip.AddrPort{}.Addr())
	case ChainKindAwgAwg:
		// W+W: both layers resolve against the WG catalog; the inner default
		// avoids the outer's IP (gool hard rule).
		outer, err = awgEp("system.warp.chains[awg+awg].outer_endpoint", c.OuterEndpoint, netip.AddrPort{}.Addr())
		if err != nil {
			return
		}
		inner, err = awgEp("system.warp.chains[awg+awg].inner_endpoint", c.InnerEndpoint, outer.Addr())
	case ChainKindMasqueMasque:
		// M+M: both layers resolve against the MASQUE-H2 catalog; the inner
		// default avoids the outer's IP (gool hard rule).
		outer, err = masqueEp("system.warp.chains[masque+masque].outer_endpoint", c.OuterEndpoint, netip.AddrPort{}.Addr())
		if err != nil {
			return
		}
		inner, err = masqueEp("system.warp.chains[masque+masque].inner_endpoint", c.InnerEndpoint, outer.Addr())
	default:
		err = fmt.Errorf("system.warp.chains.kind %q is not a nested chain kind (want masque+awg, awg+masque, awg+awg or masque+masque)", c.Kind)
		return
	}
	if err != nil {
		return
	}
	if outer.Addr() == inner.Addr() {
		err = fmt.Errorf("system.warp.chains[%s]: outer and inner terminate on the same edge IP %s (gool hard rule: different edges per layer)", c.Kind, outer.Addr())
	}
	return
}

// validateChainAWGProfile checks the AWG-layer profile head ("" is legal:
// ladder default at assembly time). awg+awg additionally requires an ACTIVE
// junk family on the outer layer (twg.ErrOuterObfRequired mirrored);
// masque+masque has NO awg layer — a profile on it is a config lie.
func (c *WarpChainConfig) validateChainAWGProfile() error {
	if c.Kind == ChainKindMasqueMasque {
		if c.AWGProfile != "" {
			return fmt.Errorf("system.warp.chains[masque+masque].awg_profile %q invalid: the M+M composition has no awg layer (leave empty)", c.AWGProfile)
		}
		return nil
	}
	if c.AWGProfile == "" {
		if c.Kind == ChainKindAwgAwg {
			p, _, err := twg.DefaultJunkActiveCfWarp()
			if err != nil {
				return fmt.Errorf("system.warp.chains[awg+awg].awg_profile: %w", err)
			}
			if p.JunkCount < 1 {
				return fmt.Errorf("system.warp.chains[awg+awg].awg_profile: no junk-active cf-warp profile is available for the outer layer")
			}
		}
		return nil
	}
	p, err := resolveCfWarpProfile("system.warp.chains["+c.Kind+"].awg_profile", c.AWGProfile)
	if err != nil {
		return err
	}
	if c.Kind == ChainKindAwgAwg && p.JunkCount < 1 {
		return fmt.Errorf("system.warp.chains[awg+awg].awg_profile %q: profile carries no junk family (jc=0); the W+W outer layer requires an active junk family (ErrOuterObfRequired)", c.AWGProfile)
	}
	return nil
}

// validateChainFingerprint checks the masque-layer fingerprint head. For
// masque+masque the fingerprint applies to the INNER layer (the outer plane's
// fingerprint is set on the supervisor template by the assembly); it stays
// a single field covering the composition's masquerade posture.
func (c *WarpChainConfig) validateChainFingerprint() error {
	if c.Kind == ChainKindAwgAwg && c.Fingerprint != "" {
		return fmt.Errorf("system.warp.chains[awg+awg].fingerprint %q invalid: the W+W composition has no masque layer (leave empty)", c.Fingerprint)
	}
	switch c.Fingerprint {
	case "", "chrome120", "firefox":
		return nil
	default:
		return fmt.Errorf("system.warp.chains[%s].fingerprint %q invalid (empty, chrome120 or firefox)", c.Kind, c.Fingerprint)
	}
}
