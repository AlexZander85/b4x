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

        twarp "github.com/daniellavrushin/b4/transport/warp"
        twg "github.com/daniellavrushin/b4/transport/wg"
)

// DefaultWarpAWGIdentityPath is the AWG-WARP identity slot. A SEPARATE file
// from the MASQUE identity on purpose: one CF device per transport (red
// line §3 of the nested design — sharing a device between planes is
// forbidden), so AWG-WARP owns its own registration.
const DefaultWarpAWGIdentityPath = "/opt/etc/b4/warp/awg-identity.json"

// Chain kinds (closed set): the two cross-transport compositions the
// transport/nested engine ships. W+W and masque+masque stay engine-pending
// until their daemon assembly lands; "nonru" is a geo-gated policy, not a
// pair — neither is accepted by this schema.
const (
        ChainKindMasqueAwg = "masque+awg" // MASQUE-H2 outer, AWG inner (M+W)
        ChainKindAwgMasque = "awg+masque" // AWG outer, MASQUE-H2 inner (W+M)
)

// WarpChainKinds is the closed chain-kind set (validation + UI catalogs).
var WarpChainKinds = []string{ChainKindMasqueAwg, ChainKindAwgMasque}

// IsWarpChainKind reports kind membership in the chain set.
func IsWarpChainKind(kind string) bool {
        return kind == ChainKindMasqueAwg || kind == ChainKindAwgMasque
}

// WarpAWGConfig enables the AWG-WARP transport (kind "warp"): one
// AmneziaWG session over the CF WARP WG edge, userspace netstack data
// plane, UDP full-scope reserve carrier. Kernel-TUN mode is deliberately
// absent: the kernel PBR wiring belongs to the field layer and no
// half-states ship (honest boundaries).
type WarpAWGConfig struct {
        Enabled bool `json:"enabled"`
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

// WarpChainConfig declares one nested chain. Each layer owns a DISTINCT
// identity slot (one CF device per layer, nested red line #3): the outer
// identity of masque+awg never serves the inner AWG layer and vice versa.
// Defaults park the slot paths next to the MASQUE identity under
// /opt/etc/b4/warp/chain-<kind>-{outer,inner}.json.
type WarpChainConfig struct {
        // Kind selects the composition: "masque+awg" (M+W) or "awg+masque" (W+M).
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
        awgEp := func(field, raw string) (netip.AddrPort, error) {
                if raw == "" {
                        seeds := twg.SeedEndpoints()
                        if len(seeds) == 0 {
                                return netip.AddrPort{}, fmt.Errorf("%s: builtin WG seed pool empty", field)
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
        masqueEp := func(field, raw string) (netip.AddrPort, error) {
                if raw == "" {
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
                outer, err = masqueEp("system.warp.chains[masque+awg].outer_endpoint", c.OuterEndpoint)
                if err != nil {
                        return
                }
                inner, err = awgEp("system.warp.chains[masque+awg].inner_endpoint", c.InnerEndpoint)
        case ChainKindAwgMasque:
                outer, err = awgEp("system.warp.chains[awg+masque].outer_endpoint", c.OuterEndpoint)
                if err != nil {
                        return
                }
                inner, err = masqueEp("system.warp.chains[awg+masque].inner_endpoint", c.InnerEndpoint)
        default:
                err = fmt.Errorf("system.warp.chains.kind %q is not a nested chain kind (want masque+awg or awg+masque)", c.Kind)
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
// ladder default at assembly time).
func (c *WarpChainConfig) validateChainAWGProfile() error {
        if c.AWGProfile == "" {
                return nil
        }
        _, err := resolveCfWarpProfile("system.warp.chains["+c.Kind+"].awg_profile", c.AWGProfile)
        return err
}

// validateChainFingerprint checks the masque-layer fingerprint head.
func (c *WarpChainConfig) validateChainFingerprint() error {
        switch c.Fingerprint {
        case "", "chrome120", "firefox":
                return nil
        default:
                return fmt.Errorf("system.warp.chains[%s].fingerprint %q invalid (empty, chrome120 or firefox)", c.Kind, c.Fingerprint)
        }
}
