package config

// AWG-WARP / chains config validation tests (tunnels panel stage 2).
import (
        "strings"
        "testing"
)

func awgWarpTestConfig() *Config {
        c := NewConfig()
        c.System.Warp.AWG = WarpAWGConfig{
                Enabled:      true,
                IdentityPath: "/tmp/awg-identity.json",
        }
        return &c
}

func TestWarpAWGValidationDefaults(t *testing.T) {
        c := NewConfig()
        if err := c.Validate(); err != nil {
                t.Fatalf("zero config must validate (disabled defaults): %v", err)
        }
        if p := c.System.Warp.AWG.EffectiveIdentityPath(); p != DefaultWarpAWGIdentityPath {
                t.Fatalf("default identity path = %q", p)
        }
        ep, err := c.System.Warp.AWG.EffectiveEndpoint()
        if err != nil {
                t.Fatalf("default endpoint: %v", err)
        }
        if ep.String() != "162.159.193.5:2408" {
                t.Fatalf("default endpoint = %s", ep)
        }
        if _, err := c.System.Warp.AWG.EffectiveProfile(); err != nil {
                t.Fatalf("default profile (ladder head): %v", err)
        }
        if c.System.Warp.AWG.EffectiveMTU() != 1280 {
                t.Fatalf("default mtu = %d", c.System.Warp.AWG.EffectiveMTU())
        }
        if c.System.Warp.AWG.EffectiveMaxRestarts() != 6 {
                t.Fatalf("default restarts = %d", c.System.Warp.AWG.EffectiveMaxRestarts())
        }
}

func TestWarpAWGValidationBadEndpoint(t *testing.T) {
        c := awgWarpTestConfig()
        // Outside the WG catalog (addendum §34: no arbitrary internet scanning).
        c.System.Warp.AWG.Endpoint = "8.8.8.8:2408"
        err := c.Validate()
        if err == nil || !strings.Contains(err.Error(), "system.warp.awg.endpoint") {
                t.Fatalf("expected endpoint catalog rejection, got: %v", err)
        }
}

func TestWarpAWGValidationBadProfile(t *testing.T) {
        c := awgWarpTestConfig()
        // awg-sh-a targets OWN AWG servers (plan Б S/H family) — not cf-warp.
        c.System.Warp.AWG.Profile = "awg-sh-a"
        err := c.Validate()
        if err == nil || !strings.Contains(err.Error(), "system.warp.awg.profile") {
                t.Fatalf("expected profile target rejection, got: %v", err)
        }
}

func chainTestConfig(kind string) *Config {
        c := NewConfig()
        c.System.Warp.Chains = []WarpChainConfig{{
                Kind:    kind,
                Enabled: true,
        }}
        return &c
}

func TestWarpChainValidationDefaults(t *testing.T) {
        for _, kind := range WarpChainKinds {
                c := chainTestConfig(kind)
                if err := c.Validate(); err != nil {
                        t.Fatalf("chain %s defaults must validate: %v", kind, err)
                }
                ch := c.System.Warp.Chains[0]
                outer, inner, err := ch.resolveChainEndpoints()
                if err != nil {
                        t.Fatalf("chain %s endpoints: %v", kind, err)
                }
                if outer.Addr() == inner.Addr() {
                        t.Fatalf("chain %s default endpoints collide: %s", kind, outer)
                }
                if p := ch.EffectiveOuterIdentityPath(); !strings.HasPrefix(p, "/opt/etc/b4/warp/chain-") {
                        t.Fatalf("chain %s outer slot = %q", kind, p)
                }
                if ch.EffectiveOuterIdentityPath() == ch.EffectiveInnerIdentityPath() {
                        t.Fatalf("chain %s slots collide by default", kind)
                }
        }
}

func TestWarpChainValidationBadKind(t *testing.T) {
        c := NewConfig()
        c.System.Warp.Chains = []WarpChainConfig{{Kind: "awg+awg", Enabled: true}}
        err := c.Validate()
        if err == nil || !strings.Contains(err.Error(), "chains[0].kind") {
                t.Fatalf("expected kind rejection, got: %v", err)
        }
}

func TestWarpChainValidationDuplicate(t *testing.T) {
        c := NewConfig()
        c.System.Warp.Chains = []WarpChainConfig{
                {Kind: ChainKindMasqueAwg, Enabled: true},
                {Kind: ChainKindMasqueAwg, Enabled: false},
        }
        err := c.Validate()
        if err == nil || !strings.Contains(err.Error(), "declared twice") {
                t.Fatalf("expected duplicate rejection, got: %v", err)
        }
}

func TestWarpChainValidationCrossCatalogEndpoint(t *testing.T) {
        c := chainTestConfig(ChainKindMasqueAwg)
        // The masque outer must resolve against the MASQUE-H2 catalog, not the
        // WG one (layered catalog gating, addendum §34).
        c.System.Warp.Chains[0].OuterEndpoint = "162.159.193.5:443"
        err := c.Validate()
        if err == nil || !strings.Contains(err.Error(), "chains[0].endpoints") {
                t.Fatalf("expected cross-catalog endpoint rejection, got: %v", err)
        }
        // Same for the awg inner against the MASQUE catalog.
        c = chainTestConfig(ChainKindMasqueAwg)
        c.System.Warp.Chains[0].InnerEndpoint = "162.159.198.2:2408"
        err = c.Validate()
        if err == nil || !strings.Contains(err.Error(), "chains[0].endpoints") {
                t.Fatalf("expected cross-catalog inner rejection, got: %v", err)
        }
}

func TestWarpChainValidationSlotCollision(t *testing.T) {
        c := chainTestConfig(ChainKindMasqueAwg)
        // The chain outer slot colliding with the MASQUE single-transport slot.
        c.System.Warp.Chains[0].OuterIdentityPath = DefaultWarpIdentityPath
        err := c.Validate()
        if err == nil || !strings.Contains(err.Error(), "collides") {
                t.Fatalf("expected slot conflict rejection, got: %v", err)
        }
}

func TestWarpChainValidationInnerMTU(t *testing.T) {
        c := chainTestConfig(ChainKindMasqueAwg)
        c.System.Warp.Chains[0].InnerMTU = 1300
        err := c.Validate()
        if err == nil || !strings.Contains(err.Error(), "chains[0].inner_mtu") {
                t.Fatalf("expected mtu cap rejection, got: %v", err)
        }
        // 1200 (the nested cap) is legal.
        c.System.Warp.Chains[0].InnerMTU = 1200
        if err := c.Validate(); err != nil {
                t.Fatalf("mtu 1200 must validate: %v", err)
        }
}

func TestRoutingTunnelKindChains(t *testing.T) {
        if !IsRoutingTunnelKind(TunnelKindChainMasqueAwg) || !IsRoutingTunnelKind(TunnelKindChainAwgMasque) {
                t.Fatal("chain kinds must be routing tunnel kinds")
        }
        if IsRoutingTunnelKind("awg+awg") || IsRoutingTunnelKind("nonru") {
                t.Fatal("engine-pending compositions must not be routing tunnel kinds")
        }
}
