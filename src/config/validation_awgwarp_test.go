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
	c.System.Warp.Chains = []WarpChainConfig{{Kind: "masque+masque", Enabled: true}}
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
	if !IsRoutingTunnelKind(TunnelKindChainMasqueAwg) || !IsRoutingTunnelKind(TunnelKindChainAwgMasque) ||
		!IsRoutingTunnelKind(TunnelKindChainAwgAwg) {
		t.Fatal("chain kinds must be routing tunnel kinds")
	}
	if IsRoutingTunnelKind("masque+masque") || IsRoutingTunnelKind("nonru") {
		t.Fatal("engine-pending compositions must not be routing tunnel kinds")
	}
}

func TestWarpChainAwgAwgFingerprintRejected(t *testing.T) {
	// W+W has no masque layer — a fingerprint is a config lie.
	c := chainTestConfig(ChainKindAwgAwg)
	c.System.Warp.Chains[0].Fingerprint = "chrome120"
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected W+W fingerprint rejection, got: %v", err)
	}
}

func TestWarpChainAwgAwgVanillaOuterProfileRejected(t *testing.T) {
	// The W+W outer layer requires an ACTIVE junk family
	// (twg.ErrOuterObfRequired mirrored at the config gate).
	c := chainTestConfig(ChainKindAwgAwg)
	c.System.Warp.Chains[0].AWGProfile = "vanilla-off" // jc=0
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "junk family") {
		t.Fatalf("expected vanilla outer profile rejection, got: %v", err)
	}
	// A junk-active profile is legal.
	c.System.Warp.Chains[0].AWGProfile = "quic-a"
	if err := c.Validate(); err != nil {
		t.Fatalf("junk-active outer profile must validate: %v", err)
	}
}

func TestWarpChainAwgAwgDistinctEdges(t *testing.T) {
	// The gool hard rule: both layers are WG-catalog endpoints and must
	// terminate on different edge IPs.
	c := chainTestConfig(ChainKindAwgAwg)
	c.System.Warp.Chains[0].OuterEndpoint = "162.159.193.5:2408"
	c.System.Warp.Chains[0].InnerEndpoint = "162.159.193.5:4500" // same IP
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "same edge IP") {
		t.Fatalf("expected same-edge rejection, got: %v", err)
	}
	// Defaults resolve to DISTINCT seeds.
	c = chainTestConfig(ChainKindAwgAwg)
	if err := c.Validate(); err != nil {
		t.Fatalf("awg+awg defaults must validate: %v", err)
	}
	outer, inner, rerr := c.System.Warp.Chains[0].resolveChainEndpoints()
	if rerr != nil {
		t.Fatalf("resolve: %v", rerr)
	}
	if outer.Addr() == inner.Addr() {
		t.Fatalf("default W+W edges collide: %s", outer.Addr())
	}
}

func TestWarpAWGKernelModeShape(t *testing.T) {
	// A bad mode head is rejected even when disabled (a typo cannot hide
	// until switch day).
	c := NewConfig()
	c.System.Warp.AWG.Mode = "kernel-tun"
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "system.warp.awg.mode") {
		t.Fatalf("expected mode rejection, got: %v", err)
	}
	// Both canonical modes validate on a disabled section.
	for _, m := range []string{"", WarpAWGModeNetstack, WarpAWGModeKernel} {
		c := NewConfig()
		c.System.Warp.AWG.Mode = m
		if err := c.Validate(); err != nil {
			t.Fatalf("mode %q must validate: %v", m, err)
		}
	}
}

func TestWarpAWGKernelRequiresSelectors(t *testing.T) {
	c := awgWarpTestConfig()
	c.System.Warp.AWG.Mode = WarpAWGModeKernel
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "from_cidrs") {
		t.Fatalf("expected the no-selectors half-state rejection, got: %v", err)
	}
	// Selectors present: valid.
	c.System.Warp.AWG.Kernel.FromCIDRs = []string{"192.168.1.0/24"}
	if err := c.Validate(); err != nil {
		t.Fatalf("kernel mode with selectors must validate: %v", err)
	}
}

func TestWarpAWGKernelFieldShapes(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*WarpAWGKernelConfig)
		want   string
	}{
		{"iface too long", func(k *WarpAWGKernelConfig) { k.Interface = "this-name-is-way-too-long" }, "kernel.interface"},
		{"iface bad charset", func(k *WarpAWGKernelConfig) { k.Interface = "1bad" }, "kernel.interface"},
		{"iface bad symbol", func(k *WarpAWGKernelConfig) { k.Interface = "bad:name" }, "kernel.interface"},
		{"table too big", func(k *WarpAWGKernelConfig) { k.Table = 1 << 30 }, "kernel.table"},
		{"priority too big", func(k *WarpAWGKernelConfig) { k.RulePriority = 32766 }, "kernel.rule_priority"},
		{"cidr garbage", func(k *WarpAWGKernelConfig) { k.FromCIDRs = []string{"192.168.1/24"} }, "from_cidrs[0]"},
		{"cidr v6", func(k *WarpAWGKernelConfig) { k.FromCIDRs = []string{"fd00::/8"} }, "from_cidrs[0]"},
	}
	for _, tc := range cases {
		c := NewConfig() // disabled: the shape rules hold ALWAYS
		tc.mutate(&c.System.Warp.AWG.Kernel)
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: expected %q rejection, got: %v", tc.name, tc.want, err)
		}
	}
}

func TestWarpAWGKernelSetConflict(t *testing.T) {
	// routing.tunnel=warp has no userspace carrier in kernel mode — the
	// honest cross-field rejection.
	c := awgWarpTestConfig()
	c.System.Warp.AWG.Mode = WarpAWGModeKernel
	c.System.Warp.AWG.Kernel.FromCIDRs = []string{"192.168.1.0/24"}
	c.Sets = append(c.Sets, &SetConfig{
		Id:   "s1",
		Name: "kernel-conflict",
		Routing: RoutingConfig{
			Mode:   RoutingModeTunnel,
			Tunnel: TunnelKindWarp,
		},
	})
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "no userspace carrier") {
		t.Fatalf("expected the kernel/warp-set cross-field rejection, got: %v", err)
	}
	// A set routed to ANOTHER kind is unaffected.
	c.Sets[0].Routing.Tunnel = TunnelKindProton
	if err := c.Validate(); err != nil {
		t.Fatalf("non-warp set must pass under kernel mode: %v", err)
	}
}
