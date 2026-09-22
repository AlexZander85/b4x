package config

// Tests for the system.warp.nonru section (tunnels panel stage 6, ADR-WARP-6):
// the base-warp prerequisite, the inner endpoint gool rule, the slot
// discipline against every existing CF device, and the gate-knob shapes.
import (
	"testing"
)

func nonruValidBase() *Config {
	c := NewConfig()
	c.System.Warp.Enabled = true
	c.System.Warp.IdentityPath = "/opt/etc/b4/warp/identity.json"
	c.System.Warp.NonRU.Enabled = true
	// The НЕ РФ checkbox is the non-RU master switch and requires the proxy.
	c.System.Warp.Socks5 = "socks5://user:pass@203.0.113.9:1080"
	return &c
}

func TestNonRURequiresBaseWarp(t *testing.T) {
	c := nonruValidBase()
	c.System.Warp.Enabled = false
	if err := c.Validate(); err == nil {
		t.Fatal("nonru over a disabled base warp must fail validation (ADR-WARP-6)")
	}
}

func TestNonRUValidSectionPasses(t *testing.T) {
	c := nonruValidBase()
	if err := c.Validate(); err != nil {
		t.Fatalf("valid nonru section rejected: %v", err)
	}
}

// Field 2026-09-22: nonru is the non-RU MASTER SWITCH for the base MASQUE
// carrier -> it requires system.warp.socks5, and the socks5 + masque-routed
// set combination is the intended, valid non-RU path.
func TestNonRURequiresSocks5(t *testing.T) {
	c := nonruValidBase()
	c.System.Warp.Socks5 = ""
	if err := c.Validate(); err == nil {
		t.Fatal("nonru.enabled without system.warp.socks5 must fail validation (master switch needs the proxy)")
	}
}

func TestNonRUSocks5AndMasqueSetAllowed(t *testing.T) {
	c := nonruValidBase()
	c.Sets = []*SetConfig{{
		Id:      "s1",
		Name:    "canary",
		Enabled: true,
		Routing: RoutingConfig{Enabled: true, Mode: RoutingModeTunnel, Tunnel: TunnelKindMasque},
	}}
	if err := c.Validate(); err != nil {
		t.Fatalf("nonru + socks5 + tunnel=masque set must validate (intended non-RU path): %v", err)
	}
}

func TestNonRURoutingKindAliasesToMasque(t *testing.T) {
	c := nonruValidBase()
	c.Sets = []*SetConfig{{
		Id:      "s1",
		Name:    "canary",
		Enabled: true,
		Routing: RoutingConfig{Enabled: true, Mode: RoutingModeTunnel, Tunnel: TunnelKindNonRU},
	}}
	if err := c.Validate(); err != nil {
		t.Fatalf("tunnel=nonru must validate: %v", err)
	}
	if c.Sets[0].Routing.Tunnel != TunnelKindMasque {
		t.Fatalf("tunnel=nonru must alias to masque (base non-RU carrier), got %q", c.Sets[0].Routing.Tunnel)
	}
}

func TestNonRUEndpointGates(t *testing.T) {
	c := nonruValidBase()
	baseAt, err := c.System.Warp.EffectiveEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	// Outside the catalog.
	c.System.Warp.NonRU.Endpoint = "9.9.9.9:443"
	if err := c.Validate(); err == nil {
		t.Fatal("non-catalog endpoint must fail")
	}
	// The base edge IP: the gool hard rule (self-nesting on one edge).
	c = nonruValidBase()
	c.System.Warp.NonRU.Endpoint = baseAt.String()
	if err := c.Validate(); err == nil {
		t.Fatalf("inner endpoint on the base edge %s must fail (gool rule)", baseAt)
	}
}

func TestNonRUDefaultEndpointAvoidsBaseEdge(t *testing.T) {
	c := nonruValidBase()
	baseAt, err := c.System.Warp.EffectiveEndpoint()
	if err != nil {
		t.Fatal(err)
	}
	inner, err := c.System.Warp.NonRU.EffectiveEndpoint(baseAt.Addr())
	if err != nil {
		t.Fatal(err)
	}
	if inner.Addr() == baseAt.Addr() {
		t.Fatalf("default inner %v sits on the base edge %v", inner, baseAt)
	}
}

func TestNonRUFingerprintAndMTU(t *testing.T) {
	c := nonruValidBase()
	c.System.Warp.NonRU.Fingerprint = "safari"
	if err := c.Validate(); err == nil {
		t.Fatal("unknown fingerprint must fail")
	}
	c = nonruValidBase()
	c.System.Warp.NonRU.InnerMTU = 1400
	if err := c.Validate(); err == nil {
		t.Fatal("inner mtu above the nested cap must fail")
	}
}

func TestNonRUTtlRefreshOrdering(t *testing.T) {
	c := nonruValidBase()
	// TTL must be at least 2x the refresh (the gate must get two probe
	// rounds inside one attestation window).
	c.System.Warp.NonRU.AttestationTTLSeconds = 90
	c.System.Warp.NonRU.RefreshIntervalSeconds = 60
	if err := c.Validate(); err == nil {
		t.Fatal("ttl < 2*refresh must fail")
	}
	// The defaults satisfy the ordering.
	c = nonruValidBase()
	if ttl, refresh := c.System.Warp.NonRU.EffectiveAttestationTTL(), c.System.Warp.NonRU.EffectiveRefreshInterval(); ttl < 2*refresh {
		t.Fatalf("defaults violate the ordering: ttl=%d refresh=%d", ttl, refresh)
	}
}

func TestNonRURUCountriesShape(t *testing.T) {
	c := nonruValidBase()
	c.System.Warp.NonRU.RUCountries = []string{"RU", "rus"}
	if err := c.Validate(); err == nil {
		t.Fatal("non-ISO ru_countries entries must fail")
	}
	// Normalization: lowercase input survives via EffectiveRUCountries.
	c = nonruValidBase()
	c.System.Warp.NonRU.RUCountries = []string{" ru ", "KZ"}
	set := c.System.Warp.NonRU.EffectiveRUCountries()
	if !set["RU"] || !set["KZ"] || len(set) != 2 {
		t.Fatalf("effective ru countries = %v", set)
	}
}

func TestNonRUSlotDiscipline(t *testing.T) {
	// Collision with the BASE warp slot: the nested device is a second CF
	// device, never the base one.
	c := nonruValidBase()
	c.System.Warp.NonRU.IdentityPath = c.System.Warp.IdentityPath
	if err := c.Validate(); err == nil {
		t.Fatal("collision with the base warp slot must fail")
	}
	// Collision with the AWG single.
	c = nonruValidBase()
	c.System.Warp.NonRU.IdentityPath = c.System.Warp.AWG.EffectiveIdentityPath()
	if err := c.Validate(); err == nil {
		t.Fatal("collision with the awg slot must fail")
	}
	// Collision with a chain layer slot.
	c = nonruValidBase()
	c.System.Warp.Chains = []WarpChainConfig{{
		Kind:              ChainKindMasqueMasque,
		Enabled:           true,
		OuterIdentityPath: "/opt/etc/b4/warp/m.json",
		InnerIdentityPath: "/opt/etc/b4/warp/i.json",
	}}
	c.System.Warp.NonRU.IdentityPath = "/opt/etc/b4/warp/i.json"
	if err := c.Validate(); err == nil {
		t.Fatal("collision with a chain layer slot must fail")
	}
	// The default is distinct and enabled-valid.
	c = nonruValidBase()
	if p := c.System.Warp.NonRU.EffectiveIdentityPath(); p == c.System.Warp.IdentityPath {
		t.Fatalf("default nonru slot %q must differ from the base", p)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("valid default slot rejected: %v", err)
	}
}

func TestNonRUDisabledHeadsStillValidated(t *testing.T) {
	// The warp canon: heads are validated even when disabled — a typo
	// cannot hide until enable day.
	c := nonruValidBase()
	c.System.Warp.NonRU.Enabled = false
	c.System.Warp.NonRU.Endpoint = "9.9.9.9:443"
	if err := c.Validate(); err == nil {
		t.Fatal("disabled nonru with a bad endpoint must still fail (head validation)")
	}
}

func TestNonRURoutingKindAccepted(t *testing.T) {
	if !IsRoutingTunnelKind(TunnelKindNonRU) {
		t.Fatal("nonru must be a valid routing.tunnel kind")
	}
	found := false
	for _, k := range RoutingTunnelKinds {
		if k == TunnelKindNonRU {
			found = true
		}
	}
	if !found {
		t.Fatal("RoutingTunnelKinds must enumerate nonru")
	}
}
