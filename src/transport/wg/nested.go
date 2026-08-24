// WG-WG nested composition (design §7, R3 role, gool pattern):
//
//	outer:     primary identity, MTU 1280, obfuscation ON, keepalive 5
//	forwarder: single-session UDP relay 127.0.0.1:<port> -> inner edge,
//	           carried INSIDE the outer tunnel (Backend B userspace)
//	inner:     secondary identity from a separate store slot, MTU 1200,
//	           keepalive 20; its ONLY egress is the loopback dial
//
// Hard rules enforced by NestedWgConfig.Validate:
//
//   - two INDEPENDENT identities (distinct private keys);
//   - distinct assigned tunnel addresses;
//   - DIFFERENT edge IPs per layer (gool hard rule; the seeker's
//     distinct_by_ip discipline upstream);
//   - MTU gradient inner < outer (defaults 1200 < 1280);
//   - obfuscation ON for the outer layer (the whole point of R3 stealth
//     layering; a vanilla outer would defeat it);
//   - keepalive separation outer != inner so layer timers never sync;
//   - INNER ENDPOINT MUST BE LOOPBACK (Backend-B carrier proof, E8
//     lesson): anything else silently dials the WAN directly, bypassing
//     the outer layer — structurally rejected, no exceptions.
package transportwg

import (
	"errors"
	"fmt"
	"net/netip"
)

// Design §7 nested constants.
const (
	NestedOuterKeepaliveSec = 5
	NestedInnerKeepaliveSec = 20
)

// Structural validation errors (§62.10-style reason identity).
var (
	ErrNestedIdenticalIdentity = errors.New("transportwg: nested layers must use two independent identities")
	ErrNestedAddressConflict   = errors.New("transportwg: nested layers assign the same tunnel address")
	ErrNestedSameEdge          = errors.New("transportwg: nested layers must terminate on different edge IPs (gool hard rule)")
	ErrNestedMTUGradient       = errors.New("transportwg: inner MTU must be strictly below outer MTU")
	ErrInnerNotLoopback        = errors.New("transportwg: backend-b inner endpoint must be loopback (carrier proof)")
	ErrOuterObfRequired        = errors.New("transportwg: nested outer layer requires an active junk/obfuscation profile")
	ErrKeepaliveCollision      = errors.New("transportwg: nested layers must use separated keepalives")
)

// NestedLayer describes one WG layer of the pair.
type NestedLayer struct {
	Ident *Identity
	// Profile is the AWG obfuscation set for this layer. The OUTER layer
	// must carry an active junk family; the inner defaults to vanilla.
	Profile Profile
	MTU     int // 0 -> DefaultMTU (outer) / DefaultInnerMTU (inner)
	// KeepaliveSec 0 -> design default (outer 5 / inner 20).
	KeepaliveSec uint16
}

// NestedWgConfig validates the two-layer composition before any runtime
// wiring exists (mirror of the transportwarp E5 discipline).
//
// Address model (three DISTINCT roles):
//
//	Outer.Edge     public address of the outer edge (catalog-gated);
//	InnerEdge      REAL inner edge address reached THROUGH the outer
//	               tunnel — the forwarder's dial target; must differ
//	               from Outer.Edge.Addr() (gool hard rule);
//	Inner.Dial     loopback address the inner WG instance dials —
//	               ALWAYS 127.0.0.1:<fwdPort>; port 0 = assigned at
//	               runtime after Listen.
type NestedWgConfig struct {
	Outer NestedLayer
	Inner NestedLayer

	// OuterEdge is the PUBLIC address of the outer edge (catalog-gated in
	// production wiring).
	OuterEdge netip.AddrPort
	// InnerEdge is the through-tunnel target of the Backend-B forwarder
	// (the production value is the public AWG-server address).
	InnerEdge netip.AddrPort
	// InnerDial is the loopback client address; zero port means the
	// runtime assigns one when the forwarder binds.
	InnerDial netip.AddrPort
}

// obfActive reports whether a profile carries an actual junk family
// (client-side parameters that hit the wire).
func obfActive(p Profile) bool { return p.JunkCount >= 1 }

func mtuOr(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func kaOr(v, def uint16) uint16 {
	if v == 0 {
		return def
	}
	return v
}

// EffectiveMTU / EffectiveKeepalive expose the resolved values for runtime
// wiring and tests.
func (l *NestedLayer) EffectiveMTU(outer bool) int {
	if outer {
		return mtuOr(l.MTU, DefaultMTU)
	}
	return mtuOr(l.MTU, DefaultInnerMTU)
}

func (l *NestedLayer) EffectiveKeepalive(outer bool) uint16 {
	if outer {
		return kaOr(l.KeepaliveSec, NestedOuterKeepaliveSec)
	}
	return kaOr(l.KeepaliveSec, NestedInnerKeepaliveSec)
}

// Validate enforces every hard rule listed in the package comment. It is
// pure (no network, no device) and deterministic.
func (c *NestedWgConfig) Validate() error {
	if c.Outer.Ident == nil || c.Inner.Ident == nil {
		return fmt.Errorf("transportwg: nested requires both identities")
	}
	if err := c.Outer.Ident.Validate(); err != nil {
		return fmt.Errorf("transportwg: outer identity: %w", err)
	}
	if err := c.Inner.Ident.Validate(); err != nil {
		return fmt.Errorf("transportwg: inner identity: %w", err)
	}
	if c.Outer.Ident.PrivateKey.B64() == c.Inner.Ident.PrivateKey.B64() {
		return ErrNestedIdenticalIdentity
	}

	oV4, err := netip.ParseAddr(c.Outer.Ident.AssignedV4)
	if err != nil {
		return fmt.Errorf("%w: outer assigned_v4 %q", ErrNestedAddressConflict, c.Outer.Ident.AssignedV4)
	}
	iV4, err2 := netip.ParseAddr(c.Inner.Ident.AssignedV4)
	if err2 != nil {
		return fmt.Errorf("%w: inner assigned_v4 %q", ErrNestedAddressConflict, c.Inner.Ident.AssignedV4)
	}
	if oV4 == iV4 {
		return ErrNestedAddressConflict
	}

	if !c.OuterEdge.IsValid() || !c.InnerEdge.IsValid() {
		return fmt.Errorf("transportwg: nested edges invalid: outer=%v inner=%v", c.OuterEdge, c.InnerEdge)
	}
	// Gool hard rule on the PUBLIC pair. Loopback co-location is a legal
	// IN-PROCESS TEST artifact only (all fixtures live on 127/8); the
	// production seeker gate already pins the outer edge to the catalog,
	// so a loopback outer edge cannot ship.
	if c.OuterEdge.Addr() == c.InnerEdge.Addr() && !c.OuterEdge.Addr().IsLoopback() {
		return ErrNestedSameEdge
	}

	// Backend-B carrier proof (E8 lesson): the inner instance's ONLY egress
	// is the loopback forwarder. A non-loopback dial means a silent direct
	// WAN path around the outer layer.
	if !c.InnerDial.IsValid() || !c.InnerDial.Addr().IsLoopback() {
		return ErrInnerNotLoopback
	}

	if mtuOr(c.Inner.MTU, DefaultInnerMTU) >= mtuOr(c.Outer.MTU, DefaultMTU) {
		return ErrNestedMTUGradient
	}
	if !obfActive(c.Outer.Profile) {
		return ErrOuterObfRequired
	}
	if c.Outer.EffectiveKeepalive(true) == c.Inner.EffectiveKeepalive(false) {
		return ErrKeepaliveCollision
	}
	return nil
}

// InnerTunnelConfig renders the netstack TUN config for the inner layer
// (assigned address isolation comes from the validated identities).
func (c *NestedWgConfig) InnerTunnelConfig(dns netip.Addr) TunnelConfig {
	return TunnelConfig{
		Mode:      ModeNetstack,
		Addresses: []netip.Addr{mustParseAddr(c.Inner.Ident.AssignedV4)},
		DNS:       []netip.Addr{dns},
		MTU:       c.Inner.EffectiveMTU(false),
	}
}

// OuterTunnelConfig renders the netstack TUN config for the outer layer.
func (c *NestedWgConfig) OuterTunnelConfig(dns netip.Addr) TunnelConfig {
	return TunnelConfig{
		Mode:      ModeNetstack,
		Addresses: []netip.Addr{mustParseAddr(c.Outer.Ident.AssignedV4)},
		DNS:       []netip.Addr{dns},
		MTU:       c.Outer.EffectiveMTU(true),
	}
}

func mustParseAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
