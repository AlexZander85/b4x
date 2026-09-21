package vlessservice

import (
	"context"
	"net"
	"net/netip"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/reserve"
)

// Kind implements reserve.Carrier. VLESS joins the selection-tree registry
// with its design priority (25, between opera and fxvpn — design §12.2).
func (r *Runtime) Kind() reserve.Kind { return reserve.KindVless }

// SupportsUDP reports UDP ASSOCIATE availability (V3): only the helper's
// SOCKS5 inbound can carry UDP, and only when the operator enabled it
// (system.vless.udp). The in-process client is stream-only, so UDP scopes are
// refused there — fail-closed, never a silent passthrough.
func (r *Runtime) SupportsUDP() bool {
	return r.cfg.UDP && r.modeFor(r.allNodes()) == config.VLESSClientHelper
}

// DialUDP opens a UDP ASSOCIATE to addr through the helper, or refuses honestly.
func (r *Runtime) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if !r.SupportsUDP() {
		return nil, reserve.ErrCarrierNoUDP
	}
	return r.dialUDP(ctx, addr)
}

// BypassDomain implements reserve.BypassDomainChecker (anti-loop). The suffix
// table is empty for V1 (nodes are owner-supplied, so their infrastructure is
// not a shared vendor domain); the method still wired so per-node bypass can
// be added without touching the routing layers.
func (r *Runtime) BypassDomain(host string) bool {
	return reserve.IsBypassDomain(reserve.KindVless, host)
}

var _ reserve.Carrier = (*Runtime)(nil)
var _ reserve.BypassDomainChecker = (*Runtime)(nil)
