// Backend B userspace adapter plumbing (design §6 BackendBProxy; addendum
// §38 "inner full proxy adapter", warp-socks upstream pattern).
//
// The inner MASQUE control stream must traverse the BASE tunnel. Two ways
// exist:
//
//   - Backend A: kernel routing of a constrained socket (SO_MARK /
//     SO_BINDTODEVICE via the base TUN) — DialPolicy, already wired;
//
//   - Backend B: the dial is served by a USERSPACE adapter running over
//     the base session (warp-socks carries a full smoltcp netstack for
//     this).
//
// CARRIER STATUS (owner decision, E8 close-out): the userspace TCP carrier
// is deliberately NOT part of the engine (zero-dependency rule preserved).
// This is a DEFERRAL, not a cancellation — the carrier is a separate mini-
// stage scheduled AFTER field session #1, and its dependency choice
// (gvisor netstack or equivalent) is explicitly gated on the netns/veth
// check of the target firmware. Until it lands, every carrier-dependent
// surface fails closed with the structural status ErrBlockedCarrier
// ("carrier absent" — a different failure layer than a network failure):
//
//   - StreamDialer: the contract a base-tunnel TCP carrier must satisfy;
//
//   - BackendBDialFunc: turns one StreamDialer into SessionConfig.DialFunc
//     so DialSession routes its raw TCP through the adapter while keeping
//     pinned TLS + capsule framing unchanged; NestedConfig.Validate
//     REQUIRES this dial func for BackendBProxy composition (a missing one
//     would mean an unconstrained direct inner dial);
//
//   - TunnelGeoTransport.WithHTTPSExchange: attaches the same class of
//     carrier to the §43 geo probe slot (CFTraceProvider becomes usable
//     once wired); until then probes fail closed with ErrBlockedCarrier.
package transportwarp

import (
	"context"
	"net"
	"net/netip"
)

// StreamDialer dials ONE TCP stream to addr THROUGH the base tunnel. The
// returned conn must behave like a normal stream conn (the pinned TLS
// handshake and H2 framing run on top unchanged). Implementations live in
// the field layer until the userspace netstack lands.
type StreamDialer interface {
	DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
}

// StreamDialerFunc adapts a function to StreamDialer.
type StreamDialerFunc func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)

// DialStream implements StreamDialer.
func (f StreamDialerFunc) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return f(ctx, addr)
}

// BackendBDialFunc converts a base-tunnel StreamDialer into a
// SessionConfig.DialFunc. The endpoint address is passed as the numeric
// ip:port string (DNS never participates — addendum §14/§27).
func BackendBDialFunc(sd StreamDialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, &net.OpError{Op: "dial", Net: network, Err: errBackendBNetwork}
		}
		ap, perr := netip.ParseAddrPort(addr)
		if perr != nil {
			return nil, &net.OpError{Op: "dial", Net: network, Err: perr}
		}
		return sd.DialStream(ctx, ap)
	}
}

var errBackendBNetwork = &net.AddrError{Err: "only tcp carriers supported", Addr: ""}

// WithHTTPSExchange attaches the base-tunnel HTTPS carrier to the geo
// transport's §62.6 probe slot. Passing nil restores the fail-closed
// ErrHTTPSNotWired default.
func (t *TunnelGeoTransport) WithHTTPSExchange(fn HTTPSExchangeFunc) *TunnelGeoTransport {
	t.https = fn
	return t
}

// HTTPSExchangeFunc fetches url through the tunnel (RFC 9110 GET semantics,
// response body returned whole; status handling belongs to the provider).
type HTTPSExchangeFunc func(ctx context.Context, url string) ([]byte, error)

// HTTPSExchange runs the attached carrier or fails closed when none is
// wired (§43: no silent direct fallback).
func (t *TunnelGeoTransport) HTTPSExchange(ctx context.Context, url string) ([]byte, error) {
	if t.https == nil {
		return nil, ErrHTTPSNotWired
	}
	return t.https(ctx, url)
}
