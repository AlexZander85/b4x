// NetstackCarrier (design 1.2): the outer runs its data plane through a
// userspace gVisor netstack (transportwg ModeNetstack), so the stack itself
// is the virtual NIC of the nested pair:
//
//	InjectUDPDatagram / DialUDPThrough -> connected UDP sockets on the stack;
//	DialTCPThrough                     -> gonet TCP dial on the stack.
//
// Zero new dependencies: the stack type comes from the already-pinned
// amneziawg-go v3 module (the same handle WG6's LoopbackForwarder dials).
// Segmentation/MSS follow the stack MTU (inner <= 1200 enforced by the
// matrix config validation), so PMTU discovery across two layers is a
// non-issue by construction.
package nested

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// NetstackCarrier carries inner traffic through the OUTER session's netstack.
type NetstackCarrier struct {
	ns *netstack.Net
	// label names the outer generation this stack belongs to (proof text).
	label string

	closed atomic.Bool
}

// NewNetstackCarrier wraps one live netstack. label should identify the
// outer generation ("gen=N") so proofs are attributable in traces.
func NewNetstackCarrier(ns *netstack.Net, label string) (*NetstackCarrier, error) {
	if ns == nil {
		return nil, fmt.Errorf("nested: netstack carrier requires a live stack")
	}
	return &NetstackCarrier{ns: ns, label: label}, nil
}

// DialUDPThrough opens one connected UDP socket on the outer stack.
func (c *NetstackCarrier) DialUDPThrough(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if c.closed.Load() {
		return nil, ErrCarrierClosed
	}
	conn, err := c.ns.DialContext(ctx, "udp", dst.String())
	if err != nil {
		return nil, fmt.Errorf("nested: netstack udp dial %v: %w", dst, err)
	}
	return conn, nil
}

// InjectUDPDatagram sends one datagram through a short-lived stack socket.
func (c *NetstackCarrier) InjectUDPDatagram(dst netip.AddrPort, payload []byte) error {
	conn, err := c.DialUDPThrough(context.Background(), dst)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, werr := conn.Write(payload)
	return werr
}

// DialTCPThrough opens one TCP stream on the outer stack (W+M inner MASQUE
// control socket path). The stack segments against its own MTU; no kernel
// MSS clamp is needed for userspace-terminating TCP.
func (c *NetstackCarrier) DialTCPThrough(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	if c.closed.Load() {
		return nil, ErrCarrierClosed
	}
	conn, err := c.ns.DialContext(ctx, "tcp", dst.String())
	if err != nil {
		return nil, fmt.Errorf("nested: netstack tcp dial %v: %w", dst, err)
	}
	return conn, nil
}

// ProofSnapshot: a live stack IS the proof (traffic cannot bypass it).
func (c *NetstackCarrier) ProofSnapshot() (string, bool) {
	if c.closed.Load() || c.ns == nil {
		return "", false
	}
	return "netstack:" + c.label, true
}

// Close marks the carrier unusable; the underlying stack dies together with
// the owning outer tunnel (ownership stays with the outer session).
func (c *NetstackCarrier) Close() { c.closed.Store(true) }
