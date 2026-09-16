// Carrier exposure (the proton canon): the AWG-WARP session becomes a
// reachable transport — DialStream (TCP through the session's netstack),
// DialUDP (the UDP full-scope leg through the same netstack) and the kind
// registration the scoped-router trees consume. The Runtime itself carries
// the reserve.Carrier implementation; this file holds only the dial paths.
//
// The NETSTACK mode owns these paths. In kernel mode the data plane is the
// /dev/net/tun device plus the PBR plane — there is no userspace netstack
// and every dial refuses with ErrKernelMode (the main.go wiring does not
// register the carrier there at all; this is the belt-and-suspenders
// posture for direct consumers).
package awgwarpservice

import (
	"context"
	"net"
	"net/netip"

	"github.com/daniellavrushin/b4/reserve"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// Kind implements reserve.Carrier: the stable kind of the AWG-WARP
// transport — the head of the reserve tree.
func (r *Runtime) Kind() reserve.Kind { return reserve.KindWarp }

// SupportsUDP implements reserve.Carrier: AWG-WARP serves native UDP
// egress through the session's gVisor netstack (the QUIC-scope leg) in
// NETSTACK mode; kernel mode has no userspace carrier at all.
func (r *Runtime) SupportsUDP() bool {
	r.mu.Lock()
	kernel := r.kernelMode
	r.mu.Unlock()
	return !kernel
}

// carrierSession snapshots the established session for one dial. No
// self-loop guard is needed here (the warpservice canon): the WARP edge
// endpoint is a foreign host — dialing it through the tunnel is merely
// pointless, never a routing loop; the DNS/scoped-router layer owns the
// domain-level bypasses.
func (r *Runtime) carrierSession() (*twg.Session, error) {
	r.mu.Lock()
	kernel := r.kernelMode
	sess := r.sess
	r.mu.Unlock()
	if kernel {
		return nil, ErrKernelMode
	}
	if sess == nil || sess.State() != twg.StateEstablished {
		return nil, ErrNotListening
	}
	return sess, nil
}

// DialStream implements reserve.Carrier: ONE TCP stream to addr THROUGH
// the established session's netstack.
func (r *Runtime) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	sess, err := r.carrierSession()
	if err != nil {
		r.recordDial(false)
		return nil, err
	}
	tun := sess.Tunnel()
	if tun == nil || tun.Netstack == nil {
		r.recordDial(false)
		return nil, ErrNotListening
	}
	conn, err := tun.Netstack.DialContextTCPAddrPort(ctx, addr)
	if err != nil {
		r.recordDial(false)
		return nil, err
	}
	r.recordDial(true)
	return conn, nil
}

// DialUDP implements reserve.Carrier: ONE UDP exchange to addr THROUGH
// the established session's netstack — the UDP full-scope leg.
func (r *Runtime) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	sess, err := r.carrierSession()
	if err != nil {
		r.recordDial(false)
		return nil, err
	}
	tun := sess.Tunnel()
	if tun == nil || tun.Netstack == nil {
		r.recordDial(false)
		return nil, ErrNotListening
	}
	conn, err := tun.Netstack.DialUDPAddrPort(netip.AddrPort{}, addr)
	if err != nil {
		r.recordDial(false)
		return nil, err
	}
	r.recordDial(true)
	return conn, nil
}

// recordDial bumps the dial counters (status view).
func (r *Runtime) recordDial(ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ok {
		r.dialOK++
	} else {
		r.dialFail++
	}
}

// Compile-time proof the Runtime satisfies the reserve contract.
var _ reserve.Carrier = (*Runtime)(nil)
