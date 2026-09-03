// Carrier exposure (review P2, stage PT6b step а): the proton session
// becomes a reachable transport — DialStream (TCP through the netstack),
// DialUDP (the UDP full-scope leg, the ONLY one among the reserves) and
// the kind registration the scoped-router trees consume.
//
// Loop protection (fxvpn F6 canon): the dials take a RESOLVED
// netip.AddrPort and refuse the ACTIVE node's own entry IP as a target —
// the last-resort net against routing the tunnel into itself. Domain-level
// bypass (BypassSuffixes) belongs to the DNS/scoped-router layer BEFORE
// resolution, exactly like every other reserve.
package protonservice

import (
        "context"
        "errors"
        "net"
        "net/netip"

        "github.com/daniellavrushin/b4/reserve"
        twg "github.com/daniellavrushin/b4/transport/wg"
)

// ErrNotListening reports a dial attempt while no established session
// serves the runtime (the honest refusal — never a silent substitute).
var ErrNotListening = errors.New("proton: no established session to dial through")

// ErrProtonSelfLoop reports a dial to the ACTIVE node's own entry IP —
// refused before it can route the tunnel into itself (anti-loop lesson).
var ErrProtonSelfLoop = errors.New("proton: dial target is the active node itself")

// Kind implements reserve.Carrier: the stable kind string of the E-PROTON
// transport (design §7).
func (r *Runtime) Kind() reserve.Kind { return reserve.KindProton }

// SupportsUDP implements reserve.Carrier: Proton is the ONLY reserve with
// native UDP egress (design §1 — UDP full-scope).
func (r *Runtime) SupportsUDP() bool { return true }

// carrierSession snapshots the established session for a dial and applies
// the self-loop guard. Counters land on dialOK/dialFail by the caller.
func (r *Runtime) carrierSession(addr netip.AddrPort) (*twg.Session, error) {
        r.mu.Lock()
        sess := r.sess
        loop := r.selfLoopAddrLocked()
        r.mu.Unlock()
        // The loop guard is a TARGET-level refusal: it fires regardless of the
        // session state (routing the tunnel into itself must never become
        // reachable just because a session happens to exist).
        if loop.IsValid() && addr.Addr().Unmap() == loop {
                return nil, ErrProtonSelfLoop
        }
        if sess == nil || sess.State() != twg.StateEstablished {
                return nil, ErrNotListening
        }
        return sess, nil
}

// selfLoopAddrLocked resolves the ACTIVE node's entry IP under r.mu (the
// in-code last-resort loop net; invalid when nothing serves).
func (r *Runtime) selfLoopAddrLocked() netip.Addr {
        if r.profIdx < 0 || r.profIdx >= len(r.profiles) {
                return netip.Addr{}
        }
        a, err := netip.ParseAddr(r.profiles[r.profIdx].Node.EntryIP)
        if err != nil {
                return netip.Addr{}
        }
        return a.Unmap()
}

// DialStream implements reserve.Carrier / warp.StreamDialer: ONE TCP
// stream to addr THROUGH the established session's netstack.
func (r *Runtime) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
        sess, err := r.carrierSession(addr)
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
// the established session's netstack — the UDP full-scope leg the QUIC
// scopes exist for. Returns a datagram-capable net.Conn bound to addr.
func (r *Runtime) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
        sess, err := r.carrierSession(addr)
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

// recordDial bumps the shared dial counters (runtime + status view).
func (r *Runtime) recordDial(ok bool) {
        r.mu.Lock()
        defer r.mu.Unlock()
        if ok {
                r.dialOK++
        } else {
                r.dialFail++
        }
}
