package tproxy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/daniellavrushin/b4/log"
	"github.com/daniellavrushin/b4/reserve"
)

// Tunnel-mode dial path (routing.mode = "tunnel"): the listener dials
// through a reserve.Carrier instead of an upstream SOCKS5 proxy. The
// carrier is resolved by kind at SyncConfig time; an unregistered kind
// never gets a listener (fail-closed: the tproxy port stays closed and
// the marked traffic is refused, never leaked around the tunnel).

// hostDialer is the optional hostname dial extension (tor: remote
// resolution keeps .onion reachable; everything else dials the IP).
type hostDialer interface {
	DialStreamHost(ctx context.Context, host string, port uint16) (net.Conn, error)
}

// tunnelAddr converts the transparent-socket original destination into the
// reserve.Carrier address shape (v4-mapped forms normalized).
func tunnelAddr(ip net.IP, port int) (netip.AddrPort, error) {
	if port < 1 || port > 65535 {
		return netip.AddrPort{}, fmt.Errorf("invalid port %d", port)
	}
	if v4 := ip.To4(); v4 != nil {
		var oct [4]byte
		copy(oct[:], v4)
		return netip.AddrPortFrom(netip.AddrFrom4(oct), uint16(port)), nil
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("bad destination ip %v", ip)
	}
	return netip.AddrPortFrom(a.Unmap(), uint16(port)), nil
}

// dialTunnelTCP dials one TCP stream through the listener's carrier. When
// the carrier is hostname-capable (tor) and the resolver knows the SNI
// domain, the domain rides the tunnel and tor resolves/remaps it (the
// .onion scope). Fail-open is honored from routing.upstream.fail_open.
func (l *Listener) dialTunnelTCP(ctx context.Context, origIP net.IP, origPort int, domain string) (net.Conn, error) {
	if l.Tunnel == nil {
		return nil, fmt.Errorf("tproxy: set %q has no tunnel carrier", l.SetName)
	}
	// Anti-loop (opera design §5): a carrier's OWN infrastructure must never
	// be routed back through it (reserve self-loop). When the carrier
	// declares the flow's domain as bypassed, deliver it DIRECT.
	if bd, ok := l.Tunnel.(reserve.BypassDomainChecker); ok && domain != "" && bd.BypassDomain(domain) {
		log.Tracef("tproxy: tunnel %s bypasses %q on set %q (direct, anti-loop)", l.TunnelKind, domain, l.SetName)
		return l.dialBypassDirect(ctx, origIP, origPort)
	}
	if hd, ok := l.Tunnel.(hostDialer); ok && domain != "" {
		if conn, err := hd.DialStreamHost(ctx, domain, uint16(origPort)); err == nil {
			return conn, nil
		} else {
			log.Tracef("tproxy: tunnel %s host dial %q failed on set %q: %v (falling back to ip)", l.TunnelKind, domain, l.SetName, err)
		}
	}
	addr, err := tunnelAddr(origIP, origPort)
	if err != nil {
		return nil, err
	}
	return l.Tunnel.DialStream(ctx, addr)
}

// dialBypassDirect delivers a bypassed flow straight to its destination. The
// bypass mark keeps it out of the set's own marked paths so the flow cannot
// re-enter the tunnel (or any tuple-split path) it is being excluded from.
func (l *Listener) dialBypassDirect(ctx context.Context, origIP net.IP, origPort int) (net.Conn, error) {
	d := markedDialer(10*time.Second, l.Upstream.BypassMark)
	return d.DialContext(ctx, "tcp", net.JoinHostPort(origIP.String(), fmt.Sprintf("%d", origPort)))
}

// connUDP adapts a datagram-capable net.Conn (reserve.Carrier.DialUDP
// shape: one conn bound to the original destination) to the udpRelay
// interface the UDP session table consumes.
type connUDP struct{ c net.Conn }

func (u *connUDP) Write(p []byte) (int, error)       { return u.c.Write(p) }
func (u *connUDP) Read(p []byte) (int, error)        { return u.c.Read(p) }
func (u *connUDP) SetReadDeadline(t time.Time) error { return u.c.SetReadDeadline(t) }
func (u *connUDP) Close() error                      { return u.c.Close() }

// dialTunnelUDP opens the carrier UDP relay for one original destination.
func (l *Listener) dialTunnelUDP(ctx context.Context, dst *net.UDPAddr) (udpRelay, error) {
	if l.Tunnel == nil {
		return nil, fmt.Errorf("tproxy: set %q has no tunnel carrier", l.SetName)
	}
	if !l.Tunnel.SupportsUDP() {
		return nil, reserve.ErrCarrierNoUDP
	}
	addr, err := tunnelAddr(dst.IP, dst.Port)
	if err != nil {
		return nil, err
	}
	conn, err := l.Tunnel.DialUDP(ctx, addr)
	if err != nil {
		return nil, err
	}
	return &connUDP{c: conn}, nil
}
