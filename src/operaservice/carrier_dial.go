package operaservice

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/daniellavrushin/b4/reserve"
)

// baseCarrierKinds are the base transports eligible as the bootstrap carrier
// (design §2: "вызовы API через активный базовый транспорт MASQUE/WG"). Nested
// chains, tor, fxvpn, proton and opera itself are not base transports and are
// explicitly excluded — the reserve must never bootstrap through itself or a
// peer reserve.
var baseCarrierKinds = map[reserve.Kind]struct{}{
	reserve.KindWarp:   {},
	reserve.KindMasque: {},
	reserve.KindH3:     {},
}

// hostStreamDialer is the hostname-capable base-carrier seam (in-tunnel DNS):
// implemented by the MASQUE and AWG-WARP runtimes.
type hostStreamDialer interface {
	DialStreamHost(ctx context.Context, host string, port uint16) (net.Conn, error)
}

// BaseCarrierDial builds the bootstrap-through-carrier dial function for
// operaservice.Build: every dial is routed through the highest-priority
// registered base transport (MASQUE/AWG-WARP/H3). The opera failover dialer
// tries DIRECT first and only falls back here, so this is the "reserve that
// reaches out through the base tunnel when the API is IP-blocked" path
// (design §2/§5). The base carrier is resolved at DIAL time, so a carrier that
// registers after Build (engine start order) is picked up without a restart.
//
// Resolution order is priority DESC via reserve.List(); when no base carrier
// is registered the dial fails closed with a typed error (the opera failover
// then surfaces the aggregate direct+carrier failure).
func BaseCarrierDial() DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, fmt.Errorf("operaservice: carrier dial: network %q unsupported (TCP only)", network)
		}
		c := pickBaseCarrier()
		if c == nil {
			return nil, fmt.Errorf("operaservice: no base transport registered for bootstrap-through-carrier")
		}
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("operaservice: carrier dial %q: %w", addr, err)
		}
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			return nil, fmt.Errorf("operaservice: carrier dial %q: bad port", addr)
		}
		// Prefer the hostname seam (the carrier resolves in-tunnel); fall back
		// to resolving here and dialing the literal address.
		if hd, ok := c.(hostStreamDialer); ok {
			if conn, herr := hd.DialStreamHost(ctx, host, uint16(p)); herr == nil {
				return conn, nil
			}
		}
		ipStr := host
		if net.ParseIP(host) == nil {
			ips, lerr := net.DefaultResolver.LookupIPAddr(ctx, host)
			if lerr != nil || len(ips) == 0 {
				return nil, fmt.Errorf("operaservice: carrier dial: resolve %q: %w", host, lerr)
			}
			ipStr = ips[0].IP.String()
		}
		ap, aerr := netip.ParseAddrPort(net.JoinHostPort(ipStr, portStr))
		if aerr != nil {
			return nil, fmt.Errorf("operaservice: carrier dial %q: %w", addr, aerr)
		}
		return c.DialStream(ctx, ap)
	}
}

// pickBaseCarrier returns the highest-priority registered base transport, or
// nil when none is registered.
func pickBaseCarrier() reserve.Carrier {
	for _, e := range reserve.List() { // priority DESC
		if _, ok := baseCarrierKinds[e.Kind]; ok {
			return e.Carrier
		}
	}
	return nil
}
