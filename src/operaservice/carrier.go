package operaservice

import (
	"context"
	"net"
	"net/netip"

	"github.com/daniellavrushin/b4/reserve"
)

// Kind implements reserve.Carrier (E-OPERA review C2: the opera engine
// joins the selection-tree registry with its design priority — TCP-only,
// below the WARP family, above fxvpn). SupportsUDP/DialStream live in
// service.go next to the data-plane dial seam.
func (r *Runtime) Kind() reserve.Kind { return reserve.KindOpera }

// DialUDP refuses: a TCP-only reserve never takes UDP scopes (fail-closed
// at the carrier, the torservice canon).
func (r *Runtime) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return nil, reserve.ErrCarrierNoUDP
}

var _ reserve.Carrier = (*Runtime)(nil)
