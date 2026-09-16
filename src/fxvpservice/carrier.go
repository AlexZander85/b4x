package fxvpservice

import (
	"context"
	"net"
	"net/netip"

	"github.com/daniellavrushin/b4/reserve"
)

// Kind implements reserve.Carrier (fxvpn-reserve-review stage: the engine
// joins the selection-tree registry with its design priority — TCP-only,
// below opera, above proton). SupportsUDP/DialStream live in service.go
// next to the data-plane dial seam.
func (r *Runtime) Kind() reserve.Kind { return reserve.KindFxvpn }

// DialUDP refuses: a TCP-only reserve never takes UDP scopes (fail-closed
// at the carrier, the torservice canon).
func (r *Runtime) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return nil, reserve.ErrCarrierNoUDP
}

var _ reserve.Carrier = (*Runtime)(nil)
