package warpservice

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/daniellavrushin/b4/reserve"
	warp "github.com/daniellavrushin/b4/transport/warp"
)

// MasqueCarrier adapts the warpservice engine (MASQUE-H2 over the WARP
// supervisor) to the reserve.Carrier seam (E-PROTON §7 canon). One netstack
// is attached to the CURRENT session generation and re-attached on the next
// dial failure after a session reconnect (the old carrier's sink dies with
// its session — netstack.go contract). IPv4/TCP only, honest SupportsUDP.
type MasqueCarrier struct {
	rt *Runtime

	mu      sync.Mutex
	carrier *warp.NetstackCarrier
	release func()
}

// NewMasqueCarrier binds the adapter. rt must be a started runtime; a nil
// runtime must never be passed (main registers only started engines).
func NewMasqueCarrier(rt *Runtime) *MasqueCarrier {
	return &MasqueCarrier{rt: rt}
}

// Kind implements reserve.Carrier.
func (c *MasqueCarrier) Kind() reserve.Kind { return reserve.KindMasque }

// SupportsUDP implements reserve.Carrier: netstack v1 carries IPv4 TCP only.
func (c *MasqueCarrier) SupportsUDP() bool { return false }

// DialUDP implements reserve.Carrier; the honest TCP-only refusal.
func (c *MasqueCarrier) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return nil, reserve.ErrCarrierNoUDP
}

// DialStream dials one TCP stream through the live MASQUE session.
func (c *MasqueCarrier) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	nc, err := c.attached()
	if err != nil {
		return nil, err
	}
	conn, derr := nc.DialStream(ctx, addr)
	if derr == nil {
		return conn, nil
	}
	// The cached netstack may belong to a dead session generation (its sink
	// fails on the first write). Tear it down, attach against the current
	// generation once, retry.
	c.rebuild()
	nc, err = c.attached()
	if err != nil {
		return nil, err
	}
	return nc.DialStream(ctx, addr)
}

// attached returns the cached netstack, attaching one on first use.
func (c *MasqueCarrier) attached() (*warp.NetstackCarrier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.carrier != nil {
		return c.carrier, nil
	}
	nc, release, err := c.rt.AttachNetstack()
	if err != nil {
		return nil, err
	}
	c.carrier = nc
	c.release = release
	return nc, nil
}

// rebuild drops the cached netstack (session reconnect path).
func (c *MasqueCarrier) rebuild() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.detachLocked()
}

// Detach releases the cached netstack (shutdown path; safe to call twice).
func (c *MasqueCarrier) Detach() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.detachLocked()
}

func (c *MasqueCarrier) detachLocked() {
	if c.release != nil {
		c.release()
		c.release = nil
	}
	c.carrier = nil
}

var _ reserve.Carrier = (*MasqueCarrier)(nil)
