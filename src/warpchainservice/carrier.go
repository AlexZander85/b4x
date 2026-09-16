// Carrier exposure: the chain's INNER layer is the data plane. masque+awg
// and awg+awg serve TCP + UDP through the inner AWG session's netstack (the
// proton canon surface); awg+masque and masque+masque serve IPv4/TCP through
// the inner MASQUE supervisor's attached netstack with the warpservice
// re-attach discipline (one netstack per supervisor generation, rebuilt on
// the first dial failure — a dead session's netstack fails on write, never
// silently).
package warpchainservice

import (
	"context"
	"net"
	"net/netip"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/reserve"
	twarp "github.com/daniellavrushin/b4/transport/warp"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// Kind implements reserve.Carrier: the chain kind ("masque+awg" |
// "awg+masque" | "awg+awg" | "masque+masque").
func (r *Runtime) Kind() reserve.Kind { return r.kind }

// SupportsUDP implements reserve.Carrier: the compositions whose data plane
// is the inner AWG netstack (masque+awg and awg+awg). The awg+masque and
// masque+masque inner MASQUE netstacks carry IPv4/TCP only.
func (r *Runtime) SupportsUDP() bool {
	return r.cfg.Kind == config.ChainKindMasqueAwg || r.cfg.Kind == config.ChainKindAwgAwg
}

// DialStream dials ONE TCP stream to addr through the chain's inner layer.
func (r *Runtime) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	switch r.cfg.Kind {
	case config.ChainKindMasqueAwg:
		return r.dialMasqueAwg(ctx, addr)
	case config.ChainKindAwgMasque:
		return r.dialAwgMasque(ctx, addr)
	case config.ChainKindAwgAwg:
		return r.dialWgWg(ctx, addr)
	case config.ChainKindMasqueMasque:
		return r.dialMasqueMasque(ctx, addr)
	default:
		r.recordDial(false)
		return nil, ErrNotListening
	}
}

// DialUDP dials ONE UDP exchange through the chain's inner AWG netstack
// leg (masque+awg and awg+awg); the honest refusal elsewhere.
func (r *Runtime) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	if r.cfg.Kind != config.ChainKindMasqueAwg && r.cfg.Kind != config.ChainKindAwgAwg {
		r.recordDial(false)
		return nil, reserve.ErrCarrierNoUDP
	}
	sess := r.innerAWGSession()
	if sess == nil {
		r.recordDial(false)
		return nil, ErrNotListening
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

// innerAWGSession snapshots the established INNER AWG session of the
// masque+awg or awg+awg composition (nil while the child is down — the
// accessor contracts, never a stale session).
func (r *Runtime) innerAWGSession() *twg.Session {
	if r.cfg.Kind == config.ChainKindAwgAwg {
		r.mu.Lock()
		ww := r.wPlusW
		r.mu.Unlock()
		if ww == nil {
			return nil
		}
		sess := ww.InnerSession()
		if sess == nil || sess.State() != twg.StateEstablished {
			return nil
		}
		return sess
	}
	r.mu.Lock()
	mw := r.mPlusW
	r.mu.Unlock()
	if mw == nil {
		return nil
	}
	sess := mw.InnerSession()
	if sess == nil || sess.State() != twg.StateEstablished {
		return nil
	}
	return sess
}

// dialMasqueAwg: TCP through the inner AWG session's netstack.
func (r *Runtime) dialMasqueAwg(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return r.dialInnerAWGTCP(ctx, addr)
}

// dialWgWg: TCP through the inner AWG session's netstack of the W+W
// composition (the InnerSession accessor snapshot — nil while the child is
// down, never a stale netstack).
func (r *Runtime) dialWgWg(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return r.dialInnerAWGTCP(ctx, addr)
}

// dialInnerAWGTCP is the shared inner-AWG-netstack TCP leg (masque+awg and
// awg+awg — the same carrier surface, different inner owners).
func (r *Runtime) dialInnerAWGTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	sess := r.innerAWGSession()
	if sess == nil {
		r.recordDial(false)
		return nil, ErrNotListening
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

// dialAwgMasque: TCP through the inner MASQUE supervisor's attached
// netstack (cached per generation; one re-attach on the first failure).
func (r *Runtime) dialAwgMasque(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return r.dialInnerMasqueTCP(ctx, addr)
}

// dialMasqueMasque: TCP through the M+M inner MASQUE supervisor's attached
// netstack — the same carrier surface and re-attach discipline as the
// awg+masque inner leg (the supervisor accessor differs, nothing else).
func (r *Runtime) dialMasqueMasque(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	return r.dialInnerMasqueTCP(ctx, addr)
}

// innerMasqueSupervisor snapshots the INNER MASQUE supervisor of the
// awg+masque or masque+masque composition (nil while the child is down —
// the accessor contracts, never a stale supervisor).
func (r *Runtime) innerMasqueSupervisor() *twarp.Supervisor {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cfg.Kind == config.ChainKindMasqueMasque {
		if r.mPlusM == nil {
			return nil
		}
		return r.mPlusM.InnerSupervisor()
	}
	if r.wPlusM == nil {
		return nil
	}
	return r.wPlusM.InnerSupervisor()
}

// dialInnerMasqueTCP is the shared inner-MASQUE-netstack TCP leg
// (awg+masque and masque+masque — the same carrier surface, different
// inner owners).
func (r *Runtime) dialInnerMasqueTCP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	sup := r.innerMasqueSupervisor()
	if sup == nil {
		r.recordDial(false)
		return nil, ErrNotListening
	}
	snap := sup.Snapshot()
	if !snap.RouteHeld {
		r.recordDial(false)
		return nil, ErrNotListening
	}
	nc, err := r.attachedNetstack(sup)
	if err != nil {
		r.recordDial(false)
		return nil, err
	}
	conn, derr := nc.DialStream(ctx, addr)
	if derr == nil {
		r.recordDial(true)
		return conn, nil
	}
	// The cached netstack may belong to a dead inner generation (the
	// warpservice canon): drop it, re-attach once, retry.
	r.detachNetstack()
	nc, err = r.attachedNetstack(sup)
	if err != nil {
		r.recordDial(false)
		return nil, err
	}
	conn, derr = nc.DialStream(ctx, addr)
	if derr != nil {
		r.recordDial(false)
	}
	return conn, derr
}

// attachedNetstack returns the cached inner netstack, attaching one on
// first use.
func (r *Runtime) attachedNetstack(sup *twarp.Supervisor) (*twarp.NetstackCarrier, error) {
	r.nsMu.Lock()
	defer r.nsMu.Unlock()
	if r.nsCarrier != nil {
		return r.nsCarrier, nil
	}
	local, ok := sup.AssignedLocalV4()
	if !ok {
		return nil, ErrNotListening
	}
	nc, release, err := sup.AttachNetstack(local, r.innerMTU())
	if err != nil {
		return nil, err
	}
	r.nsCarrier, r.nsRelease = nc, release
	return nc, nil
}

// detachNetstack drops the cached inner netstack (generation switch /
// teardown path; safe to call twice).
func (r *Runtime) detachNetstack() {
	r.nsMu.Lock()
	defer r.nsMu.Unlock()
	if r.nsRelease != nil {
		r.nsRelease()
		r.nsRelease = nil
	}
	r.nsCarrier = nil
}

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
