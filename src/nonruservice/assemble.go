// Assembly + geo-gate wiring + the reserve carrier (nonruservice part 2).
package nonruservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/daniellavrushin/b4/reserve"
	"github.com/daniellavrushin/b4/transport/nested"
	twarp "github.com/daniellavrushin/b4/transport/warp"
)

// ErrInnerTransportDown is the honest geo-transport refusal while the inner
// path is unavailable (the gate treats it as inner-path-lost when open).
var ErrInnerTransportDown = errors.New("nonru: inner transport unavailable")

// ErrNotListening is the honest carrier refusal without a live inner layer.
var ErrNotListening = errors.New("nonru: gate closed or no live inner layer to dial through")

// assemble provisions nothing itself (the M+M runtime's inner reconciler owns
// the secondary slot); it loads the BASE identity for the outer netstack
// source address and builds the composition + the gate on top of the plane.
// A missing base identity parks in waiting-base (the base reconciler writes
// the slot; the next tick retries).
func (r *Runtime) assemble(ctx context.Context) error {
	r.mu.Lock()
	baseSlot := r.baseSlot
	r.mu.Unlock()

	ident, err := (&twarp.IdentityStore{Path: baseSlot}).Load()
	if err != nil {
		if errors.Is(err, twarp.ErrIdentityAbsent) || errors.Is(err, twarp.ErrIdentityCorrupt) {
			r.setState(StateWaitingBase)
			r.appendEvent(Event{Name: "nonru_waiting_base_identity", Detail: err.Error()})
			return nil // not a failure: the base reconciler provisions the slot
		}
		return fmt.Errorf("base identity slot: %w", err)
	}
	local, perr := netip.ParseAddr(ident.AssignedV4)
	if perr != nil || !local.Is4() {
		return fmt.Errorf("nonru: base identity assigned v4 %q invalid", ident.AssignedV4)
	}
	var b4 [4]byte
	b4 = local.As4()

	r.setState(StateAssembling)
	mtu := r.cfg.InnerMTU
	if mtu <= 0 {
		mtu = nested.MaxInnerMTU
	}
	rt, aerr := nested.NewMasqueMasqueRuntime(nested.MasqueMasqueConfig{
		Pair: nested.PairConfig{
			// The OUTER layer IS the base warp: primary slot, the base
			// endpoint, the base plane (ADR-WARP-6 — the composition rides
			// the verified base path; the different-edge rule is enforced
			// by config validation).
			Outer: nested.LayerSpec{
				Kind:         nested.KindMasqueH2,
				IdentitySlot: nested.SlotPrimary,
				ProfileID:    "masque",
				Endpoint:     r.baseAt,
				MTU:          twarp.DefaultMTU,
			},
			Inner: nested.LayerSpec{
				Kind:         nested.KindMasqueH2,
				IdentitySlot: nested.SlotSecondary,
				ProfileID:    "masque",
				Endpoint:     r.innerAt,
				MTU:          mtu,
			},
		},
		Plane:   r.basePlane,
		LocalV4: b4,
		// The composition's masquerade posture: the INNER layer's hello
		// (the outer plane's fingerprint belongs to the base supervisor
		// template — system.warp.masquerade).
		Fingerprint:   r.cfg.Fingerprint,
		InnerEnroll:   &twarp.EnrollClient{HTTP: r.opts.HTTP, BaseURL: r.opts.EnrollBaseURL},
		InnerSlotPath: r.cfg.EffectiveIdentityPath(),
		OnEvent: func(ev nested.Event) {
			r.appendEvent(Event{Name: "nonru_composition_event", Detail: ev.Class + ": " + ev.Reason})
		},
		InnerSink: func(ev twarp.SupervisorEvent) {
			r.appendEvent(Event{Name: "nonru_inner_event", Detail: ev.Name})
		},
	})
	if aerr != nil {
		return fmt.Errorf("nonru assembly: %w", aerr)
	}
	if err := rt.Start(ctx); err != nil {
		return fmt.Errorf("nonru start: %w", err)
	}

	gate, gerr := twarp.NewNonRUGate(twarp.NonRUConfig{
		Providers: []twarp.GeoProvider{
			// The quorum voters (dns-resolver-authority class; §43 — two
			// independent authorities must agree on the same non-RU
			// country; the classify oracle is the shared E7 seam).
			twarp.NewWhoamiDNSProvider("akamai-whoami", "whoami.akamai.net", r.classifyFn()),
			twarp.NewWhoamiDNSProvider("google-myaddr", "o-o.myaddr.l.google.com", r.classifyFn()),
			// The corroborator: CF's own view of the egress (warp=on|plus
			// proves the tunnel path; loc= cross-checks the oracle). It
			// carries no DNS proof and never votes.
			twarp.NewCFTraceProvider("cf-trace"),
		},
		RequiredProviders: 2,
		Transport:         r.geoTransport,
		CurrentGen:        r.currentPathSerial,
		// ConfigGen: intentionally not wired — config changes restart the
		// daemon (the standard b4 posture; recorded in the package docs).
		AttestationTTL:  time.Duration(r.cfg.EffectiveAttestationTTL()) * time.Second,
		RefreshInterval: time.Duration(r.cfg.EffectiveRefreshInterval()) * time.Second,
		RUCountries:     r.cfg.EffectiveRUCountries(),
		FallbackToBase:  r.cfg.FallbackToBase,
		OnRouteOpen:     r.promoteRoute,
		OnRouteRevoke:   r.revokeRoute,
		Sink: func(ev twarp.NonRUEvent) {
			r.appendEvent(Event{Name: ev.Name, Detail: nonruEventDetail(ev)})
		},
		Now: r.opts.Now,
		BaseColo: func() string {
			return r.base.Status().Status.LastColo
		},
		InnerColo: func() string {
			sup := r.innerSupervisor()
			if sup == nil {
				return ""
			}
			return sup.Snapshot().LastColo
		},
	})
	if gerr != nil {
		rt.Stop()
		return fmt.Errorf("nonru gate: %w", gerr)
	}
	if err := gate.Start(ctx); err != nil {
		rt.Stop()
		return fmt.Errorf("nonru gate start: %w", err)
	}

	r.mu.Lock()
	r.mm = rt
	r.gate = gate
	r.state = StateUp
	r.mu.Unlock()
	r.appendEvent(Event{Name: "nonru_composition_started",
		Detail: fmt.Sprintf("inner=%s gate=probing oracle=%t", r.innerAt, r.oracleLoaded)})
	return nil
}

// classifyFn returns the active classify closure (nil-safe: an unloaded
// oracle classifies everything unknown — the engine treats "" as unknown).
func (r *Runtime) classifyFn() func(netip.Addr) string {
	if r.classify == nil {
		return func(netip.Addr) string { return "" }
	}
	return r.classify
}

// nonruEventDetail renders one gate event compactly for the event ring.
func nonruEventDetail(ev twarp.NonRUEvent) string {
	detail := ev.Detail
	if ev.Provider != "" {
		detail = "provider=" + ev.Provider + " " + detail
	}
	if ev.Reason != "" {
		detail = "reason=" + ev.Reason + " " + detail
	}
	if ev.Verdict != "" {
		detail = "verdict=" + ev.Verdict + " " + detail
	}
	return detail
}

func (r *Runtime) setState(s string) {
	r.mu.Lock()
	r.state = s
	r.mu.Unlock()
}

// ---- geo-gate plumbing (E7) ----

// innerSupervisor snapshots the live INNER supervisor of the composition
// (nil while the child is down — the accessor contracts, never stale).
func (r *Runtime) innerSupervisor() *twarp.Supervisor {
	r.mu.Lock()
	mm := r.mm
	r.mu.Unlock()
	if mm == nil {
		return nil
	}
	return mm.InnerSupervisor()
}

// currentPathSerial is the gate's CurrentGen: the identity of the PROBE PATH.
// Every observed inner-session change bumps the serial, so an open
// attestation stamped against an older path is revoked (§69-20 stale parent
// route token / parent-reconnected).
func (r *Runtime) currentPathSerial() uint64 {
	r.pathMu.Lock()
	defer r.pathMu.Unlock()
	return r.pathSerial
}

// geoTransport returns the geo probe transport bound to the CURRENT inner
// session (cached per path identity): DNS probes ride the session's packet
// surface with the §43 counter-delta proof, the HTTPS exchange rides the
// shared inner netstack (the carrier's host — one tunnel source address).
func (r *Runtime) geoTransport() (twarp.GeoProbeTransport, error) {
	sup := r.innerSupervisor()
	if sup == nil {
		return nil, ErrInnerTransportDown
	}
	if !sup.Snapshot().RouteHeld {
		return nil, ErrInnerTransportDown
	}
	sess := sup.CurrentSession()
	if sess == nil {
		return nil, ErrInnerTransportDown
	}
	r.pathMu.Lock()
	defer r.pathMu.Unlock()
	if r.geoTr != nil && r.geoSess == sess {
		return r.geoTr, nil
	}
	// A new path identity: drop the stale cache, rebind, bump the serial.
	r.closeGeoTransportLocked()
	ns, err := r.attachedNetstack(sup)
	if err != nil {
		return nil, err
	}
	tr := twarp.AttachTunnelGeoTransport(sess).
		WithHTTPSExchange(twarp.HTTPSExchangeViaNetstack(ns))
	r.geoSess, r.geoTr = sess, tr
	r.pathSerial++
	return tr, nil
}

// closeGeoTransport drops the cached geo transport (session identity change
// / teardown). The transport's tap stop is idempotent through the session.
func (r *Runtime) closeGeoTransport() {
	r.pathMu.Lock()
	defer r.pathMu.Unlock()
	r.closeGeoTransportLocked()
}

func (r *Runtime) closeGeoTransportLocked() {
	if r.geoTr != nil {
		r.geoTr.Close()
	}
	r.geoTr = nil
	r.geoSess = nil
}

// ---- route promotion / revocation (the reserve registry IS the route) ----

// promoteRoute is the gate's OnRouteOpen: the carrier joins the reserve
// registry (kind=nonru) — from this moment routing.mode=tunnel sets resolve
// it. Local-only, well inside any hook budget.
func (r *Runtime) promoteRoute(att twarp.GeoAttestation) error {
	reserve.Register(r)
	r.mu.Lock()
	r.gateOpen = true
	r.mu.Unlock()
	r.appendEvent(Event{Name: "nonru_route_promoted",
		Detail: fmt.Sprintf("country=%s providers=%d/%d", att.Country, att.Providers, att.Quorum)})
	return nil
}

// revokeRoute is the gate's OnRouteRevoke: unregister the carrier, detach the
// inner netstack (in-flight dials fail fast instead of hanging on a dead
// plane) — the §63 revocation latency is measured AROUND this call.
func (r *Runtime) revokeRoute(reason string) error {
	reserve.Unregister(reserve.KindNonRU)
	r.detachNetstack()
	r.mu.Lock()
	r.gateOpen = false
	r.mu.Unlock()
	r.appendEvent(Event{Name: "nonru_route_revoked", Detail: "reason=" + reason})
	return nil
}

// ---- the reserve carrier (kind=nonru, IPv4/TCP — addendum §38 posture) ----

// Kind implements reserve.Carrier.
func (r *Runtime) Kind() reserve.Kind { return reserve.KindNonRU }

// SupportsUDP implements reserve.Carrier: the honest v1 refusal — the inner
// MASQUE netstack carries IPv4/TCP only (addendum §38: an L4 TCP-only proxy
// MUST report the limitation instead of pretending).
func (r *Runtime) SupportsUDP() bool { return false }

// DialStream dials ONE TCP stream to addr through the nested inner layer
// (the chain-carrier canon: cached netstack, one re-attach on failure).
func (r *Runtime) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	sup := r.innerSupervisor()
	if sup == nil {
		r.dialFail.Add(1)
		return nil, ErrNotListening
	}
	if !sup.Snapshot().RouteHeld {
		r.dialFail.Add(1)
		return nil, ErrNotListening
	}
	nc, err := r.attachedNetstack(sup)
	if err != nil {
		r.dialFail.Add(1)
		return nil, err
	}
	conn, derr := nc.DialStream(ctx, addr)
	if derr == nil {
		r.dialOK.Add(1)
		return conn, nil
	}
	// The cached netstack may belong to a dead inner generation (the
	// warpservice canon): drop it, re-attach once, retry.
	r.detachNetstack()
	nc, err = r.attachedNetstack(sup)
	if err != nil {
		r.dialFail.Add(1)
		return nil, err
	}
	conn, derr = nc.DialStream(ctx, addr)
	if derr != nil {
		r.dialFail.Add(1)
	}
	return conn, derr
}

// DialUDP implements reserve.Carrier: the honest refusal.
func (r *Runtime) DialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	r.dialFail.Add(1)
	return nil, reserve.ErrCarrierNoUDP
}

// attachedNetstack returns the cached inner netstack, attaching one on
// first use (the chains-carrier canon — the geo HTTPS exchange shares it).
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
	mtu := r.cfg.InnerMTU
	if mtu <= 0 {
		mtu = nested.MaxInnerMTU
	}
	nc, release, err := sup.AttachNetstack(local, mtu)
	if err != nil {
		return nil, err
	}
	r.nsCarrier, r.nsRelease = nc, release
	return nc, nil
}

// detachNetstack drops the cached inner netstack (revocation / teardown /
// re-attach path; safe to call twice).
func (r *Runtime) detachNetstack() {
	r.nsMu.Lock()
	defer r.nsMu.Unlock()
	if r.nsRelease != nil {
		r.nsRelease()
		r.nsRelease = nil
	}
	r.nsCarrier = nil
}

// Compile-time proof the Runtime satisfies the reserve contract.
var _ reserve.Carrier = (*Runtime)(nil)
