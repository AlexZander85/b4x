// Nested WG-WG runtime (design §7 R3, gool pattern): the OUTER session is
// the primary AWG transport; the INNER session's ONLY egress is a Backend-B
// LoopbackForwarder dialed through the outer tunnel's netstack (carrier
// proof lives in NestedWgConfig.Validate — ErrInnerNotLoopback).
//
// The controller is callback-driven (the session exposes honest
// OnEstablished/OnLost transitions, unlike the polled RouteHeld of
// transportwarp E5):
//
//	outer OnEstablished -> parent generation bumps, CHILD-FIRST teardown of
//	                        the previous pair (inner Stop -> forwarder
//	                        Close), then a NEW forwarder against THIS
//	                        generation's netstack (every generation gets a
//	                        fresh netstack!) and a fresh inner session
//	                        against the fresh forwarder address;
//	outer OnLost        -> immediate child invalidation: zero dialing
//	                        through a dead parent (transportwarp E5
//	                        semantics; the inner watchdog never gets the
//	                        chance — child-first is the point).
//
// Handler serialization: parent callbacks run on the outer session's run
// goroutine; Stop runs on the caller's. Both mutate the child pair, so they
// serialize on the runtime mutex — a Stop racing a revalidation observes
// either the old child (kills it) or the new one (never an orphan).
package transportwg

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// NestedLinkState mirrors transportwarp LinkState semantics for the WG-WG
// composition.
type NestedLinkState string

const (
	NestedWaitingParent    NestedLinkState = "waiting-parent"
	NestedUp               NestedLinkState = "up"
	NestedChildInvalidated NestedLinkState = "child-invalidated"
)

// WgLayerStatus is one layer's post-establishment snapshot (PATCH-28, N-5;
// local mirror of the nested package's LayerStatus — importing nested here
// would close the nested->wg import cycle).
type WgLayerStatus struct {
	// HandshakeMS is the AGE of the layer's last handshake in ms; -1 = never.
	HandshakeMS int64
	RXBytes     uint64
	TXBytes     uint64
}

// NestedWgStatus is the externally visible snapshot.
type NestedWgStatus struct {
	Link      NestedLinkState
	ParentGen uint64 // bumps on every newly established outer generation
	// ChildRunning: the inner session exists and is not closed. Note the
	// inner layer self-manages restarts (its own supervisor); the runtime
	// only respawns children on PARENT transitions.
	ChildRunning bool
	// Per-layer transfer snapshots (PATCH-28, N-5 / design §1.2).
	Outer WgLayerStatus
	Inner WgLayerStatus
}

// wgLayerStatusOf converts one session's telemetry (nil/closed session ->
// never established).
func wgLayerStatusOf(sess *Session) WgLayerStatus {
	if sess == nil || sess.State() == StateClosed {
		return WgLayerStatus{HandshakeMS: -1}
	}
	tel := sess.Telemetry()
	ms := int64(-1)
	if tel.HandshakeUnix > 0 {
		ms = time.Since(time.Unix(tel.HandshakeUnix, 0)).Milliseconds()
		if ms < 0 {
			ms = 0
		}
	}
	return WgLayerStatus{HandshakeMS: ms, RXBytes: tel.RXBytes, TXBytes: tel.TXBytes}
}

// NestedWgOptions carries tuning knobs; zero values map to design defaults.
type NestedWgOptions struct {
	// DNS resolver configured inside BOTH netstacks (default 8.8.8.8).
	DNS netip.Addr
	// MaxGenerations bounds INNER restart cycles (0 = unlimited). The outer
	// layer intentionally has no cap here: its lifecycle policy belongs to
	// the supervisor above the R3 composition.
	MaxGenerations int
	// OuterHealth / InnerHealth adjust each layer's HealthConfig at build
	// time (CI shrinks handshake/gate/watchdog windows through them;
	// production leaves them nil and gets design numbers). KeepaliveSec is
	// preset from the validated layers before the hook runs — a hook MAY
	// override it, breaking outer!=inner separation at its own risk.
	OuterHealth func(*HealthConfig)
	InnerHealth func(*HealthConfig)
	// OnEvent receives both layers' lifecycle events plus the runtime's own
	// wg_nested_* bridge events. Must be non-blocking and must not call
	// Stop synchronously (same contract as SessionCallbacks).
	OnEvent func(SessionEvent)
	// VerboseDiagnostics routes BOTH layers' per-generation device logs to
	// stdout (debug aid; production keeps the silent logger).
	VerboseDiagnostics bool
	// ObserveGate optionally records per-layer trust-gate durations
	// (PATCH-09, MAJOR-5 / design §1.2: per-layer attribution for all three
	// runtimes). transportwg cannot import transport/nested (import cycle),
	// so the composition site wires nested.Metrics.ObserveGate through this
	// function seam. nil = disabled (no behavior change).
	ObserveGate func(layer string, d time.Duration)
}

// NestedWgRuntime owns the outer+inner lifecycles and the Backend-B carrier.
type NestedWgRuntime struct {
	cfg NestedWgConfig
	opt NestedWgOptions

	mu             sync.Mutex
	link           NestedLinkState
	parentGen      uint64
	ctx            context.Context
	cancel         context.CancelFunc
	outer          *Session
	fwd            *LoopbackForwarder
	inner          *Session
	outerGateStart time.Time // PATCH-09: armed at Start / on parent loss
	// parentUp tracks the OUTER layer's aliveness for the child-retry
	// chain (PATCH-08): retries are allowed ONLY while the parent lives.
	parentUp bool

	// PATCH-08/WG MINOR 13: child-retry ladder knobs (test seams;
	// production defaults base 1s / cap 30s, doubling per consecutive
	// failure, reset on every parent flap).
	retryBase time.Duration
	retryCap  time.Duration

	startOnce sync.Once
	stopOnce  sync.Once
	startErr  error
}

// NewNestedWgRuntime validates the composition up front (pure rules of
// NestedWgConfig.Validate) without touching network.
func NewNestedWgRuntime(cfg NestedWgConfig, opt NestedWgOptions) (*NestedWgRuntime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &NestedWgRuntime{cfg: cfg, opt: opt, link: NestedWaitingParent}, nil
}

// Start launches the outer session; the inner follows only through the
// OnEstablished bridge. Idempotent; returns the first construction error on
// repeated calls.
func (r *NestedWgRuntime) Start(parent context.Context) error {
	r.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(parent)
		sc, cerr := r.outerSessionConfig()
		if cerr != nil {
			cancel()
			r.startErr = cerr
			return
		}
		sess, err := NewSession(sc)
		if err != nil {
			cancel()
			r.startErr = err
			return
		}
		r.mu.Lock()
		r.ctx, r.cancel, r.outer = ctx, cancel, sess
		r.link = NestedWaitingParent
		r.outerGateStart = time.Now() // PATCH-09: arm the outer gate
		r.mu.Unlock()
		if err := sess.Start(); err != nil {
			r.startErr = err
			return
		}
	})
	return r.startErr
}

// Stop tears everything down CHILD-FIRST (inner session, then forwarder),
// then the outer session. Idempotent.
func (r *NestedWgRuntime) Stop() {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		cancel := r.cancel
		r.cancel = nil // handlers must never respawn past this point
		r.stopChildLocked()
		r.link = NestedChildInvalidated
		outer := r.outer
		r.mu.Unlock()
		if cancel != nil {
			cancel()
		}
		if outer != nil {
			outer.Stop()
		}
	})
}

// Status snapshots the link state with per-layer transfer telemetry
// (PATCH-28, N-5).
func (r *NestedWgRuntime) Status() NestedWgStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := NestedWgStatus{Link: r.link, ParentGen: r.parentGen}
	if r.inner != nil && r.inner.State() != StateClosed {
		st.ChildRunning = true
	}
	st.Outer = wgLayerStatusOf(r.outer)
	st.Inner = wgLayerStatusOf(r.inner)
	return st
}

// onParentEstablished / onParentLost / establishChild / loseChild: the
// callback bridge. Events are collected under the lock and emitted after
// unlock so user callbacks may call Status() freely.
func (r *NestedWgRuntime) onParentEstablished() {
	// PATCH-09: this callback IS the outer trust gate closing (first
	// establishment or a repair after parent loss).
	r.mu.Lock()
	start := r.outerGateStart
	r.outerGateStart = time.Time{}
	r.parentUp = true // PATCH-08: the parent lives; child retries allowed
	r.mu.Unlock()
	if !start.IsZero() && r.opt.ObserveGate != nil {
		r.opt.ObserveGate("outer", time.Since(start))
	}
	evs := r.establishChild()
	for _, ev := range evs {
		r.emit(ev)
	}
	// PATCH-08/WG MINOR 13: a failed child start used to leave a dead
	// child until the NEXT parent flap; schedule a bounded-backoff retry
	// while the parent stays alive. A fresh parent flap resets to base.
	if r.childNeedsRetry() {
		base := r.retryBase
		if base <= 0 {
			base = time.Second
		}
		r.scheduleChildRetry(base)
	}
}

// childNeedsRetry reports that the runtime is started, the parent is up,
// and the child is dead-but-retryable (start failed, not a parent loss).
func (r *NestedWgRuntime) childNeedsRetry() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cancel != nil && r.parentUp &&
		r.link == NestedChildInvalidated && r.inner == nil
}

// scheduleChildRetry re-attempts establishChild after backoff; a failed
// re-attempt schedules the next one with a doubled delay up to the cap
// (30s default). The chain dies on Stop, parent loss, or a successful child.
func (r *NestedWgRuntime) scheduleChildRetry(backoff time.Duration) {
	r.mu.Lock()
	ctx := r.ctx
	r.mu.Unlock()
	if ctx == nil {
		return
	}
	capD := r.retryCap
	if capD <= 0 {
		capD = 30 * time.Second
	}
	go func() {
		t := time.NewTimer(backoff)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !r.childNeedsRetry() {
			return
		}
		for _, ev := range r.establishChild() {
			r.emit(ev)
		}
		if r.childNeedsRetry() {
			r.scheduleChildRetry(min(backoff*2, capD))
		}
	}()
}

func (r *NestedWgRuntime) onParentLost(f Failure) {
	r.mu.Lock()
	if r.cancel == nil {
		r.mu.Unlock()
		return
	}
	r.parentUp = false // PATCH-08: no child retries while the parent is down
	r.stopChildLocked()
	r.link = NestedChildInvalidated
	// PATCH-09: re-arm the outer gate — the next OnEstablished measures the
	// REPAIR gate (loss -> re-establishment).
	r.outerGateStart = time.Now()
	evs := []SessionEvent{
		{
			Name:   "wg_nested_parent_lost",
			Class:  f.Class,
			Reason: fmt.Sprintf("%s/%s", f.Class, f.Reason),
		},
		{
			Name:   "wg_nested_child_invalidated",
			Class:  f.Class,
			Reason: fmt.Sprintf("parent:%s/%s", f.Class, f.Reason),
		},
	}
	r.mu.Unlock()
	for _, ev := range evs {
		r.emit(ev)
	}
}

// establishChild rebuilds the whole carrier pair against the CURRENT outer
// generation. Serialized against Stop via r.mu: whoever wins, no orphan
// survives.
func (r *NestedWgRuntime) establishChild() []SessionEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel == nil {
		return nil // stopped (or not started): never respawn
	}
	r.parentGen++
	gen := r.parentGen
	r.stopChildLocked()
	invalidate := func(reason string) []SessionEvent {
		r.link = NestedChildInvalidated
		return []SessionEvent{{
			Name:   "wg_nested_child_invalidated",
			Reason: fmt.Sprintf("gen=%d:%s", gen, reason),
		}}
	}

	innerStart := time.Now() // PATCH-09: inner gate starts here
	// A fresh generation carries a FRESH netstack — the forwarder must be
	// rebuilt against it, never reused across generations.
	tun := r.outer.Tunnel()
	if tun == nil || tun.Netstack == nil {
		return invalidate("no-live-netstack")
	}
	fwd, err := NewLoopbackForwarder(nsUDPDial(tun.Netstack), r.cfg.InnerEdge)
	if err != nil {
		return invalidate(fmt.Sprintf("forwarder-build: %v", err))
	}
	addr, err := fwd.Start(r.ctx)
	if err != nil {
		_ = fwd.Close()
		return invalidate(fmt.Sprintf("forwarder-start: %v", err))
	}
	innerCfg, cerr := r.innerSessionConfig(addr.String())
	if cerr != nil {
		_ = fwd.Close()
		return invalidate(fmt.Sprintf("inner-config: %v", cerr))
	}
	sess, err := NewSession(innerCfg)
	if err != nil {
		_ = fwd.Close()
		return invalidate(fmt.Sprintf("inner-config: %v", err))
	}
	if err := sess.Start(); err != nil {
		_ = fwd.Close()
		return invalidate(fmt.Sprintf("inner-start: %v", err))
	}
	// PATCH-09: the inner gate spans forwarder+session launch -> the
	// session's own establishment callback; only the launch portion is
	// attributable here, the handshake age lands in Session telemetry.
	if r.opt.ObserveGate != nil {
		r.opt.ObserveGate("inner", time.Since(innerStart))
	}
	r.fwd, r.inner = fwd, sess
	r.link = NestedUp
	return []SessionEvent{{
		Name:   "wg_nested_child_revalidated",
		Reason: fmt.Sprintf("gen=%d fwd=%s", gen, addr),
	}}
}

// stopChildLocked requires r.mu held. Order is the E5 red line: the inner
// dialer dies BEFORE its carrier.
func (r *NestedWgRuntime) stopChildLocked() {
	inner, fwd := r.inner, r.fwd
	r.inner, r.fwd = nil, nil
	if inner != nil {
		inner.Stop()
	}
	if fwd != nil {
		_ = fwd.Close()
	}
}

func (r *NestedWgRuntime) outerSessionConfig() (SessionConfig, error) {
	// PATCH-02: the tunnel render is error-returning; on a malformed
	// identity the session construction fails structurally (never panics).
	outerTun, err := r.cfg.OuterTunnelConfig(r.dns())
	if err != nil {
		return SessionConfig{}, err
	}
	hc := HealthConfig{KeepaliveSec: r.cfg.Outer.EffectiveKeepalive(true)}
	if r.opt.OuterHealth != nil {
		r.opt.OuterHealth(&hc)
	}
	return SessionConfig{
		Ident:              r.cfg.Outer.Ident,
		Profile:            r.cfg.Outer.Profile,
		Endpoint:           r.cfg.OuterEdge.String(),
		Tunnel:             outerTun,
		Health:             hc,
		VerboseDiagnostics: r.opt.VerboseDiagnostics,
		Callbacks: SessionCallbacks{
			OnEvent:       r.emit,
			OnEstablished: r.onParentEstablished,
			OnLost:        r.onParentLost,
		},
	}, nil
}

func (r *NestedWgRuntime) innerSessionConfig(endpoint string) (SessionConfig, error) {
	innerTun, err := r.cfg.InnerTunnelConfig(r.dns())
	if err != nil {
		return SessionConfig{}, err
	}
	hc := HealthConfig{KeepaliveSec: r.cfg.Inner.EffectiveKeepalive(false)}
	if r.opt.InnerHealth != nil {
		r.opt.InnerHealth(&hc)
	}
	return SessionConfig{
		Ident:              r.cfg.Inner.Ident,
		Profile:            r.cfg.Inner.Profile,
		Endpoint:           endpoint,
		Tunnel:             innerTun,
		Health:             hc,
		MaxGenerations:     r.opt.MaxGenerations,
		VerboseDiagnostics: r.opt.VerboseDiagnostics,
		Callbacks:          SessionCallbacks{OnEvent: r.emit},
	}, nil
}

func (r *NestedWgRuntime) dns() netip.Addr {
	if r.opt.DNS.IsValid() {
		return r.opt.DNS
	}
	return netip.AddrFrom4([4]byte{8, 8, 8, 8})
}

func (r *NestedWgRuntime) emit(ev SessionEvent) {
	if cb := r.opt.OnEvent; cb != nil {
		cb(ev)
	}
}
