// M+M composition (design 3.3, tunnels panel stage 4): a MASQUE-H2 outer
// carrying a MASQUE-H2 inner. The OUTER supervisor is the capsule plane (the
// caller owns it, exactly like the M+W runtime); the INNER supervisor's
// control TCP dials THROUGH the outer's userspace netstack (twarp.
// AttachNetstack over the plane's packet surface — the same adapter the
// warpservice carrier path uses). Both layers own DISTINCT identity slots:
// the outer's reconciler provisions the outer slot, the inner's reconciler
// provisions the SECONDARY slot (red line #3 — one CF device per layer).
//
// Parent-link contract (the M+W canon): a run-loop poller watches the plane's
// RouteHeld; every rising edge rebuilds the child pair FRESH — a new netstack
// attached to the current plane generation plus a new inner supervisor
// (supervisors are single-shot by design) — and a falling edge invalidates
// the child IMMEDIATELY (zero dialing through a dead parent). A failed child
// start retries on a bounded exponential ladder while the parent stays up.
//
// Data-plane posture (honest): the composition serves IPv4/TCP only — the
// inner supervisor's attached netstack v1 carries no UDP leg. The inner
// supervisor's own reconnection is ITS business; this runtime rebuilds the
// child only on parent transitions.
package nested

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	twarp "github.com/daniellavrushin/b4/transport/warp"
)

// MasqueMasqueConfig wires the composed M+M pair.
type MasqueMasqueConfig struct {
	// Pair must validate as masque-h2 outer + masque-h2 inner.
	Pair PairConfig

	// Plane is the OUTER MASQUE CONNECT-IP instance (*twarp.Supervisor in
	// production; the CapsulePlane slice keeps the runtime unit-testable).
	Plane CapsulePlane
	// LocalV4 is the outer's assigned WARP address — the source of the
	// inner control TCP inside the outer netstack.
	LocalV4 [4]byte

	// Fingerprint applies to the INNER layer's uTLS ClientHello ("",
	// "chrome120", "firefox"). The OUTER plane's fingerprint belongs to
	// its creator (the supervisor template), not this runtime.
	Fingerprint string

	// INNER secondary-slot enrollment material (REQUIRED — fail closed:
	// one CF device must never serve both layers, red line #3).
	InnerEnroll   *twarp.EnrollClient
	InnerSlotPath string

	// PollInterval is the parent-link tick; default 20ms (the M+W canon).
	PollInterval time.Duration

	// Metrics optionally receives this pair's counter surface (design 5).
	// All methods nil-safe; nil = no-op.
	Metrics *Metrics

	OnEvent   func(Event)
	InnerSink func(twarp.SupervisorEvent)
}

// Validate checks every structural rule without touching network state.
func (c *MasqueMasqueConfig) Validate() error {
	if err := c.Pair.Validate(); err != nil {
		return err
	}
	if c.Pair.Outer.Kind != KindMasqueH2 || c.Pair.Inner.Kind != KindMasqueH2 {
		return fmt.Errorf("nested: MasqueMasqueRuntime requires masque-h2+masque-h2, got %s+%s",
			c.Pair.Outer.Kind, c.Pair.Inner.Kind)
	}
	if c.Plane == nil {
		return errors.New("nested: masque+masque requires the capsule plane")
	}
	if c.InnerEnroll == nil || c.InnerSlotPath == "" {
		return fmt.Errorf("nested: m+m inner requires secondary slot enrollment " +
			"(EnrollClient + store path); sharing the outer identity is forbidden")
	}
	switch c.Fingerprint {
	case "", "chrome120", "firefox":
	default:
		return fmt.Errorf("nested: m+m fingerprint %q invalid (empty, chrome120 or firefox)", c.Fingerprint)
	}
	return nil
}

// MasqueMasqueRuntime owns the composed M+M pair lifecycle. The plane stays
// owned by its creator (Stop never touches it — the M+W contract).
type MasqueMasqueRuntime struct {
	cfg MasqueMasqueConfig

	mu        sync.Mutex
	link      string // waiting-parent | up | child-invalidated
	parentGen uint64
	inner     *twarp.Supervisor
	innerCan  context.CancelFunc
	// nsRelease detaches the control-plane netstack (one per child
	// generation — a fresh outer session needs a fresh attachment, the
	// warpservice re-attach canon).
	nsRelease func()
	// pairUp guards the PairActive gauge transition.
	pairUp bool

	// Gate stamps (MAJOR-5, design 62.9): unix nanos, 0 = disarmed.
	outerGateStart atomic.Int64
	innerGateStart atomic.Int64

	metrics *Metrics

	// Post-connect edge witnesses (PATCH-17, B-N3); guarded by mu.
	outerWitness edgeWitness
	innerWitness edgeWitness
	witnessGen   uint64
	outerUpSince time.Time
	innerUpSince time.Time

	// retry ladder knobs (test seams; production base 1s / cap 30s).
	retryBase    time.Duration
	retryCap     time.Duration
	startChildFn func(gen uint64) error

	cancel    context.CancelFunc
	done      chan struct{}
	doneClose sync.Once
	startOne  sync.Once
	stopOnce  sync.Once
	started   atomic.Bool
	stopped   atomic.Bool
}

// NewMasqueMasqueRuntime validates the declaration and returns a stopped
// runtime. No network is touched until Start.
func NewMasqueMasqueRuntime(cfg MasqueMasqueConfig) (*MasqueMasqueRuntime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 20 * time.Millisecond
	}
	return &MasqueMasqueRuntime{
		cfg:  cfg,
		link: "waiting-parent",
		done: make(chan struct{}),
	}, nil
}

// Start launches the parent-link controller. Idempotent; Start-after-Stop
// is the structural ErrRuntimeStopped verdict (PATCH-19/E15).
func (r *MasqueMasqueRuntime) Start(parent context.Context) error {
	if r.stopped.Load() {
		return ErrRuntimeStopped
	}
	r.startOne.Do(func() {
		ctx, cancel := context.WithCancel(parent)
		r.cancel = cancel
		if r.stopped.Load() {
			return // Stop won the race: run never launches
		}
		// MAJOR-5: the outer gate is attributable only when THIS runtime
		// witnesses the plane's establishment.
		if !r.cfg.Plane.Snapshot().RouteHeld {
			r.armOuterGate()
		}
		r.started.Store(true)
		go r.run(ctx)
	})
	select {
	case <-r.done:
		if r.stopped.Load() {
			return ErrRuntimeStopped
		}
		return fmt.Errorf("nested: masque+masque runtime exited during start")
	default:
		return nil
	}
}

// Stop tears down CHILD-FIRST (inner supervisor, then its netstack), then
// the controller. The plane stays owned by its creator. Idempotent;
// Stop-before-Start completes immediately.
func (r *MasqueMasqueRuntime) Stop() {
	r.stopOnce.Do(func() {
		r.stopped.Store(true)
		if r.cancel != nil {
			r.cancel()
			<-r.done
		} else {
			r.closeDone() // never started: unblock Stop and Status watchers
		}
		r.stopChild()
		r.pairGauge(-1)
	})
}

// Status snapshots the parent-link state.
func (r *MasqueMasqueRuntime) Status() (link string, parentGen uint64, childRunning bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	child := false
	if r.inner != nil && r.inner.Snapshot().State != twarp.StateStopped {
		child = true
	}
	return r.link, r.parentGen, child
}

// StatusDetailed returns the per-layer snapshot (PATCH-28, N-5): neither
// MASQUE layer exposes transfer counters on the supervisor surface — the
// witnessed establishment timestamps are the honest handshake-age surrogates.
func (r *MasqueMasqueRuntime) StatusDetailed() PairStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := PairStatus{Link: r.link, ParentGen: r.parentGen, ChildRunning: r.inner != nil}
	if !r.outerUpSince.IsZero() {
		st.Outer.HandshakeMS = time.Since(r.outerUpSince).Milliseconds()
	} else {
		st.Outer.HandshakeMS = neverEstablished
	}
	if r.inner != nil && !r.innerUpSince.IsZero() {
		st.Inner.HandshakeMS = time.Since(r.innerUpSince).Milliseconds()
	} else {
		st.Inner.HandshakeMS = neverEstablished
	}
	return st
}

// InnerSupervisor snapshots the live INNER supervisor (the daemon-assembly
// accessor canon: snapshots only, never lifecycle control; nil while the
// child is down). The consumer attaches the supervisor's netstack
// (AttachNetstack + AssignedLocalV4) for the chain's data plane.
func (r *MasqueMasqueRuntime) InnerSupervisor() *twarp.Supervisor {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inner == nil || r.inner.Snapshot().State == twarp.StateStopped {
		return nil
	}
	return r.inner
}

func (r *MasqueMasqueRuntime) closeDone() { r.doneClose.Do(func() { close(r.done) }) }

// run is the parent-link controller (the M+W PATCH-08/E3 structure): `held`
// reflects ONLY the plane state; the child state is its own variable and a
// failed startChild retries on a bounded exponential ladder while the
// parent stays up.
func (r *MasqueMasqueRuntime) run(ctx context.Context) {
	defer r.closeDone()
	t := time.NewTicker(r.cfg.PollInterval)
	defer t.Stop()
	retryBase := r.retryBase
	if retryBase <= 0 {
		retryBase = time.Second
	}
	retryCap := r.retryCap
	if retryCap <= 0 {
		retryCap = 30 * time.Second
	}
	held := false    // parent state ONLY
	childUp := false // child state tracked independently
	var nextRetry time.Time
	backoff := retryBase
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		nowHeld := r.cfg.Plane.Snapshot().RouteHeld
		if !nowHeld {
			if held || childUp {
				r.stopChild()
				r.pairGauge(-1)
				// MAJOR-5: re-arm — the next held edge measures
				// the REPAIR gate.
				r.armOuterGate()
				r.mu.Lock()
				r.link = "child-invalidated"
				r.mu.Unlock()
				r.emit(Event{Class: "warp_masque_disconnected",
					Reason: "parent lost: child invalidated"})
				r.emit(Event{Class: ClassChildInvalidated,
					Reason: "parent:warp_masque_disconnected"})
			}
			held, childUp = false, false
			continue
		}
		if !held {
			// Parent (re)rose: the flap resets the retry ladder.
			held = true
			backoff = retryBase
			nextRetry = time.Time{}
		}
		if !childUp && !time.Now().Before(nextRetry) {
			if nextRetry.IsZero() {
				// MAJOR-5: the RouteHeld RISING edge closes the outer
				// gate (once per parent generation).
				r.observeOuterGate()
				r.mu.Lock()
				r.outerWitness = edgeWitness{ip: r.cfg.Pair.Outer.Endpoint.Addr().String()}
				r.outerUpSince = time.Now()
				r.mu.Unlock()
			}
			gen := r.parentGen + 1
			start := r.startChild
			if r.startChildFn != nil {
				start = r.startChildFn
			}
			if err := start(gen); err != nil {
				r.setLink("child-invalidated", gen, err.Error())
				nextRetry = time.Now().Add(backoff)
				backoff = min(backoff*2, retryCap)
			} else {
				r.pairGauge(1)
				childUp = true
			}
		}
	}
}

// startChild builds the child pair for the CURRENT plane generation: a fresh
// control-plane netstack (the plane's packet surface) plus a fresh inner
// supervisor whose control TCP dials through it. Serialized against Stop by
// the run-loop single-threading; the mu discipline still guards the fields.
func (r *MasqueMasqueRuntime) startChild(gen uint64) error {
	outerMTU := r.cfg.Pair.Outer.MTU
	if outerMTU <= 0 {
		outerMTU = twarp.DefaultMTU
	}
	// The plane implements PacketSink (WritePacket); SubscribePackets feeds
	// the inbound side. One attachment per child generation.
	src, cancelSrc := r.cfg.Plane.SubscribePackets()
	ns, err := twarp.AttachNetstack(r.cfg.Plane, r.cfg.LocalV4, outerMTU, src)
	if err != nil {
		cancelSrc()
		return fmt.Errorf("outer netstack attach: %w", err)
	}
	release := func() {
		ns.Close()
		cancelSrc()
	}

	sup, serr := twarp.NewSupervisor(twarp.SupervisorConfig{
		Template: r.innerTemplate(ns),
		Reconciler: &twarp.Reconciler{
			API:   r.cfg.InnerEnroll,
			Store: &twarp.IdentityStore{Path: r.cfg.InnerSlotPath},
		},
		Sink: r.innerSinkBridge(),
	})
	if serr != nil {
		release()
		return fmt.Errorf("inner supervisor: %w", serr)
	}
	ictx, icancel := context.WithCancel(context.Background())
	// MAJOR-5: the inner gate spans identity + connect phases (the
	// supervisor's per-attempt DurationMS covers only the final dial).
	r.armInnerGate()
	if err := sup.Start(ictx); err != nil {
		icancel()
		gateDisarm(&r.innerGateStart) // dead generation owns no gate
		release()
		return fmt.Errorf("inner start: %w", err)
	}
	r.mu.Lock()
	r.inner = sup
	r.innerCan = icancel
	r.nsRelease = release
	r.parentGen = gen
	r.link = "up"
	r.innerUpSince = time.Now()
	// PATCH-17: the inner dials its endpoint through the outer netstack —
	// record the witness; the colo lands through the sink bridge.
	r.innerWitness = edgeWitness{ip: r.cfg.Pair.Inner.Endpoint.Addr().String()}
	r.checkEdgeCollisionLocked(gen)
	r.mu.Unlock()
	r.emit(Event{Class: "warp_nested_child_revalidated",
		Reason: fmt.Sprintf("gen=%d outer_netstack=attached ctrl=tcp-through-outer", gen)})
	return nil
}

// innerTemplate renders the INNER supervisor's session template: the control
// TCP dials through the outer netstack (the Backend-B adapter canon).
func (r *MasqueMasqueRuntime) innerTemplate(ns *twarp.NetstackCarrier) twarp.SessionConfig {
	mtu := r.cfg.Pair.Inner.MTU
	if mtu <= 0 {
		mtu = MaxInnerMTU
	}
	return twarp.SessionConfig{
		Endpoint:    r.cfg.Pair.Inner.Endpoint,
		MTU:         mtu,
		Fingerprint: r.cfg.Fingerprint,
		DialFunc:    nsDialThrough(ns),
	}
}

// nsDialThrough adapts the outer netstack carrier to the inner session's
// DialFunc seam (raw TCP; v4 only — the netstack v1 posture).
func nsDialThrough(ns *twarp.NetstackCarrier) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, fmt.Errorf("nested: m+m control dial carries tcp only, got %q", network)
		}
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, fmt.Errorf("nested: m+m control endpoint: %w", err)
		}
		return ns.DialStream(ctx, ap)
	}
}

// stopChild tears the child pair down CHILD-FIRST: the inner supervisor dies
// BEFORE its carrier (the E5 red line).
func (r *MasqueMasqueRuntime) stopChild() {
	r.mu.Lock()
	inner := r.inner
	icancel := r.innerCan
	release := r.nsRelease
	r.inner, r.innerCan, r.nsRelease = nil, nil, nil
	r.mu.Unlock()
	if icancel != nil {
		icancel()
	}
	if inner != nil {
		inner.Stop()
	}
	if release != nil {
		release()
	}
}

func (r *MasqueMasqueRuntime) setLink(link string, gen uint64, reason string) {
	r.mu.Lock()
	r.link = link
	r.mu.Unlock()
	// PATCH-07 (M-14): a start failure is a child-lifecycle outcome, never a
	// route incident.
	r.emit(Event{Class: ClassChildStartFailed,
		Reason: fmt.Sprintf("gen=%d %s", gen, reason)})
}

// innerSinkBridge wraps the operator sink (MAJOR-5 + PATCH-17): the first
// warp_masque_connected of the generation closes the inner gate and records
// the colo witness; every event reaches the operator verbatim.
func (r *MasqueMasqueRuntime) innerSinkBridge() func(twarp.SupervisorEvent) {
	user := r.cfg.InnerSink
	return func(ev twarp.SupervisorEvent) {
		if ev.Name == twarp.EvMasqueConnected {
			r.observeInnerGate()
			r.mu.Lock()
			r.innerWitness.colo = ev.Colo
			r.checkEdgeCollisionLocked(r.parentGen)
			r.mu.Unlock()
		}
		if user != nil {
			user(ev)
		}
	}
}

// checkEdgeCollisionLocked runs the B-N3 post-connect fact-check once BOTH
// layers' witnesses are non-zero; emits the collision event once per
// generation. Callers hold r.mu.
func (r *MasqueMasqueRuntime) checkEdgeCollisionLocked(gen uint64) {
	if gen == 0 || r.witnessGen == gen {
		return
	}
	if r.outerWitness.ip == "" || r.innerWitness.ip == "" {
		return
	}
	if edgeCollision(r.outerWitness, r.innerWitness) {
		r.witnessGen = gen
		reason := fmt.Sprintf("post-connect: outer=%s/%s inner=%s/%s",
			r.outerWitness.ip, r.outerWitness.colo,
			r.innerWitness.ip, r.innerWitness.colo)
		r.emit(Event{Class: ClassEdgeCollision, Reason: reason})
	}
}

// pairGauge moves the pair-active gauge under the up-transition guard (no
// double-decrement across repeated lost->held cycles and Stop).
func (r *MasqueMasqueRuntime) pairGauge(delta int64) {
	r.mu.Lock()
	up := r.pairUp
	if delta > 0 {
		r.pairUp = true
	} else {
		r.pairUp = false
	}
	r.mu.Unlock()
	if delta > 0 && up {
		return // already up: no double increment
	}
	if delta < 0 && !up {
		return // already down: no double decrement
	}
	r.metrics.PairGaugeMove(delta)
}

// ---- gate-stamp wrappers (MAJOR-5; shared math in metrics.go) ----

func (r *MasqueMasqueRuntime) armOuterGate()     { gateArm(&r.outerGateStart) }
func (r *MasqueMasqueRuntime) armInnerGate()     { gateArm(&r.innerGateStart) }
func (r *MasqueMasqueRuntime) observeOuterGate() { gateObserve(&r.outerGateStart, r.metrics, "outer") }
func (r *MasqueMasqueRuntime) observeInnerGate() { gateObserve(&r.innerGateStart, r.metrics, "inner") }

func (r *MasqueMasqueRuntime) emit(ev Event) {
	ev.At = time.Now()
	if cb := r.cfg.OnEvent; cb != nil {
		cb(ev)
	}
}
