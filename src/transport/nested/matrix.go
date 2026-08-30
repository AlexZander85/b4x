// Matrix layer (N3, design 3/6): ONE declarative schema for every outer x
// inner combination plus the assembly helpers that compose them from the two
// shipping engines. Rules enforced here are common to all pairs (design 2):
//
//   - different edge IPs per layer (gool hard rule, cross-transport);
//   - inner MTU <= 1200 under any outer;
//   - inner identity lives in the SECONDARY slot (one CF device per layer);
//   - failure_mode is fail-closed-scoped only;
//   - carrier resolves by the OUTER data-plane mode, never by transports.
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
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// Kind selects the transport family of one layer.
type Kind string

const (
	KindAWG      Kind = "awg"
	KindMasqueH2 Kind = "masque-h2"
)

func (k Kind) valid() bool { return k == KindAWG || k == KindMasqueH2 }

// Identity slots (design 2: one CF device cannot be two layers).
const (
	SlotPrimary   = "primary"
	SlotSecondary = "secondary"
)

// CarrierMode selects (or auto-resolves) the outer-side carrier.
type CarrierMode string

const (
	CarrierAuto        CarrierMode = "auto"
	CarrierKernelRoute CarrierMode = "kernel-route"
	CarrierNetstack    CarrierMode = "netstack"
	// CarrierDatagram is the resolved mode for a MASQUE CONNECT-IP outer.
	CarrierDatagram CarrierMode = "masque-datagram"
)

// FailureMode: the only supported posture (design 6).
const FailureModeFailClosedScoped = "fail-closed-scoped"

// Validation errors carry structural identity (design 5 classes).
var (
	// ErrEdgeCollision names its class in the text so traces can classify
	// without parsing free form (nested/edge-collision).
	ErrEdgeCollision = errors.New("nested/edge-collision: layers terminate on the same edge IP")
	ErrBadKind       = errors.New("nested: illegal layer kind")
	ErrBadSlot       = errors.New("nested: inner identity slot must be " + SlotSecondary)
)

// MaxInnerMTU is the hard cap under ANY outer (design 2: encapsulation headroom).
const MaxInnerMTU = 1200

// LayerSpec declares one layer of the pair.
type LayerSpec struct {
	Kind         Kind
	IdentitySlot string
	ProfileID    string // profile catalog reference; resolved by wiring
	Endpoint     netip.AddrPort
	MTU          int // 0 = engine default (outer) / MaxInnerMTU (inner cap)
}

// PairConfig is the declarative schema of one nested pair (design 6).
type PairConfig struct {
	Outer LayerSpec
	Inner LayerSpec
	// Carrier: auto | kernel-route | netstack (datagram is resolved-only).
	Carrier CarrierMode
	// FailureMode: empty or fail-closed-scoped.
	FailureMode string
}

// Validate enforces every matrix rule without touching network state.
func (p *PairConfig) Validate() error {
	if !p.Outer.Kind.valid() || !p.Inner.Kind.valid() {
		return fmt.Errorf("%w: outer=%q inner=%q", ErrBadKind, p.Outer.Kind, p.Inner.Kind)
	}
	if p.Outer.IdentitySlot != SlotPrimary {
		return fmt.Errorf("nested: outer identity slot must be %q", SlotPrimary)
	}
	if p.Inner.IdentitySlot != SlotSecondary {
		return ErrBadSlot
	}
	if p.Outer.ProfileID == "" || p.Inner.ProfileID == "" {
		return errors.New("nested: profile_id required for both layers")
	}
	if !p.Outer.Endpoint.IsValid() || p.Outer.Endpoint.Port() == 0 ||
		!p.Inner.Endpoint.IsValid() || p.Inner.Endpoint.Port() == 0 {
		return errors.New("nested: both layer endpoints must be valid addr:port")
	}
	if p.Outer.Endpoint.Addr() == p.Inner.Endpoint.Addr() {
		return ErrEdgeCollision
	}
	innerMTU := p.Inner.MTU
	if innerMTU == 0 {
		innerMTU = MaxInnerMTU
	}
	if innerMTU > MaxInnerMTU {
		return fmt.Errorf("nested: inner mtu %d exceeds cap %d", innerMTU, MaxInnerMTU)
	}
	// PATCH-18/E13: when BOTH layer MTUs are declared, the encapsulation
	// invariant must hold: every inner datagram rides inside an outer one.
	// If the outer MTU is left to the engine default, the effective value is
	// the plane's and only the carrier's write gate applies.
	if p.Outer.MTU > 0 && p.Inner.MTU > 0 &&
		innerMTU+UDPDatagramOverhead > p.Outer.MTU {
		return fmt.Errorf("nested: inner mtu %d + datagram overhead %d exceeds outer mtu %d",
			innerMTU, UDPDatagramOverhead, p.Outer.MTU)
	}
	switch p.Carrier {
	case "", CarrierAuto, CarrierKernelRoute, CarrierNetstack:
	default:
		return fmt.Errorf("nested: carrier mode %q is not declarable (resolved only)", p.Carrier)
	}
	if p.FailureMode != "" && p.FailureMode != FailureModeFailClosedScoped {
		return fmt.Errorf("nested: unsupported failure_mode %q", p.FailureMode)
	}
	return nil
}

// ResolveCarrier implements the auto rule: the OUTER data-plane mode decides.
// awg outer -> kernel route when the outer rides a kernel TUN, netstack when
// it runs the gVisor stack; masque-h2 outer -> datagram plane.
func ResolveCarrier(p PairConfig, outerKernelTUN bool) (CarrierMode, error) {
	// PATCH-24/E18: CarrierDatagram is RESOLVED-ONLY — a caller declaring it
	// gets a structural error, in sync with PairConfig.Validate (which
	// rejects it as not declarable). The old passthrough accepted what
	// Validate forbids, a contract desync.
	switch p.Carrier {
	case CarrierKernelRoute, CarrierNetstack:
		return p.Carrier, nil
	case "", CarrierAuto:
	default:
		return "", fmt.Errorf("nested: carrier mode %q is not declarable (resolved only)", p.Carrier)
	}
	switch p.Outer.Kind {
	case KindMasqueH2:
		return CarrierDatagram, nil
	case KindAWG:
		if outerKernelTUN {
			return CarrierKernelRoute, nil
		}
		return CarrierNetstack, nil
	default:
		return "", ErrBadKind
	}
}

// ---- assembly seams ----

// ForwarderSeam adapts any UDPSessionCarrier to the transportwg Backend-B
// forwarder dial seam: the relay keeps its tested pump logic while its
// upstream becomes the carrier session (M+W path).
func ForwarderSeam(c UDPSessionCarrier) twg.DialUDPFunc {
	return func(ctx context.Context, network, address string) (twg.UDPConn, error) {
		if network != "udp" && network != "udp4" {
			return nil, fmt.Errorf("nested: forwarder seam carries udp only, got %q", network)
		}
		ap, err := netip.ParseAddrPort(address)
		if err != nil {
			return nil, fmt.Errorf("nested: forwarder seam endpoint: %w", err)
		}
		return c.DialUDPThrough(ctx, ap)
	}
}

// CarrierDialFunc adapts a NestedCarrier to transportwarp SessionConfig.DialFunc:
// the inner MASQUE control socket dials THROUGH the outer (W+M path).
func CarrierDialFunc(c NestedCarrier) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if network != "tcp" {
			return nil, fmt.Errorf("nested: carrier dial func carries tcp only, got %q", network)
		}
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			return nil, fmt.Errorf("nested: carrier dial endpoint: %w", err)
		}
		return c.DialTCPThrough(ctx, ap)
	}
}

// ---- M+W runtime: MASQUE outer carrying an AWG inner ----

// MasqueAwgConfig wires the composed pair. Engine specifics stay with the
// caller (identity enrollment, profiles, catalogs); the runtime owns ONLY
// the composition lifecycle (parent-link contracts reused from E5/WG6).
type MasqueAwgConfig struct {
	Pair PairConfig // must validate as masque-h2 outer + awg inner

	// Plane is the OUTER MASQUE CONNECT-IP instance (*warp.Supervisor in
	// production; the interface keeps the runtime e2e-testable with a
	// direct DialSession adapter).
	Plane   CapsulePlane
	LocalV4 [4]byte // outer assigned address (carrier source)

	// Inner AWG layer pieces.
	InnerIdent   *twg.Identity
	InnerProfile twg.Profile
	DNS          netip.Addr // inside BOTH planes' resolvers; default 8.8.8.8

	MaxInnerGenerations int
	PollInterval        time.Duration // parent-link tick; default 20ms

	// Metrics optionally receives this pair's counter surface (design 5):
	// per-layer gate latency (design 62.9), the pair-active gauge and the
	// composition counters. All methods are nil-safe; nil = no-op surface.
	Metrics *Metrics

	OnEvent      func(Event)
	InnerOnEvent func(twg.SessionEvent) // engine-native passthrough

	// OuterSink optionally receives the OUTER MASQUE supervisor's events
	// (PATCH-17: the post-connect edge-collision fact-check consumes the
	// outer layer's cf-warp-colo through it). Must be non-blocking.
	OuterSink func(twarp.SupervisorEvent)
}

// MasqueAwgRuntime owns the composed M+W pair: the MASQUE supervisor is the
// parent plane; the inner AWG session's ONLY egress is the Backend-B
// forwarder dialed through the MasqueDatagramCarrier (ErrInnerNotLoopback
// proof inherited from WG6 - the inner still dials loopback; its datagrams
// physically ride the capsule stream).
type MasqueAwgRuntime struct {
	cfg     MasqueAwgConfig
	carrier *MasqueDatagramCarrier

	// innerV4 is the inner identity's assigned address, parsed ONCE at
	// construction (PATCH-02/E10: a malformed AssignedV4 is a structural
	// construction failure, never a MustParse panic inside run()).
	innerV4 netip.Addr

	mu        sync.Mutex
	link      string // waiting-parent | up | child-invalidated
	parentGen uint64
	inner     *twg.Session
	fwd       *twg.LoopbackForwarder
	// pairUp guards the PairActive gauge transition (no double-decrement
	// across repeated lost->held cycles and Stop).
	pairUp bool

	// Gate stamps (MAJOR-5, design 62.9): unix nanos, 0 = disarmed; see
	// gateObserve in metrics.go. The inner OnEstablished fires on the
	// session's goroutine, hence atomics over the runtime mutex.
	outerGateStart atomic.Int64
	innerGateStart atomic.Int64

	metrics *Metrics

	// Post-connect edge witnesses (PATCH-17, B-N3): written when each layer
	// establishes; the fact-check runs once both are non-zero.
	outerWitness edgeWitness
	innerWitness edgeWitness
	witnessGen   uint64    // generation the collision alert fired for
	outerUpSince time.Time // last outer establishment (StatusDetailed)

	cancel    context.CancelFunc
	done      chan struct{}
	doneClose sync.Once // PATCH-19/E15: done closes exactly once
	startOne  sync.Once
	stopOnce  sync.Once
	started   atomic.Bool // PATCH-19/E15 lifecycle contract
	stopped   atomic.Bool

	// PATCH-08/E3: child-retry ladder. Production: base 1s, cap 30s,
	// doubling per consecutive failed start, reset on every parent flap
	// (a new parent generation deserves a fresh attempt immediately).
	// retryBase/retryCap are test knobs (house style, cf. assertInterval).
	// startChildFn is the child-start seam (tests inject failures;
	// production leaves it nil).
	retryBase    time.Duration
	retryCap     time.Duration
	startChildFn func(gen uint64) error
}

// NewMasqueAwgRuntime validates the declaration and returns a stopped runtime.
func NewMasqueAwgRuntime(cfg MasqueAwgConfig) (*MasqueAwgRuntime, error) {
	if err := cfg.Pair.Validate(); err != nil {
		return nil, err
	}
	if cfg.Pair.Outer.Kind != KindMasqueH2 || cfg.Pair.Inner.Kind != KindAWG {
		return nil, fmt.Errorf("nested: MasqueAwgRuntime requires masque-h2+awg, got %s+%s",
			cfg.Pair.Outer.Kind, cfg.Pair.Inner.Kind)
	}
	if cfg.Plane == nil || cfg.InnerIdent == nil {
		return nil, errors.New("nested: masque+awg requires capsule plane and inner identity")
	}
	// PATCH-02/E10: validate the inner identity's assigned address at
	// construction — the run()/startChild goroutine must never parse
	// unvalidated config input.
	innerV4, err := netip.ParseAddr(cfg.InnerIdent.AssignedV4)
	if err != nil || !innerV4.IsValid() || !innerV4.Is4() {
		return nil, fmt.Errorf("nested: inner identity AssignedV4 %q invalid: %w", cfg.InnerIdent.AssignedV4, err)
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 20 * time.Millisecond
	}
	if !cfg.DNS.IsValid() {
		cfg.DNS = netip.AddrFrom4([4]byte{8, 8, 8, 8})
	}
	// PATCH-18/E13: propagate the OUTER plane's MTU into the carrier — the
	// old code always crafted against the 1280 default, so a plane with a
	// smaller MTU turned every inner datagram into a silent local rejection
	// ("up" black hole). The inner<=outer invariant is validated below.
	outerMTU := cfg.Pair.Outer.MTU
	if outerMTU <= 0 {
		outerMTU = twarp.DefaultMTU
	}
	carrier, err := NewMasqueDatagramCarrier(MasqueCarrierConfig{
		Plane:    cfg.Plane,
		LocalV4:  cfg.LocalV4,
		OuterMTU: outerMTU,
	})
	if err != nil {
		return nil, err
	}
	return &MasqueAwgRuntime{
		cfg:     cfg,
		innerV4: innerV4,
		carrier: carrier,
		link:    "waiting-parent",
		metrics: cfg.Metrics,
		done:    make(chan struct{}),
	}, nil
}

// ErrRuntimeStopped is the structural verdict for Start-after-Stop
// (PATCH-19/E15): a stopped runtime must not silently zombie.
var ErrRuntimeStopped = errors.New("nested: runtime stopped")

// closeDone closes done exactly once (run's exit and Stop's never-started
// branch share it).
func (r *MasqueAwgRuntime) closeDone() { r.doneClose.Do(func() { close(r.done) }) }

// Start launches the parent-link controller and the carrier pump.
// PATCH-19/E15: Stop-before-Start no longer deadlocks (Stop closes done
// itself), and Start-after-Stop is a structural error instead of a silent
// zombie whose second Stop is a no-op.
func (r *MasqueAwgRuntime) Start(parent context.Context) error {
	if r.stopped.Load() {
		return ErrRuntimeStopped
	}
	r.startOne.Do(func() {
		ctx, cancel := context.WithCancel(parent)
		r.cancel = cancel
		if r.stopped.Load() {
			return // Stop won the race: run never launches
		}
		// MAJOR-5: the outer gate is attributable only when THIS
		// runtime witnesses the plane's establishment; an already-held
		// plane predates the runtime (no gate claim is allowed).
		if !r.cfg.Plane.Snapshot().RouteHeld {
			r.armOuterGate()
		}
		r.carrier.StartPumping()
		r.started.Store(true)
		go r.run(ctx)
	})
	select {
	case <-r.done:
		if r.stopped.Load() {
			return ErrRuntimeStopped
		}
		return fmt.Errorf("nested: masque+awg runtime exited during start")
	default:
		return nil
	}
}

// Stop tears down CHILD-FIRST (inner, forwarder), then the controller and
// the carrier. The MASQUE supervisor itself stays owned by its creator.
// PATCH-19/E15: Stop-before-Start completes immediately (done is closed by
// Stop itself — the old code deadlocked on <-r.done forever) and marks the
// runtime stopped so a later Start fails structurally.
func (r *MasqueAwgRuntime) Stop() {
	r.stopOnce.Do(func() {
		r.stopped.Store(true)
		if r.cancel != nil {
			r.cancel()
			<-r.done
		} else {
			r.closeDone() // never started: unblock Stop and any Status watchers
		}
		r.stopChild()
		r.pairGauge(-1) // MAJOR-5: teardown drops the pair gauge
		r.carrier.Close()
	})
}

// Status snapshots the parent-link state.
func (r *MasqueAwgRuntime) Status() (link string, parentGen uint64, childRunning bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	child := r.inner != nil && r.inner.State() != twg.StateClosed
	return r.link, r.parentGen, child
}

// LayerStatus is one composed layer's post-establishment snapshot
// (PATCH-28, N-5 / design §1.2): last handshake age, per-layer transfer
// counters. Sources differ per engine: WG sessions expose peer telemetry
// (IpcGet), the MASQUE plane interface carries none (zeros stay honest).
type LayerStatus struct {
	// HandshakeMS is the AGE of the layer's last handshake in milliseconds;
	// -1 = never established.
	HandshakeMS int64
	RXBytes     uint64
	TXBytes     uint64
	// RXPackets/TXPackets: engines that count packets (H3 datagram path)
	// fill these; WG telemetry exposes bytes only (zero here).
	RXPackets uint64
	TXPackets uint64
}

// PairStatus is one snapshot of both composed layers (design §1.2).
type PairStatus struct {
	Link         string
	ParentGen    uint64
	ChildRunning bool
	Outer        LayerStatus
	Inner        LayerStatus
}

// neverEstablished is the "never" handshake marker.
const neverEstablished = int64(-1)

// handshakeAgeMS converts a unix handshake stamp to its age in ms
// (0/absent stamp -> neverEstablished).
func handshakeAgeMS(unixSec int64) int64 {
	if unixSec <= 0 {
		return neverEstablished
	}
	age := time.Since(time.Unix(unixSec, 0))
	if age < 0 {
		return 0
	}
	return age.Milliseconds()
}

// StatusDetailed returns the per-layer snapshot without breaking the
// degraded Status() callers.
func (r *MasqueAwgRuntime) StatusDetailed() PairStatus {
	r.mu.Lock()
	link, gen := r.link, r.parentGen
	innerSess := r.inner
	outerUp := r.outerUpSince
	r.mu.Unlock()

	st := PairStatus{Link: link, ParentGen: gen}
	// Outer MASQUE plane: no telemetry on CapsulePlane; the witnessed
	// establishment timestamp is the honest "handshake age" surrogate.
	if !outerUp.IsZero() {
		st.Outer.HandshakeMS = time.Since(outerUp).Milliseconds()
	} else {
		st.Outer.HandshakeMS = neverEstablished
	}
	// Inner AWG session: real peer telemetry via IpcGet.
	if innerSess != nil && innerSess.State() != twg.StateClosed {
		st.ChildRunning = true
		tel := innerSess.Telemetry()
		st.Inner.HandshakeMS = handshakeAgeMS(tel.HandshakeUnix)
		st.Inner.RXBytes = tel.RXBytes
		st.Inner.TXBytes = tel.TXBytes
	} else {
		st.Inner.HandshakeMS = neverEstablished
	}
	return st
}

// RelayDroppedInbound exposes the carrier's demux drop counter (diagnostics).
func (r *MasqueAwgRuntime) RelayDroppedInbound() uint64 {
	return r.carrier.DroppedInbound()
}

// RelayDemuxStats exposes matched/unknown inbound demux counters.
func (r *MasqueAwgRuntime) RelayDemuxStats() (matched, unknown uint64) {
	return r.carrier.DemuxStats()
}

// run is the parent-link controller. PATCH-08/E3 restructure: `held`
// reflects ONLY the parent (plane) state; the child state is its own
// variable and a failed child start is RETRIED with a bounded exponential
// ladder while the parent stays up (previously one failed startChild left a
// dead child until the next parent flap).
func (r *MasqueAwgRuntime) run(ctx context.Context) {
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
				// MAJOR-5: re-arm - the next held edge measures
				// the REPAIR gate (plane loss -> re-establishment).
				r.armOuterGate()
				r.mu.Lock()
				r.link = "child-invalidated"
				r.mu.Unlock()
				r.emit(Event{Class: "warp_masque_disconnected",
					Reason: "parent lost: child invalidated"})
				// PATCH-07 (M-14): parity with W+M — parent loss is
				// a child invalidation, not a route incident.
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
				// gate (once per parent generation, on the first
				// child attempt).
				r.observeOuterGate()
				// PATCH-17: the outer plane is held — record its
				// witness (the colo arrives through OuterSink).
				r.mu.Lock()
				r.outerWitness = edgeWitness{ip: r.cfg.Pair.Outer.Endpoint.Addr().String()}
				r.outerUpSince = time.Now() // PATCH-28: handshake-age surrogate
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

func (r *MasqueAwgRuntime) startChild(gen uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	fwd, err := twg.NewLoopbackForwarder(ForwarderSeam(r.carrier), r.cfg.Pair.Inner.Endpoint)
	if err != nil {
		return fmt.Errorf("forwarder: %w", err)
	}
	addr, err := fwd.Start(context.Background())
	if err != nil {
		_ = fwd.Close()
		return fmt.Errorf("forwarder start: %w", err)
	}
	sessCfg := twg.SessionConfig{
		Ident:          r.cfg.InnerIdent,
		Profile:        r.cfg.InnerProfile,
		Endpoint:       addr.String(),
		Tunnel:         r.innerTunnel(),
		MaxGenerations: r.cfg.MaxInnerGenerations,
		Health:         twg.HealthConfig{KeepaliveSec: twg.NestedInnerKeepaliveSec},
		Callbacks: twg.SessionCallbacks{
			OnEvent: r.innerEvent,
			// MAJOR-5: the inner session's trust gate closes here
			// (atomic-only body - safe under the runtime mutex held
			// by startChild).
			OnEstablished: r.observeInnerGate,
		},
	}
	sess, err := twg.NewSession(sessCfg)
	if err != nil {
		_ = fwd.Close()
		return fmt.Errorf("inner config: %w", err)
	}
	// MAJOR-5: inner gate = forwarder+session launch -> OnEstablished.
	r.armInnerGate()
	if err := sess.Start(); err != nil {
		_ = fwd.Close()
		gateDisarm(&r.innerGateStart) // dead generation owns no gate
		return fmt.Errorf("inner start: %w", err)
	}
	r.inner, r.fwd = sess, fwd
	r.parentGen = gen
	r.link = "up"
	r.emit(Event{Class: "wg_nested_child_revalidated",
		Reason: fmt.Sprintf("gen=%d fwd=%s proof=%v", gen, addr, r.proofText())})
	return nil
}

func (r *MasqueAwgRuntime) stopChild() {
	r.mu.Lock()
	inner, fwd := r.inner, r.fwd
	r.inner, r.fwd = nil, nil
	r.mu.Unlock()
	if inner != nil {
		inner.Stop()
	}
	if fwd != nil {
		_ = fwd.Close()
	}
}

// pairGauge moves the pair-active gauge under the up-transition guard
// (MAJOR-5): repeated same-direction transitions cannot drift the gauge.
func (r *MasqueAwgRuntime) pairGauge(delta int64) {
	r.mu.Lock()
	up := r.pairUp
	r.pairUp = delta > 0
	r.mu.Unlock()
	if delta > 0 && !up {
		r.metrics.PairGaugeMove(1)
	}
	if delta < 0 && up {
		r.metrics.PairGaugeMove(-1)
	}
}

// ---- gate-stamp wrappers (MAJOR-5; shared math in metrics.go) ----

func (r *MasqueAwgRuntime) armOuterGate()     { gateArm(&r.outerGateStart) }
func (r *MasqueAwgRuntime) armInnerGate()     { gateArm(&r.innerGateStart) }
func (r *MasqueAwgRuntime) observeOuterGate() { gateObserve(&r.outerGateStart, r.metrics, "outer") }
func (r *MasqueAwgRuntime) observeInnerGate() { gateObserve(&r.innerGateStart, r.metrics, "inner") }

// checkEdgeCollisionLocked runs the B-N3 post-connect fact-check once BOTH
// layers' witnesses are non-zero; emits the collision event once per
// generation. Called under r.mu (callers hold it).
func (r *MasqueAwgRuntime) checkEdgeCollisionLocked(gen uint64) {
	if r.witnessGen == gen {
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

// ObserveOuterEvent is the PATCH-17 colo feed for the M+W composition: the
// OUTER MASQUE supervisor is owned by the wiring layer, so production wiring
// forwards its events here (the runtime extracts the established edge's
// cf-warp-colo and passes everything through to OuterSink verbatim).
func (r *MasqueAwgRuntime) ObserveOuterEvent(ev twarp.SupervisorEvent) {
	if ev.Name == twarp.EvMasqueConnected && ev.Colo != "" {
		r.mu.Lock()
		r.outerWitness.colo = ev.Colo
		r.checkEdgeCollisionLocked(r.parentGen)
		r.mu.Unlock()
	}
	if cb := r.cfg.OuterSink; cb != nil {
		cb(ev)
	}
}

func (r *MasqueAwgRuntime) setLink(link string, gen uint64, reason string) {
	r.mu.Lock()
	r.link, r.parentGen = link, gen
	r.mu.Unlock()
	if reason != "" {
		// PATCH-07 (M-14): child start failures carry their own class —
		// route-lost stays strictly a kernel-route incident.
		r.emit(Event{Class: ClassChildStartFailed, Reason: reason})
	}
}

func (r *MasqueAwgRuntime) innerTunnel() twg.TunnelConfig {
	mtu := r.cfg.Pair.Inner.MTU
	if mtu <= 0 {
		mtu = MaxInnerMTU
	}
	return twg.TunnelConfig{
		Mode:      twg.ModeNetstack,
		Addresses: []netip.Addr{r.innerV4}, // parsed at construction (PATCH-02/E10)
		DNS:       []netip.Addr{r.cfg.DNS},
		MTU:       mtu,
	}
}

// innerEvent forwards engine-native events to the operator and produces the
// nested-level ClassInnerVersionMismatch mapping (PATCH-20/E12(г)): the WG
// layer classifies an AWG parameter disagreement as awg-version-mismatch;
// the composition surface re-labels it with its own class so consumers can
// attribute the mismatch to the INNER layer without string parsing.
func (r *MasqueAwgRuntime) innerEvent(ev twg.SessionEvent) {
	if ev.Class == twg.ClassVersionMismatch {
		r.emit(Event{Class: ClassInnerVersionMismatch,
			Reason: "inner:" + string(ev.Class) + ":" + ev.Reason})
	}
	if cb := r.cfg.InnerOnEvent; cb != nil {
		cb(ev)
	}
}

func (r *MasqueAwgRuntime) proofText() string {
	p, _ := r.carrier.ProofSnapshot()
	return p
}

func (r *MasqueAwgRuntime) emit(ev Event) {
	ev.At = time.Now()
	if cb := r.cfg.OnEvent; cb != nil {
		cb(ev)
	}
}
