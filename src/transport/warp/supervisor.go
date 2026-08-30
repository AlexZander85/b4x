// Instance supervisor (design §1 L2, addendum v1.2 §19): the owner of one
// MASQUE instance lifecycle — identity -> connect -> validate -> health ->
// reconnect — replacing the child-process supervisor of the addendum with an
// in-process loop (ADR-WARP-1 deferral, design §11.1).
//
// Properties implemented here (addendum §19 + z2k lesson #14):
//   - single loop, single start lock;
//   - bounded exponential backoff 1s -> 30s, reset after a stable run of
//     ResetAfterStable (60s);
//   - identity lifecycle delegated to Reconciler (refuse-vs-throttle,
//     cooldown stamps); the supervisor NEVER dials while identity state is
//     blocked, and re-runs Ensure only at start and every
//     RevalidationInterval (24h), so reconnect storms cannot hammer the
//     registration API;
//   - health watchdog: periodic data-plane probe; failure streak reaching
//     HealthFailureLimit triggers FAIL-OPEN — the route is released
//     immediately and the session torn down while reconnection continues in
//     background (a black-hole route is worse than direct access, z2k #7);
//   - first-packet fix (design §2, our usque-bug fix): the packet that wakes
//     an idle reconnect is buffered (single slot, latest wins) and flushed
//     right after the next validated connection;
//   - structured §62.1 events through an injectable sink; adapting them to
//     the src/warp TracePipeline envelope is the integration layer's job
//     (E7), keeping this package dependency-free.
package transportwarp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// §62.1 event names emitted by the supervisor (minimum required set).
const (
	EvSessionGenerationStarted     = "warp_session_generation_started"
	EvReconnectScheduled           = "warp_reconnect_scheduled"
	EvMasqueConnected              = "warp_masque_connected"
	EvMasqueRejected               = "warp_masque_rejected"
	EvMasqueDisconnected           = "warp_masque_disconnected"
	EvKeepaliveFailed              = "warp_keepalive_failed"
	EvIdentityBlocked              = "warp_identity_blocked"
	EvIdentityRevalidationDeferred = "warp_identity_revalidation_deferred"
	EvRouteReleasedFailOpen        = "warp_route_released_failopen"

	// E-H3 ladder taxonomy (EH3/EH4): transport changes are NEVER silent.
	EvH3Negotiated      = "warp_h3_negotiated"
	EvTransportSwitched = "warp_transport_switched"

	// Panic isolation (M3-07): engine-goroutine panics are recovered, never
	// fatal to the process. Every caught panic emits EvEnginePanic; a streak of
	// PanicLimit consecutive panics escalates to a StateOperatorPause.
	EvEnginePanic   = "warp_engine_panic"
	EvOperatorPause = "warp_operator_pause"
)

// Disconnect reasons (structural enums, not free text).
const (
	ReasonStop         = "stop"
	ReasonSessionLost  = "idle-disconnect"
	ReasonHealthStreak = "packet-pump-stall"
)

// SupervisorState is the coarse lifecycle phase reported by Snapshot.
type SupervisorState string

const (
	StateIdle          SupervisorState = "idle"
	StateIdentity      SupervisorState = "identity"
	StateConnecting    SupervisorState = "connecting"
	StateConnected     SupervisorState = "connected"
	StateBackoff       SupervisorState = "backoff"
	StateStopped       SupervisorState = "stopped"
	StateOperatorPause SupervisorState = "operator-paused"
)

// PanicLimit is the number of consecutive recovered engine panics that escalate
// a session from "live with anomaly" to an operator pause.
const PanicLimit = 3

const recentEventRing = 64

// SupervisorConfig tunes the loop. Zero durations fall back to the
// addendum/design defaults noted inline.
type SupervisorConfig struct {
	// Template carries static per-instance parameters: Endpoint, SNI,
	// ConnectURI, Policy, MTU. Key material comes from the identity.
	Template SessionConfig
	// Reconciler owns identity state and the registration API.
	Reconciler *Reconciler
	// Dialer selects the carrier for every generation (E-H3 ladder,
	// design §6). nil keeps the legacy H2-only behavior unchanged —
	// existing configurations and tests are unaffected.
	Dialer TransportDialer

	InitialBackoff       time.Duration // 1s
	MaxBackoff           time.Duration // 30s
	ResetAfterStable     time.Duration // 60s
	HealthInterval       time.Duration // 60s
	ProbeTimeout         time.Duration // 2s
	HealthFailureLimit   int           // 3 (z2k/Aether streak)
	RevalidationInterval time.Duration // 24h
	RestartCooldown      time.Duration // 300s (z2k kick)

	// Now / Sleep / Sink are injectables for deterministic tests and trace
	// wiring; production leaves Now and Sleep nil.
	Now   func() time.Time
	Sleep func(ctx context.Context, d time.Duration) error
	Sink  func(SupervisorEvent)
	// PanicHook observes a recovered engine-goroutine panic (M3-07). Nil in
	// production; tests use it to deterministically inject/observe panics that
	// would otherwise race the event sink.
	PanicHook func(any)

	// DeferRevalidation trusts a locally valid stored identity for the
	// FIRST connect without contacting the registration API. Field finding
	// (2026-08-25): networks that SNI-filter api.cloudflareclient.com turn
	// the start-of-session Ensure() into a permanent blocked-throttle loop —
	// the supervisor never dials, although the tunnel itself may be the very
	// path that restores API reachability. With the flag on: a stored
	// identity that passes local field validation is used directly,
	// ensuredAt is stamped at load time and periodic revalidation resumes on
	// the normal cadence after that. Absent/corrupt stores fall through to
	// the regular Ensure() path unchanged.
	DeferRevalidation bool
}

func (c *SupervisorConfig) fillDefaults() {
	if c.InitialBackoff <= 0 {
		c.InitialBackoff = time.Second
	}
	if c.MaxBackoff <= 0 {
		c.MaxBackoff = 30 * time.Second
	}
	if c.ResetAfterStable <= 0 {
		c.ResetAfterStable = 60 * time.Second
	}
	if c.HealthInterval <= 0 {
		c.HealthInterval = 60 * time.Second
	}
	if c.ProbeTimeout <= 0 {
		c.ProbeTimeout = 2 * time.Second
	}
	if c.HealthFailureLimit <= 0 {
		c.HealthFailureLimit = 3
	}
	if c.RevalidationInterval <= 0 {
		c.RevalidationInterval = 24 * time.Hour
	}
	if c.RestartCooldown <= 0 {
		c.RestartCooldown = 300 * time.Second
	}
}

// SupervisorEvent is one structured lifecycle event (§62.1 subset). Payloads
// carry redacted identifiers only (pin digest prefix, failure classes,
// statuses) — never tokens or keys (§61.3 enforcement lives in the pipeline
// adapter upstream).
type SupervisorEvent struct {
	Name         string
	Attempt      uint32
	FailureClass string
	Status       int
	BackoffMS    uint64
	DurationMS   uint64
	Colo         string // cf-warp-colo of the established edge (telemetry)
	Detail       string
	ObservedAt   time.Time
}

// Status is the externally visible snapshot of the supervisor.
type Status struct {
	State            SupervisorState
	Attempt          uint32
	RouteHeld        bool
	BackoffUntil     time.Time
	LastFailureClass string
	LastColo         string
	// LastTransport names the carrier of the last established session
	// ("h2"/"h3"; "" before the first connection or with the legacy H2
	// dialer path).
	LastTransport  string
	PendingPacket  bool
	DroppedWakeups uint64
}

var ErrAlreadyRunning = errors.New("transportwarp: supervisor already running")

// Supervisor runs the lifecycle loop described in the package comment.
type Supervisor struct {
	cfg SupervisorConfig

	mu            sync.Mutex
	state         SupervisorState
	attempt       uint32
	routeHeld     bool
	backoffUntil  time.Time
	lastClass     string
	panicStreak   int
	pausedByPanic bool
	lastColo      string
	lastTransport string
	pending       []byte
	dropped       uint64
	lastKick      time.Time
	events        []SupervisorEvent
	cur           packetTransport
	lastIdent     *Identity

	// pktSubs: secondary consumers of inbound DATAGRAM payloads (nested
	// carriers). Channels survive across session generations; each live
	// session gets its own pump goroutine (see SubscribePackets).
	pktSubs map[chan []byte]struct{}

	startOnce sync.Once
	stopOnce  sync.Once
	cancel    context.CancelFunc
	done      chan struct{}
}

// NewSupervisor validates the config shape and returns a stopped supervisor.
func NewSupervisor(cfg SupervisorConfig) (*Supervisor, error) {
	if cfg.Reconciler == nil {
		return nil, errors.New("transportwarp: supervisor requires a reconciler")
	}
	cfg.fillDefaults()
	return &Supervisor{cfg: cfg, state: StateIdle, done: make(chan struct{})}, nil
}

// Start launches the lifecycle loop once; later calls report
// ErrAlreadyRunning after the loop has finished.
func (s *Supervisor) Start(parent context.Context) error {
	s.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(parent)
		s.cancel = cancel
		go s.run(ctx)
	})
	select {
	case <-s.done:
		return ErrAlreadyRunning
	default:
		return nil
	}
}

// Stop cancels the loop and waits for completion. Idempotent.
func (s *Supervisor) Stop() {
	s.stopOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
	})
	<-s.done
}

// Done exposes loop termination.
func (s *Supervisor) Done() <-chan struct{} { return s.done }

// Snapshot returns the current status under the lock.
func (s *Supervisor) Snapshot() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		State:            s.state,
		Attempt:          s.attempt,
		RouteHeld:        s.routeHeld,
		BackoffUntil:     s.backoffUntil,
		LastFailureClass: s.lastClass,
		LastColo:         s.lastColo,
		LastTransport:    s.lastTransport,
		PendingPacket:    s.pending != nil,
		DroppedWakeups:   s.dropped,
	}
}

// RecentEvents returns a copy of the diagnostic ring (oldest first).
func (s *Supervisor) RecentEvents() []SupervisorEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]SupervisorEvent(nil), s.events...)
}

// WritePacket sends one outbound packet through the live session. With no
// live session (or one that dies mid-write) it implements the first-packet
// fix: the latest waking packet is buffered (single slot, latest wins) and
// flushed after the next validated connect; overwritten buffers count as
// dropped wake-ups.
func (s *Supervisor) WritePacket(pkt []byte) error {
	s.mu.Lock()
	sess := s.cur
	if sess != nil {
		select {
		case <-sess.Done():
			sess = nil // already terminating: use the wake-up path
		default:
		}
	}
	if sess == nil {
		if s.pending != nil {
			s.dropped++
		}
		s.pending = append([]byte(nil), pkt...)
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()

	if err := sess.WritePacket(pkt); err != nil {
		select {
		case <-sess.Done():
			// Session died mid-write: preserve the wake-up semantics.
			s.mu.Lock()
			if s.pending != nil {
				s.dropped++
			}
			s.pending = append([]byte(nil), pkt...)
			s.mu.Unlock()
			return nil
		default:
			return err
		}
	}
	return nil
}

// SubscribePackets registers a secondary consumer of inbound DATAGRAM
// payloads of the CURRENT session and of every future generation: nested
// carriers subscribe once at composition start and keep receiving frames
// across reconnects. Delivery is drop-instead-of-block (same discipline as
// Session.fanOut); overflow counts toward DroppedTaps. The cancel function
// unsubscribes and closes the channel exactly once; Supervisor loop exit
// closes all remaining taps.
func (s *Supervisor) SubscribePackets() (<-chan []byte, func()) {
	ch := make(chan []byte, 64)
	s.mu.Lock()
	if s.pktSubs == nil {
		s.pktSubs = make(map[chan []byte]struct{})
	}
	s.pktSubs[ch] = struct{}{}
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		if _, ok := s.pktSubs[ch]; ok {
			delete(s.pktSubs, ch)
			close(ch)
		}
		s.mu.Unlock()
	}
	return ch, cancel
}

// guardTapPump runs tapPump inside a recover frame: a panic in a tap-forwarding
// goroutine must never take the process down (M3-07). The caught panic is
// surfaced through failSafePanic, which emits an engine-panic event and, at a
// streak of PanicLimit, escalates to an operator pause.
func (s *Supervisor) guardTapPump(ctx context.Context, sess packetTransport) {
	defer func() {
		if r := recover(); r != nil {
			s.failSafePanic(r)
		}
	}()
	s.tapPump(ctx, sess)
}

// failSafePanic handles a recovered engine-goroutine panic. It records the
// streak, emits EvEnginePanic, and — once the streak hits PanicLimit — emits
// EvOperatorPause and pauses the tunnel. The panic does not crash the process:
// the supervisor (and any other engine goroutine) stays alive.
func (s *Supervisor) failSafePanic(r any) {
	if s.cfg.PanicHook != nil {
		s.cfg.PanicHook(r)
	}
	s.mu.Lock()
	s.panicStreak++
	streak := s.panicStreak
	alreadyPaused := s.pausedByPanic
	s.lastClass = FailureInternalPanic
	s.state = StateBackoff
	s.mu.Unlock()

	s.emit(SupervisorEvent{Name: EvEnginePanic, FailureClass: FailureInternalPanic, Detail: fmt.Sprintf("recovered: %v", r)})
	if streak >= PanicLimit && !alreadyPaused {
		s.mu.Lock()
		s.pausedByPanic = true
		s.state = StateOperatorPause
		s.mu.Unlock()
		s.emit(SupervisorEvent{Name: EvOperatorPause, FailureClass: FailureInternalPanic, Detail: fmt.Sprintf("panic limit reached (%d)", streak)})
	}
}

// clearPanicStreak resets the consecutive-panic counter once the tunnel reaches
// a healthy (connected) state: an operator pause requires a contiguous run, not
// panics spread across otherwise-healthy sessions.
func (s *Supervisor) clearPanicStreak() {
	s.mu.Lock()
	s.panicStreak = 0
	s.pausedByPanic = false
	s.mu.Unlock()
}

// tapPump forwards one live session's tap stream to supervisor-level
// subscribers. Exactly one pump runs per generation; it exits when the
// session's own tap channel closes (Session.Close) or ctx is cancelled.
func (s *Supervisor) tapPump(ctx context.Context, sess packetTransport) {
	src, _ := sess.SubscribePackets()
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, open := <-src:
			if !open {
				return
			}
			s.fanOutTaps(pkt)
		}
	}
}

// fanOutTaps delivers one inbound packet to every packet subscriber.
// PATCH-24/E19: each subscriber receives a PRIVATE COPY (M-30 parity with
// the session-level taps) — the old code handed the SAME slice to everyone,
// so one mutating subscriber would silently corrupt the data of the others.
func (s *Supervisor) fanOutTaps(pkt []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ch := range s.pktSubs {
		cp := make([]byte, len(pkt))
		copy(cp, pkt)
		select {
		case ch <- cp:
		default:
		}
	}
}

// closeTaps terminates every subscriber channel (loop teardown).
func (s *Supervisor) closeTaps() {
	s.mu.Lock()
	taps := make([]chan []byte, 0, len(s.pktSubs))
	for ch := range s.pktSubs {
		taps = append(taps, ch)
	}
	s.pktSubs = nil
	s.mu.Unlock()
	for _, ch := range taps {
		close(ch)
	}
}

// Restart requests an immediate reconnect (kick). Kicks are cooldown-paced
// (z2k kick 300s); force bypasses the cooldown for operator actions.
func (s *Supervisor) Restart(force bool) error {
	now := s.cfg.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !force && now.Sub(s.lastKick) < s.cfg.RestartCooldown {
		return fmt.Errorf("transportwarp: restart kick cooldown active")
	}
	s.lastKick = now
	if s.cur != nil {
		_ = s.cur.Close() // health loop observes Done() -> clean reconnect
	}
	return nil
}

// ---- internals ----

func (c *SupervisorConfig) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *SupervisorConfig) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Supervisor) setState(st SupervisorState) {
	s.mu.Lock()
	s.state = st
	s.mu.Unlock()
}

func (s *Supervisor) setClass(class string) {
	s.mu.Lock()
	s.lastClass = class
	s.mu.Unlock()
}

func (s *Supervisor) setLastIdent(ident *Identity) {
	s.mu.Lock()
	s.lastIdent = ident
	s.mu.Unlock()
}

func (s *Supervisor) emit(ev SupervisorEvent) {
	s.mu.Lock()
	ev.ObservedAt = s.cfg.now()
	s.events = append(s.events, ev)
	if len(s.events) > recentEventRing {
		s.events = s.events[1:]
	}
	sink := s.cfg.Sink
	s.mu.Unlock()
	if sink != nil {
		sink(ev)
	}
}

// backoffSeq produces InitialBackoff<<n capped at MaxBackoff (1,2,4,...,30).
type backoffSeq struct {
	cfg   *SupervisorConfig
	index int
}

func (b *backoffSeq) next() time.Duration {
	d := b.cfg.InitialBackoff << b.index
	if d > b.cfg.MaxBackoff || d <= 0 {
		d = b.cfg.MaxBackoff
	}
	if b.index < 62 {
		b.index++
	}
	return d
}

// observeLifetime implements the stable-run reset: a session that lived at
// least ResetAfterStable resets the sequence; shorter lifetimes keep it.
func (b *backoffSeq) observeLifetime(lived time.Duration) {
	if lived >= b.cfg.ResetAfterStable {
		b.index = 0
	}
}

// run is the main loop; it owns everything and terminates on ctx cancel.
func (s *Supervisor) run(ctx context.Context) {
	defer close(s.done)
	defer s.setState(StateStopped)
	defer s.closeTaps()

	var (
		ident     *Identity
		ensuredAt time.Time
		bo        = backoffSeq{cfg: &s.cfg}
	)

	for {
		if ctx.Err() != nil {
			return
		}

		// --- identity phase ---
		now := s.cfg.now()
		if ident == nil && s.cfg.DeferRevalidation {
			if stored, err := s.cfg.Reconciler.Store.Load(); err == nil {
				ident = stored
				ensuredAt = s.cfg.now()
				s.setLastIdent(stored)
				s.emit(SupervisorEvent{Name: EvIdentityRevalidationDeferred})
			}
			// Load failure (absent/corrupt/quarantined) intentionally falls
			// through to the standard Ensure() path below: provisioning and
			// quarantine handling stay exactly as before.
		}
		if ident == nil || now.Sub(ensuredAt) >= s.cfg.RevalidationInterval {
			res, err := s.cfg.Reconciler.Ensure(ctx)
			// Order matters: a blocked outcome is STRUCTURED even when err
			// is non-nil (throttled enrollment reports both); it must win
			// over the generic error path.
			switch {
			case res.Action == ActionBlockedThrottle || res.Action == ActionBlockedCooldown:
				// M3-05: throttle = "never re-enroll", NOT "stop tunnelling".
				// When the reconciler kept a LIVE identity through the throttle
				// (res.Identity != nil), adopt it and proceed to connect (the
				// keep-old dial) instead of idling until the throttle lifts —
				// liveness is proven by the data plane, not account state. Only
				// a missing identity (cold start / refused / revoked) pauses.
				if res.Identity != nil {
					ident = res.Identity
					// Do not revalidate before the throttle ends (kept identity
					// is already valid; the reconciler refused to reprovision).
					ensuredAt = res.ThrottleUntil
					s.setLastIdent(ident)
					s.emit(SupervisorEvent{Name: EvIdentityBlocked, FailureClass: res.FailureClass, Detail: string(res.Action)})
					continue // straight into the connect phase with keep-old identity
				}
				s.setState(StateBackoff)
				until := res.ThrottleUntil
				if !until.After(s.cfg.now()) {
					until = s.cfg.now().Add(bo.next())
				}
				s.schedule(until.Sub(s.cfg.now()))
				s.emit(SupervisorEvent{Name: EvIdentityBlocked, FailureClass: res.FailureClass, Detail: string(res.Action)})
				s.emit(SupervisorEvent{Name: EvReconnectScheduled, BackoffMS: msDur(until.Sub(s.cfg.now()))})
				if !s.pauseUntil(ctx, until) {
					return
				}
				continue
			case err != nil:
				s.setClass(ClassEnrollmentRequest)
				s.setState(StateBackoff)
				s.emit(SupervisorEvent{Name: EvIdentityBlocked, FailureClass: ClassEnrollmentRequest})
				d := bo.next()
				s.schedule(d)
				if !s.pause(ctx, d) {
					return
				}
				continue
			case res.Identity == nil:
				// Enrolling produced nothing usable; pace and retry.
				s.setState(StateBackoff)
				d := bo.next()
				s.schedule(d)
				s.emit(SupervisorEvent{Name: EvIdentityBlocked, FailureClass: ClassEnrollmentNetwork})
				s.emit(SupervisorEvent{Name: EvReconnectScheduled, BackoffMS: msDur(d)})
				if !s.pause(ctx, d) {
					return
				}
				continue
			}
			ident = res.Identity
			ensuredAt = s.cfg.now()
			s.setLastIdent(ident)
			bo.index = 0 // fresh identity generation: clean slate
		}

		// --- connect phase ---
		scfg, err := buildSessionConfig(s.cfg.Template, ident)
		if err != nil {
			// Unusable stored identity: force a reconcile round.
			ident = nil
			s.emit(SupervisorEvent{Name: EvMasqueRejected, FailureClass: FailureTLSAlert, Detail: truncate(err.Error(), 80)})
			continue
		}

		s.mu.Lock()
		s.attempt++
		attempt := s.attempt
		s.state = StateConnecting
		s.mu.Unlock()
		started := s.cfg.now()
		s.emit(SupervisorEvent{Name: EvSessionGenerationStarted, Attempt: attempt})

		sess, att, derr := s.dialCarrier(ctx, scfg)
		// Ladder events (transport_switched / h3_negotiated) are emitted by
		// the supervisor on the single event path — never by the dialer.
		for _, ev := range att.Events {
			ev.Attempt = attempt
			s.emit(ev)
		}
		if derr != nil {
			s.setClass(att.Result.FailureClass)
			s.setState(StateBackoff)
			s.emit(SupervisorEvent{Name: EvMasqueRejected, Attempt: attempt, FailureClass: att.Result.FailureClass, Status: att.Result.Status, DurationMS: att.Result.DurationMS})
			d := bo.next()
			s.schedule(d)
			s.emit(SupervisorEvent{Name: EvReconnectScheduled, Attempt: attempt, FailureClass: att.Result.FailureClass, BackoffMS: msDur(d)})
			if !s.pause(ctx, d) {
				return
			}
			continue
		}

		if verr := sess.ValidateDataPlane(ctx); verr != nil {
			if s.cfg.Dialer != nil {
				for _, ev := range s.cfg.Dialer.ObserveValidation(att.Transport, verr) {
					ev.Attempt = attempt
					s.emit(ev)
				}
			}
			sess.Close()
			s.setClass(FailureValidation)
			s.setState(StateBackoff)
			s.emit(SupervisorEvent{Name: EvMasqueRejected, Attempt: attempt, FailureClass: FailureValidation, DurationMS: msDur(s.cfg.now().Sub(started))})
			d := bo.next()
			s.schedule(d)
			s.emit(SupervisorEvent{Name: EvReconnectScheduled, Attempt: attempt, FailureClass: FailureValidation, BackoffMS: msDur(d)})
			if !s.pause(ctx, d) {
				return
			}
			continue
		}
		if s.cfg.Dialer != nil {
			for _, ev := range s.cfg.Dialer.ObserveValidation(att.Transport, nil) {
				ev.Attempt = attempt
				s.emit(ev)
			}
		}

		// --- connected ---
		s.mu.Lock()
		s.cur = sess
		s.routeHeld = true
		s.state = StateConnected
		s.attempt = 0 // validated connection resets the attempt counter
		s.lastColo = att.Result.Colo
		s.lastTransport = att.Transport
		s.mu.Unlock()
		s.clearPanicStreak()
		attempt = 0
		sessStart := s.cfg.now()
		s.emit(SupervisorEvent{Name: EvMasqueConnected, DurationMS: msDur(sessStart.Sub(started)), Colo: att.Result.Colo, Detail: "transport=" + att.Transport})

		// Packet taps for secondary in-tunnel consumers (nested carriers):
		// one pump per generation; it dies together with the session while
		// the subscriber channels survive across reconnects.
		go s.guardTapPump(ctx, sess)

		// First-packet fix: flush the buffered wake-up packet, if any.
		if pkt := s.takePending(); pkt != nil {
			_ = sess.WritePacket(pkt)
		}

		reason := s.healthLoop(ctx, sess, scfg.LocalV4)
		lived := s.cfg.now().Sub(sessStart)
		bo.observeLifetime(lived)

		s.mu.Lock()
		if s.cur == sess {
			s.cur = nil
		}
		s.routeHeld = false // fail-open default between sessions
		s.mu.Unlock()

		sess.Close()
		s.emit(SupervisorEvent{Name: EvMasqueDisconnected, FailureClass: reason, DurationMS: msDur(lived)})

		if reason == ReasonHealthStreak || reason == ReasonSessionLost {
			d := bo.next()
			s.schedule(d)
			s.emit(SupervisorEvent{Name: EvReconnectScheduled, FailureClass: reason, BackoffMS: msDur(d)})
			if !s.pause(ctx, d) {
				return
			}
		}
	}
}

// dialCarrier routes one generation through the configured TransportDialer,
// or the legacy H2 carrier when no dialer is wired (byte-for-byte the
// pre-EH3 behavior: DialSession + supervisor-side validation).
func (s *Supervisor) dialCarrier(ctx context.Context, scfg SessionConfig) (packetTransport, TransportAttempt, error) {
	if s.cfg.Dialer == nil {
		sess, cres, err := DialSession(ctx, scfg)
		return sess, TransportAttempt{Transport: TransportH2, Result: cres}, err
	}
	return s.cfg.Dialer.Dial(ctx, scfg)
}

// healthLoop probes the established session every HealthInterval. Any
// inbound packet counts as alive; ProbeTimeout without a reply is one
// failure. The streak reaching HealthFailureLimit tears the session down
// with ReasonHealthStreak (fail-open was applied by the caller).
// Exactly ONE reader goroutine exists per call; it terminates when the
// session closes or the context is cancelled. localV4 feeds the synthetic
// DNS probe (carrier-independent since the E-H3 ladder).
func (s *Supervisor) healthLoop(ctx context.Context, sess packetTransport, localV4 [4]byte) string {
	pktCh := make(chan packetMsg, 16)
	readerDone := make(chan struct{})
	go func() {
		// readerDone is owned by the reader and closed exactly once (M3-02);
		// tests trace reader termination through this channel.
		defer close(pktCh)
		defer close(readerDone)
		defer func() {
			if r := recover(); r != nil {
				s.failSafePanic(r)
			}
		}()
		for {
			pkt, err := sess.ReadPacket(ctx)
			if err != nil {
				return
			}
			select {
			case pktCh <- packetMsg{data: pkt}:
			case <-sess.Done():
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	// On ANY exit, drain pktCh so a reader blocked in `pktCh <-` is released
	// and never leaks. M3-01's ok-semantics makes ReadPacket return
	// ErrSessionClosed immediately afterwards, so the reader terminates.
	// The drain MUST be bounded: a `select { case <-pktCh: default: return }`
	// against a CLOSED channel spins forever (a closed channel is always
	// ready, starving `default`). A hard cap of cap+1 covers the buffered
	// packets plus the one in-flight send the reader releases; after that the
	// reader has exited, so nothing more can arrive.
	defer func() {
		for i := 0; i < cap(pktCh)+1; i++ {
			select {
			case <-pktCh:
			default:
				return
			}
		}
	}()

	ticker := time.NewTicker(s.cfg.HealthInterval)
	defer ticker.Stop()
	failures := 0
	for {
		select {
		case <-ctx.Done():
			return ReasonStop
		case <-sess.Done():
			return ReasonSessionLost
		case <-ticker.C:
		}

		probe, err := NewDNSProbe(localV4, [4]byte{8, 8, 8, 8}, "cloudflare.com")
		if err == nil {
			err = sess.WritePacket(probe.Packet)
		}
		if err != nil {
			failures++
		} else {
			alive := false
			timer := time.NewTimer(s.cfg.ProbeTimeout)
		probeWait:
			for !alive {
				select {
				case m, open := <-pktCh:
					if !open || m.err != nil {
						break probeWait // terminal: handled via Done()/close below
					}
					alive = true
				case <-timer.C:
					break probeWait
				case <-ctx.Done():
					timer.Stop()
					return ReasonStop
				case <-sess.Done():
					timer.Stop()
					return ReasonSessionLost
				}
			}
			timer.Stop()
			if alive {
				failures = 0
				s.setClass("")
			} else {
				failures++
			}
		}

		if failures > 0 {
			s.emit(SupervisorEvent{Name: EvKeepaliveFailed, FailureClass: ReasonHealthStreak})
		}
		if failures >= s.cfg.HealthFailureLimit {
			s.emit(SupervisorEvent{Name: EvRouteReleasedFailOpen, FailureClass: ReasonHealthStreak})
			s.setState(StateBackoff)
			return ReasonHealthStreak
		}
	}
}

func (s *Supervisor) takePending() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending
	s.pending = nil
	return p
}

func (s *Supervisor) schedule(d time.Duration) {
	s.mu.Lock()
	s.backoffUntil = s.cfg.now().Add(d)
	s.state = StateBackoff
	s.mu.Unlock()
}

// pause sleeps for d; false means the loop must terminate.
func (s *Supervisor) pause(ctx context.Context, d time.Duration) bool {
	if err := s.cfg.sleep(ctx, d); err != nil {
		return false
	}
	return ctx.Err() == nil
}

// pauseUntil sleeps until t (bounded below to avoid busy-looping on stale
// timestamps).
func (s *Supervisor) pauseUntil(ctx context.Context, until time.Time) bool {
	d := until.Sub(s.cfg.now())
	if d < time.Millisecond {
		d = time.Millisecond
	}
	return s.pause(ctx, d)
}

// buildSessionConfig fills the template's key/address fields from identity.
func buildSessionConfig(t SessionConfig, ident *Identity) (SessionConfig, error) {
	priv, err := ParseClientKeyB64(ident.PrivateKey)
	if err != nil {
		return SessionConfig{}, err
	}
	pin, _, err := ParsePublicKeyPEM(ident.PinPEM)
	if err != nil {
		return SessionConfig{}, err
	}
	// defense-in-depth (BLOCKER B-1): guard before As4() — a tampered identity
	// or a v6/4-in-6 string in AssignedV4 must never reach the panicking As4().
	v4, err := netip.ParseAddr(ident.AssignedV4)
	if err != nil || !v4.Is4() {
		return SessionConfig{}, fmt.Errorf("%w: assigned_v4 %q", ErrIdentityInvalid, ident.AssignedV4)
	}
	out := t
	out.ClientKey = priv
	out.Pin = pin
	out.LocalV4 = v4.As4()
	return out, nil
}

func msDur(d time.Duration) uint64 {
	if d < 0 {
		return 0
	}
	return uint64(d.Milliseconds())
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
