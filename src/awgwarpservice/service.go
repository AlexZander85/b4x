// Package awgwarpservice assembles the AWG-WARP transport (reserve kind
// "warp", tunnels panel stage 2) from the transport/wg engine and the
// system.warp.awg config branch.
//
// The deliberately-thin last mile, the warpservice canon: the engine owns
// sessions, trust gates and telemetry; this package binds them to the
// daemon loop (identity slot -> supervisor tick -> carrier exposure).
// One registration per boot, restart caps, honest states — no half-alive
// shapes (the config gate belongs to main, exactly like warpservice).
//
// Data plane: the session's userspace netstack (gVisor) serves BOTH the
// TCP streams and the UDP full-scope leg — the same carrier surface proton
// exposes. Kernel-TUN/PBR wiring stays field-layer work and is not shipped
// half-done here.
//
// Secret discipline: the identity file (private key) never leaves the
// store; StatusView carries derived fields only.
package awgwarpservice

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// superviseTick is the supervisor cadence (the proton canon: 30 s).
const superviseTick = 30 * time.Second

// Event ring capacity.
const eventRingCap = 32

// Event is one structured service event (sink consumers render these).
type Event struct {
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
	At     int64  `json:"at"`
}

// StatusView is the externally visible state (no secrets).
type StatusView struct {
	Enabled         bool    `json:"enabled"`
	Running         bool    `json:"running"`
	Listening       bool    `json:"listening"`
	State           string  `json:"state"`
	IdentityPresent bool    `json:"identity_present"`
	AssignedV4      string  `json:"assigned_v4,omitempty"`
	Endpoint        string  `json:"endpoint,omitempty"`
	Restarts        int     `json:"restarts"`
	LastFailure     string  `json:"last_failure,omitempty"`
	Events          []Event `json:"events,omitempty"`
}

// Service states (closed set, honest transitions).
const (
	StateIdle        = "idle"
	StateRegistering = "registering"
	StateStarting    = "starting"
	StateEstablished = "established"
	StateBackoff     = "backoff"
	StateCapped      = "restart-capped"
	StateStopped     = "stopped"
)

// ErrNotListening is the honest refusal for dials without an established
// session (never a silent direct fallback).
var ErrNotListening = errors.New("awgwarp: no established session to dial through")

// Options carries the injection seams (tests wire httptest; production
// leaves them nil).
type Options struct {
	// HTTP is the enrollment transport escape hatch (SNI-filtered networks).
	HTTP *http.Client
	// EnrollBaseURL overrides the registration API base (tests point it at
	// a fake server; production leaves it empty for the canonical API).
	EnrollBaseURL string
	// Now is the clock seam (tests).
	Now func() time.Time
	// OnEvent is the non-blocking event sink (the daemon log renderer).
	OnEvent func(Event)
}

// Runtime owns the AWG-WARP engine for one config generation. The Runtime
// itself is the reserve.Carrier (the proton canon: one object, one
// lifecycle).
type Runtime struct {
	cfg      config.WarpAWGConfig
	opts     Options
	store    *twg.IdentityStore
	enroll   *twg.EnrollClient
	endpoint netip.AddrPort
	profile  twg.Profile
	guard    restartGuard

	mu               sync.Mutex
	cancel           context.CancelFunc
	running          bool
	stopped          bool
	identity         *twg.Identity
	sess             *twg.Session
	state            string
	events           []Event
	restarts         int
	lastFailure      string
	dialOK, dialFail uint64

	registeredThisBoot atomic.Bool
}

// Build validates the system.warp.awg section and constructs the runtime
// WITHOUT starting anything or touching the network. It succeeds even when
// Enabled=false (the warp/proton parity: the daemon gates on config; the
// CLI enrollment path reuses the assembly).
func Build(cfg *config.Config, opts Options) (*Runtime, error) {
	awg := cfg.System.Warp.AWG
	if err := cfg.System.Warp.Masquerade.Validate(); err != nil {
		// The masquerade section belongs to the whole system.warp domain.
		return nil, err
	}
	endpoint, err := awg.EffectiveEndpoint()
	if err != nil {
		return nil, err
	}
	profile, err := awg.EffectiveProfile()
	if err != nil {
		return nil, err
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Runtime{
		cfg:      awg,
		opts:     opts,
		store:    &twg.IdentityStore{Path: awg.EffectiveIdentityPath()},
		enroll:   &twg.EnrollClient{HTTP: opts.HTTP, BaseURL: opts.EnrollBaseURL},
		endpoint: endpoint,
		profile:  profile,
		guard:    restartGuard{now: opts.Now, max: awg.EffectiveMaxRestarts()},
		state:    StateIdle,
	}, nil
}

// Start launches the supervisor loop (daemon mode only; the config gate
// belongs to the caller — warp/proton parity).
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return errors.New("awgwarp: runtime already stopped")
	}
	if r.running {
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.running = true
	go r.loop(runCtx)
	return nil
}

// Stop tears the loop and the live session down (no-op before Start).
func (r *Runtime) Stop() {
	r.mu.Lock()
	if !r.running || r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	cancel := r.cancel
	sess := r.sess
	r.sess = nil
	r.state = StateStopped
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if sess != nil {
		sess.Stop()
	}
}

// RestartNow retires the live session and forces an immediate supervision
// cycle — the GUI restart button. The rebuild still passes the restart caps
// (an operator hammering the button cannot exhaust CF slots).
func (r *Runtime) RestartNow(ctx context.Context) {
	r.mu.Lock()
	sess := r.sess
	r.sess = nil
	r.mu.Unlock()
	if sess != nil {
		sess.Stop()
		r.appendEvent(Event{Name: "awgwarp_session_retired", Detail: "restart-now"})
	}
	r.tick(ctx)
}

// EnrollOnce runs one identity pass (provision or keep) — the CLI path.
func (r *Runtime) EnrollOnce(ctx context.Context) error {
	return r.ensureIdentity(ctx)
}

// Status snapshots the externally visible state (safe before Start).
func (r *Runtime) Status() StatusView {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := StatusView{
		Enabled:     r.cfg.Enabled,
		State:       r.state,
		LastFailure: r.lastFailure,
		Restarts:    r.restarts,
		Events:      append([]Event(nil), r.events...),
		Endpoint:    r.endpoint.String(),
	}
	if r.identity != nil {
		v.IdentityPresent = true
		v.AssignedV4 = r.identity.AssignedV4
	}
	if r.sess != nil && r.sess.State() == twg.StateEstablished {
		v.Running = true
		v.Listening = true
	}
	return v
}

// ---- supervisor loop ------------------------------------------------------

func (r *Runtime) loop(ctx context.Context) {
	ticker := time.NewTicker(superviseTick)
	defer ticker.Stop()
	r.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

// tick is one deterministic supervision cycle: identity -> session. A
// disabled config is a truthful no-op (zero wire calls).
func (r *Runtime) tick(ctx context.Context) {
	if !r.cfg.Enabled {
		return
	}
	if err := r.ensureIdentity(ctx); err != nil {
		return // identity gates everything else
	}
	r.ensureSession(ctx)
}

// ensureIdentity loads the stored identity or registers exactly once per
// boot (the proton canon: no registration loops, no slot burning).
func (r *Runtime) ensureIdentity(ctx context.Context) error {
	r.mu.Lock()
	ident := r.identity
	r.mu.Unlock()
	if ident != nil {
		return nil
	}
	id, err := r.store.Load()
	switch {
	case err == nil:
		r.mu.Lock()
		r.identity = id
		r.mu.Unlock()
		r.registeredThisBoot.Store(true) // the stored key IS registered
		r.appendEvent(Event{Name: "awgwarp_identity_loaded", Detail: id.AssignedV4})
		return nil
	case errors.Is(err, twg.ErrIdentityAbsent):
		// fall through to registration
	case errors.Is(err, twg.ErrIdentityCorrupt):
		// Load already quarantined the file; a fresh registration on the
		// clean slot is the proton canon (never a silent skip).
		r.appendEvent(Event{Name: "awgwarp_identity_corrupt", Detail: err.Error()})
	default:
		r.fail(StateBackoff, "identity store: "+err.Error())
		return err
	}

	if !r.registeredThisBoot.CompareAndSwap(false, true) {
		r.fail(StateCapped, "registration budget spent for this boot")
		return errors.New("awgwarp: registration budget spent for this boot")
	}
	r.setState(StateRegistering)
	id, out, err := r.enroll.Enroll(ctx)
	if err != nil {
		r.fail(classifyEnroll(out), "registration failed: "+err.Error())
		return err
	}
	if err := r.store.Save(id); err != nil {
		r.fail(StateBackoff, "identity store save: "+err.Error())
		return err
	}
	r.mu.Lock()
	r.identity = id
	r.mu.Unlock()
	r.appendEvent(Event{Name: "awgwarp_registered", Detail: id.AssignedV4})
	return nil
}

// ensureSession builds and starts the AWG session when none is alive
// (restart caps guard every rebuild).
func (r *Runtime) ensureSession(ctx context.Context) {
	r.mu.Lock()
	sess := r.sess
	alive := sess != nil && sess.State() != twg.StateClosed
	ident := r.identity
	r.mu.Unlock()
	if alive || ident == nil {
		return
	}
	if !r.guard.allowed() {
		r.fail(StateCapped, "restart capped")
		return
	}

	r.setState(StateStarting)
	v4, err := netip.ParseAddr(ident.AssignedV4)
	if err != nil {
		r.fail(StateBackoff, "identity assigned_v4: "+err.Error())
		return
	}
	s, err := twg.NewSession(twg.SessionConfig{
		Ident:    ident,
		Profile:  r.profile,
		Endpoint: r.endpoint.String(),
		Tunnel: twg.TunnelConfig{
			Mode:      twg.ModeNetstack,
			Addresses: []netip.Addr{v4},
			// CF-native resolver: 1.1.1.1 rides inside the WARP tunnel.
			DNS: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
			MTU: r.cfg.EffectiveMTU(),
		},
		// The service owns rebuilds: one generation per session build, the
		// supervisor loop re-ensures after a loss (proton canon).
		MaxGenerations: 1,
		Health: twg.HealthConfig{
			KeepaliveSec: 25,
			Gate:         twg.TrustGate{RoundTrips: 2, DNSServer: [4]byte{1, 1, 1, 1}},
		},
		Callbacks: twg.SessionCallbacks{
			OnEvent: func(ev twg.SessionEvent) {
				r.appendEvent(Event{Name: "awgwarp_session_event", Detail: string(ev.Class)})
			},
			OnEstablished: func() {
				r.mu.Lock()
				r.state = StateEstablished
				r.lastFailure = ""
				r.mu.Unlock()
				r.appendEvent(Event{Name: "awgwarp_session_established"})
			},
			OnLost: func(f twg.Failure) {
				r.mu.Lock()
				r.lastFailure = string(f.Class)
				r.state = StateBackoff
				r.mu.Unlock()
				r.appendEvent(Event{Name: "awgwarp_session_lost", Detail: string(f.Class)})
			},
		},
	})
	if err != nil {
		r.fail(StateBackoff, "session build: "+err.Error())
		return
	}
	if err := s.Start(); err != nil {
		r.fail(StateBackoff, "session start: "+err.Error())
		return
	}
	r.guard.record()
	r.mu.Lock()
	r.sess = s
	r.restarts++
	r.state = StateStarting
	r.mu.Unlock()
	r.appendEvent(Event{Name: "awgwarp_session_started", Detail: r.endpoint.String()})
}

// ---- internals ------------------------------------------------------------

func (r *Runtime) setState(s string) {
	r.mu.Lock()
	r.state = s
	r.mu.Unlock()
}

func (r *Runtime) fail(state, detail string) {
	r.mu.Lock()
	r.state = state
	r.lastFailure = detail
	r.mu.Unlock()
	r.appendEvent(Event{Name: "awgwarp_failure", Detail: detail})
}

func (r *Runtime) appendEvent(ev Event) {
	ev.At = r.opts.Now().Unix()
	r.mu.Lock()
	r.appendEventLocked(ev)
	r.mu.Unlock()
	if cb := r.opts.OnEvent; cb != nil {
		cb(ev)
	}
}

func (r *Runtime) appendEventLocked(ev Event) {
	r.events = append(r.events, ev)
	if len(r.events) > eventRingCap {
		r.events = r.events[len(r.events)-eventRingCap:]
	}
}

func classifyEnroll(out twg.EnrollOutcome) string {
	// Refused (slot dead) and throttled (rate limit) land in backoff alike:
	// neither ever triggers an automatic re-registration — the boot budget
	// is spent either way, the next boot or the owner action decides.
	return StateBackoff
}

// restartGuard is the per-hour rebuild cap (the proton canon: caps apply to
// the supervisor's own rebuilds; a capped state is honest, never bypassed).
type restartGuard struct {
	now    func() time.Time
	max    int
	stamps []time.Time
}

func (g *restartGuard) allowed() bool {
	if g.max <= 0 {
		return true
	}
	now := g.now()
	keep := g.stamps[:0]
	for _, t := range g.stamps {
		if now.Sub(t) < time.Hour {
			keep = append(keep, t)
		}
	}
	g.stamps = keep
	return len(g.stamps) < g.max
}

func (g *restartGuard) record() {
	g.stamps = append(g.stamps, g.now())
}
