// Package warp runtime — production controller of the built-in WARP/MASQUE
// transport lifecycle (FB-02 WARP section).
//
// src/warp is a pure library of transport primitives (enrollment, TUN
// registry, mark allocation, health, authorization, trace pipeline) with no
// observability. This file is the production layer: it instantiates the
// primitives, owns the per-session lifecycle state machine
// (enrollment -> TUN -> routing -> promotion -> rollback) and increments the
// ten §72 base-transport hard-gate counters exactly on the violating branch
// of each real check. The violating branches are the production violation
// paths: a count != 0 in a validation window is a genuine base-transport
// violation, not synthetic telemetry.
//
// The runtime is a controller loop: Start() launches the worker, Stop()
// shuts it down, Submit() feeds bounded control events from the future
// HTTP/CLI/control-plane callers. The direct methods (Register, ApplyRoute,
// Restart, ...) are the same handlers the loop dispatches to, so integration
// tests enter through the same production roots as the daemon.
package warp

import (
	"bytes"
	"errors"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

// warpControlRouteMark is the reserved mark of the base control socket
// (addendum v1.2 §17 "base control socket -> B4-assigned SO_MARK
// warp-control-direct", WARP-6). A route applied with the control mark
// targets the control path's own socket — that is the recursive-control-route
// violation.
const warpControlRouteMark uint32 = 0x6001

// Config is the production tuning of the WARP lifecycle controller.
// Defaults follow the addendum: bounded restart budget (3), bounded event bus.
type Config struct {
	MaxRestarts int
	BusCapacity int
}

// DefaultConfig returns the production runtime defaults.
func DefaultConfig() Config {
	return Config{MaxRestarts: 3, BusCapacity: 64}
}

// ControlEventKind is the kind of a lifecycle control event dispatched to the
// runtime loop.
type ControlEventKind string

const (
	EventEnroll        ControlEventKind = "enroll"
	EventRestart       ControlEventKind = "restart"
	EventApplyRoute    ControlEventKind = "apply-route"
	EventControlAction ControlEventKind = "control-action"
	EventRollback      ControlEventKind = "rollback"
	EventTraceExport   ControlEventKind = "trace-export"
)

// ControlEvent is one bounded control-plane event for the runtime loop. Every
// field is the exact argument set of the corresponding handler; unused fields
// are zero values.
type ControlEvent struct {
	Kind          ControlEventKind
	Session       string
	Policy        DialPolicy
	Lease         TunLease
	Destinations  []string
	Auth          *TransportAuthorization
	Flow          string
	AllowControl  bool
	Trace         TransportTraceEnvelope
	IncludeSecret bool
	Now           time.Time
}

// sessionState is the per-session lifecycle state of the controller.
type sessionState struct {
	policy       EnrollmentPolicy
	attempts     int
	restarts     int
	health       *HealthTracker
	secrets      map[string][]byte
	auth         *TransportAuthorization
	destinations []string
	mark         uint32
	hasApplied   bool
	hasPrevious  bool
}

// Runtime owns the production WARP lifecycle state and the ten §72
// base-transport hard-gate producers.
type Runtime struct {
	cfg Config

	marks   *MarkAllocator
	tun     *TunRegistry
	secrets *SecretStore
	trace   *TracePipeline

	mu         sync.Mutex
	sessions   map[string]*sessionState
	markOwners map[uint32]string

	events chan ControlEvent
	stop   chan struct{}
	wg     sync.WaitGroup
}

// NewRuntime builds the production WARP lifecycle controller from the library
// primitives. It is a production call site of MarkAllocator/TunRegistry/
// SecretStore/TracePipeline (FB-02 wiring probe).
func NewRuntime(cfg Config) *Runtime {
	if cfg.MaxRestarts <= 0 {
		cfg.MaxRestarts = 3
	}
	if cfg.BusCapacity <= 0 {
		cfg.BusCapacity = 64
	}
	return &Runtime{
		cfg:        cfg,
		marks:      NewMarkAllocator(),
		tun:        NewTunRegistry(),
		secrets:    NewSecretStore(),
		trace:      NewTracePipeline(256),
		sessions:   map[string]*sessionState{},
		markOwners: map[uint32]string{},
		events:     make(chan ControlEvent, cfg.BusCapacity),
	}
}

// Start launches the lifecycle controller loop. Safe to call once.
func (rt *Runtime) Start() {
	if rt == nil || rt.stop != nil {
		return
	}
	rt.stop = make(chan struct{})
	rt.wg.Add(1)
	go rt.loop()
}

// Stop shuts down the controller loop. Safe to call on a stopped runtime.
func (rt *Runtime) Stop() {
	if rt == nil || rt.stop == nil {
		return
	}
	close(rt.stop)
	rt.wg.Wait()
}

// Submit feeds one bounded control event into the loop; returns false when
// the runtime is stopped or the bounded bus is full (never blocks callers).
func (rt *Runtime) Submit(ev ControlEvent) bool {
	if rt == nil || rt.stop == nil {
		return false
	}
	select {
	case rt.events <- ev:
		return true
	default:
		return false
	}
}

// loop is the controller loop: it dispatches bounded control events to the
// same handlers the direct methods expose.
func (rt *Runtime) loop() {
	defer rt.wg.Done()
	for {
		select {
		case <-rt.stop:
			return
		case ev := <-rt.events:
			switch ev.Kind {
			case EventEnroll:
				_ = rt.Register(ev.Session, DefaultEnrollmentPolicy())
			case EventRestart:
				_ = rt.Restart(ev.Session)
			case EventApplyRoute:
				_ = rt.ApplyRoute(ev.Session, ev.Policy, ev.Lease, ev.Destinations, ev.Auth)
			case EventControlAction:
				_ = rt.ControlAction(ev.Session, ev.Flow, ev.AllowControl)
			case EventRollback:
				_ = rt.Rollback(ev.Session)
			case EventTraceExport:
				_ = rt.PublishTrace(ev.Session, ev.Trace)
			}
		}
	}
}

func (rt *Runtime) session(s string) *sessionState {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.sessions[s]
}

// ---------------------------------------------------------------------------
// §72 hard-gate producers (violating branches only)
// ---------------------------------------------------------------------------

// Register opens one enrollment attempt for a session under the bounded
// attempts policy. The violation branch is an attempt beyond the policy
// MaxAttempts (warp_unbounded_registration_total — repeated registration is
// forbidden by the addendum).
func (rt *Runtime) Register(session string, policy EnrollmentPolicy) error {
	if rt == nil || session == "" {
		return errors.New("warp runtime not initialized")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st := rt.sessions[session]
	if st == nil {
		st = &sessionState{policy: policy, health: &HealthTracker{}}
		rt.sessions[session] = st
	}
	st.attempts++
	if st.attempts > st.policy.MaxAttempts {
		observability.Default().Metrics.Inc(observability.MetricWarpUnboundedRegistration, nil, 1)
		return errors.New("unbounded enrollment attempts")
	}
	return nil
}

// PutSecret stores a session secret in the physical SecretStore and in the
// session key material used by PublishTrace redaction checks.
func (rt *Runtime) PutSecret(session, id string, secret []byte) error {
	if rt == nil || session == "" || id == "" || len(secret) == 0 {
		return errors.New("invalid secret")
	}
	if err := rt.secrets.Put(session+"/"+id, secret); err != nil {
		return err
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st := rt.sessions[session]
	if st == nil {
		return errors.New("session not registered")
	}
	if st.secrets == nil {
		st.secrets = map[string][]byte{}
	}
	st.secrets[id] = append([]byte(nil), secret...)
	return nil
}

// ObserveHealth feeds one protocol/data liveness sample into the session
// health tracker.
func (rt *Runtime) ObserveHealth(session string, protocol, data bool) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	st := rt.sessions[session]
	rt.mu.Unlock()
	if st != nil {
		st.health.Observe(protocol, data, time.Now().UTC())
	}
}

// ApplyRoute applies a route for a session. It is the composition point of
// the lifecycle: liveness proof, TUN ownership, recursion guard, mark
// ownership, atomic destination set. Violating branches (in evaluation
// order) increment exactly one §72 counter each.
func (rt *Runtime) ApplyRoute(session string, policy DialPolicy, lease TunLease, destinations []string, auth *TransportAuthorization) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st := rt.sessions[session]
	if st == nil {
		return errors.New("session not registered")
	}

	// 1. Liveness: a route must not be activated without data-plane liveness
	// proof (warp_route_without_liveness_total).
	if st.health.State != HealthDataAlive {
		observability.Default().Metrics.Inc(observability.MetricWarpRouteWithoutLiveness, nil, 1)
		return errors.New("route activation without liveness proof")
	}

	// 2. Foreign interface: the base transport owns exactly its own TUN; a
	// lease owned by another session is foreign and must never be modified
	// (warp_foreign_interface_modified_total).
	if err := rt.tun.Claim(lease); err != nil {
		observability.Default().Metrics.Inc(observability.MetricWarpForeignInterfaceModified, nil, 1)
		return err
	}

	// 3. Recursion guard: a control route applied with the base control
	// socket mark targets its own socket (warp_recursive_control_route_total).
	if policy.Mark == warpControlRouteMark {
		observability.Default().Metrics.Inc(observability.MetricWarpRecursiveControlRoute, nil, 1)
		return errors.New("recursive control route")
	}

	// 4. Mark ownership: a policy-pinned mark is owned by exactly one
	// session (warp_mark_collision_total).
	if owner, ok := rt.markOwners[policy.Mark]; ok && owner != session {
		observability.Default().Metrics.Inc(observability.MetricWarpMarkCollision, nil, 1)
		return errors.New("mark collision")
	}
	rt.markOwners[policy.Mark] = session

	// 5. Atomic destination set: a partially applied set (some entries
	// applied, some not) is forbidden (warp_destination_set_partial_apply_total).
	applied := append([]string(nil), st.destinations...)
	for _, d := range destinations {
		if d == "" {
			if len(applied) > len(st.destinations) {
				observability.Default().Metrics.Inc(observability.MetricWarpDestinationSetPartialApply, nil, 1)
			}
			return errors.New("destination set partially applied")
		}
		applied = append(applied, d)
	}

	st.mark = policy.Mark
	st.destinations = applied
	st.auth = auth
	if st.hasApplied {
		st.hasPrevious = true
	}
	st.hasApplied = true
	return nil
}

// Restart restarts a session's transport under the bounded restart budget.
// The violation branch is a restart beyond the configured MaxRestarts
// (warp_unbounded_restart_total).
func (rt *Runtime) Restart(session string) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st := rt.sessions[session]
	if st == nil {
		return errors.New("session not registered")
	}
	st.restarts++
	if st.restarts > rt.cfg.MaxRestarts {
		observability.Default().Metrics.Inc(observability.MetricWarpUnboundedRestart, nil, 1)
		return errors.New("unbounded restarts")
	}
	return nil
}

// ControlAction executes a control action against a flow. The violation
// branch is an action on a flow the exact-scoped TransportAuthorization does
// not own (warp_unrelated_control_action_total).
func (rt *Runtime) ControlAction(session, flow string, allowControl bool) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st := rt.sessions[session]
	if st == nil || st.auth == nil || st.auth.FlowID != flow || (allowControl && !st.auth.AllowControl) {
		observability.Default().Metrics.Inc(observability.MetricWarpUnrelatedControlAction, nil, 1)
		return errors.New("unrelated control action")
	}
	return nil
}

// Rollback rolls back a session's lifecycle state. The violation branch is a
// rollback with no previous applied state to return to
// (warp_rollback_failure_total).
func (rt *Runtime) Rollback(session string) error {
	if rt == nil {
		return errors.New("warp runtime not initialized")
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	st := rt.sessions[session]
	if st == nil || !st.hasPrevious {
		observability.Default().Metrics.Inc(observability.MetricWarpRollbackFailure, nil, 1)
		return errors.New("rollback without previous state")
	}
	st.hasPrevious = false
	st.hasApplied = false
	st.destinations = nil
	st.auth = nil
	return nil
}

// PublishTrace exports a trace event for a session. The violation branch is a
// payload carrying raw session key material (warp_secret_leak_total; secrets
// must never reach trace payloads per the addendum).
func (rt *Runtime) PublishTrace(session string, event TransportTraceEnvelope) bool {
	if rt == nil {
		return false
	}
	st := rt.session(session)
	if st == nil {
		return false
	}
	for _, v := range event.Payload {
		for _, secret := range st.secrets {
			if bytes.Equal(secret, []byte(v)) {
				observability.Default().Metrics.Inc(observability.MetricWarpSecretLeak, nil, 1)
				return false
			}
		}
	}
	return rt.trace.Publish(event)
}

// Trace returns the live trace pipeline (read-only usage).
func (rt *Runtime) Trace() *TracePipeline { return rt.trace }
