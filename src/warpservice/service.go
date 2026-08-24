// Package warpservice assembles the dependency-free WARP/MASQUE engine
// (src/transport/warp: L1 session + L2 supervisor) from the main config.
//
// This is the deliberately-thin "last mile" left out of the E0-E8 engine
// stages (see docs/reports/warp/WARP_IMPLEMENTATION_REPORT.md known gaps):
// the engine never touches kernel state, config files or the daemon loop;
// this package binds them for daemon mode (system.warp.enabled) and CLI
// operations (b4 warp enroll/status). TUN/PBR application stays field-layer
// work per design SS11.3 (.ag/research/warp-dataplane-design.md).
//
// Secret discipline: Identity.Token / PrivateKey / PinPEM never leave this
// package; Summaries carry derived identifiers only (device id, assigned
// address, pin digest prefix) matching the SupervisorEvent payload contract.
package warpservice

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/config"
	warp "github.com/daniellavrushin/b4/transport/warp"
)

// Event aliases the engine supervisor event so daemon/CLI callers do not
// need to import the engine package directly.
type Event = warp.SupervisorEvent

// StatusSnapshot is the externally visible engine state plus recent events.
type StatusSnapshot struct {
	Status warp.Status
	Events []warp.SupervisorEvent
}

const pinDigestPrefixLen = 12

// Summary is the redacted identity/enrollment summary printed by the CLI.
type Summary struct {
	State           string `json:"state"` // absent | present | invalid
	Action          string `json:"action,omitempty"`
	FailureClass    string `json:"failure_class,omitempty"`
	DeviceID        string `json:"device_id,omitempty"`
	AssignedV4      string `json:"assigned_v4,omitempty"`
	PinDigestPrefix string `json:"pin_digest_prefix,omitempty"` // first 12 hex chars of the endpoint pin digest
	EndpointHint    string `json:"endpoint_hint,omitempty"`
	CreatedAt       string `json:"created_at,omitempty"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	ThrottleUntil   string `json:"throttle_until,omitempty"`
	Quarantined     bool   `json:"quarantined,omitempty"`
	IdentityPath    string `json:"identity_path"`
}

// Runtime owns the assembled engine for one config generation.
type Runtime struct {
	cfg     config.WarpConfig
	rec     *warp.Reconciler
	sup     *warp.Supervisor
	mu      sync.Mutex
	started bool
	stopped bool
}

// Build validates the system.warp section and constructs the runtime
// WITHOUT starting anything. It succeeds even when Enabled=false so CLI
// enrollment can provision an identity BEFORE the transport switch (field
// session phase B precedes phase C). sink may be nil.
func Build(cfg *config.Config, sink func(Event)) (*Runtime, error) {
	wc := cfg.System.Warp
	endpoint, err := wc.EffectiveEndpoint()
	if err != nil {
		return nil, err
	}
	rec := &warp.Reconciler{
		API:   &warp.EnrollClient{},
		Store: &warp.IdentityStore{Path: wc.IdentityPath},
	}
	sup, err := warp.NewSupervisor(warp.SupervisorConfig{
		Template: warp.SessionConfig{
			Endpoint: endpoint,
			// Client key + pin are injected per-generation by the
			// supervisor from the stored identity (buildSessionConfig).
		},
		Reconciler: rec,
		Sink:       sink,
	})
	if err != nil {
		return nil, err
	}
	return &Runtime{cfg: wc, rec: rec, sup: sup}, nil
}

// Start launches the supervisor loop. Daemon mode only; callers check
// system.warp.enabled themselves. The engine's own startOnce guards against
// double starts; Stop is terminal for this runtime instance.
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return errors.New("warpservice: runtime already stopped")
	}
	if r.started {
		return nil
	}
	r.started = true
	return r.sup.Start(ctx)
}

// Stop tears the supervisor down (no-op before Start).
func (r *Runtime) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started || r.stopped {
		return
	}
	r.stopped = true
	r.sup.Stop()
}

// Status returns the current engine snapshot with recent events (safe to
// call before Start: reports the zero/idle state).
func (r *Runtime) Status() StatusSnapshot {
	return StatusSnapshot{Status: r.sup.Snapshot(), Events: r.sup.RecentEvents()}
}

// EnrollOnce runs one reconciler pass (provision / keep-valid / renew /
// blocked) against the registration API using the same store the daemon
// supervisor uses. Idempotent by design: a valid identity produces zero
// registrations.
func (r *Runtime) EnrollOnce(ctx context.Context) (warp.EnsureResult, error) {
	return r.rec.Ensure(ctx)
}

// EnrollSummary converts an EnsureResult into a redacted CLI summary.
func EnrollSummary(res warp.EnsureResult, identityPath string) Summary {
	s := Summary{
		State:        "present",
		Action:       string(res.Action),
		FailureClass: res.FailureClass,
		IdentityPath: identityPath,
		Quarantined:  res.Quarantined,
	}
	if !res.ThrottleUntil.IsZero() {
		s.ThrottleUntil = res.ThrottleUntil.UTC().Format(time.RFC3339)
	}
	if res.Identity != nil {
		fillFromIdentity(&s, res.Identity)
	}
	return s
}

// OfflineSummary reads the stored identity without any network activity.
// Load() already field-validates on success; absent/corrupt/read-error are
// reported structurally so operators never confuse "not provisioned yet"
// with "store unreadable" (a wrong guess would invite a second device).
func OfflineSummary(identityPath string) Summary {
	s := Summary{State: "absent", IdentityPath: identityPath}
	store := &warp.IdentityStore{Path: identityPath}
	ident, err := store.Load()
	switch {
	case err == nil:
	case errors.Is(err, warp.ErrIdentityAbsent):
		return s
	case errors.Is(err, warp.ErrIdentityCorrupt):
		s.State = "invalid"
		s.Quarantined = true
		return s
	default:
		s.State = "invalid"
		s.FailureClass = err.Error()
		return s
	}
	fillFromIdentity(&s, ident)
	return s
}

func fillFromIdentity(s *Summary, ident *warp.Identity) {
	s.State = "present"
	s.DeviceID = ident.ID
	s.AssignedV4 = ident.AssignedV4
	s.EndpointHint = ident.EndpointHint
	if len(ident.PinDigest) > pinDigestPrefixLen {
		s.PinDigestPrefix = ident.PinDigest[:pinDigestPrefixLen]
	} else {
		s.PinDigestPrefix = ident.PinDigest
	}
	if !ident.CreatedAt.IsZero() {
		s.CreatedAt = ident.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !ident.ExpiresAt.IsZero() {
		s.ExpiresAt = ident.ExpiresAt.UTC().Format(time.RFC3339)
	}
}
