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
	"fmt"
	"net/http"
	"net/netip"
	"os"
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

	// template is the static session template the supervisor (and the endpoint
	// discovery) build from.
	template warp.SessionConfig
	// winner is the discovery-adopted endpoint (bd b4x-wh6 pt.1): the zero
	// value means "keep the configured/default endpoint".
	winnerMu sync.Mutex
	winner   netip.AddrPort
}

// discoveryRunner is the seam over *warp.Discoverer (tests inject a fake so no
// catalog candidate is ever probed from unit tests).
type discoveryRunner interface {
	Discover(ctx context.Context) (warp.DiscoveryResult, error)
}

// newDiscoverer is the construction seam (tests replace it).
var newDiscoverer = func(cfg warp.DiscovererConfig) (discoveryRunner, error) {
	return warp.NewDiscoverer(cfg)
}

// Endpoint discovery budgets (bd b4x-wh6 pt.1). The proven static default is
// tried first, so a healthy network never pays for a scan.
const (
	discoveryAfter  = 45 * time.Second
	discoveryRetry  = 10 * time.Minute
	discoveryBudget = 90 * time.Second
)

// Build validates the system.warp section and constructs the runtime
// WITHOUT starting anything. It succeeds even when Enabled=false so CLI
// enrollment can provision an identity BEFORE the transport switch (field
// session phase B precedes phase C). sink may be nil.
func Build(cfg *config.Config, sink func(Event)) (*Runtime, error) {
	return BuildWithHTTP(cfg, sink, nil)
}

// BuildWithHTTP is Build with an explicit enrollment HTTP client — the
// escape hatch for SNI-filtered networks, where registration must ride a
// proxy (field1 finding: api.cloudflareclient.com is filtered network-wide,
// home ISP and mobile operators alike). Only the registration path uses it;
// the MASQUE session itself always dials the numeric edge directly.
func BuildWithHTTP(cfg *config.Config, sink func(Event), enrollmentHTTP *http.Client) (*Runtime, error) {
	wc := cfg.System.Warp
	if err := wc.Masquerade.Validate(); err != nil {
		return nil, err
	}
	endpoint, err := wc.EffectiveEndpoint()
	if err != nil {
		return nil, err
	}
	rec := &warp.Reconciler{
		API:   &warp.EnrollClient{HTTP: enrollmentHTTP},
		Store: &warp.IdentityStore{Path: wc.IdentityPath},
	}
	// b4x-h6o: bind the fake-QUIC establishment cover to the H3 ladder. The
	// ladder arms it before every H3 dial and releases it after
	// ValidateDataPlane; a nil cover would silently ship the uncovered
	// (DPI-flagged) H3 handshake.
	tpl := warp.SessionConfig{
		Endpoint: endpoint,
		// Cover SNI: the canonical MASQUE name is DPI-flagged in RU and
		// the edge blackholes the data phase once it is seen (bd b4x-5oy).
		// Identity binds by public-key pinning, so the SNI is a free cover.
		SNI: wc.Masquerade.EffectiveSNI(),
		// Client key + pin are injected per-generation by the
		// supervisor from the stored identity (buildSessionConfig).
		Fingerprint: wc.Masquerade.Fingerprint,
	}
	var dialer warp.TransportDialer
	if socksAddr := os.Getenv("B4_WARP_SOCKS5"); socksAddr != "" {
		// b4x-rnn: force the MASQUE H2 control TCP through a SOCKS5 egress so
		// Cloudflare assigns a non-RU WARP country. SOCKS5 is TCP-only, so the
		// H3 (UDP) ladder is intentionally bypassed for this seam.
		df, derr := socks5DialFunc(socksAddr)
		if derr != nil {
			return nil, fmt.Errorf("system.warp socks5: %w", derr)
		}
		tpl.DialFunc = df
	} else {
		cover, cerr := newFakeQUICCover()
		if cerr != nil {
			return nil, cerr
		}
		dialer, err = warp.NewH3FirstDialer(warp.LadderConfig{Cover: cover})
		if err != nil {
			return nil, err
		}
	}
	rt := &Runtime{cfg: wc, rec: rec, template: tpl}
	sup, err := warp.NewSupervisor(warp.SupervisorConfig{
		Template:          tpl,
		Reconciler:        rec,
		Dialer:            dialer,
		Sink:              sink,
		DeferRevalidation: wc.DeferRevalidation,
		// bd b4x-wh6 pt.1: a discovery-verified endpoint overrides the static
		// one for the next generation while the static endpoint stays the
		// fallback (no winner => behavior unchanged).
		EndpointFor: rt.currentEndpoint,
	})
	if err != nil {
		return nil, err
	}
	rt.sup = sup
	return rt, nil
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
	if err := r.sup.Start(ctx); err != nil {
		return err
	}
	// bd b4x-wh6 pt.1: adopt a discovery-verified endpoint after the static one
	// has failed to connect (fail-safe — see discoverLoop).
	go r.discoverLoop(ctx)
	return nil
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

// currentEndpoint is the warp.SupervisorConfig.EndpointFor seam: the adopted
// discovery winner, or "not set" so the static template endpoint is kept.
func (r *Runtime) currentEndpoint() (netip.AddrPort, bool) {
	r.winnerMu.Lock()
	defer r.winnerMu.Unlock()
	if r.winner.IsValid() {
		return r.winner, true
	}
	return netip.AddrPort{}, false
}

// discoverLoop runs MASQUE endpoint discovery only while the static endpoint
// fails to connect (bd b4x-wh6 pt.1). Every failure path is a silent no-op:
// the configured/default endpoint stays in place, so this can never be worse
// than the previous behavior.
func (r *Runtime) discoverLoop(ctx context.Context) {
	t := time.NewTimer(discoveryAfter)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return
	case <-t.C:
	}
	for {
		if ctx.Err() != nil {
			return
		}
		if r.sup.Snapshot().State != warp.StateConnected {
			if ep, ok := r.discoverOnce(ctx); ok {
				r.winnerMu.Lock()
				changed := r.winner != ep
				r.winner = ep
				r.winnerMu.Unlock()
				if changed {
					r.sup.Restart(true)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(discoveryRetry):
		}
	}
}

// discoverOnce runs ONE bounded discovery pass over the versioned catalog with
// the current identity. Any error (absent identity, no verified candidate,
// budget) returns ok=false and leaves the static endpoint untouched.
func (r *Runtime) discoverOnce(ctx context.Context) (netip.AddrPort, bool) {
	ident, err := r.rec.Store.Load()
	if err != nil {
		return netip.AddrPort{}, false
	}
	tpl, err := warp.SessionConfigForIdentity(r.template, ident)
	if err != nil {
		return netip.AddrPort{}, false
	}
	d, err := newDiscoverer(warp.DiscovererConfig{
		Template:     tpl,
		Strategy:     warp.StrategyBalanced,
		LastGoodPath: r.cfg.IdentityPath + ".lastgood",
		H3:           &warp.H3VerifyConfig{},
	})
	if err != nil {
		return netip.AddrPort{}, false
	}
	cctx, cancel := context.WithTimeout(ctx, discoveryBudget)
	defer cancel()
	res, err := d.Discover(cctx)
	if err != nil || !res.Winner.Endpoint.IsValid() {
		return netip.AddrPort{}, false
	}
	return res.Winner.Endpoint, true
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

// AttachNetstack mounts the userspace TCP/IP carrier (bd b4x-9aa) on the
// current session generation; the tunnel-local address is taken from the
// loaded identity.
func (r *Runtime) AttachNetstack() (*warp.NetstackCarrier, func(), error) {
	local, ok := r.sup.AssignedLocalV4()
	if !ok {
		return nil, nil, errors.New("warpservice: no assigned tunnel address yet")
	}
	return r.sup.AttachNetstack(local, 0)
}

// Plane is the BASE warp's capsule surface for nested compositions (ADR-WARP-6:
// the nested НЕ РФ session rides the verified base path): packet writes into
// the live session, the generation-surviving tap fan-out, and the status
// snapshot. Read-only data plane — no lifecycle control leaks (the nested
// runtime composes ON TOP of the base session; it never restarts or stops it).
// The method set is exactly the nested CapsulePlane contract, satisfied
// structurally so warpservice stays free of the transport/nested import.
type Plane struct{ sup *warp.Supervisor }

// WritePacket implements the nested CapsulePlane contract.
func (p Plane) WritePacket(pkt []byte) error {
	if p.sup == nil {
		return errors.New("warpservice: plane not bound to a supervisor")
	}
	return p.sup.WritePacket(pkt)
}

// SubscribePackets implements the nested CapsulePlane contract.
func (p Plane) SubscribePackets() (<-chan []byte, func()) {
	if p.sup == nil {
		ch := make(chan []byte)
		return ch, func() {}
	}
	return p.sup.SubscribePackets()
}

// Snapshot implements the nested CapsulePlane contract.
func (p Plane) Snapshot() warp.Status {
	if p.sup == nil {
		return warp.Status{}
	}
	return p.sup.Snapshot()
}

// Plane exposes the base warp capsule surface (the nonru nested-composition
// seam). The surface is live for the lifetime of the base supervisor; the
// caller composes on top without owning the lifecycle.
func (r *Runtime) Plane() Plane { return Plane{sup: r.sup} }

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
