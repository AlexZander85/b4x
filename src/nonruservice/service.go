// Package nonruservice assembles the experimental НЕ РФ (non-RU) mode —
// addendum §3.2 / ADR-WARP-6, the E6/E7 daemon wiring the transport/warp
// engine deliberately left to the field layer:
//
//	topology (ADR-WARP-6: the second isolated WARP session rides the base):
//
//	  selected client traffic
//	    → inner WARP data path (a SECOND CF device, its own identity slot)
//	    → inner MASQUE TCP-443 control connection
//	    → forced through the verified BASE warp netstack (warpservice.Plane)
//	    → observed public egress
//
// The nested transport reuses the M+M composition engine
// (nested.MasqueMasqueRuntime) with the BASE warp supervisor as the capsule
// plane — the base is a prerequisite, never replaced: base down ⇒ the child is
// invalidated, base back ⇒ a fresh child generation (the runtime's own
// parent-link ladder). The isolation requirement of §36 is satisfied in
// userspace the way the chains do it: the inner control TCP dials through the
// outer netstack (Backend-B adapter, transport/warp.BackendBDialFunc), so no
// second kernel TUN and no shared address ambiguity exists.
//
// On top of the transport sits the geo gate (transport/warp NonRUGate): the
// route is promoted into the reserve registry (kind=nonru) ONLY while a
// fresh multi-provider PASS_NON_RU attestation holds; every §62.5 close
// reason revokes IMMEDIATELY (unregister + inner-netstack detach — local
// operations, well inside the gate's RouteRevokeTimeout budget). The E7 probe
// wiring lives here too: the geo transport over the live inner session
// (TunnelGeoTransport + the inner netstack HTTPS exchange), the classify
// oracle over geoip.dat (oracle.go), and the provider pair — two
// dns-resolver-authority whoami probes (the quorum voters) plus the CF-trace
// corroborator (warp=on|plus path proof).
//
// Honest boundaries (§6 posture): the carrier is IPv4/TCP only (inner
// MASQUE netstack v1 — UDP refuses with reserve.ErrCarrierNoUDP, addendum
// §38 "L4 TCP-only proxy MUST report that limitation"); the classify oracle
// is only as good as the operator's geoip.dat — absent file ⇒ every
// observation classifies unknown ⇒ the quorum never forms ⇒ the gate stays
// closed (OracleLoaded=false in the status, no half-states); ConfigGen is
// not wired (config changes restart the daemon — the standard b4 posture).
package nonruservice

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/reserve"
	"github.com/daniellavrushin/b4/transport/nested"
	twarp "github.com/daniellavrushin/b4/transport/warp"
	"github.com/daniellavrushin/b4/warpservice"
)

// ErrNoBase is the honest Build refusal when the base warp runtime is absent.
var ErrNoBase = errors.New("nonru: the base warp runtime is required (ADR-WARP-6: base WARP not ACTIVE makes the nested mode ineligible)")

// Supervision states.
const (
	StateWaitingBase  = "waiting-base" // no base identity yet (the base reconciler provisions it)
	StateProvisioning = "provisioning"
	StateAssembling   = "assembling"
	StateUp           = "up" // nested composition started (the GATE may still be closed)
	StateBackoff      = "backoff"
	StateCapped       = "restart-capped"
	StateStopped      = "stopped"
)

const (
	eventRingCap = 64
	// restartCapPerHour caps the service-level rebuilds (proton canon).
	restartCapPerHour = 6
	// superviseTick drives the assembly supervision (the chains canon).
	superviseTick = 500 * time.Millisecond
)

// Event is one structured nonru event (the chains canon).
type Event struct {
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
	At     int64  `json:"at"`
}

// GateView is the geo-gate projection of the status (no secrets; the
// attestation carries the hashed public IP only by design).
type GateView struct {
	Open                    bool   `json:"open"`
	Verdict                 string `json:"verdict,omitempty"`
	Country                 string `json:"country,omitempty"`
	CloseReason             string `json:"close_reason,omitempty"`
	AttestationFreshUntil   string `json:"attestation_fresh_until,omitempty"`
	Revocations             uint64 `json:"revocations"`
	LastRevocationLatencyMS uint64 `json:"last_revocation_latency_ms"`
	RevokeDegraded          bool   `json:"revoke_degraded"`
	ManualDisabled          bool   `json:"manual_disabled"`
	Providers               int    `json:"providers"`
	BaseColo                string `json:"base_colo,omitempty"`
	InnerColo               string `json:"inner_colo,omitempty"`
}

// StatusView is the externally visible runtime state (no secrets).
type StatusView struct {
	Enabled      bool     `json:"enabled"`
	Running      bool     `json:"running"`   // the nested composition is started
	Listening    bool     `json:"listening"` // the gate is OPEN (route promoted)
	State        string   `json:"state"`
	ParentGen    uint64   `json:"parent_gen"` // the M+M composition's child generation
	Gate         GateView `json:"gate"`
	OracleLoaded bool     `json:"oracle_loaded"`
	Restarts     int      `json:"restarts"`
	LastFailure  string   `json:"last_failure,omitempty"`
	Events       []Event  `json:"events,omitempty"`
}

// Options carries the injection seams (tests wire httptest and fakes;
// production leaves them nil).
type Options struct {
	// HTTP is the inner enrollment transport (the SNI-filter escape hatch).
	HTTP *http.Client
	// EnrollBaseURL overrides the registration API base (tests).
	EnrollBaseURL string
	// Now is the clock seam (tests).
	Now func() time.Time
	// OnEvent is the non-blocking event sink (the daemon log renderer).
	OnEvent func(Event)
	// GeoIPPath overrides the classify-oracle source (tests; default:
	// the daemon config's system.geo.ipdat_path).
	GeoIPPath string
	// Classify replaces the oracle wholesale (tests; wins over GeoIPPath).
	Classify func(netip.Addr) string
}

// Runtime owns one nonru assembly for one config generation.
type Runtime struct {
	cfg  config.WarpNonRUConfig
	opts Options

	// The base warp (never owned, only composed on top of — ADR-WARP-6).
	base      *warpservice.Runtime
	basePlane warpservice.Plane
	baseSlot  string // the base identity slot (read-only for LocalV4)
	baseAt    netip.AddrPort
	innerAt   netip.AddrPort

	oracle       *geoOracle
	oracleLoaded bool
	classify     func(netip.Addr) string

	mu          sync.Mutex
	cancel      context.CancelFunc
	running     bool
	stopped     bool
	state       string
	events      []Event
	lastFailure string
	restarts    int
	mm          *nested.MasqueMasqueRuntime
	gate        *twarp.NonRUGate
	gateOpen    bool

	// pathMu guards the geo-transport cache and the path serial (the
	// gate's CurrentGen source: the identity of the probe PATH — a new
	// inner session bumps the serial, §69-20 stale parent route token).
	pathMu     sync.Mutex
	pathSerial uint64
	geoSess    *twarp.Session
	geoTr      *twarp.TunnelGeoTransport

	// The shared inner netstack: carrier dials AND the geo HTTPS exchange
	// ride ONE userspace host over the inner session (one tunnel source
	// address, the chains-carrier re-attach canon on dial failure).
	nsMu      sync.Mutex
	nsCarrier *twarp.NetstackCarrier
	nsRelease func()

	dialOK   atomic.Uint64
	dialFail atomic.Uint64

	guard restartCap
}

// Build validates the nonru section against the LIVE base runtime and
// constructs the service WITHOUT starting anything or touching the network.
// The base identity may still be absent (the base reconciler provisions it);
// the supervision loop then parks in waiting-base.
func Build(cfg *config.Config, base *warpservice.Runtime, opts Options) (*Runtime, error) {
	nr := cfg.System.Warp.NonRU
	if base == nil {
		return nil, ErrNoBase
	}
	if !cfg.System.Warp.Enabled {
		return nil, fmt.Errorf("nonru: system.warp.enabled=false — the nested mode requires the base warp (ADR-WARP-6)")
	}
	baseAt, err := cfg.System.Warp.EffectiveEndpoint()
	if err != nil {
		return nil, fmt.Errorf("nonru: base endpoint: %w", err)
	}
	innerAt, err := nr.EffectiveEndpoint(baseAt.Addr())
	if err != nil {
		return nil, err
	}
	if now := opts.Now; now == nil {
		opts.Now = time.Now
	}
	r := &Runtime{
		cfg:       nr,
		opts:      opts,
		base:      base,
		basePlane: base.Plane(),
		baseSlot:  cfg.System.Warp.IdentityPath,
		baseAt:    baseAt,
		innerAt:   innerAt,
		classify:  opts.Classify,
		guard:     restartCap{now: opts.Now, max: restartCapPerHour},
	}
	if r.classify == nil {
		path := opts.GeoIPPath
		if path == "" {
			path = cfg.System.Geo.GeoIpPath
		}
		if path != "" {
			o, oerr := loadGeoOracle(path)
			if oerr == nil {
				r.oracle, r.oracleLoaded = o, true
				r.classify = o.Classify
			} else {
				r.appendEvent(Event{Name: "nonru_oracle_unavailable", Detail: oerr.Error()})
			}
		} else {
			r.appendEvent(Event{Name: "nonru_oracle_absent", Detail: "system.geo.ipdat_path not configured: every geo observation classifies unknown and the gate stays closed"})
		}
	}
	return r, nil
}

// Start launches the supervision loop. Daemon mode only; the engine's own
// startOnce guards against double starts.
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return errors.New("nonru: runtime already stopped")
	}
	if r.running {
		r.mu.Unlock()
		return nil
	}
	r.running = true
	cctx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.mu.Unlock()
	go r.loop(cctx)
	return nil
}

// Stop tears the assembly down child-first: the gate (a consumer of the
// inner path), then the nested composition (the inner supervisor and its
// control-plane netstack). The BASE warp plane is never touched (the M+W
// contract). Idempotent.
func (r *Runtime) Stop() {
	// Stop retires EVERYTHING this runtime owns — the supervision loop AND
	// the assembly itself. The assembly may exist without the loop (tests
	// drive tick() directly; the waiting-base posture assembles later), so
	// the teardown does not depend on r.running.
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	r.running = false
	gate, mm := r.gate, r.mm
	r.gate, r.mm = nil, nil
	cancel := r.cancel
	r.state = StateStopped
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	reserve.Unregister(reserve.KindNonRU) // trees see the stop immediately
	r.detachNetstack()
	r.closeGeoTransport()
	if gate != nil {
		gate.Stop()
	}
	if mm != nil {
		mm.Stop()
	}
}

// RestartNow retires the assembly and forces one immediate rebuild under
// the restart cap (the chains canon; the supervision loop reassembles).
func (r *Runtime) RestartNow(ctx context.Context) {
	if !r.guard.allowed() {
		r.fail(StateCapped, "restart capped (max %d/hour)", restartCapPerHour)
		return
	}
	r.guard.record()
	r.mu.Lock()
	gate, mm := r.gate, r.mm
	r.gate, r.mm = nil, nil
	r.mu.Unlock()
	reserve.Unregister(reserve.KindNonRU)
	r.detachNetstack()
	r.closeGeoTransport()
	if gate != nil {
		gate.Stop()
	}
	if mm != nil {
		mm.Stop()
	}
	r.mu.Lock()
	r.restarts++
	r.mu.Unlock()
	r.appendEvent(Event{Name: "nonru_restart_dispatched"})
}

// Status snapshots the runtime state (nil-safe fields throughout).
//
// LOCK DISCIPLINE (a real deadlock taught here): r.mu is RELEASED before
// the gate / composition projections — gate.Status() calls back into the
// InnerColo/BaseColo closures, and those take r.mu again
// (innerSupervisor). Holding r.mu across the gate projection is a
// self-deadlock; the snapshots are taken under the lock, the projections
// outside it.
func (r *Runtime) Status() StatusView {
	r.mu.Lock()
	mm, gate := r.mm, r.gate
	v := StatusView{
		Enabled:      r.cfg.Enabled,
		Running:      mm != nil,
		Listening:    r.gateOpen,
		State:        r.state,
		Restarts:     r.restarts,
		LastFailure:  r.lastFailure,
		OracleLoaded: r.oracleLoaded,
		Events:       append([]Event(nil), r.events...),
	}
	r.mu.Unlock()

	if mm != nil {
		_, gen, _ := mm.Status()
		v.ParentGen = gen
	}
	if gate != nil {
		st := gate.Status()
		v.Gate = GateView{
			Open:                    st.Open,
			Verdict:                 string(st.Verdict),
			Country:                 st.Attestation.Country,
			CloseReason:             st.CloseReason,
			Revocations:             st.Revocations,
			LastRevocationLatencyMS: uint64(st.LastRevocationLatency.Milliseconds()),
			RevokeDegraded:          st.RevokeDegraded,
			ManualDisabled:          st.ManualDisabled,
			Providers:               3, // akamai + google (voters) + cf-trace (corroborator)
			BaseColo:                st.BaseColo,
			InnerColo:               st.InnerColo,
		}
		if !st.Attestation.FreshUntil.IsZero() {
			v.Gate.AttestationFreshUntil = st.Attestation.FreshUntil.UTC().Format(time.RFC3339)
		}
	}
	return v
}

// loop is the supervision loop: one deterministic tick until the composition
// is assembled; the M+M runtime self-heals the child afterwards.
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

// tick is one deterministic supervision cycle (the chains canon).
func (r *Runtime) tick(ctx context.Context) {
	if !r.cfg.Enabled {
		return
	}
	r.mu.Lock()
	composed := r.mm != nil
	r.mu.Unlock()
	if composed {
		return
	}
	if !r.guard.allowed() {
		r.fail(StateCapped, "rebuild capped (max %d/hour)", restartCapPerHour)
		return
	}
	if err := r.assemble(ctx); err != nil {
		r.fail(StateBackoff, "%s", err.Error())
	}
}

// fail records a supervision failure (the chains canon).
func (r *Runtime) fail(state, format string, args ...any) {
	detail := fmt.Sprintf(format, args...)
	r.mu.Lock()
	r.state = state
	r.lastFailure = detail
	r.mu.Unlock()
	r.appendEvent(Event{Name: "nonru_failure", Detail: detail})
}

func (r *Runtime) appendEvent(ev Event) {
	ev.At = r.opts.Now().Unix()
	r.mu.Lock()
	r.events = append(r.events, ev)
	if len(r.events) > eventRingCap {
		r.events = r.events[len(r.events)-eventRingCap:]
	}
	r.mu.Unlock()
	if cb := r.opts.OnEvent; cb != nil {
		cb(ev)
	}
}

// restartCap is the per-hour rebuild cap (proton canon; local mirror of the
// chains' guard — it stays private there).
type restartCap struct {
	now    func() time.Time
	max    int
	stamps []time.Time
}

func (g *restartCap) allowed() bool {
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

func (g *restartCap) record() {
	g.stamps = append(g.stamps, g.now())
}
