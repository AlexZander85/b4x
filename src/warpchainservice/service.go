// Package warpchainservice assembles the nested chains (reserve kinds
// "masque+awg", "awg+masque", "awg+awg" and "masque+masque" — tunnels
// panel stage 2/3/4) from the transport composition engines and the
// system.warp.chains config.
//
// One Runtime per chain entry. The identity discipline is the nested red
// line #3: each layer owns a DISTINCT slot (one CF device per layer); the
// M+W outer identity comes from the outer supervisor's own reconciler, the
// inner AWG identity is provisioned by this service (wg enrollment client);
// the W+M outer AWG identity is provisioned here, the inner MASQUE identity
// by the inner supervisor embedded in the engine runtime; the W+W pair owns
// TWO wg slots — the outer (obfuscated, junk-active profile) and the inner
// (vanilla) — both provisioned here with a per-slot once-per-boot budget.
//
// Lifecycle ownership: M+W and M+M own the outer MASQUE supervisor and pass
// it as the composition plane to the engine runtime; W+M and W+W own the
// whole composition (the engines build outer session + inner layer per
// generation; the W+W runtime is transportwg.NestedWgRuntime — design §7
// R3, gool pattern, the inner rides a Backend-B loopback forwarder carried
// inside the outer netstack). RestartNow tears the composition down and
// forces one rebuild under the restart caps.
//
// Data planes are honest per composition: masque+awg serves TCP + UDP
// (the inner AWG netstack); awg+masque serves IPv4/TCP only (the inner
// MASQUE netstack v1 — reserve.ErrCarrierNoUDP on the UDP leg); awg+awg
// serves TCP + UDP through the inner AWG netstack (same surface as the
// single AWG-WARP transport); masque+masque serves IPv4/TCP only (the
// inner MASQUE netstack v1 posture — reserve.ErrCarrierNoUDP on the UDP
// leg).
package warpchainservice

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
	twg "github.com/daniellavrushin/b4/transport/wg"
)

// superviseTick is the supervisor cadence (the proton/warpservice canon).
const superviseTick = 30 * time.Second

// Event ring capacity.
const eventRingCap = 32

// Service states (closed set).
const (
	StateIdle         = "idle"
	StateProvisioning = "provisioning"
	StateAssembling   = "assembling"
	StateUp           = "up"
	StateBackoff      = "backoff"
	StateCapped       = "restart-capped"
	StateStopped      = "stopped"
)

// ErrNotListening is the honest refusal for dials without a live inner layer.
var ErrNotListening = errors.New("warpchain: no live inner layer to dial through")

// Event is one structured chain event.
type Event struct {
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
	At     int64  `json:"at"`
}

// StatusView is the externally visible chain state (no secrets).
type StatusView struct {
	Enabled     bool    `json:"enabled"`
	Kind        string  `json:"kind"`
	Running     bool    `json:"running"`
	Listening   bool    `json:"listening"`
	State       string  `json:"state"`
	OuterState  string  `json:"outer_state,omitempty"`
	InnerState  string  `json:"inner_state,omitempty"`
	ParentGen   uint64  `json:"parent_gen"`
	Restarts    int     `json:"restarts"`
	LastFailure string  `json:"last_failure,omitempty"`
	Events      []Event `json:"events,omitempty"`
}

// Options carries the injection seams (tests wire httptest; production
// leaves them nil).
type Options struct {
	// HTTP is the enrollment transport for both layers' registration clients.
	HTTP *http.Client
	// MasqueEnrollBaseURL / WGEnrollBaseURL override the registration API
	// bases (tests point them at fake servers).
	MasqueEnrollBaseURL string
	WGEnrollBaseURL     string
	// Now is the clock seam (tests).
	Now func() time.Time
	// OnEvent is the non-blocking event sink (the daemon log renderer).
	OnEvent func(Event)
}

// Runtime owns one chain assembly for one config generation.
type Runtime struct {
	cfg  config.WarpChainConfig
	opts Options
	kind reserve.Kind

	// Resolved at Build (fail-fast, no network).
	awgProfile    twg.Profile
	outerEndpoint netip.AddrPort
	innerEndpoint netip.AddrPort

	// Identity slots, per layer (DISTINCT paths — red line #3).
	wgStore *twg.IdentityStore // the AWG layer's wg identity (outer W+M / inner M+W / outer W+W)
	// wgInnerStore is the W+W INNER AWG slot (a second CF wg device;
	// nil unless kind == awg+awg).
	wgInnerStore *twg.IdentityStore

	// M+W / M+M: the outer MASQUE supervisor (the composition plane).
	outerSup *twarp.Supervisor

	mu          sync.Mutex
	cancel      context.CancelFunc
	running     bool
	stopped     bool
	mPlusW      *nested.MasqueAwgRuntime    // masque+awg composition
	wPlusM      *nested.WgMasqueRuntime     // awg+masque composition
	wPlusW      *twg.NestedWgRuntime        // awg+awg composition (W+W)
	mPlusM      *nested.MasqueMasqueRuntime // masque+masque composition (M+M)
	state       string
	events      []Event
	lastFailure string
	restarts    int
	dialOK      uint64
	dialFail    uint64

	// W+W carrier cache: one netstack attached to the CURRENT inner
	// session, re-attached after a dial failure (the warpservice canon).
	nsMu      sync.Mutex
	nsCarrier *twarp.NetstackCarrier
	nsRelease func()

	registeredThisBoot  atomic.Bool // the AWG layer slot budget (outer W+M / inner M+W / outer W+W)
	registeredInnerBoot atomic.Bool // the W+W inner slot budget
	guard               restartGuard
}

// Build validates the chain entry and constructs the runtime WITHOUT
// starting anything or touching the network.
func Build(cfg *config.Config, chain config.WarpChainConfig, opts Options) (*Runtime, error) {
	if !config.IsWarpChainKind(chain.Kind) {
		return nil, fmt.Errorf("warpchain: kind %q is not a nested chain kind", chain.Kind)
	}
	outer, inner, err := chain.ResolveEndpoints()
	if err != nil {
		return nil, err
	}
	awgProfile, awgProfileID, err := chain.EffectiveAWGProfile()
	if err != nil {
		return nil, err
	}
	// Bootstrap cover (bd b4x-b7n): a runtime-I1 AWG profile (cf-quic-cover)
	// ships a real QUIC Initial in front of the WireGuard initiation on the
	// layer that egresses directly (awg+masque outer). Filling here keeps the
	// profile contract identical to the single AWG transport — an unfilled
	// runtime-I1 slot would ship as vanilla WG with no obfuscation at all.
	runtimeI1, err := twg.RuntimeI1Required(twg.TargetCfWarp, awgProfileID)
	if err != nil {
		return nil, err
	}
	awgProfile = twg.FillBootstrapCover(awgProfile, runtimeI1, cfg.System.Warp.Masquerade.EffectiveSNI())
	if err := awgProfile.Validate(); err != nil {
		return nil, fmt.Errorf("warpchain: awg profile: %w", err)
	}
	// W+W defense in depth (the config gates own the primary rules): the
	// outer layer must carry an active junk family (the engine's
	// ErrOuterObfRequired) and the composition has no masque layer — a
	// fingerprint is a config lie.
	if chain.Kind == config.ChainKindAwgAwg {
		if awgProfile.JunkCount < 1 {
			return nil, fmt.Errorf("warpchain: awg+awg outer layer requires a junk-active profile (got a vanilla one)")
		}
		if chain.Fingerprint != "" {
			return nil, fmt.Errorf("warpchain: awg+awg has no masque layer (fingerprint must be empty)")
		}
	}
	if err := validateFingerprint(chain.Fingerprint); err != nil {
		return nil, err
	}
	innerMTU := chain.InnerMTU
	if innerMTU <= 0 {
		innerMTU = nested.MaxInnerMTU
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}

	awgStore := (*twg.IdentityStore)(nil)
	if chain.Kind != config.ChainKindMasqueMasque {
		// The AWG layer's wg identity slot: outer for awg+masque and
		// awg+awg, inner for masque+awg. masque+masque owns NO wg identity
		// (both layers are MASQUE — the two masque slots carry the red line
		// #3 discipline instead).
		awgStore = &twg.IdentityStore{Path: chainAWGSlot(&chain)}
	}

	r := &Runtime{
		cfg:           chain,
		opts:          opts,
		kind:          reserve.Kind(chain.Kind),
		awgProfile:    awgProfile,
		outerEndpoint: outer,
		innerEndpoint: inner,
		wgStore:       awgStore,
		state:         StateIdle,
		guard:         restartGuard{now: opts.Now, max: chain.EffectiveMaxRestarts()},
	}
	if chain.Kind == config.ChainKindAwgAwg {
		// W+W: a SECOND wg identity slot for the inner layer (a distinct CF
		// device — red line #3; the outer slot is wgStore above).
		r.wgInnerStore = &twg.IdentityStore{Path: chain.EffectiveInnerIdentityPath()}
	}
	if chain.Kind == config.ChainKindMasqueAwg || chain.Kind == config.ChainKindMasqueMasque {
		// M+W / M+M: the outer supervisor owns the outer MASQUE identity (its
		// reconciler provisions/renews it); we only hand it the template + slot.
		sup, serr := twarp.NewSupervisor(twarp.SupervisorConfig{
			Template: twarp.SessionConfig{
				Endpoint:    outer,
				Fingerprint: chain.Fingerprint,
			},
			Reconciler: &twarp.Reconciler{
				API:   &twarp.EnrollClient{HTTP: opts.HTTP, BaseURL: opts.MasqueEnrollBaseURL},
				Store: &twarp.IdentityStore{Path: chain.EffectiveOuterIdentityPath()},
			},
		})
		if serr != nil {
			return nil, fmt.Errorf("warpchain: outer supervisor: %w", serr)
		}
		r.outerSup = sup
	}
	return r, nil
}

// chainAWGSlot returns the AWG layer's identity path for the compositions
// that own one: outer for awg+masque and awg+awg, inner for masque+awg.
// masque+masque must never call here (it owns no wg identity slot).
func chainAWGSlot(c *config.WarpChainConfig) string {
	if c.Kind == config.ChainKindAwgMasque || c.Kind == config.ChainKindAwgAwg {
		return c.EffectiveOuterIdentityPath()
	}
	return c.EffectiveInnerIdentityPath()
}

// chainMasqueSlot returns the MASQUE layer's identity path.
func chainMasqueSlot(c *config.WarpChainConfig) string {
	if c.Kind == config.ChainKindAwgMasque {
		return c.EffectiveInnerIdentityPath()
	}
	return c.EffectiveOuterIdentityPath()
}

func validateFingerprint(fp string) error {
	switch fp {
	case "", "chrome120", "firefox":
		return nil
	default:
		return fmt.Errorf("warpchain: fingerprint %q invalid (empty, chrome120 or firefox)", fp)
	}
}

// Start launches the supervisor loop.
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return errors.New("warpchain: runtime already stopped")
	}
	if r.running {
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.running = true
	if r.outerSup != nil {
		// M+W: the outer plane starts FIRST (the reconciler provisions the
		// outer identity; the composition assembles once both slots exist).
		if err := r.outerSup.Start(runCtx); err != nil {
			r.running = false
			cancel()
			return fmt.Errorf("warpchain: outer supervisor start: %w", err)
		}
	}
	go r.loop(runCtx)
	return nil
}

// Stop tears the composition down child-first (the engine contract), then
// the outer supervisor (M+W). No-op before Start.
func (r *Runtime) Stop() {
	r.mu.Lock()
	if !r.running || r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	cancel := r.cancel
	mw, wm, ww, mm := r.mPlusW, r.wPlusM, r.wPlusW, r.mPlusM
	r.mPlusW, r.wPlusM, r.wPlusW, r.mPlusM = nil, nil, nil, nil
	r.state = StateStopped
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if mw != nil {
		mw.Stop()
	}
	if wm != nil {
		wm.Stop()
	}
	if ww != nil {
		ww.Stop()
	}
	if mm != nil {
		mm.Stop()
	}
	r.detachNetstack()
	if r.outerSup != nil {
		r.outerSup.Stop()
	}
}

// RestartNow tears the composition down and forces one immediate rebuild
// (the caps still apply).
func (r *Runtime) RestartNow(ctx context.Context) {
	r.mu.Lock()
	mw, wm, ww, mm := r.mPlusW, r.wPlusM, r.wPlusW, r.mPlusM
	r.mPlusW, r.wPlusM, r.wPlusW, r.mPlusM = nil, nil, nil, nil
	r.mu.Unlock()
	if mw != nil {
		mw.Stop()
	}
	if wm != nil {
		wm.Stop()
	}
	if ww != nil {
		ww.Stop()
	}
	if mm != nil {
		mm.Stop()
	}
	r.detachNetstack()
	r.appendEvent(Event{Name: "warpchain_composition_retired", Detail: "restart-now"})
	r.tick(ctx)
}

// Status snapshots the chain state (safe before Start).
func (r *Runtime) Status() StatusView {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := StatusView{
		Enabled:     r.cfg.Enabled,
		Kind:        string(r.kind),
		State:       r.state,
		LastFailure: r.lastFailure,
		Restarts:    r.restarts,
		Events:      append([]Event(nil), r.events...),
	}
	if r.cfg.Kind == config.ChainKindMasqueAwg && r.mPlusW != nil {
		link, gen, child := r.mPlusW.Status()
		v.OuterState = link
		v.ParentGen = gen
		v.InnerState = fmt.Sprintf("child=%v", child)
		v.Running = link == "up" && child
		v.Listening = v.Running
	} else if r.cfg.Kind == config.ChainKindAwgMasque && r.wPlusM != nil {
		link, gen, child := r.wPlusM.Status()
		v.OuterState = link
		v.ParentGen = gen
		v.InnerState = fmt.Sprintf("child=%v", child)
		v.Running = link == "up" && child
		v.Listening = v.Running
	} else if r.cfg.Kind == config.ChainKindAwgAwg && r.wPlusW != nil {
		st := r.wPlusW.Status()
		v.OuterState = string(st.Link)
		v.ParentGen = st.ParentGen
		v.InnerState = fmt.Sprintf("child=%v hs_out=%dms hs_in=%dms", st.ChildRunning, st.Outer.HandshakeMS, st.Inner.HandshakeMS)
		v.Running = st.Link == twg.NestedUp && st.ChildRunning
		v.Listening = v.Running
	} else if r.cfg.Kind == config.ChainKindMasqueMasque && r.mPlusM != nil {
		link, gen, child := r.mPlusM.Status()
		v.OuterState = link
		v.ParentGen = gen
		v.InnerState = fmt.Sprintf("child=%v", child)
		v.Running = link == "up" && child
		v.Listening = v.Running
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

// tick is one deterministic supervision cycle: identities -> composition.
func (r *Runtime) tick(ctx context.Context) {
	if !r.cfg.Enabled {
		return
	}
	if r.compositionAlive() {
		return
	}
	if !r.guard.allowed() {
		r.fail(StateCapped, "restart capped")
		return
	}
	if err := r.assemble(ctx); err != nil {
		r.fail(StateBackoff, err.Error())
	}
}

func (r *Runtime) compositionAlive() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.cfg.Kind {
	case config.ChainKindMasqueAwg:
		return r.mPlusW != nil
	case config.ChainKindAwgAwg:
		return r.wPlusW != nil
	case config.ChainKindMasqueMasque:
		return r.mPlusM != nil
	default:
		return r.wPlusM != nil
	}
}

// assemble provisions the missing identity slots and builds the composed
// runtime for this chain kind.
func (r *Runtime) assemble(ctx context.Context) error {
	r.setState(StateProvisioning)

	// M+M owns NO wg identity (both layers are MASQUE; the outer's slot is
	// provisioned by this service's supervisor, the inner's SECONDARY slot
	// by the engine runtime's reconciler).
	if r.cfg.Kind == config.ChainKindMasqueMasque {
		return r.assembleMasqueMasque(ctx)
	}

	// The AWG layer's wg identity (outer for W+M / W+W, inner for M+W).
	wgIdent, err := r.ensureWGIdentity(ctx)
	if err != nil {
		return err
	}
	if wgIdent == nil {
		return nil // provisioned this tick or waiting for a slot; next tick continues
	}

	switch r.cfg.Kind {
	case config.ChainKindMasqueAwg:
		return r.assembleMasqueAwg(ctx, wgIdent)
	case config.ChainKindAwgAwg:
		return r.assembleWgWg(ctx, wgIdent)
	default:
		return r.assembleWgMasque(wgIdent)
	}
}

// ensureWGIdentity loads or provisions the AWG layer identity. Returns nil
// (no error) when the slot simply is not ready yet.
func (r *Runtime) ensureWGIdentity(ctx context.Context) (*twg.Identity, error) {
	return r.ensureWGIdentityAt(ctx, r.wgStore, &r.registeredThisBoot, "awg")
}

// ensureWGIdentityAt is the per-slot discipline (one registration budget per
// slot per boot — the W+W pair burns at most two, one per layer).
func (r *Runtime) ensureWGIdentityAt(ctx context.Context, store *twg.IdentityStore, budget *atomic.Bool, tag string) (*twg.Identity, error) {
	if store == nil {
		return nil, errors.New("warpchain: wg identity slot not configured for this chain kind")
	}
	id, err := store.Load()
	switch {
	case err == nil:
		return id, nil
	case errors.Is(err, twg.ErrIdentityAbsent):
		// fall through to registration
	case errors.Is(err, twg.ErrIdentityCorrupt):
		r.appendEvent(Event{Name: "warpchain_" + tag + "_identity_corrupt", Detail: err.Error()})
	default:
		return nil, err
	}
	if !budget.CompareAndSwap(false, true) {
		return nil, fmt.Errorf("warpchain: %s slot registration budget spent for this boot", tag)
	}
	r.setState(StateProvisioning)
	id, out, err := (&twg.EnrollClient{HTTP: r.opts.HTTP, BaseURL: r.opts.WGEnrollBaseURL}).Enroll(ctx)
	if err != nil {
		return nil, fmt.Errorf("%s layer registration (outcome %d): %w", tag, out, err)
	}
	if err := store.Save(id); err != nil {
		return nil, err
	}
	r.appendEvent(Event{Name: "warpchain_" + tag + "_registered", Detail: id.AssignedV4})
	return id, nil
}

// assembleMasqueAwg builds the M+W composition: the outer supervisor is
// the capsule plane, the inner AWG session rides it through the carrier.
func (r *Runtime) assembleMasqueAwg(ctx context.Context, inner *twg.Identity) error {
	outerIdent, err := (&twarp.IdentityStore{Path: chainMasqueSlot(&r.cfg)}).Load()
	if err != nil {
		// The outer supervisor's reconciler owns provisioning; when the slot
		// materializes the next tick assembles the composition.
		if errors.Is(err, twarp.ErrIdentityAbsent) || errors.Is(err, twarp.ErrIdentityCorrupt) {
			r.appendEvent(Event{Name: "warpchain_waiting_outer_identity", Detail: err.Error()})
			return nil
		}
		return err
	}
	localV4, perr := netip.ParseAddr(outerIdent.AssignedV4)
	if perr != nil || !localV4.Is4() {
		return fmt.Errorf("warpchain: outer identity assigned v4 %q invalid", outerIdent.AssignedV4)
	}
	var b4 [4]byte
	b4 = localV4.As4()

	r.setState(StateAssembling)
	rt, err := nested.NewMasqueAwgRuntime(nested.MasqueAwgConfig{
		Pair: nested.PairConfig{
			Outer: nested.LayerSpec{
				Kind:         nested.KindMasqueH2,
				IdentitySlot: nested.SlotPrimary,
				ProfileID:    "masque",
				Endpoint:     r.outerEndpoint,
				MTU:          twarp.DefaultMTU,
			},
			Inner: nested.LayerSpec{
				Kind:         nested.KindAWG,
				IdentitySlot: nested.SlotSecondary,
				ProfileID:    "awg",
				Endpoint:     r.innerEndpoint,
				MTU:          r.innerMTU(),
			},
		},
		Plane:        r.outerSup,
		LocalV4:      b4,
		InnerIdent:   inner,
		InnerProfile: r.awgProfile,
		DNS:          netip.MustParseAddr("1.1.1.1"),
		OnEvent: func(ev nested.Event) {
			r.appendEvent(Event{Name: "warpchain_composition_event", Detail: ev.Class + ": " + ev.Reason})
		},
		OuterSink: func(ev twarp.SupervisorEvent) {
			r.appendEvent(Event{Name: "warpchain_outer_event", Detail: ev.Name})
		},
	})
	if err != nil {
		return fmt.Errorf("m+w assembly: %w", err)
	}
	if err := rt.Start(ctx); err != nil {
		return fmt.Errorf("m+w start: %w", err)
	}
	r.guard.record()
	r.mu.Lock()
	r.mPlusW = rt
	r.restarts++
	r.state = StateUp
	r.mu.Unlock()
	r.appendEvent(Event{Name: "warpchain_composition_started", Detail: "masque+awg"})
	return nil
}

// assembleMasqueMasque builds the M+M composition: the outer supervisor is
// the capsule plane (this service owns it, the M+W canon), the inner
// MASQUE supervisor's control TCP dials THROUGH the outer's netstack and
// its reconciler provisions the SECONDARY slot (one CF device per layer —
// red line #3). The engine runtime owns the per-generation child rebuilds.
func (r *Runtime) assembleMasqueMasque(ctx context.Context) error {
	outerIdent, err := (&twarp.IdentityStore{Path: chainMasqueSlot(&r.cfg)}).Load()
	if err != nil {
		// The outer supervisor's reconciler owns provisioning; when the slot
		// materializes the next tick assembles the composition.
		if errors.Is(err, twarp.ErrIdentityAbsent) || errors.Is(err, twarp.ErrIdentityCorrupt) {
			r.appendEvent(Event{Name: "warpchain_waiting_outer_identity", Detail: err.Error()})
			return nil
		}
		return err
	}
	localV4, perr := netip.ParseAddr(outerIdent.AssignedV4)
	if perr != nil || !localV4.Is4() {
		return fmt.Errorf("warpchain: outer identity assigned v4 %q invalid", outerIdent.AssignedV4)
	}
	var b4 [4]byte
	b4 = localV4.As4()

	r.setState(StateAssembling)
	rt, aerr := nested.NewMasqueMasqueRuntime(nested.MasqueMasqueConfig{
		Pair: nested.PairConfig{
			Outer: nested.LayerSpec{
				Kind:         nested.KindMasqueH2,
				IdentitySlot: nested.SlotPrimary,
				ProfileID:    "masque",
				Endpoint:     r.outerEndpoint,
				MTU:          twarp.DefaultMTU,
			},
			Inner: nested.LayerSpec{
				Kind:         nested.KindMasqueH2,
				IdentitySlot: nested.SlotSecondary,
				ProfileID:    "masque",
				Endpoint:     r.innerEndpoint,
				MTU:          r.innerMTU(),
			},
		},
		Plane:   r.outerSup,
		LocalV4: b4,
		// The single fingerprint field covers the composition's masquerade
		// posture: the inner layer's ClientHello here, the outer's via the
		// supervisor template above.
		Fingerprint:   r.cfg.Fingerprint,
		InnerEnroll:   &twarp.EnrollClient{HTTP: r.opts.HTTP, BaseURL: r.opts.MasqueEnrollBaseURL},
		InnerSlotPath: r.cfg.EffectiveInnerIdentityPath(),
		OnEvent: func(ev nested.Event) {
			r.appendEvent(Event{Name: "warpchain_composition_event", Detail: ev.Class + ": " + ev.Reason})
		},
		InnerSink: func(ev twarp.SupervisorEvent) {
			r.appendEvent(Event{Name: "warpchain_inner_event", Detail: ev.Name})
		},
	})
	if aerr != nil {
		return fmt.Errorf("m+m assembly: %w", aerr)
	}
	if err := rt.Start(ctx); err != nil {
		return fmt.Errorf("m+m start: %w", err)
	}
	r.guard.record()
	r.mu.Lock()
	r.mPlusM = rt
	r.restarts++
	r.state = StateUp
	r.mu.Unlock()
	r.appendEvent(Event{Name: "warpchain_composition_started", Detail: "masque+masque"})
	return nil
}

// assembleWgMasque builds the W+M composition: the outer AWG session is
// owned by the engine runtime; the inner MASQUE supervisor's reconciler
// provisions the inner identity from the secondary slot.
func (r *Runtime) assembleWgMasque(outer *twg.Identity) error {
	r.setState(StateAssembling)
	rt, err := nested.NewWgMasqueRuntime(nested.WgMasqueConfig{
		Pair: nested.PairConfig{
			Outer: nested.LayerSpec{
				Kind:         nested.KindAWG,
				IdentitySlot: nested.SlotPrimary,
				ProfileID:    "awg",
				Endpoint:     r.outerEndpoint,
				MTU:          twg.DefaultMTU,
			},
			Inner: nested.LayerSpec{
				Kind:         nested.KindMasqueH2,
				IdentitySlot: nested.SlotSecondary,
				ProfileID:    "masque",
				Endpoint:     r.innerEndpoint,
				MTU:          r.innerMTU(),
			},
		},
		OuterIdent:   outer,
		OuterProfile: r.awgProfile,
		DNS:          netip.MustParseAddr("1.1.1.1"),
		// The inner secondary slot enrollment — NEVER the primary device
		// (red line #3).
		InnerEnroll:   &twarp.EnrollClient{HTTP: r.opts.HTTP, BaseURL: r.opts.MasqueEnrollBaseURL},
		InnerSlotPath: chainMasqueSlot(&r.cfg),
		OnEvent: func(ev nested.Event) {
			r.appendEvent(Event{Name: "warpchain_composition_event", Detail: ev.Class + ": " + ev.Reason})
		},
		InnerSink: func(ev twarp.SupervisorEvent) {
			r.appendEvent(Event{Name: "warpchain_inner_event", Detail: ev.Name})
		},
	})
	if err != nil {
		return fmt.Errorf("w+m assembly: %w", err)
	}
	if err := rt.Start(context.Background()); err != nil {
		return fmt.Errorf("w+m start: %w", err)
	}
	r.guard.record()
	r.mu.Lock()
	r.wPlusM = rt
	r.restarts++
	r.state = StateUp
	r.mu.Unlock()
	r.appendEvent(Event{Name: "warpchain_composition_started", Detail: "awg+masque"})
	return nil
}

// assembleWgWg builds the W+W composition over transportwg.NestedWgRuntime
// (design §7 R3, gool pattern): the obfuscated outer AWG session owns the
// carrier netstack; the inner vanilla AWG session's ONLY egress is the
// Backend-B loopback forwarder dialed through that netstack. Both identity
// slots are provisioned by this service (a second CF device for the inner
// layer — red line #3); the engine owns the per-generation child rebuilds
// and the bounded child-retry ladder.
func (r *Runtime) assembleWgWg(ctx context.Context, outer *twg.Identity) error {
	inner, err := r.ensureWGIdentityAt(ctx, r.wgInnerStore, &r.registeredInnerBoot, "awg-inner")
	if err != nil {
		return err
	}
	if inner == nil {
		return nil // provisioned this tick; the next tick continues
	}

	r.setState(StateAssembling)
	rt, err := twg.NewNestedWgRuntime(twg.NestedWgConfig{
		Outer: twg.NestedLayer{
			Ident:   outer,
			Profile: r.awgProfile, // junk-active (config + Build gates)
			// MTU 0 -> DefaultMTU (1280); keepalive 0 -> 5 (nested canon).
		},
		Inner: twg.NestedLayer{
			Ident: inner,
			// Vanilla inner profile: the obfuscation duty is the outer
			// layer's; the inner is the plain WG payload riding it.
			// MTU -> r.innerMTU() (<= 1200, the gradient headroom);
			// keepalive 0 -> 20 (separated from the outer's 5).
			MTU: r.innerMTU(),
		},
		OuterEdge: r.outerEndpoint,
		InnerEdge: r.innerEndpoint,
		// Backend-B carrier proof: the inner dials ONLY the loopback
		// forwarder; port 0 = assigned at bind (E8 lesson).
		InnerDial: netip.MustParseAddrPort("127.0.0.1:0"),
	}, twg.NestedWgOptions{
		DNS: netip.MustParseAddr("1.1.1.1"),
		OnEvent: func(ev twg.SessionEvent) {
			r.appendEvent(Event{Name: "warpchain_composition_event", Detail: ev.Name + " " + string(ev.Class) + ": " + ev.Reason})
		},
	})
	if err != nil {
		return fmt.Errorf("w+w assembly: %w", err)
	}
	if err := rt.Start(ctx); err != nil {
		return fmt.Errorf("w+w start: %w", err)
	}
	r.guard.record()
	r.mu.Lock()
	r.wPlusW = rt
	r.restarts++
	r.state = StateUp
	r.mu.Unlock()
	r.appendEvent(Event{Name: "warpchain_composition_started", Detail: "awg+awg"})
	return nil
}

func (r *Runtime) innerMTU() int {
	if r.cfg.InnerMTU > 0 {
		return r.cfg.InnerMTU
	}
	return nested.MaxInnerMTU
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
	r.appendEvent(Event{Name: "warpchain_failure", Detail: detail})
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

// restartGuard is the per-hour rebuild cap (proton canon).
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
