// W+M composition (design 3.3): AWG outer punches the UDP hole; the INNER
// layer is a MASQUE CONNECT-IP instance whose control TCP dials THROUGH the
// outer via the carrier (CarrierDialFunc seam). Production wiring owns the
// SECONDARY identity slot: its Reconciler talks the enrollment API through
// whatever path the operator configured - the runtime never shares the
// primary device's identity with the inner layer (red line #3).
//
// Parent-link contracts are reused verbatim: the AWG outer session is
// callback-driven (OnEstablished/OnLost); every new outer generation builds
// a FRESH carrier proof and a FRESH inner supervisor; teardown is strictly
// child-first.
package nested

import (
        "context"
        "errors"
        "fmt"
        "net/netip"
        "sync"
        "sync/atomic"
        "time"

        twarp "github.com/daniellavrushin/b4/transport/warp"
        twg "github.com/daniellavrushin/b4/transport/wg"
)

// WgMasqueConfig wires the composed pair.
type WgMasqueConfig struct {
        Pair PairConfig // must validate as awg outer + masque-h2 inner

        OuterIdent   *twg.Identity
        OuterProfile twg.Profile
        DNS          netip.Addr // inside the outer tunnel; default 8.8.8.8

        // OUTER data-plane mode decides the carrier (ResolveCarrier rule):
        OuterKernelTUN bool // false => ModeNetstack (userspace stack carrier)
        KernelDevice   string
        KernelRunner   RouteRunner
        FamilyPolicy   FamilyPolicy

        // INNER secondary-slot enrollment material (REQUIRED - fail closed:
        // one CF device must never serve both layers, red line #3).
        InnerEnroll   *twarp.EnrollClient
        InnerSlotPath string

        // InnerTCPMSS optionally clamps the inner control TCP segment size
        // (design 3.3: PMTU across two layers is unreliable - set it explicitly).
        // Effective ONLY for the kernel-route carrier (linux); the netstack
        // carrier segments against its own MTU by construction. 0 = off.
        InnerTCPMSS int

        OnEvent   func(Event)
        InnerSink func(twarp.SupervisorEvent)

        // Metrics optionally receives this pair's counter surface (design 5):
        // per-layer gate latency (design 62.9 - the price of nesting must be
        // attributable per layer), the pair-active gauge and the composition
        // counters. All methods are nil-safe; nil = no-op surface.
        Metrics *Metrics
}

// Validate checks every structural rule WITHOUT touching network state.
func (c *WgMasqueConfig) Validate() error {
        if err := c.Pair.Validate(); err != nil {
                return err
        }
        if c.Pair.Outer.Kind != KindAWG || c.Pair.Inner.Kind != KindMasqueH2 {
                return fmt.Errorf("nested: WgMasqueRuntime requires awg+masque-h2, got %s+%s",
                        c.Pair.Outer.Kind, c.Pair.Inner.Kind)
        }
        if c.OuterIdent == nil {
                return errors.New("nested: w+m requires the outer identity")
        }
        if c.OuterKernelTUN && (c.KernelDevice == "" || c.KernelRunner == nil) {
                return errors.New("nested: kernel-TUN outer requires device and RouteRunner")
        }
        if !c.OuterKernelTUN && (c.KernelDevice != "" || c.KernelRunner != nil) {
                return errors.New("nested: kernel fields set but OuterKernelTUN is false")
        }
        if c.InnerEnroll == nil || c.InnerSlotPath == "" {
                return fmt.Errorf("nested: w+m inner requires secondary slot enrollment " +
                        "(EnrollClient + store path); sharing the primary identity is forbidden")
        }
        return nil
}

// routeRestorer is implemented by carriers owning kernel state that MUST be
// torn down explicitly on pair shutdown (cleanup ownership red line #5).
type routeRestorer interface {
        Restore(ctx context.Context)
}

// WgMasqueRuntime owns the composed pair lifecycle.
type WgMasqueRuntime struct {
        cfg WgMasqueConfig

        mu        sync.Mutex
        link      string // waiting-parent | up | child-invalidated
        parentGen uint64
        carrier   NestedCarrier
        kernel    *KernelRouteCarrier // non-nil iff kernel mode
        // pairUp guards the PairActive gauge transition: repeated parent
        // losses / stops must not drive the gauge negative.
        pairUp bool

        // Gate stamps (MAJOR-5, design 62.9): unix nanos, 0 = disarmed.
        // Atomics because OnEstablished and the inner sink fire on foreign
        // goroutines; see gateObserve in metrics.go.
        outerGateStart atomic.Int64
        innerGateStart atomic.Int64

        metrics *Metrics
        // assertInterval is the kernel assertion-loop cadence (test seam: unit
        // tests shrink it; production keeps the 30s discipline).
        assertInterval time.Duration
        inner          *twarp.Supervisor
        innerCancel    context.CancelFunc
        cancelCtx      context.Context
        outerSession   *twg.Session

        startErr error

        cancel   context.CancelFunc
        done     chan struct{}
        startOne sync.Once
        stopOnce sync.Once
}

// NewWgMasqueRuntime validates the declaration; no network is touched and
// the OUTER session is not created until Start.
func NewWgMasqueRuntime(cfg WgMasqueConfig) (*WgMasqueRuntime, error) {
        if err := cfg.Validate(); err != nil {
                return nil, err
        }
        if !cfg.DNS.IsValid() {
                cfg.DNS = netip.AddrFrom4([4]byte{8, 8, 8, 8})
        }
        return &WgMasqueRuntime{cfg: cfg, metrics: cfg.Metrics, link: "waiting-parent", done: make(chan struct{})}, nil
}

// Start creates and launches the OUTER session; the inner MASQUE supervisor
// follows only through the OnEstablished bridge (fresh instance per
// generation - supervisors are single-shot by design).
func (r *WgMasqueRuntime) Start(parent context.Context) error {
        r.startOne.Do(func() {
                ctx, cancel := context.WithCancel(parent)
                r.cancel = cancel
                r.mu.Lock()
                r.cancelCtx = ctx
                r.mu.Unlock()

                tunMode := twg.ModeNetstack
                if r.cfg.OuterKernelTUN {
                        tunMode = twg.ModeKernel
                }
                sessCfg := twg.SessionConfig{
                        Ident:    r.cfg.OuterIdent,
                        Profile:  r.cfg.OuterProfile,
                        Endpoint: r.cfg.Pair.Outer.Endpoint.String(),
                        Tunnel: twg.TunnelConfig{
                                Mode:      tunMode,
                                Addresses: []netip.Addr{netip.MustParseAddr(r.cfg.OuterIdent.AssignedV4)},
                                DNS:       []netip.Addr{r.cfg.DNS},
                                MTU:       r.outerMTU(),
                        },
                        Health: twg.HealthConfig{KeepaliveSec: twg.NestedOuterKeepaliveSec},
                        Callbacks: twg.SessionCallbacks{
                                OnEvent:       r.outerEvent,
                                OnEstablished: r.onParentUp,
                                OnLost:        r.onParentLost,
                        },
                }
                sess, err := twg.NewSession(sessCfg)
                if err != nil {
                        cancel()
                        close(r.done)
                        r.startErr = fmt.Errorf("outer config: %w", err)
                        return
                }
                r.mu.Lock()
                r.outerSession = sess
                r.mu.Unlock()
                // MAJOR-5: arm BEFORE the session launches - OnEstablished
                // fires from the session goroutine and may beat a post-Start
                // arm on a fast handshake; the gate spans launch -> trust.
                r.armOuterGate()
                if serr := sess.Start(); serr != nil {
                        cancel()
                        close(r.done)
                        r.startErr = fmt.Errorf("outer start: %w", serr)
                        return
                }
                go r.watch()
        })
        select {
        case <-r.done:
                return r.startErr
        default:
                return nil
        }
}

// Status snapshots the parent-link state.
func (r *WgMasqueRuntime) Status() (link string, parentGen uint64, childRunning bool) {
        r.mu.Lock()
        defer r.mu.Unlock()
        child := false
        if r.inner != nil && r.inner.Snapshot().State != twarp.StateStopped {
                child = true
        }
        return r.link, r.parentGen, child
}

// Stop tears down CHILD-FIRST (inner supervisor), then kernel pins if owned,
// then the outer session. Idempotent.
func (r *WgMasqueRuntime) Stop() {
        r.stopOnce.Do(func() {
                if r.cancel != nil {
                        r.cancel()
                }
                r.stopInner()
                r.pairDown() // MAJOR-5: teardown drops the pair gauge
                r.mu.Lock()
                kernel := r.kernel
                r.mu.Unlock()
                if kernel != nil {
                        kernel.StopAssertionLoop()
                        kernel.Restore(context.Background())
                        kernel.Close()
                }
                r.mu.Lock()
                outer := r.outerSession
                r.mu.Unlock()
                if outer != nil {
                        outer.Stop()
                }
                // PATCH-05: bounded wait for the watch goroutine — Stop must never
                // hang on it, and done MUST close even when the parent context
                // outlives the runtime. Early Start error paths close done manually
                // (watch is not launched there); the close is idempotent-safe.
                select {
                case <-r.done:
                case <-time.After(2 * time.Second):
                }
        })
}

// ---- internals ----

func (r *WgMasqueRuntime) outerMTU() int {
        mtu := r.cfg.Pair.Outer.MTU
        if mtu <= 0 {
                mtu = twg.DefaultMTU
        }
        return mtu
}

func (r *WgMasqueRuntime) watch() {
        defer close(r.done)
        // PATCH-05 (M-12): wait on the RUNTIME-derived context, not the caller's
        // parent — Stop() cancels this one, so done always closes on teardown
        // and the goroutine never outlives the runtime.
        r.mu.Lock()
        ctx := r.cancelCtx
        r.mu.Unlock()
        if ctx == nil {
                return
        }
        <-ctx.Done()
}

// onParentUp builds a FRESH carrier for THIS generation and starts a FRESH
// inner supervisor against it. Serialized against Stop via mu discipline of
// the runtime (callbacks run on the outer session's goroutine).
func (r *WgMasqueRuntime) onParentUp() {
        gen := r.bumpGen()
        // MAJOR-5: this callback IS the outer trust gate closing (first
        // establishment or a repair after parent loss).
        r.observeOuterGate()

        // Carrier lifecycle (B-N2/N6): exactly one kernel carrier may be
        // alive per runtime. Teardown the previous generation BEFORE building
        // the next one: Restore() returns the foreign prev-route, so the new
        // Setup() snapshots the TRUE foreign state and the final Stop()
        // restores it (first-generation prev survives across generations).
        r.mu.Lock()
        oldKernel := r.kernel
        r.carrier, r.kernel = nil, nil
        r.mu.Unlock()
        if oldKernel != nil {
                oldKernel.StopAssertionLoop()
                oldKernel.Restore(context.Background())
                oldKernel.Close()
                r.emit(Event{Class: "wg_nested_carrier_replaced",
                        Reason: fmt.Sprintf("gen=%d carrier torn down before rebuild", gen)})
        }

        carrier, krc, cerr := r.buildCarrier(gen)
        if cerr != nil {
                r.setInvalidated(gen, cerr.Error())
                return
        }
        r.mu.Lock()
        r.carrier, r.kernel = carrier, krc
        r.mu.Unlock()

        sup, err := twarp.NewSupervisor(twarp.SupervisorConfig{
                Template: r.innerTemplate(carrier),
                Reconciler: &twarp.Reconciler{
                        API:   r.cfg.InnerEnroll,
                        Store: &twarp.IdentityStore{Path: r.cfg.InnerSlotPath},
                },
                // MAJOR-5: the bridge closes the inner gate on this
                // generation's first warp_masque_connected and forwards every
                // event to the operator sink verbatim.
                Sink: r.innerSinkBridge(),
        })
        if err != nil {
                r.setInvalidated(gen, "inner supervisor: "+err.Error())
                return
        }
        ictx, icancel := context.WithCancel(r.ctxOrBackground())
        // MAJOR-5: the inner gate spans identity + connect phases (the
        // supervisor's per-attempt DurationMS covers only the final dial).
        r.armInnerGate()
        if err := sup.Start(ictx); err != nil {
                icancel()
                gateDisarm(&r.innerGateStart) // dead generation owns no gate
                r.setInvalidated(gen, "inner start: "+err.Error())
                return
        }
        r.mu.Lock()
        r.inner = sup
        r.innerCancel = icancel
        r.link = "up"
        r.parentGen = gen
        freshUp := !r.pairUp
        r.pairUp = true
        r.mu.Unlock()
        if freshUp {
                r.metrics.PairGaugeMove(1)
        }
        r.emit(Event{Class: "wg_nested_child_revalidated",
                Reason: fmt.Sprintf("gen=%d proof=%v", gen, proofText(carrier))})
}

// onParentLost invalidates the child IMMEDIATELY (zero dialing through a
// dead parent); the next establishment builds everything fresh.
func (r *WgMasqueRuntime) onParentLost(f twg.Failure) {
        r.stopInner()
        r.pairDown()
        // MAJOR-5: re-arm the outer gate - the next OnEstablished measures
        // the REPAIR gate (loss -> re-establishment).
        r.armOuterGate()
        r.mu.Lock()
        r.link = "child-invalidated"
        r.mu.Unlock()
        r.emit(Event{Class: "wg_nested_parent_lost", Reason: string(f.Class)})
        r.emit(Event{Class: ClassChildInvalidated, Reason: "parent:" + string(f.Class)})
}

// buildCarrier resolves the carrier per the OUTER data-plane mode.
func (r *WgMasqueRuntime) buildCarrier(gen uint64) (NestedCarrier, *KernelRouteCarrier, error) {
        if r.cfg.OuterKernelTUN {
                krc, err := NewKernelRouteCarrier(KernelRouteCarrierConfig{
                        Endpoint: r.cfg.Pair.Inner.Endpoint,
                        Device:   r.cfg.KernelDevice,
                        Policy:   r.cfg.FamilyPolicy,
                        Runner:   r.cfg.KernelRunner,
                        Dialer:   DialerWithMSS(nil, r.cfg.InnerTCPMSS),
                        OnEvent:  r.emit,
                })
                if err != nil {
                        return nil, nil, err
                }
                if err := krc.Setup(context.Background()); err != nil {
                        return nil, nil, err
                }
                interval := r.assertInterval
                if interval <= 0 {
                        interval = 30 * time.Second
                }
                krc.RunAssertionLoop(context.Background(), interval)
                return krc, krc, nil
        }
        r.mu.Lock()
        outer := r.outerSession
        r.mu.Unlock()
        tun := outer.Tunnel()
        if tun == nil || tun.Netstack == nil {
                return nil, nil, ErrCarrierUnproven
        }
        ns, err := NewNetstackCarrier(tun.Netstack, fmt.Sprintf("gen=%d", gen))
        if err != nil {
                return nil, nil, err
        }
        return ns, nil, nil
}

func (r *WgMasqueRuntime) innerTemplate(carrier NestedCarrier) twarp.SessionConfig {
        mtu := r.cfg.Pair.Inner.MTU
        if mtu <= 0 {
                mtu = MaxInnerMTU
        }
        return twarp.SessionConfig{
                Endpoint: r.cfg.Pair.Inner.Endpoint,
                MTU:      mtu,
                DialFunc: CarrierDialFunc(carrier),
        }
}

func (r *WgMasqueRuntime) stopInner() {
        r.mu.Lock()
        inner := r.inner
        icancel := r.innerCancel
        r.inner = nil
        r.innerCancel = nil
        r.mu.Unlock()
        if icancel != nil {
                icancel()
        }
        if inner != nil {
                inner.Stop()
        }
}

func (r *WgMasqueRuntime) bumpGen() uint64 {
        r.mu.Lock()
        defer r.mu.Unlock()
        r.parentGen++
        return r.parentGen
}

func (r *WgMasqueRuntime) setInvalidated(gen uint64, reason string) {
        r.mu.Lock()
        r.link = "child-invalidated"
        r.mu.Unlock()
        // PATCH-07 (M-14): a start failure is a child-lifecycle outcome, never a
        // route incident — it must not feed ClassCarrierRouteLost/RouteLostTotal.
        r.emit(Event{Class: ClassChildStartFailed,
                Reason: fmt.Sprintf("gen=%d %s", gen, reason)})
}

func (r *WgMasqueRuntime) ctxOrBackground() context.Context {
        r.mu.Lock()
        defer r.mu.Unlock()
        if r.cancelCtx != nil {
                return r.cancelCtx
        }
        return context.Background()
}

// innerSinkBridge wraps the operator sink (MAJOR-5): the first
// warp_masque_connected of the generation closes the inner gate; every
// event still reaches the operator verbatim. The user sink is read at
// bridge-build time so tests can inject it before onParentUp runs.
func (r *WgMasqueRuntime) innerSinkBridge() func(twarp.SupervisorEvent) {
        user := r.cfg.InnerSink
        return func(ev twarp.SupervisorEvent) {
                if ev.Name == twarp.EvMasqueConnected {
                        r.observeInnerGate()
                }
                if user != nil {
                        user(ev)
                }
        }
}

// pairDown drops the pair-active gauge under the up-transition guard
// (onParentLost and Stop may both arrive; only the first decrement counts).
func (r *WgMasqueRuntime) pairDown() {
        r.mu.Lock()
        up := r.pairUp
        r.pairUp = false
        r.mu.Unlock()
        if up {
                r.metrics.PairGaugeMove(-1)
        }
}

// ---- gate-stamp wrappers (MAJOR-5; shared math in metrics.go) ----

func (r *WgMasqueRuntime) armOuterGate()     { gateArm(&r.outerGateStart) }
func (r *WgMasqueRuntime) armInnerGate()     { gateArm(&r.innerGateStart) }
func (r *WgMasqueRuntime) observeOuterGate() { gateObserve(&r.outerGateStart, r.metrics, "outer") }
func (r *WgMasqueRuntime) observeInnerGate() { gateObserve(&r.innerGateStart, r.metrics, "inner") }

func (r *WgMasqueRuntime) outerEvent(ev twg.SessionEvent) {
        // engine-native passthrough hook point (kept minimal)
        _ = ev
}

func (r *WgMasqueRuntime) emit(ev Event) {
        ev.At = time.Now()
        if cb := r.cfg.OnEvent; cb != nil {
                cb(ev)
        }
}

func proofText(c NestedCarrier) string {
        p, _ := c.ProofSnapshot()
        return p
}
