// Nested warp+warp runtime (design §6; addendum §35/§39, gool/warp-socks
// field lessons): a BASE instance carries scoped traffic; an INNER instance
// — provisioned with its OWN independent identity — dials from inside the
// base network. The inner role exists for the non-RU mode (§35: nested
// depends on base).
//
// Hard rules enforced by NestedConfig.Validate (gool lib.rs:1546-1551 and
// design §6 "жёсткое правило"):
//   - DIFFERENT edge IPs per layer: same-address layers fail together and
//     make latency selection pointless;
//   - inner MTU strictly below outer MTU (gool: 1200 vs 1280) so
//     encapsulation never fragments;
//   - duplicate assigned addresses are rejected (§9 address_conflict:
//     "tunnel up but carries nothing", z2k #4);
//   - two INDEPENDENT identities (never share device/token between layers);
//   - Backend A requires an explicit constrained inner policy
//     (SO_MARK or SO_BINDTODEVICE via the base interface) — an unconstrained
//     inner control socket would leak direct, defeating the whole mode.
//
// Parent-link lifecycle mirrors the src/warp TunnelDependencyLink contract:
// while the base route is not held the child is INVALIDATED (stopped, zero
// dialing); every new validated base session bumps ParentSessionGen and the
// child is restarted REVALIDATED against that generation.
//
// Keepalive separation note: outer and inner supervisors MUST be wired with
// different HealthInterval values at composition time (design: outer 20s /
// inner 30s, gool 5s/20s) so reconnects do not synchronize; the engine
// constants below document the intended numbers without cross-supervisor
// coupling.
package transportwarp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"
)

// Latency/separation constants (design §6).
const (
	// DefaultNestedInnerMTU is gool's inner MTU (1200 < outer 1280).
	DefaultNestedInnerMTU = 1200
	// NestedOuterProbeInterval / NestedInnerProbeInterval are the intended
	// health-probe cadences for outer/inner supervisors (kept apart so
	// layer reconnects never synchronize).
	NestedOuterProbeInterval = 20 * time.Second
	NestedInnerProbeInterval = 30 * time.Second
)

// NestedBackendMode selects how the inner control socket reaches its edge.
type NestedBackendMode string

const (
	// BackendANetns routes the inner socket through the base network
	// namespace path: SO_MARK warp-inner-control-via-base and/or
	// SO_BINDTODEVICE on the base TUN (field-layer names arrive via config).
	BackendANetns NestedBackendMode = "backend-a-netns"
	// BackendBProxy dials the inner session through a userspace adapter
	// running over the base session (warp-socks/upstream pattern). The
	// adapter itself belongs to the E7 wiring pass; the engine validates
	// configuration and lifecycle around it.
	BackendBProxy NestedBackendMode = "backend-b-proxy"
)

// Validation errors carry structural identity so diagnostics can name the
// violated rule (§62.10 reason enums upstream).
var (
	ErrIdenticalIdentity  = errors.New("transportwarp: nested layers must use two independent identities")
	ErrAddressConflict    = errors.New("transportwarp: nested layers assign the same tunnel address")
	ErrSameEdge           = errors.New("transportwarp: nested layers must terminate on different edge IPs (gool hard rule)")
	ErrMTUGradient        = errors.New("transportwarp: inner MTU must be strictly below outer MTU")
	ErrUnconstrainedInner = errors.New("transportwarp: backend-a inner policy must be constrained (mark/bind-device)")
	ErrNestedNotRunning   = errors.New("transportwarp: nested runtime is not running")
)

// LinkState is the parent-dependency state of the child (mirrors
// TunnelDependencyLink semantics from the contracts package).
type LinkState string

const (
	LinkWaitingParent    LinkState = "waiting-parent"
	LinkUp               LinkState = "up"
	LinkChildInvalidated LinkState = "child-invalidated"
)

// NestedConfig validates the two-layer composition.
type NestedConfig struct {
	BaseTemplate  SessionConfig
	InnerTemplate SessionConfig
	BaseIdentity  *Identity
	InnerIdentity *Identity

	Backend       NestedBackendMode
	BaseInterface string // Backend A: SO_BINDTODEVICE target (base TUN)
	InnerFwMark   uint32 // Backend A alternative: SO_MARK on inner sockets

	// AllowUnconstrainedInner relaxes the fail-closed constrained-policy
	// requirement of Backend A. TESTS ONLY — production wiring must leave
	// it false.
	AllowUnconstrainedInner bool

	PollInterval time.Duration // controller poll tick, default 20ms
}

func (c *NestedConfig) fillDefaults() {
	if c.Backend == "" {
		c.Backend = BackendANetns
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 20 * time.Millisecond
	}
}

func mtuOr(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// Validate enforces every hard rule of the header comment.
func (c *NestedConfig) Validate() error {
	if c.BaseIdentity == nil || c.InnerIdentity == nil {
		return errors.New("transportwarp: nested requires both identities")
	}
	if c.BaseIdentity.ID == "" || c.InnerIdentity.ID == "" {
		return ErrIdenticalIdentity
	}
	if c.BaseIdentity.ID == c.InnerIdentity.ID {
		return ErrIdenticalIdentity
	}
	bV4, err := netip.ParseAddr(c.BaseIdentity.AssignedV4)
	if err != nil {
		return fmt.Errorf("%w: base assigned_v4 %q", ErrAddressConflict, c.BaseIdentity.AssignedV4)
	}
	iV4, err := netip.ParseAddr(c.InnerIdentity.AssignedV4)
	if err != nil {
		return fmt.Errorf("%w: inner assigned_v4 %q", ErrAddressConflict, c.InnerIdentity.AssignedV4)
	}
	if bV4 == iV4 {
		return ErrAddressConflict
	}
	if c.BaseEndpoint().Addr() == c.InnerEndpoint().Addr() && c.BaseEndpoint().IsValid() && c.InnerEndpoint().IsValid() {
		return ErrSameEdge
	}
	if mtuOr(c.InnerTemplate.MTU, DefaultNestedInnerMTU) >= mtuOr(c.BaseTemplate.MTU, DefaultMTU) {
		return ErrMTUGradient
	}
	if c.Backend == BackendANetns && !c.AllowUnconstrainedInner &&
		c.BaseInterface == "" && c.InnerFwMark == 0 {
		return ErrUnconstrainedInner
	}
	// Backend B has no kernel policy to constrain the inner socket, so the
	// ONLY proof the inner control stream will traverse the base is an
	// attached carrier (SessionConfig.DialFunc from BackendBDialFunc).
	// Without it the inner session would dial DIRECT — a recursive/direct
	// control leak. Owner decision (E8 close-out): this is BLOCKED_CARRIER,
	// a structural blocked state distinct from a network failure; fail
	// closed at config time.
	if c.Backend == BackendBProxy && c.InnerTemplate.DialFunc == nil {
		return fmt.Errorf("%w: backend-b inner requires SessionConfig.DialFunc (base-tunnel StreamDialer)", ErrBlockedCarrier)
	}
	return nil
}

// BaseEndpoint / InnerEndpoint expose the configured edges for validation
// and telemetry.
func (c *NestedConfig) BaseEndpoint() netip.AddrPort  { return c.BaseTemplate.Endpoint }
func (c *NestedConfig) InnerEndpoint() netip.AddrPort { return c.InnerTemplate.Endpoint }

// SupervisorFactory builds one supervisor instance. The inner factory is
// invoked once per parent generation: Supervisor instances are single-shot
// by design, so each revalidation cycle gets a fresh object.
type SupervisorFactory func(ctx context.Context) (*Supervisor, error)

// NestedStatus is the externally visible snapshot.
type NestedStatus struct {
	Link             LinkState
	ParentSessionGen uint64 // bumps on every new validated base session
	ChildRevalidated bool   // child running against the CURRENT generation
	BaseRouteHeld    bool
	InnerRunning     bool
	BaseColo         string
	InnerColo        string
}

// NestedRuntime owns base+inner lifecycles and the parent-link controller.
type NestedRuntime struct {
	cfg         NestedConfig
	baseFactory SupervisorFactory
	innerFact   SupervisorFactory

	mu               sync.Mutex
	link             LinkState
	parentGen        uint64
	childRevalidated bool
	baseSup          *Supervisor
	curInner         *Supervisor
	innerCancel      context.CancelFunc
	lastErr          error

	cancel context.CancelFunc
	done   chan struct{}
	startO sync.Once
	stopO  sync.Once
}

func NewNestedRuntime(cfg NestedConfig, baseF, innerF SupervisorFactory) (*NestedRuntime, error) {
	if baseF == nil || innerF == nil {
		return nil, errors.New("transportwarp: nested requires both supervisor factories")
	}
	cfg.fillDefaults()
	n := &NestedRuntime{
		cfg:         cfg,
		baseFactory: baseF,
		innerFact:   innerF,
		link:        LinkWaitingParent,
		done:        make(chan struct{}),
	}
	if err := n.cfg.Validate(); err != nil {
		return nil, err
	}
	return n, nil
}

// Start launches the controller. The BASE supervisor starts immediately;
// the INNER one follows only once the base route is held.
func (n *NestedRuntime) Start(parent context.Context) error {
	n.startO.Do(func() {
		ctx, cancel := context.WithCancel(parent)
		n.cancel = cancel
		go n.run(ctx)
	})
	select {
	case <-n.done:
		return ErrNestedNotRunning
	default:
		return nil
	}
}

// Stop cancels the controller: child first, then base (teardown order).
func (n *NestedRuntime) Stop() {
	n.stopO.Do(func() {
		if n.cancel != nil {
			n.cancel()
		}
	})
	<-n.done
}

// Done exposes controller termination.
func (n *NestedRuntime) Done() <-chan struct{} { return n.done }

// Base returns the running base supervisor (operator kicks, diagnostics).
// Nil before Start.
func (n *NestedRuntime) Base() *Supervisor {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.baseSup
}

// Status snapshots the link state.
func (n *NestedRuntime) Status() NestedStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	st := NestedStatus{
		Link:             n.link,
		ParentSessionGen: n.parentGen,
		ChildRevalidated: n.childRevalidated,
	}
	if n.baseSup != nil {
		bs := n.baseSup.Snapshot()
		st.BaseRouteHeld = bs.RouteHeld
		st.BaseColo = bs.LastColo
	}
	if n.curInner != nil {
		is := n.curInner.Snapshot()
		st.InnerRunning = is.State != StateStopped
		st.InnerColo = is.LastColo
	}
	return st
}

func (n *NestedRuntime) setState(link LinkState, gen uint64, revalidated bool) {
	n.mu.Lock()
	n.link = link
	n.parentGen = gen
	n.childRevalidated = revalidated
	n.mu.Unlock()
}

// stopInner tears the current child down (idempotent).
func (n *NestedRuntime) stopInner() {
	n.mu.Lock()
	inner := n.curInner
	cancel := n.innerCancel
	n.curInner = nil
	n.innerCancel = nil
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if inner != nil {
		inner.Stop()
	}
}

// startInner builds and starts a fresh child against the current generation.
func (n *NestedRuntime) startInner(ctx context.Context) error {
	innerCtx, cancel := context.WithCancel(ctx)
	inner, err := n.innerFact(innerCtx)
	if err != nil {
		cancel()
		return err
	}
	if err := inner.Start(innerCtx); err != nil {
		cancel()
		return err
	}
	n.mu.Lock()
	n.curInner = inner
	n.innerCancel = cancel
	n.mu.Unlock()
	return nil
}

func (n *NestedRuntime) run(ctx context.Context) {
	defer close(n.done)

	// Base comes up first; it lives for the whole runtime lifetime.
	base, err := n.baseFactory(ctx)
	if err != nil {
		n.mu.Lock()
		n.lastErr = err
		n.mu.Unlock()
		return
	}
	n.mu.Lock()
	n.baseSup = base
	n.mu.Unlock()
	if err := base.Start(ctx); err != nil {
		n.mu.Lock()
		n.lastErr = err
		n.mu.Unlock()
		return
	}
	defer func() {
		n.stopInner() // CHILD FIRST — never orphan the inner layer
		base.Stop()
	}()

	ticker := time.NewTicker(n.cfg.PollInterval)
	defer ticker.Stop()
	innerRunning := false

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		held := base.Snapshot().RouteHeld
		switch {
		case held && !innerRunning:
			// New validated parent session => new generation; the child is
			// started already revalidated against THIS generation.
			n.mu.Lock()
			gen := n.parentGen + 1
			n.parentGen = gen
			n.mu.Unlock()
			if serr := n.startInner(ctx); serr != nil {
				n.setState(LinkChildInvalidated, gen, false)
				break
			}
			innerRunning = true
			n.setState(LinkUp, gen, true)
		case !held && innerRunning:
			// Parent lost: invalidate the child IMMEDIATELY (zero dialing
			// through a dead base); the next held transition bumps a NEW
			// generation and restarts the child revalidated against it.
			n.stopInner()
			innerRunning = false
			n.setState(LinkChildInvalidated, n.currentGen(), false)
		}
	}
}

func (n *NestedRuntime) currentGen() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.parentGen
}
