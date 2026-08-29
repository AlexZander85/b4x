// KernelRouteCarrier (design 1.1): the outer works through a KERNEL TUN,
// so the carrier's whole job is owning the host route to the inner edge:
//
//	snapshot previous route -> idempotent /32(/128) pin via outer dev
//	                        -> VERIFY with "route get" (never exit codes)
//	                        -> re-asserted EVERY supervisor tick
//	teardown                -> restore the PREVIOUS route verbatim,
//	                           foreign routes are never deleted blindly
//
// This ports the field-proven zapret-gui ownership cycle (_pin_route_owned,
// _restore_route, _routes_cover) AND fixes their documented gap: an outer
// recreate silently loses the pin there; here Assert() runs on every tick
// and emits nested/carrier-route-lost + nested/pin-restored instead.
//
// Family criticality is asymmetric by design: a failed v6 pin is a warning,
// a failed v4 pin rolls the setup back (zapret-gui :296-330).
//
// All route mutation goes through the injectable RouteRunner seam so unit
// tests drive a FAKE table on any OS; production wiring passes IPRouteRunner
// (linux-only file).
package nested

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// RouteRunner executes one route-manipulation command and returns combined
// stdout/stderr. Production impl shells out to iproute2 ("ip"); tests inject
// a fake table.
type RouteRunner func(ctx context.Context, args ...string) (string, error)

// pinnedRoute is one OWNED pin entry with its teardown evidence.
type pinnedRoute struct {
	family string // "-4" | "-6"
	dst    netip.Addr
	dev    string
	prev   string // previous route line, "" when none existed
	// lostActive marks a route-lost episode in progress (B-N2: exactly one
	// route-lost event per episode; reset on successful repair).
	lostActive bool
}

// KernelRouteCarrierConfig wires one carrier instance.
type KernelRouteCarrierConfig struct {
	// Endpoint is the inner edge the pins protect (/32 or /128).
	Endpoint netip.AddrPort
	// Device is the OUTER interface name (traffic to Endpoint rides it).
	Device string
	// Policy: v4 mandatory by default; v6 opt-in warn-only.
	Policy FamilyPolicy
	// Runner is REQUIRED (production: IPRouteRunner).
	Runner RouteRunner
	// OnEvent receives carrier lifecycle events; must be non-blocking.
	OnEvent func(Event)
	// Dialer overrides socket dialing (tests); nil = sane defaults with
	// timeouts (no unbounded dials).
	Dialer *net.Dialer
}

// KernelRouteCarrier carries inner traffic through kernel routing pins.
type KernelRouteCarrier struct {
	cfg     KernelRouteCarrierConfig
	policy  FamilyPolicy
	dialerD func(ctx context.Context, network, address string) (net.Conn, error)

	mu    sync.Mutex
	owned []pinnedRoute

	proofOK atomic.Bool
	closed  atomic.Bool
	stopCh  chan struct{}
	loopWg  sync.WaitGroup
}

// NewKernelRouteCarrier validates config shape without touching the network.
func NewKernelRouteCarrier(cfg KernelRouteCarrierConfig) (*KernelRouteCarrier, error) {
	if !cfg.Endpoint.IsValid() || cfg.Endpoint.Port() == 0 {
		return nil, fmt.Errorf("nested: kernel carrier invalid endpoint %v", cfg.Endpoint)
	}
	if cfg.Device == "" {
		return nil, errors.New("nested: kernel carrier requires outer device name")
	}
	if cfg.Runner == nil {
		return nil, errors.New("nested: kernel carrier requires a RouteRunner")
	}
	c := &KernelRouteCarrier{
		cfg:    cfg,
		policy: cfg.Policy,
		stopCh: make(chan struct{}),
	}
	d := cfg.Dialer
	if d == nil {
		d = &net.Dialer{Timeout: 5 * time.Second}
	}
	c.dialerD = d.DialContext
	return c, nil
}

// Setup performs the initial ownership cycle: pin every required family,
// verify each pin by reading back the effective route (coverage gate), and
// only then mark the carrier proven. A failed MANDATORY family rolls
// everything back (v4 posture); a failed optional family emits a warning
// event and continues.
func (c *KernelRouteCarrier) Setup(ctx context.Context) error {
	if c.closed.Load() {
		return ErrCarrierClosed
	}
	ep := c.cfg.Endpoint
	var mandatoryFailed error
	if err := c.pinFamily(ctx, ep); err != nil {
		if isMandatoryFamily(ep.Addr(), c.policy) {
			mandatoryFailed = err
		} else {
			// PATCH-07 (M-14): an optional-family pin failure is a carrier
			// build warning, not a route incident — child-start-failed keeps
			// RouteLostTotal strictly about live-pin losses.
			c.emit(Event{Class: ClassChildStartFailed,
				Reason: fmt.Sprintf("optional-family %s: %v", familyOf(ep.Addr()), err)})
		}
	}
	if mandatoryFailed != nil {
		restCtx := ctx
		c.Restore(restCtx)
		return fmt.Errorf("nested: mandatory family pin failed: %w", mandatoryFailed)
	}
	if !c.coverageOK() {
		c.Restore(ctx)
		return fmt.Errorf("%w: coverage gate failed after setup", ErrCarrierUnproven)
	}
	c.proofOK.Store(true)
	return nil
}

// pinFamily snapshots the current route, applies the owned pin and verifies
// it. Idempotent: a route already pointing at our device AND already owned
// is left untouched (no modification, no duplicate ownership records).
func (c *KernelRouteCarrier) pinFamily(ctx context.Context, ep netip.AddrPort) error {
	fam := familyOf(ep.Addr())
	dst := ep.Addr()
	plen := prefixLenOf(fam)

	prevRaw, _ := c.cfg.Runner(ctx, fam, "route", "show", dst.String())
	prev := strings.TrimSpace(prevRaw)

	if strings.Contains(prev, "dev "+c.cfg.Device) && c.ownedIndex(dst) >= 0 {
		return nil // already ours and owned: idempotent no-op
	}

	// B-N1 pin discipline (zapret-gui :175; PATCH-14, M-1): add first — the
	// clean case never transiently removes a foreign route; on conflict fall
	// back to a single replace (idempotent, never EEXIST in practice). The
	// old replace->del->replace ladder could transiently drop a foreign /32
	// between del and the retry — an avoidable ownership violation.
	out, err := c.cfg.Runner(ctx, fam, "route", "add", dst.String()+"/"+plen, "dev", c.cfg.Device)
	if err != nil {
		var rerr error
		if _, rerr = c.cfg.Runner(ctx, fam, "route", "replace", dst.String()+"/"+plen, "dev", c.cfg.Device); rerr == nil {
			err = nil
			out = ""
		} else {
			err = rerr
		}
	}
	if err != nil {
		return fmt.Errorf("pin %s: %v (%s)", dst, err, strings.TrimSpace(out))
	}

	if verr := c.verifyRoute(ctx, fam, dst); verr != nil {
		// Self-clean: our replace may have landed even though verification
		// failed. Delete OUR pin and restore the previous route verbatim
		// before reporting the failure (rollback discipline).
		_, _ = c.cfg.Runner(ctx, fam, "route", "del", dst.String()+"/"+plen)
		if tok := strings.Fields(strings.TrimSpace(prev)); len(tok) > 0 &&
			!strings.Contains(prev, "dev "+c.cfg.Device) {
			full := append([]string{fam, "route", "replace"}, stripFamilyTokens(tok, fam)...)
			_, _ = c.cfg.Runner(ctx, full...)
		}
		return verr
	}
	c.recordOwned(pinnedRoute{family: fam, dst: dst, dev: c.cfg.Device, prev: prev})
	return nil
}

// verifyRoute reads back the EFFECTIVE route: the exit code alone never
// proves anything (zapret-gui lesson baked into the design).
func (c *KernelRouteCarrier) verifyRoute(ctx context.Context, fam string, dst netip.Addr) error {
	got, err := c.cfg.Runner(ctx, fam, "route", "get", dst.String())
	if err != nil {
		return fmt.Errorf("verify %s: %v", dst, err)
	}
	if !strings.Contains(got, "dev "+c.cfg.Device) {
		return fmt.Errorf("verify %s: effective route misses dev %s: %s",
			dst, c.cfg.Device, strings.TrimSpace(got))
	}
	return nil
}

func (c *KernelRouteCarrier) recordOwned(r pinnedRoute) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.owned {
		if c.owned[i].dst == r.dst {
			c.owned[i] = r // refresh evidence, never duplicate
			return
		}
	}
	c.owned = append(c.owned, r)
}

func (c *KernelRouteCarrier) ownedIndex(dst netip.Addr) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.owned {
		if c.owned[i].dst == dst {
			return i
		}
	}
	return -1
}

// coverageOK is the coverage gate: every MANDATORY family must have an
// owned pin before the composition may proceed.
func (c *KernelRouteCarrier) coverageOK() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	v4 := false
	for _, r := range c.owned {
		if r.family == "-4" {
			v4 = true
		}
	}
	return v4 || !c.policy.RequireV4
}

// ownedList snapshots the ownership table.
func (c *KernelRouteCarrier) ownedList() []pinnedRoute {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]pinnedRoute(nil), c.owned...)
}

// setLostActive flips the episode flag on the ORIGINAL owned record under
// c.mu (ownedList returns copies, so Assert must write back through this
// helper).
func (c *KernelRouteCarrier) setLostActive(dst netip.Addr, v bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.owned {
		if c.owned[i].dst == dst {
			c.owned[i].lostActive = v
			return
		}
	}
}

func (c *KernelRouteCarrier) emit(ev Event) {
	ev.At = time.Now()
	if cb := c.cfg.OnEvent; cb != nil {
		cb(ev)
	}
}

func closeOnce(ch chan struct{}) (already bool) {
	select {
	case <-ch:
		return true
	default:
	}
	defer func() { _ = recover() }() // concurrent closer wins; that is fine
	close(ch)
	return false
}
