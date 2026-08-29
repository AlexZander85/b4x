// nfq wiring, engine side (design §8; z2k lessons #6/#16; addendum §50
// invariant + §62.7 camouflage cutoff): the CONTROL-FLOW GUARD keeps the
// fork's generic desync away from established MASQUE control flows and
// re-arms strategy coverage for establishment phases.
//
// Semantics (z2k #6, adapted):
//   - while NO validated session is live, control endpoint IPs stay OUT of
//     the exclusion set — establishment traffic (TLS ClientHello to the
//     MASQUE edge, enrollment API calls) keeps receiving the normal
//     strategy treatment (this is also the Nova bootstrap-protection
//     posture);
//   - the moment a session is VALIDATED (supervisor emits masque_connected
//     strictly after data-plane validation — the structural §C.4 cutoff),
//     its endpoint IPs enter the exclusion set so fake/split mutations can
//     never touch the established tunnel;
//   - membership is REASSERTED on a fixed cadence (kernel sets do not
//     survive restarts) and diff-applied otherwise;
//   - every connected→disconnected transition re-emits the camouflage
//     authorization (coverage re-armed) — §62.7 warp_camouflage_authorized;
//     every disconnected→connected transition emits the structural cutoff —
//     §62.7 warp_camouflage_cutoff.
//
// The engine stays dependency-free: SetApplier is bound by the field layer
// to `ipset add/del -exist` or nft set updates against the set the NFQUEUE
// rules already reference.
package transportwarp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Required camouflage event names (§62.7 subset emitted here).
const (
	EvCamouflageAuthorized = "warp_camouflage_authorized"
	EvCamouflageCutoff     = "warp_camouflage_cutoff"
)

// DefaultReassertEvery mirrors the z2k self-heal cadence (re-add well
// within typical lease/timeout windows).
const DefaultReassertEvery = 30 * time.Second

// ErrGuardConfig reports invalid NewControlFlowGuard configurations.
var ErrGuardConfig = errors.New("transportwarp: invalid control-flow guard config")

// SetApplier applies one membership diff to a named kernel set.
type SetApplier interface {
	Apply(set string, add []netip.Addr, remove []netip.Addr) error
}

// SetApplierFunc adapts a function to SetApplier.
type SetApplierFunc func(set string, add, remove []netip.Addr) error

// Apply implements SetApplier.
func (f SetApplierFunc) Apply(set string, add, remove []netip.Addr) error {
	return f(set, add, remove)
}

// ControlAuthorization mirrors src/warp.TransportControlAuthorization with
// identical Valid semantics; the warpwire layer converts it 1:1.
type ControlAuthorization struct {
	SocketID, FlowKey, EndpointHash, InstanceID string
	Purpose                                     string // camouflage | established
	ProcessGeneration, ConfigGeneration         uint64
	IssuedAt                                    time.Time
}

// Valid mirrors the contract-package check (identity-complete + matching
// generations).
func (a ControlAuthorization) Valid(processGen, configGen uint64) bool {
	return a.SocketID != "" && a.FlowKey != "" && a.EndpointHash != "" &&
		a.InstanceID != "" && a.Purpose != "" &&
		a.ProcessGeneration == processGen && a.ConfigGeneration == configGen
}

// GuardEvent is one structured wiring event.
type GuardEvent struct {
	Name         string
	EndpointHash string
	Detail       string
	ObservedAt   time.Time
}

// ControlFlowGuardConfig wires the guard.
type ControlFlowGuardConfig struct {
	// SetName is the kernel exclusion set the NFQUEUE rules already skip.
	SetName string
	// Apply performs the membership diff.
	Apply SetApplier
	// ControlIPs lists ALL candidate control endpoint IPs (base and, for
	// nested, inner). Called once per poll tick.
	ControlIPs func() []netip.Addr
	// Connected reports whether a VALIDATED session is currently live.
	Connected func() bool

	InstanceID        string
	ProcessGeneration func() uint64
	ConfigGeneration  func() uint64

	ReassertEvery time.Duration // DefaultReassertEvery when zero
	PollInterval  time.Duration // controller tick, default 100ms
	Sink          func(GuardEvent)
	Now           func() time.Time
}

func (c *ControlFlowGuardConfig) fillDefaults() {
	if c.ReassertEvery <= 0 {
		c.ReassertEvery = DefaultReassertEvery
	}
	if c.PollInterval <= 0 {
		c.PollInterval = 100 * time.Millisecond
	}
}

// ControlFlowGuardStatus is the externally visible snapshot.
type ControlFlowGuardStatus struct {
	Excluding         bool
	AppliedAddrs      []string // hashes? plain addrs fine (endpoints are public)
	Authorizations    uint64
	Cutoffs           uint64
	ApplyErrors       uint64
	LastError         string
	LastAuthorization ControlAuthorization
}

// ControlFlowGuard owns the exclusion-set membership and the camouflage
// authorization/cutoff lifecycle.
type ControlFlowGuard struct {
	cfg ControlFlowGuardConfig

	mu          sync.Mutex
	applied     map[netip.Addr]bool
	lastAssert  time.Time
	excluding   bool
	authCount   uint64
	cutoffCount uint64
	applyErrors uint64
	lastErr     string
	lastAuth    ControlAuthorization
	cancel      context.CancelFunc
	done        chan struct{}
	startOnce   sync.Once
	stopOnce    sync.Once
}

// NewControlFlowGuard validates the configuration.
func NewControlFlowGuard(cfg ControlFlowGuardConfig) (*ControlFlowGuard, error) {
	cfg.fillDefaults()
	if cfg.SetName == "" || cfg.Apply == nil || cfg.ControlIPs == nil || cfg.Connected == nil {
		return nil, ErrGuardConfig
	}
	return &ControlFlowGuard{
		cfg:     cfg,
		applied: map[netip.Addr]bool{},
		done:    make(chan struct{}),
	}, nil
}

// Start launches the guard loop once.
func (g *ControlFlowGuard) Start(parent context.Context) error {
	g.startOnce.Do(func() {
		ctx, cancel := context.WithCancel(parent)
		g.cancel = cancel
		go g.run(ctx)
	})
	select {
	case <-g.done:
		return ErrNestedNotRunning
	default:
		return nil
	}
}

// Stop cancels the loop and waits for completion. Idempotent.
func (g *ControlFlowGuard) Stop() {
	g.stopOnce.Do(func() {
		if g.cancel != nil {
			g.cancel()
		}
	})
	<-g.done
}

// Done exposes loop termination.
func (g *ControlFlowGuard) Done() <-chan struct{} { return g.done }

// Status snapshots the guard state.
func (g *ControlFlowGuard) Status() ControlFlowGuardStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := ControlFlowGuardStatus{
		Excluding:         g.excluding,
		Authorizations:    g.authCount,
		Cutoffs:           g.cutoffCount,
		ApplyErrors:       g.applyErrors,
		LastError:         g.lastErr,
		LastAuthorization: g.lastAuth,
	}
	for addr := range g.applied {
		st.AppliedAddrs = append(st.AppliedAddrs, addr.String())
	}
	sort.Strings(st.AppliedAddrs)
	return st
}

func (g *ControlFlowGuard) now() time.Time {
	if g.cfg.Now != nil {
		return g.cfg.Now()
	}
	return time.Now()
}

func (g *ControlFlowGuard) emit(ev GuardEvent) {
	ev.ObservedAt = g.now()
	if g.cfg.Sink != nil {
		g.cfg.Sink(ev)
	}
}

func (g *ControlFlowGuard) run(ctx context.Context) {
	defer close(g.done)
	ticker := time.NewTicker(g.cfg.PollInterval)
	defer ticker.Stop()

	// Coverage starts ARMED (no validated session yet at Start time).
	g.emit(GuardEvent{Name: EvCamouflageAuthorized, Detail: "guard started; establishment coverage armed"})
	g.mu.Lock()
	g.authCount++
	g.lastAuth = ControlAuthorization{
		SocketID:          "cfg-guard",
		FlowKey:           "control",
		EndpointHash:      hashAddrs(g.cfg.ControlIPs()),
		InstanceID:        g.cfg.InstanceID,
		Purpose:           "camouflage",
		ProcessGeneration: genOf(g.cfg.ProcessGeneration),
		ConfigGeneration:  genOf(g.cfg.ConfigGeneration),
		IssuedAt:          g.now(),
	}
	g.lastAssert = g.now().Add(-g.cfg.ReassertEvery) // force first assert pass
	g.mu.Unlock()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		ips := g.cfg.ControlIPs()
		conn := g.cfg.Connected()
		now := g.now()

		g.mu.Lock()
		desired := map[netip.Addr]bool{}
		if conn {
			for _, ip := range ips {
				desired[ip] = true
			}
		}
		var add, remove []netip.Addr
		for ip := range desired {
			if !g.applied[ip] {
				add = append(add, ip)
			}
		}
		for ip := range g.applied {
			if !desired[ip] {
				remove = append(remove, ip)
			}
		}
		reassertDue := now.Sub(g.lastAssert) >= g.cfg.ReassertEvery && len(desired) > 0
		diffOnly := len(add) == 0 && len(remove) == 0
		if diffOnly && !reassertDue {
			g.mu.Unlock()
			continue
		}
		if reassertDue {
			add = sortedAddrs(desired)
			remove = nil
			g.lastAssert = now
		}
		set, applier := g.cfg.SetName, g.cfg.Apply
		g.mu.Unlock()

		sort.Slice(add, func(i, j int) bool { return add[i].String() < add[j].String() })
		sort.Slice(remove, func(i, j int) bool { return remove[i].String() < remove[j].String() })

		var applyErr string
		if len(add)+len(remove) > 0 {
			if err := applier.Apply(set, add, remove); err != nil {
				applyErr = err.Error()
			}
		}

		g.mu.Lock()
		if applyErr != "" {
			g.applyErrors++
			g.lastErr = applyErr
			g.mu.Unlock()
			continue // retry next tick; never silently drop exclusions
		}
		for _, ip := range add {
			g.applied[ip] = true
		}
		for _, ip := range remove {
			delete(g.applied, ip)
		}
		wasExcluding := g.excluding
		g.excluding = conn
		g.mu.Unlock()

		switch {
		case !wasExcluding && conn:
			// Structural C.4 cutoff: reached ONLY because Connected() is
			// fed from post-validation state (masque_connected semantics).
			g.emit(GuardEvent{Name: EvCamouflageCutoff, Detail: "validated control flow excluded from generic desync", EndpointHash: hashAddrs(ips)})
			g.mu.Lock()
			g.cutoffCount++
			g.mu.Unlock()
		case wasExcluding && !conn:
			// Session lost: coverage re-arms for the next establishment.
			g.emit(GuardEvent{Name: EvCamouflageAuthorized, Detail: "session lost; establishment coverage re-armed", EndpointHash: hashAddrs(ips)})
			g.mu.Lock()
			g.authCount++
			g.lastAuth.Purpose = "camouflage"
			g.mu.Unlock()
		}
	}
}

func genOf(fn func() uint64) uint64 {
	if fn == nil {
		return 0
	}
	return fn()
}

func sortedAddrs(m map[netip.Addr]bool) []netip.Addr {
	out := make([]netip.Addr, 0, len(m))
	for ip := range m {
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}

func hashAddrs(addrs []netip.Addr) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, ",")))
	return hex.EncodeToString(sum[:8])
}

// ---- fake-QUIC bootstrap cover (E-H3 continuation, EH5) ----
//
// While an H3 establishment is IN FLIGHT, QUIC traffic to the WARP ranges
// must receive the fake-QUIC NFQ profile (Nova warp.json pattern: CF ipset
// v4+v6, the 7 catalog ports, fake-bin repeats×6, AutoTTL). The cover is
// armed by the transport ladder right before the H3 dial and released on
// every terminal outcome — STRICTLY after the trust gate when the session
// establishes (established ⇒ camouflage off, §C.4 semantics; the ladder's
// ObserveValidation(success) path owns that release).
//
// Engine-side discipline mirrors ControlFlowGuard: this package never
// touches netfilter. The field layer binds CoverApplier to `ipset add/del
// -exist` (or nft set updates) against the sets its fake-QUIC rules already
// reference; ports/repeats/autottl are RULE-SIDE parameters whose values are
// pinned here by the profile contract so hook and engine cannot drift.

// Cover lifecycle event names (§62.7 family).
const (
	EvFakeQUICCoverArmed    = "warp_fake_quic_cover_armed"
	EvFakeQUICCoverReleased = "warp_fake_quic_cover_released"
	// PATCH-23 (M-15): release-failure escalation (first failure, then one
	// event per discharged-cadence retry; never more than one per cadence).
	EvFakeQUICCoverReleaseFailed = "warp_fake_quic_cover_release_failed"
)

// DefaultFakeQUICCoverSetV4/V6 are the kernel set names the fake-QUIC rules
// reference (Nova naming, b4- prefixed to avoid collisions).
const (
	DefaultFakeQUICCoverSetV4 = "b4_cf_fakequic_v4"
	DefaultFakeQUICCoverSetV6 = "b4_cf_fakequic_v6"
)

// DefaultFakeBinRepeats is the Nova fake-bin repetition count.
const DefaultFakeBinRepeats = 6

// FakeQUICProfile pins the establishment-cover parameters.
type FakeQUICProfile struct {
	SetNameV4      string   `json:"set_v4"`
	SetNameV6      string   `json:"set_v6"`
	Ports          []uint16 `json:"ports"`
	FakeBinRepeats int      `json:"fake_bin_repeats"`
	AutoTTL        bool     `json:"autottl"`
}

// DefaultFakeQUICCoverProfile returns the Nova-conformant profile: distinct
// v4/v6 set names, EXACTLY the versioned catalog port set, repeats×6,
// AutoTTL enabled.
func DefaultFakeQUICCoverProfile() FakeQUICProfile {
	return FakeQUICProfile{
		SetNameV4:      DefaultFakeQUICCoverSetV4,
		SetNameV6:      DefaultFakeQUICCoverSetV6,
		Ports:          append([]uint16(nil), Ports...),
		FakeBinRepeats: DefaultFakeBinRepeats,
		AutoTTL:        true,
	}
}

// Validate enforces the Nova pattern. A drifted profile is a hard error:
// half-applied camouflage is worse than none (z2k lesson #16 discipline).
func (p FakeQUICProfile) Validate() error {
	switch {
	case p.SetNameV4 == "" || p.SetNameV6 == "":
		return fmt.Errorf("%w: cover set names must be non-empty", ErrGuardConfig)
	case p.SetNameV4 == p.SetNameV6:
		return fmt.Errorf("%w: cover set names must differ (v4 vs v6)", ErrGuardConfig)
	case p.FakeBinRepeats != DefaultFakeBinRepeats:
		return fmt.Errorf("%w: fake-bin repeats = %d, want %d", ErrGuardConfig, p.FakeBinRepeats, DefaultFakeBinRepeats)
	case !p.AutoTTL:
		return fmt.Errorf("%w: autottl disabled breaks the Nova pattern", ErrGuardConfig)
	}
	if len(p.Ports) != len(Ports) {
		return fmt.Errorf("%w: cover ports = %d entries, want the %d-port catalog set", ErrGuardConfig, len(p.Ports), len(Ports))
	}
	for i, port := range p.Ports {
		if port != Ports[i] || !KnownPort(port) {
			return fmt.Errorf("%w: cover port [%d]=%d drifts from the catalog set", ErrGuardConfig, i, port)
		}
	}
	return nil
}

// CoverApplier activates/deactivates the coverage sets. Activate MUST ensure
// every prefix of each family is present in the named set (partial applies
// are forbidden — warp_destination_set_partial_apply_total discipline);
// Deactivate releases coverage entirely.
type CoverApplier interface {
	Activate(setV4, setV6 string, v4 []netip.Prefix, v6 []netip.Prefix) error
	Deactivate(setV4, setV6 string) error
}

// FakeQUICCoverConfig wires the cover.
type FakeQUICCoverConfig struct {
	Profile FakeQUICProfile
	Apply   CoverApplier
	Sink    func(GuardEvent)
	Now     func() time.Time

	// Release retry cadence (PATCH-23, M-15): a failed Deactivate starts ONE
	// background retry loop — fast attempts every ReleaseRetryEvery (up to
	// ReleaseRetryFastAttempts), then the discharged ReleaseRetrySlowEvery
	// cadence until success or the next Arm(). Zero values map to the
	// production numbers (5s × 3 → 60s); tests shrink them.
	ReleaseRetryEvery        time.Duration
	ReleaseRetryFastAttempts int
	ReleaseRetrySlowEvery    time.Duration
}

// FakeQUICCover owns the arm/release lifecycle around H3 establishments.
// It implements BootstrapCover and is safe for concurrent use.
type FakeQUICCover struct {
	cfg FakeQUICCoverConfig

	mu             sync.Mutex
	armed          bool
	arms           uint64
	releases       uint64
	applyErrors    uint64
	releaseRetries uint64
	lastErr        string
	retryCancel    context.CancelFunc // live retry loop; nil = none
	retryGen       uint64             // retry-loop generation (identity for cleanup)
}

// NewFakeQUICCover validates the profile shape.
func NewFakeQUICCover(cfg FakeQUICCoverConfig) (*FakeQUICCover, error) {
	if err := cfg.Profile.Validate(); err != nil {
		return nil, err
	}
	if cfg.Apply == nil {
		return nil, fmt.Errorf("%w: cover requires an applier", ErrGuardConfig)
	}
	return &FakeQUICCover{cfg: cfg}, nil
}

// Arm activates the fake-QUIC coverage. Idempotent within one window;
// errors are structural — the ladder fails closed to H2 for the generation.
func (c *FakeQUICCover) Arm() error {
	c.mu.Lock()
	if c.armed {
		c.mu.Unlock()
		return nil
	}
	profile, applier := c.cfg.Profile, c.cfg.Apply
	// PATCH-23: re-arm overlaps and cancels any pending release retry — the
	// sets are about to be (re)activated, cleanup is no longer wanted.
	if c.retryCancel != nil {
		c.retryCancel()
		c.retryCancel = nil
		c.retryGen++
	}
	c.mu.Unlock()

	v4, v6 := cfCoverPrefixes()
	if err := applier.Activate(profile.SetNameV4, profile.SetNameV6, v4, v6); err != nil {
		c.mu.Lock()
		c.applyErrors++
		c.lastErr = err.Error()
		c.mu.Unlock()
		return err
	}

	c.mu.Lock()
	wasArmed := c.armed
	c.armed = true
	if !wasArmed {
		c.arms++
	}
	c.mu.Unlock()
	c.emit(GuardEvent{
		Name:   EvFakeQUICCoverArmed,
		Detail: "profile=nova sets=" + profile.SetNameV4 + "+" + profile.SetNameV6 + " ports=7 fake_bin_repeats=6 autottl=on",
	})
	return nil
}

// Release deactivates the coverage. Safe to call from every terminal path;
// no-op when nothing is armed. Non-blocking: a failed Deactivate hands the
// cleanup to ONE background retry loop (PATCH-23, M-15) instead of leaving
// the fake-QUIC rules matched against an ESTABLISHED session (risk §C.4).
func (c *FakeQUICCover) Release(reason string) {
	c.mu.Lock()
	if !c.armed {
		c.mu.Unlock()
		return
	}
	profile, applier := c.cfg.Profile, c.cfg.Apply
	c.armed = false
	c.releases++
	c.mu.Unlock()

	if err := applier.Deactivate(profile.SetNameV4, profile.SetNameV6); err != nil {
		c.mu.Lock()
		c.applyErrors++
		c.lastErr = err.Error()
		startRetry := c.retryCancel == nil // single retry loop, never duplicates
		c.mu.Unlock()
		// Escalation: the first failure is loud; the retry loop escalates at
		// the discharged cadence (>= one cadence apart — no spam).
		c.emit(GuardEvent{Name: EvFakeQUICCoverReleaseFailed,
			Detail: fmt.Sprintf("reason=%s attempt=0 err=%v", reason, err)})
		if startRetry {
			c.startReleaseRetry(reason)
		}
	}
	c.emit(GuardEvent{Name: EvFakeQUICCoverReleased, Detail: "reason=" + reason})
}

// startReleaseRetry re-attempts the Deactivate: ReleaseRetryEvery for
// ReleaseRetryFastAttempts fast attempts, then the discharged
// ReleaseRetrySlowEvery cadence. Stops on success, on Close, or when the
// next Arm() cancels it (re-arm overlaps and replaces the stale context).
func (c *FakeQUICCover) startReleaseRetry(reason string) {
	ctx, cancel := context.WithCancel(context.Background())
	c.mu.Lock()
	c.retryCancel = cancel
	c.retryGen++
	gen := c.retryGen
	fast := c.cfg.ReleaseRetryFastAttempts
	if fast <= 0 {
		fast = 3
	}
	fastEvery := c.cfg.ReleaseRetryEvery
	if fastEvery <= 0 {
		fastEvery = 5 * time.Second
	}
	slowEvery := c.cfg.ReleaseRetrySlowEvery
	if slowEvery <= 0 {
		slowEvery = 60 * time.Second
	}
	profile, applier := c.cfg.Profile, c.cfg.Apply
	c.mu.Unlock()

	go func() {
		defer func() {
			c.mu.Lock()
			if c.retryGen == gen {
				c.retryCancel = nil
			}
			c.mu.Unlock()
		}()
		attempt := 0
		for {
			wait := fastEvery
			if attempt >= fast {
				wait = slowEvery
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			attempt++
			c.mu.Lock()
			c.releaseRetries++ // every re-attempt counts, including the clearing one
			c.mu.Unlock()
			err := applier.Deactivate(profile.SetNameV4, profile.SetNameV6)
			if err == nil {
				c.emit(GuardEvent{Name: EvFakeQUICCoverReleased,
					Detail: fmt.Sprintf("reason=%s attempt=%d cleared", reason, attempt)})
				cancel() // stops the loop on the next select
				continue
			}
			c.mu.Lock()
			c.applyErrors++
			c.lastErr = err.Error()
			c.mu.Unlock()
			// Escalation cadence: fast retries stay quiet (seconds apart);
			// every discharged (slow-cadence) failure escalates again.
			if attempt > fast {
				c.emit(GuardEvent{Name: EvFakeQUICCoverReleaseFailed,
					Detail: fmt.Sprintf("reason=%s attempt=%d err=%v", reason, attempt, err)})
			}
		}
	}()
}

// Status snapshots the cover counters.
type FakeQUICCoverStatus struct {
	Armed       bool
	Arms        uint64
	Releases    uint64
	ApplyErrors uint64
	// ReleaseRetries counts background Deactivate re-attempts since
	// construction (PATCH-23, M-15: the self-healing surface is observable).
	ReleaseRetries uint64
	LastError      string
}

func (c *FakeQUICCover) Status() FakeQUICCoverStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	return FakeQUICCoverStatus{
		Armed:          c.armed,
		Arms:           c.arms,
		Releases:       c.releases,
		ApplyErrors:    c.applyErrors,
		ReleaseRetries: c.releaseRetries,
		LastError:      c.lastErr,
	}
}

// cfCoverPrefixes splits the versioned WARP gateway map into the v4/v6
// families for the coverage sets (the QUIC gateways live inside the same
// blocks, so one range set covers both carriers' bootstrap traffic).
func cfCoverPrefixes() (v4, v6 []netip.Prefix) {
	for _, p := range h2GatewayCIDRs {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	return v4, v6
}

func (c *FakeQUICCover) emit(ev GuardEvent) {
	ev.ObservedAt = c.now()
	if c.cfg.Sink != nil {
		c.cfg.Sink(ev)
	}
}

func (c *FakeQUICCover) now() time.Time {
	if c.cfg.Now != nil {
		return c.cfg.Now()
	}
	return time.Now()
}
