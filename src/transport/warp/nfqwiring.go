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
