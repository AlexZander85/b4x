// Package operaservice assembles the dependency-free Opera/SurfEasy reserve
// engine (src/transport/opera: OP1 control channel + OP2 data plane + OP3
// health) from the main config — the deliberately-thin "last mile" mirroring
// warpservice.
//
// Integration contract (design §5, stage OP4):
//
//   - role kind "opera": a userspace Backend-B style TCP carrier; consumers
//     take Runtime.DialStream (the warp StreamDialer shape) and the scoped
//     router treats it like every other userspace carrier;
//
//   - anti-loop: sec-tunnel.com must always stay DIRECT at the route level
//     (zapret-gui chain lesson). In-code, DialStream refuses dialing the
//     transport's OWN node addresses through itself, and
//     SecTunnelBypassSuffixes is exported for the field layer to build its
//     DIRECT rules;
//
//   - bootstrap-through-carrier: when the direct egress cannot reach
//     api2.sec-tunnel.com, control-channel AND data-plane dials fall back to
//     the injected base-transport carrier (failover dialer);
//
//   - UDP fail-closed: the transport is TCP-only by protocol; non-tcp dials
//     fail closed at the dialer and SupportsUDP() reports false honestly.
package operaservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/daniellavrushin/b4/config"
	opera "github.com/daniellavrushin/b4/transport/opera"
)

// DialFunc is the base TCP dial shape shared with the warp engine.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// SecTunnelBypassSuffixes lists domains that must NEVER traverse any tunnel
// route (anti-loop, design §5). The field layer consumes this for its DIRECT
// rules; in-code the same invariant is enforced by refuseNodeSelfLoop.
var SecTunnelBypassSuffixes = []string{"sec-tunnel.com"}

// IsBypassDomain reports whether host is (a subdomain of) a bypass domain.
func IsBypassDomain(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, s := range SecTunnelBypassSuffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// ErrOperaSelfLoop is returned when a consumer asks the opera tunnel to
// carry traffic addressed to the transport's own infrastructure.
var ErrOperaSelfLoop = errors.New("operaservice: refusing self-loop through opera tunnel")

// Options assembles the runtime; zero values are valid.
type Options struct {
	// Carrier is the active base-transport dial (MASQUE/WG). When set,
	// every opera dial tries DIRECT first and falls back to the carrier —
	// "the reserve that reaches out through the base tunnel" (design §5).
	Carrier DialFunc
	// Client overrides the constructed engine client (test injection).
	Client *opera.Client
	// Supervisor overrides the constructed health supervisor (tests).
	Supervisor func(c *opera.Client) (*opera.HealthSupervisor, error)
}

// Runtime owns one assembled Opera transport for a config generation.
type Runtime struct {
	cfg    config.OperaConfig
	client *opera.Client
	sup    *opera.HealthSupervisor
	ring   *eventRing

	// masquerade is the resolved anti-DPI state; nfqBait is the OP-M3
	// OUTPUT-hook handle (nil when the bait is disabled); ladder is the
	// OP-M4 rung state machine (nil when the masquerade is off).
	masquerade opera.MasqueradeSettings
	nfqBait    NFWBait
	ladder     *masqueradeLadder

	mu      sync.Mutex
	started bool
	stopped bool
	cancel  context.CancelFunc
}

// NFWBait is the interface the NFQ OUTPUT-hook (OP-M3) satisfies; nil or
// inactive means the bait is not applied (honest status). SetActive is
// implemented by the concrete handle for the daemon wiring.
type NFWBait interface {
	Active() bool
}

// SetBaitActive records the tables-layer confirmation of the OUTPUT rule
// (daemon wiring after tables.ApplyOperaBaitOnly).
func (r *Runtime) SetBaitActive(active bool) {
	if s, ok := r.nfqBait.(*nfwBaitState); ok {
		s.SetActive(active)
	}
}

// Build validates the system.opera section and constructs the runtime
// WITHOUT starting anything. It succeeds even when Enabled=false so the
// daemon gates on config itself (warpservice parity).
func Build(cfg *config.Config, opts Options) (*Runtime, error) {
	oc := cfg.System.Opera
	if oc.IdentityPath == "" {
		oc.IdentityPath = config.DefaultOperaIdentityPath
	}
	if strings.TrimSpace(oc.Region) == "" {
		oc.Region = opera.RegionEU // zero-config assembly defaults to EU
	}
	region, err := opera.NormalizeRegion(oc.Region)
	if err != nil {
		return nil, fmt.Errorf("operaservice: system.opera.region: %w", err)
	}

	// Masquerade resolution (review §7.3): defaults live in the engine;
	// the config layer only validated shapes.
	mq := opera.ResolveMasquerade(
		oc.Masquerade.Profile, oc.Masquerade.SNIMode,
		oc.Masquerade.SNIPool, oc.Masquerade.ALPN,
		oc.Masquerade.SessionResumption, oc.Masquerade.TTLFake)

	client := opts.Client
	if client == nil {
		var control func(network, address string, c syscall.RawConn) error
		if mq.TTLFake {
			control = baitControl()
		}
		dial := failoverDialerFnWithControl(nil, opts.Carrier, control)
		c, err := opera.New(opera.Options{
			DialContext: dial,
			Slot:        &opera.IdentityStore{Path: oc.IdentityPath},
			Masquerade:  mq,
		})
		if err != nil {
			return nil, fmt.Errorf("operaservice: engine client: %w", err)
		}
		client = c
	}

	var sup *opera.HealthSupervisor
	ring := &eventRing{}
	if opts.Supervisor != nil {
		sup, err = opts.Supervisor(client)
	} else {
		hc := opera.DefaultHealthConfig(region)
		hc.ControlTarget = oc.ControlTarget
		// Persistent discover cache (review H3): the last successful node
		// list becomes an offline asset next to the identity slot, adopted
		// when the API is down / region unavailable (801).
		hc.NodeCache = &opera.NodeCache{Path: opera.DefaultNodeCachePath(oc.IdentityPath)}
		// Observability hooks (review M3): lifecycle events -> ring +
		// registry counters; probes and discovers -> their counters.
		hc.OnEvent = makeOnEvent(ring)
		hc.OnProbe = recordProbe
		hc.OnDiscover = recordDiscover
		sup, err = opera.NewHealthSupervisor(client, hc)
	}
	if err != nil {
		return nil, fmt.Errorf("operaservice: health supervisor: %w", err)
	}
	rt := &Runtime{cfg: oc, client: client, sup: sup, ring: ring, masquerade: mq}
	rt.nfqBait = newNFWBaitIfConfigured(oc.Masquerade.TTLFake)
	if mq.Profile != opera.MasqueradeOff {
		rt.ladder = newMasqueradeLadder(client.MasqueradeBox(), ring,
			&LadderStore{Path: opera.DefaultLadderStorePath(oc.IdentityPath)},
			ladderHeadForProfile(mq.Profile), mq.SNIPool, mq.TTLFake, nil)
	}
	return rt, nil
}

// ladderHeadForProfile maps the configured profile onto the ladder ceiling:
// browser starts at the top; minimal skips the uTLS rungs (§7.5 rung
// 'plain-Go'); off never builds a ladder.
func ladderHeadForProfile(p opera.MasqueradeProfile) int {
	if p == opera.MasqueradeMinimal {
		return 3
	}
	return 0
}

// failoverDialer composes direct-first / carrier-second egress with a
// negative cache on the direct stage (review E-OPERA H2): the direct dial
// is hard-bounded at 5s (the OS-level ~2min black hole made every data
// dial AND every supervisor probe pay full price on a blocked egress), and
// after two consecutive direct failures the stage is considered dead for a
// 60s TTL — dials then go carrier-first, with a periodic direct self-heal
// probe when the carrier also fails.
const (
	directDialTimeout   = 5 * time.Second
	directFailThreshold = 2
	directDeadTTL       = 60 * time.Second
)

type failoverDial struct {
	direct  DialFunc
	carrier DialFunc

	now func() time.Time

	mu              sync.Mutex
	directFails     int
	directDeadUntil time.Time
}

func newFailoverDial(direct, carrier DialFunc) *failoverDial {
	return newFailoverDialWithControl(direct, carrier, nil)
}

// newFailoverDialWithControl attaches the bait Control (SO_MARK on the
// DIRECT stage sockets only — review OP-M3/§7.8.3) to the default direct
// dialer; injected dialers (tests, custom egress) pass through untouched.
func newFailoverDialWithControl(direct, carrier DialFunc, control func(network, address string, c syscall.RawConn) error) *failoverDial {
	if direct == nil {
		d := &net.Dialer{Timeout: directDialTimeout, KeepAlive: 30 * time.Second, Control: control}
		direct = d.DialContext
	}
	return &failoverDial{direct: direct, carrier: carrier, now: time.Now}
}

func (f *failoverDial) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	if f.carrier == nil {
		return f.direct(ctx, network, addr)
	}
	if f.directAlive() {
		conn, err := f.direct(ctx, network, addr)
		if err == nil {
			f.recordDirect(true)
			return conn, nil
		}
		f.recordDirect(false)
		cconn, cerr := f.carrier(ctx, network, addr)
		if cerr != nil {
			return nil, fmt.Errorf("direct: %v; carrier: %w", err, cerr)
		}
		return cconn, nil
	}
	// Direct presumed dead (negative cache): carrier-first — the typical
	// RF-censored path pays zero direct black-hole time. If the carrier
	// also fails, probe direct once so recovery is noticed (the record
	// re-arms the cache when it succeeds).
	cconn, cerr := f.carrier(ctx, network, addr)
	if cerr == nil {
		return cconn, nil
	}
	dconn, derr := f.direct(ctx, network, addr)
	if derr == nil {
		f.recordDirect(true)
		return dconn, nil
	}
	return nil, fmt.Errorf("carrier: %v; direct: %w", cerr, derr)
}

func (f *failoverDial) directAlive() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now().After(f.directDeadUntil)
}

func (f *failoverDial) recordDirect(ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ok {
		f.directFails = 0
		f.directDeadUntil = time.Time{} // self-heal re-arms the stage immediately
		return
	}
	f.directFails++
	if f.directFails >= directFailThreshold {
		f.directDeadUntil = f.now().Add(directDeadTTL)
		f.directFails = 0 // fresh count for the next TTL window
	}
}

// failoverDialerFn keeps the historical constructor shape used by Build
// and the unit tests.
func failoverDialerFn(direct, carrier DialFunc) DialFunc {
	return failoverDialerFnWithControl(direct, carrier, nil)
}

func failoverDialerFnWithControl(direct, carrier DialFunc, control func(network, address string, c syscall.RawConn) error) DialFunc {
	f := newFailoverDialWithControl(direct, carrier, control)
	if f.carrier == nil {
		return f.direct
	}
	return f.Dial
}

// failoverDialer (func-typed legacy alias) — kept for test parity.
func failoverDialer(direct, carrier DialFunc) DialFunc { return failoverDialerFn(direct, carrier) }

// Start launches the health supervisor loop (daemon mode only). The config
// gate (system.opera.enabled) belongs to the caller, like warpservice.
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return errors.New("operaservice: runtime already stopped")
	}
	if r.started {
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.started = true
	go r.sup.Run(runCtx)
	return nil
}

// Stop tears the loop down (no-op before Start).
func (r *Runtime) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started || r.stopped {
		return
	}
	r.stopped = true
	if r.cancel != nil {
		r.cancel()
	}
}

// SetRegion switches the desired megaregion keeping the device identity
// (design §5: region lives in discover, not in registration).
func (r *Runtime) SetRegion(region string) error { return r.sup.SetDesiredRegion(region) }

// Kick runs one supervision step immediately on its own goroutine (HTTP
// restart endpoint). Caps and cooldowns inside the health layer still apply;
// the call itself never blocks on the supervisor mutex.
func (r *Runtime) Kick(ctx context.Context) {
	go r.sup.Tick(r.sup.Now())
}

// SupportsUDP is a protocol constant: SurfEasy nodes speak CONNECT over
// TLS/TCP only. UDP-scope traffic must never be routed here (design §5,
// red line #5) — honest static answer for status consumers.
func (r *Runtime) SupportsUDP() bool { return false }

// Status combines health state with assembly-level facts.
type Status struct {
	opera.HealthStatus
	Enabled       bool             `json:"enabled"`
	Transport     string           `json:"transport"` // constant "tcp-only"
	FakeSNI       string           `json:"fake_sni,omitempty"`
	IdentityPath  string           `json:"identity_path"`
	NodeCachePath string           `json:"node_cache_path"`
	Events        []Event          `json:"events,omitempty"`
	Masquerade    MasqueradeStatus `json:"masquerade"`
}

// MasqueradeStatus is the honest observability of the anti-DPI layer
// (review §7.8 red line 5: every step observable, silent-fallback
// forbidden).
type MasqueradeStatus struct {
	Profile           string   `json:"profile"`
	SNIMode           string   `json:"sni_mode"`
	ALPN              []string `json:"alpn"`
	SessionResumption bool     `json:"session_resumption"`
	TTLFake           bool     `json:"ttl_fake"`
	TTLFakeActive     bool     `json:"ttl_fake_active"`
}

// Status snapshots the runtime (including the bounded event tail).
func (r *Runtime) Status() Status {
	st := Status{
		HealthStatus:  r.sup.Status(),
		Enabled:       r.cfg.Enabled,
		Transport:     "tcp-only",
		FakeSNI:       r.cfg.FakeSNI,
		IdentityPath:  r.cfg.IdentityPath,
		NodeCachePath: opera.DefaultNodeCachePath(r.cfg.IdentityPath),
	}
	if r.ring != nil {
		st.Events = r.ring.snapshot()
	}
	st.Masquerade = r.masqueradeStatus()
	exportNodesSource(st.HealthStatus.NodesSource)
	return st
}

// masqueradeStatus snapshots the resolved masquerade settings. TTLFake
// reports CONFIG intent; TTLFakeActive reports whether the NFQ OUTPUT hook
// is actually applied (OP-M3) — honest status when the engine cannot
// enforce the bait.
func (r *Runtime) masqueradeStatus() MasqueradeStatus {
	mq := r.masquerade
	if r.client != nil {
		mq = r.client.CurrentMasquerade()
	}
	return MasqueradeStatus{
		Profile:           string(mq.Profile),
		SNIMode:           string(mq.SNIMode),
		ALPN:              mq.ALPN,
		SessionResumption: mq.SessionResumption,
		TTLFake:           mq.TTLFake,
		TTLFakeActive:     mq.TTLFake && r.nfqHookActive(),
	}
}

// nfqHookActive reports whether the OUTPUT NFQ bait rule is applied
// (OP-M3). Until the tables layer confirms the rule, the honest answer is
// false.
func (r *Runtime) nfqHookActive() bool {
	return r.nfqBait != nil && r.nfqBait.Active()
}

// DialStream dials ONE TCP stream to addr THROUGH the currently selected
// node (the warp StreamDialer contract, Backend-B userspace carrier shape).
// Self-loop targets (the transport's own node IPs) are refused. A 407 on
// the CONNECT is fed to the health supervisor as a credential-rejection
// signal (review M1/M2: the refresh cycle used to be blind to it) and an
// immediate supervision kick runs in the background.
func (r *Runtime) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	entry := r.sup.ActiveEntry()
	if entry.IP == "" {
		return nil, errors.New("operaservice: no active node (bootstrap pending)")
	}
	if refuseNodeSelfLoop(entry, addr.Addr()) {
		return nil, ErrOperaSelfLoop
	}
	nd, err := r.client.NodeDialer(entry, r.cfg.FakeSNI)
	if err != nil {
		return nil, err
	}
	conn, err := nd.DialContext(ctx, "tcp", addr.String())
	if err != nil {
		if opera.IsClass(err, opera.ClassDataPlaneConnectRefused) &&
			opera.FailureStatus(err) == http.StatusProxyAuthRequired {
			r.sup.NoteDataPlaneAuthRejected()
			go r.sup.Tick(r.sup.Now())
		}
		r.recordDial("fail")
		if r.ladder != nil {
			r.ladder.ObserveDial(false, err)
		}
		return nil, err
	}
	r.recordDial("ok")
	if r.ladder != nil {
		r.ladder.ObserveDial(true, nil)
	}
	return conn, nil
}

// ActiveNodeAddr exposes the current node for diagnostics/status pages.
func (r *Runtime) ActiveNodeAddr() string { return r.sup.Status().ActiveNode }

// refuseNodeSelfLoop reports whether target equals one of the transport's
// own node addresses (dialing ourselves through ourselves = loop).
func refuseNodeSelfLoop(entry opera.SEIPEntry, target netip.Addr) bool {
	tip, err := netip.ParseAddr(entry.IP)
	if err != nil {
		return false
	}
	return tip == target.Unmap()
}
