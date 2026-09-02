// Package fxvpservice assembles the Firefox VPN reserve transport
// (src/transport/fxvpn: FX1 control plane + FX2 data plane + FX3 account
// pool) from the main config - the deliberately-thin "last mile" mirroring
// operaservice/warpservice.
//
// Integration contract (E-FXVPN design Part I SS5, stage FX4):
//
//   - role kind "fxvpn": a userspace Backend-B style TCP carrier; consumers
//     take Runtime.DialStream (the warp StreamDialer shape);
//
//   - TCP-only by protocol (connect dialect): SupportsUDP() reports false
//     honestly; UDP-scope traffic must never be routed here;
//
//   - anti-loop: Mozilla/Fastly control hosts and the active node hostname
//     must never traverse the fxvpn tunnel itself (zapret-gui lesson,
//     opera parity); BypassSuffixes is exported for DIRECT rules;
//
//   - bootstrap-through-carrier: when enabled, CONTROL-plane TCP legs fall
//     back to the injected base-transport carrier (SPKI pinning stays on);
//
//   - supervisor discipline: session rebuilds capped <=6/hour with 300s
//     cooldown stamps, running/listening reported separately, event ring
//     for the GUI feed.
package fxvpservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniellavrushin/b4/config"
	fxvpn "github.com/daniellavrushin/b4/transport/fxvpn"
	warp "github.com/daniellavrushin/b4/transport/warp"
)

// DialFunc is the base dial shape shared with the warp/opera engines.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// BypassSuffixes must NEVER traverse the fxvpn tunnel (anti-loop).
var BypassSuffixes = []string{
	"accounts.firefox.com",
	"vpn.mozilla.org",
	"firefox.settings.services.mozilla.com",
	"fastly-masque.net",
}

// IsBypassDomain reports whether host is (a subdomain of) a bypass domain.
func IsBypassDomain(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if h == "" {
		return false
	}
	for _, s := range BypassSuffixes {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

var (
	ErrFxvpnSelfLoop = errors.New("fxvpservice: refusing self-loop through fxvpn tunnel")
	ErrNotListening  = errors.New("fxvpservice: no serving session yet")
)

// Restart discipline shared across transports.
const (
	MaxRestartsPerHour = 6
	RestartCooldown    = 300 * time.Second
	superviseTick      = 30 * time.Second
	eventsRingCap      = 32

	// defaultQuotaPollInterval is the 15-min X-Quota-* poll of design
	// Ч.I §3 (review F7): cheap FetchProxyPass re-mint that refreshes the
	// rotation triggers' quota view and re-issues the pass early.
	defaultQuotaPollInterval = 15 * time.Minute
)

type restartGuard struct {
	mu       sync.Mutex
	now      func() time.Time
	stamps   []time.Time
	cooldown time.Time
}

func (g *restartGuard) allowed() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	if now.Before(g.cooldown) {
		return false
	}
	cutoff := now.Add(-time.Hour)
	kept := g.stamps[:0]
	for _, s := range g.stamps {
		if s.After(cutoff) {
			kept = append(kept, s)
		}
	}
	g.stamps = kept
	return len(g.stamps) < MaxRestartsPerHour
}

func (g *restartGuard) stamp() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	g.stamps = append(g.stamps, now)
	if len(g.stamps) >= MaxRestartsPerHour {
		g.cooldown = now.Add(RestartCooldown)
	}
}

// Options assembles the runtime; zero values are valid.
type Options struct {
	// Carrier is the active base-transport dial. When set AND
	// bootstrap_through_carrier is on, control-plane TCP legs fail over to
	// it (direct first, carrier second).
	Carrier DialFunc
	// Now injects the clock (tests); defaults to time.Now.
	Now func() time.Time
	// ExtraEvents receives every pool/supervisor event (metrics wiring).
	ExtraEvents func(fxvpn.PoolEvent)
	// QuotaPollInterval overrides the 15-min X-Quota-* poll cadence
	// (tests). <=0 keeps the default.
	QuotaPollInterval time.Duration
	// Resolver resolves the ACTIVE node hostname for the anti-loop IP
	// guard (review F6; tests inject a fake). nil = net.DefaultResolver.
	Resolver hostResolver
}

// hostResolver is the node-IP lookup seam (*net.Resolver satisfies it).
type hostResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// ExitView is the last verified exit observation.
type ExitView struct {
	IP        string    `json:"ip,omitempty"`
	Country   string    `json:"country,omitempty"`
	OK        bool      `json:"ok"`
	CheckedAt time.Time `json:"checked_at,omitempty"`
	Error     string    `json:"error,omitempty"`
}

// Runtime owns one assembled fxvpn transport for a config generation.
type Runtime struct {
	cfg      config.FxVPNConfig
	pool     *fxvpn.Pool
	cp       *fxvpn.ControlPlane
	sl       *fxvpn.ServerlistCache
	preferH3 atomic.Bool

	guard restartGuard

	mu          sync.Mutex
	session     fxvpn.TunnelOpener
	sessionHost string
	carrier     string
	running     bool
	stopped     bool
	cancel      context.CancelFunc

	exit        ExitView
	lastFailure string
	events      []fxvpn.PoolEvent
	dialOK      uint64
	dialFail    uint64

	quotaPollInterval time.Duration
	lastQuotaPoll     time.Time

	adminRebuild bool // explicit SetLocation/RestartNow rebuild (F10)
	resolver     hostResolver
	nodeIPs      []netip.Addr // resolved ACTIVE node (anti-loop, F6; per session)

	masq fxvpn.MasqueradeSettings // resolved masquerade (review chapter 7)

	// Carrier-nesting state (review §7.5, FX-M2): when the :2499 port/IP
	// block is detected, the data plane nests in the base-tunnel carrier
	// (TCP/H2 only — UDP nesting is a designed extension §7.6.4).
	carrierDial   DialFunc  // the injected base-transport dial (nil = no carrier)
	nested        bool      // nested mode active
	nestAnnounced bool      // fxvpn_nested_activated emitted (red line: never silent)
	nestStrikes   int       // consecutive port-block-suspect dial failures
	lastNestProbe time.Time // last hourly direct-path return probe

	bytesUp     uint64         // relay bytes out (F7b)
	bytesDown   uint64         // relay bytes in (F7b)
	nodeStrikes map[string]int // consecutive dial failures per node host:port (F8)
}

// Build validates system.fxvpn and constructs the runtime WITHOUT starting
// anything or touching the network. Enabled=false still builds (daemon gates
// on config, warpservice parity). A corrupt accounts store fails the build
// deliberately (fxvpn-account-store-corrupt).
func Build(cfg *config.Config, opts Options) (*Runtime, error) {
	fc := cfg.System.FxVPN
	if fc.AccountsPath == "" {
		fc.AccountsPath = config.DefaultFxvpnAccountsPath
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.QuotaPollInterval <= 0 {
		opts.QuotaPollInterval = defaultQuotaPollInterval
	}

	cp, err := fxvpn.NewControlPlane(pinPathFor(fc.AccountsPath))
	if err != nil {
		return nil, fmt.Errorf("fxvpservice: control plane: %w", err)
	}
	if fc.BootstrapThroughCarrier && opts.Carrier != nil {
		cp.SetBaseDial(failoverDial(directDial(), opts.Carrier))
	}

	store := fxvpn.NewAccountStore(fc.AccountsPath)
	r := &Runtime{
		cfg:               fc,
		cp:                cp,
		quotaPollInterval: opts.QuotaPollInterval,
		resolver:          opts.Resolver,
		carrierDial:       opts.Carrier,
		masq: fxvpn.ResolveMasquerade(fc.Masquerade.Profile, fc.Masquerade.PreflightFake,
			fc.Masquerade.FakeSNI, fc.Masquerade.FakeTTL, fc.Masquerade.FakeCount,
			fc.Masquerade.InitialPadding, fc.Masquerade.HelloShaping),
	}
	// Last-good rung (§7.5): a previous run that ended nested starts
	// nested — releasing without proof would walk straight back into the
	// port block. The activation event fires on the first tick (red
	// line 3: never silent).
	if fc.Masquerade.NestOnPortBlock {
		if loadLadderState(siblingPath(fc.AccountsPath, ladderStateFile)).Nested && r.carrierDial != nil {
			r.nested = true
		}
	}
	r.preferH3.Store(fc.PreferH3)
	r.guard.now = opts.Now

	poolCfg := fxvpn.PoolConfig{
		RotateThresholdPct: fc.EffectiveRotateThreshold(),
		Now:                opts.Now,
	}
	poolCfg.Events = func(ev fxvpn.PoolEvent) {
		r.appendEvent(ev)
		r.exportPoolMetrics()
		if opts.ExtraEvents != nil {
			opts.ExtraEvents(ev)
		}
	}
	pool, perr := fxvpn.NewPool(store, &fxvpn.FXA{CP: cp}, &fxvpn.Guardian{CP: cp}, poolCfg)
	if perr != nil {
		return nil, fmt.Errorf("fxvpservice: account pool: %w", perr)
	}
	r.pool = pool
	return r, nil
}

func failoverDial(direct, carrier DialFunc) DialFunc {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := direct(ctx, network, addr)
		if err == nil {
			return conn, nil
		}
		cconn, cerr := carrier(ctx, network, addr)
		if cerr != nil {
			return nil, fmt.Errorf("direct: %v; carrier: %w", err, cerr)
		}
		return cconn, nil
	}
}

func directDial() DialFunc {
	d := &net.Dialer{}
	return d.DialContext
}

func pinPathFor(accountsPath string) string {
	if i := strings.LastIndex(accountsPath, "/"); i > 0 {
		return accountsPath[:i+1] + "pins.json"
	}
	return "pins.json"
}

func siblingPath(base, name string) string {
	if i := strings.LastIndex(base, "/"); i > 0 {
		return base[:i+1] + name
	}
	return name
}

// Start launches the supervisor loop (daemon mode only). The config gate
// (system.fxvpn.enabled) belongs to the caller, like warpservice.
func (r *Runtime) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return errors.New("fxvpservice: runtime already stopped")
	}
	if r.running {
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.running = true
	go r.loop(runCtx)
	return nil
}

// Stop tears the loop down (no-op before Start).
func (r *Runtime) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running || r.stopped {
		return
	}
	r.stopped = true
	if r.cancel != nil {
		r.cancel()
	}
}

// SupportsUDP is a protocol constant for the connect dialect.
func (r *Runtime) SupportsUDP() bool { return false }

// StreamDialer exposes the serving session in the warp StreamDialer shape
// (DialStream over netip.AddrPort) — the seam the scoped router consumes
// once the selection trees learn the fxvpn kind (review F4: DialStream had
// no consumers; the daemon wiring plus this accessor give the router a
// stable contract without importing the service internals).
func (r *Runtime) StreamDialer() warp.StreamDialer { return r }

// RestartNow forces an immediate supervision cycle (GUI button). It bypasses
// the tick cadence; as an EXPLICIT admin action its rebuild bypasses the
// automatic-rebuild cap too (review F10: a location change or a manual
// restart must not die silently inside the <=6/hour budget — only
// supervisor-driven rebuilds consume the cap, refusals emit
// fxvpn_restart_capped).
func (r *Runtime) RestartNow(ctx context.Context) {
	r.mu.Lock()
	r.adminRebuild = true
	r.mu.Unlock()
	r.tick(ctx)
}

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

// tick is one deterministic supervision cycle: recycle -> renew ->
// quota-poll -> pre-emptive rotate (review F3: UNCONDITIONALLY, i.e. while
// the session is alive — that is the only window the <15% / reset-lead
// triggers exist for) -> rebuild-if-dead, then refresh the /metrics gauges.

func (r *Runtime) tick(ctx context.Context) {
	r.pool.RecycleDue()
	if _, err := r.pool.RenewActivePassIfNeeded(ctx); err != nil {
		r.noteFailure(fxvpn.Classify(err))
	}
	r.pollQuotaIfDue(ctx)
	swapped, err := r.pool.RotateIfDue(ctx)
	if err != nil && !errors.Is(err, fxvpn.ErrPoolBlocked) {
		r.noteFailure(classifyServiceErr(err))
	}
	if swapped {
		r.applySoftSwap()
	}
	if err := r.ensureSession(ctx); err != nil {
		r.noteFailure(classifyServiceErr(err))
	}
	// Last-good nesting from a previous run announces itself on the first
	// tick (§7.8.3: nesting never turns on silently).
	r.mu.Lock()
	startNested := r.nested && r.carrierDial != nil
	r.mu.Unlock()
	if startNested {
		r.announceNested()
	}
	r.probeDirect(ctx) // hourly last-good return probe (§7.5)
	r.exportPoolMetrics()
}

// pollQuotaIfDue runs the 15-min X-Quota-* poll (review F7a) so the
// pre-emptive rotation below reads fresh quota numbers, not hours-old ones.
func (r *Runtime) pollQuotaIfDue(ctx context.Context) {
	r.mu.Lock()
	due := time.Since(r.lastQuotaPoll) >= r.quotaPollInterval
	if due {
		r.lastQuotaPoll = time.Now()
	}
	r.mu.Unlock()
	if !due {
		return
	}
	if _, err := r.pool.PollActiveQuota(ctx); err != nil {
		r.noteFailure(fxvpn.Classify(err))
	}
}

// applySoftSwap applies a pre-emptive pool rotation to a LIVE session
// (review F3 soft swap): open streams keep their old relay (they ride the
// old account's already-opened tunnels and die naturally), NEW tunnels get
// the new account's bearer via the in-place UpdateToken seam, and the
// session object itself is rebuilt by the next natural ensureSession cycle
// when it dies. The old session is deliberately NOT closed here — a hard
// close would break exactly the streams the pre-emptive rotation exists to
// protect.
func (r *Runtime) applySoftSwap() {
	r.mu.Lock()
	s := r.session
	alive := s != nil && s.IsAlive()
	r.mu.Unlock()
	if !alive {
		return // dead session: ensureSession rebuilds with the new bearer
	}
	bearerRaw, ok := r.pool.ActiveBearer()
	if !ok {
		return
	}
	if err := s.UpdateToken(bearerRaw); err != nil {
		r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_session_bearer_rotate_failed", Detail: short(err)})
		return
	}
	r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_session_bearer_rotated",
		Detail: "pre-emptive rotation applied in place; session rebuilds on next natural cycle"})
}

// ensureSession rebuilds the data-plane session when absent/dead. Pool
// rotation runs first so an exhausted/rejected seat moves before dialing.
// F10: an ADMIN rebuild (SetLocation/RestartNow — explicit user actions)
// bypasses the automatic-rebuild cap; the cap still counts every automatic
// rebuild, and a cap refusal emits fxvpn_restart_capped so the GUI knows
// why nothing happened.
func (r *Runtime) ensureSession(ctx context.Context) error {
	r.mu.Lock()
	s := r.session
	alive := s != nil && s.IsAlive()
	admin := r.adminRebuild
	r.mu.Unlock()
	if alive {
		return nil
	}

	if _, err := r.pool.RotateIfDue(ctx); err != nil && !errors.Is(err, fxvpn.ErrPoolBlocked) {
		return fmt.Errorf("rotate: %w", err)
	}
	bearerRaw, ok := r.pool.ActiveBearer()
	if !ok {
		return errors.New("no active account bearer")
	}
	if !admin && !r.guard.allowed() {
		r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_restart_capped",
			Detail: fmt.Sprintf("automatic rebuild refused (<= %d/hour or cooldown %s)", MaxRestartsPerHour, RestartCooldown)})
		return fmt.Errorf("restart capped (<=%d/hour or cooldown %s)", MaxRestartsPerHour, RestartCooldown)
	}

	if admin {
		r.mu.Lock()
		r.adminRebuild = false
		r.mu.Unlock()
	} else {
		r.guard.stamp()
	}

	host, port, lerr := r.resolveLocation(ctx)
	if lerr != nil {
		return lerr
	}

	// Nesting policy (§7.5/FX-M2): when nested, the TCP leg dials through
	// the base-tunnel carrier; H3 is forced off (QUIC through a TCP-only
	// carrier needs UDP egress — a designed extension, §7.6.4).
	r.mu.Lock()
	nested := r.nested
	r.mu.Unlock()
	policy := fxvpn.DialPolicy{}
	if nested && r.carrierDial != nil {
		policy.BaseDial = r.carrierDial
	}
	sess, carrier, serr := dialSession(ctx, r.cp, host, port, bearerRaw, r.preferH3.Load() && !nested, r.masq, policy)
	if serr != nil {
		// F8: consecutive dial failures degrade the node; after the
		// threshold the candidate selection rotates to the next server.
		r.strikeNode(net.JoinHostPort(host, strconv.Itoa(port)))
		r.onDialFailure(serr)
		return serr
	}
	r.clearNodeStrikes(net.JoinHostPort(host, strconv.Itoa(port)))
	r.mu.Lock()
	r.nestStrikes = 0
	r.mu.Unlock()

	r.mu.Lock()
	old := r.session
	r.session = sess
	r.sessionHost = net.JoinHostPort(host, strconv.Itoa(port))
	r.carrier = carrier
	r.mu.Unlock()
	if old != nil {
		_ = old.Close() // swap already atomic; old streams die naturally
	}

	// F6: cache the ACTIVE node's resolved IPs for the DialStream
	// anti-loop guard. Best-effort: on lookup failure the guard falls
	// back to the domain rules only (BypassSuffixes / router layer).
	r.nodeIPs = r.resolveNodeIPs(ctx, host)

	r.verifyExit(ctx, sess)
	return nil
}

// resolveNodeIPs resolves the node hostname (best-effort, 2s). Failure
// yields nil — DialStream then relies on the domain-level bypass rules.
func (r *Runtime) resolveNodeIPs(ctx context.Context, host string) []netip.Addr {
	res := r.resolver
	if res == nil {
		res = net.DefaultResolver
	}
	lctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	ips, err := res.LookupIPAddr(lctx, host)
	if err != nil || len(ips) == 0 {
		return nil
	}
	out := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.IP); ok {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// resolveLocation picks host/port from the cached server list per mode.
// F8: the pick is strike-aware — a node with nodeStrikeThreshold consecutive
// dial failures is skipped in favor of the next candidate (the RTT-ranking
// complement of the review was deliberately NOT added: a pre-dial TCP probe
// is exactly the behavioral fingerprint §7.4.4 of the masquerade chapter
// warns against).
func (r *Runtime) resolveLocation(ctx context.Context) (string, int, error) {
	sl, err := r.serverlist()
	if err != nil {
		return "", 0, fmt.Errorf("server list cache: %w", err)
	}
	countries, _, gerr := sl.Get(ctx)
	if gerr != nil {
		return "", 0, fmt.Errorf("server list: %w", gerr)
	}
	loc := r.cfg.Location
	var cands []fxvpn.ConnectCandidate
	switch strings.ToLower(loc.Mode) {
	case "", "auto":
		cands = fxvpn.ConnectCandidates(countries, "", "", "")
	case "country":
		cands = fxvpn.ConnectCandidates(countries, loc.Country, loc.City, "")
	case "host":
		cands = fxvpn.ConnectCandidates(countries, "", "", loc.Host)
	default:
		return "", 0, fmt.Errorf("location.mode %q invalid", loc.Mode)
	}
	if len(cands) == 0 {
		return "", 0, fmt.Errorf("%w: mode %q country=%q city=%q host=%q",
			fxvpn.ErrNoServers, loc.Mode, loc.Country, loc.City, loc.Host)
	}
	cand := r.pickCandidate(cands)
	return cand.Hostname, cand.Port, nil
}

// nodeStrikeThreshold is the consecutive-failure count after which a node
// is skipped in candidate selection (review F8; canon StrikeState N=2).
const nodeStrikeThreshold = 2

// strikeNode records one dial failure for node (host:port key) and announces
// the degradation exactly once per episode (at the threshold crossing).
func (r *Runtime) strikeNode(node string) {
	r.mu.Lock()
	if r.nodeStrikes == nil {
		r.nodeStrikes = make(map[string]int)
	}
	r.nodeStrikes[node]++
	n := r.nodeStrikes[node]
	r.mu.Unlock()
	if n == nodeStrikeThreshold {
		r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_node_degraded",
			Label: node, Detail: "consecutive dial failures; rotating candidates"})
	}
}

// clearNodeStrikes forgets the node's streak after a successful dial.
func (r *Runtime) clearNodeStrikes(node string) {
	r.mu.Lock()
	delete(r.nodeStrikes, node)
	r.mu.Unlock()
}

// pickCandidate returns the first candidate without a threshold-reaching
// streak; when every candidate is degraded it keeps rotating from the top
// (a bad chance beats no chance for a reserve transport).
func (r *Runtime) pickCandidate(cands []fxvpn.ConnectCandidate) fxvpn.ConnectCandidate {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range cands {
		key := net.JoinHostPort(cands[i].Hostname, strconv.Itoa(cands[i].Port))
		if r.nodeStrikes[key] < nodeStrikeThreshold {
			return cands[i]
		}
	}
	return cands[0]
}

// nestStrikeThreshold is the consecutive port-block-suspect failures after
// which the ladder escalates into the carrier (§7.5).
const (
	nestStrikeThreshold = 3
	nestReturnProbe     = time.Hour // hourly return probe (last-good canon)
)

// onDialFailure feeds one session-dial failure into the nest detector: N
// consecutive QUIC-handshake blackholes or TCP timeouts/resets on the node
// dial trip fxvpn_port_block_suspected and switch the ladder to the nested
// rung (review §7.5). Account-level verdicts never count.
func (r *Runtime) onDialFailure(err error) {
	r.mu.Lock()
	enabled := r.cfg.Masquerade.NestOnPortBlock && r.carrierDial != nil
	nested := r.nested
	r.mu.Unlock()
	if !enabled || nested || err == nil {
		return
	}
	if !portBlockSuspicion(err) {
		return
	}
	r.mu.Lock()
	r.nestStrikes++
	trip := r.nestStrikes >= nestStrikeThreshold
	if trip {
		r.nested = true
		r.nestStrikes = 0
		r.nestAnnounced = false
	}
	r.mu.Unlock()
	if trip {
		r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_port_block_suspected", Detail: short(err)})
		r.announceNested()
		r.persistLadderState()
	}
}

// announceNested emits the activation event exactly once per nested episode
// (§7.8.3: nesting never turns on silently). Covers the last-good start
// from Build as well.
func (r *Runtime) announceNested() {
	r.mu.Lock()
	if r.nestAnnounced {
		r.mu.Unlock()
		return
	}
	r.nestAnnounced = true
	r.mu.Unlock()
	r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_nested_activated",
		Detail: "data plane nested in the base-tunnel carrier (TCP/H2 only — honest status)"})
}

// portBlockSuspicion classifies one dial failure as a potential :2499
// block: QUIC handshake blackholes (udp-egress-blocked) and TCP
// timeouts/resets. Account-level verdicts never count.
func portBlockSuspicion(err error) bool {
	if err == nil {
		return false
	}
	if fxvpn.ClassifyDialError(err) == "udp-egress-blocked" {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := err.Error()
	return strings.Contains(msg, "connection reset") || strings.Contains(msg, "connection refused")
}

// probeDirect is the hourly last-good return probe (§7.5): while nested,
// try the DIRECT path once per interval; a working direct session releases
// the nesting (with an event) and becomes the serving session.
func (r *Runtime) probeDirect(ctx context.Context) {
	r.mu.Lock()
	due := time.Since(r.lastNestProbe) >= nestReturnProbe
	if due {
		r.lastNestProbe = time.Now()
	}
	nested := r.nested
	r.mu.Unlock()
	if !due || !nested || r.carrierDial == nil {
		return
	}
	if _, err := r.pool.RotateIfDue(ctx); err != nil && !errors.Is(err, fxvpn.ErrPoolBlocked) {
		return
	}
	bearerRaw, ok := r.pool.ActiveBearer()
	if !ok {
		return
	}
	host, port, lerr := r.resolveLocation(ctx)
	if lerr != nil {
		return
	}
	sess, carrier, serr := dialSession(ctx, r.cp, host, port, bearerRaw, r.preferH3.Load(), r.masq, fxvpn.DialPolicy{})
	if serr != nil {
		return // still blocked: stay nested
	}
	r.clearNodeStrikes(net.JoinHostPort(host, strconv.Itoa(port)))
	r.mu.Lock()
	old := r.session
	r.session = sess
	r.sessionHost = net.JoinHostPort(host, strconv.Itoa(port))
	r.carrier = carrier
	r.nested = false
	r.mu.Unlock()
	if old != nil {
		_ = old.Close()
	}
	r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_nested_released",
		Detail: "direct path verified; carrier nesting released"})
	r.persistLadderState()
}

// ladderStateFile persists the last-good rung (§7.5 last-good canon): a
// restart of a nested transport starts nested instead of walking back into
// the port block unannounced.
const ladderStateFile = "masquerade-ladder.json"

type ladderState struct {
	Version int       `json:"version"`
	Nested  bool      `json:"nested"`
	SavedAt time.Time `json:"saved_at"`
}

func loadLadderState(path string) ladderState {
	st := ladderState{}
	blob, err := os.ReadFile(path)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(blob, &st)
	return st
}

func (r *Runtime) persistLadderState() {
	r.mu.Lock()
	st := ladderState{Version: 1, Nested: r.nested, SavedAt: time.Now().UTC()}
	r.mu.Unlock()
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(siblingPath(r.cfg.AccountsPath, ladderStateFile), blob, 0600)
}

// dialSession establishes the carrier per ladder preference: H3 first when
// configured with exactly one confirmed-class fallback to H2; otherwise H2.
// masq rides the TunnelConfig into both carriers (review chapter 7).
func dialSession(ctx context.Context, cp *fxvpn.ControlPlane, host string, port int, bearerRaw string, preferH3 bool, masq fxvpn.MasqueradeSettings, policy fxvpn.DialPolicy) (fxvpn.TunnelOpener, string, error) {
	cfg := fxvpn.TunnelConfig{Host: host, Port: port, Token: bearerRaw, Masquerade: masq, Policy: policy}
	ladder := fxvpn.NewLadder(fxvpn.LadderConfig{PreferH3: preferH3})
	pick := ladder.Preferred()
	for attempt := 0; attempt < 2; attempt++ {
		switch pick {
		case fxvpn.CarrierH3:
			s, err := fxvpn.DialH3(ctx, cfg)
			if err == nil {
				return s, fxvpn.CarrierH3, nil
			}
			next, switched := ladder.ObserveDialFailure(pick, err)
			if !switched {
				return nil, "", err
			}
			pick = next
		default:
			s, err := fxvpn.DialH2(ctx, cfg)
			if err == nil {
				return s, fxvpn.CarrierH2, nil
			}
			return nil, "", err
		}
	}
	return nil, "", errors.New("carrier ladder exhausted")
}

// verifyExit probes the verified exit through the fresh session. Review F9:
// a FAILED PROBE (tunnel down, trace unavailable) is telemetry-distinct
// from a verified EXIT MISMATCH — only the mismatch carries
// ClassExitMismatch; probe failures carry ClassExitProbeFailed so the
// mismatch statistics stay meaningful.
func (r *Runtime) verifyExit(ctx context.Context, sess fxvpn.TunnelOpener) {
	info, err := fxvpn.ProbeExit(ctx, sess)
	r.mu.Lock()
	r.exit = ExitView{IP: info.IP, Country: info.Country, CheckedAt: r.now()}
	if err != nil {
		r.exit.Error = err.Error()
	} else {
		r.exit.OK = true
	}
	want := strings.ToUpper(strings.TrimSpace(r.cfg.Location.Country))
	mismatch := err == nil && want != "" && want != "AUTO" && !strings.EqualFold(info.Country, want)
	r.mu.Unlock()

	if err != nil {
		r.noteFailure(fxvpn.ClassExitProbeFailed)
		r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_exit_probe_failed", Detail: short(err)})
		return
	}
	if mismatch {
		r.noteFailure(fxvpn.ClassExitMismatch)
		r.appendEvent(fxvpn.PoolEvent{Type: "fxvpn_exit_mismatch",
			Label: info.IP, Detail: "got " + info.Country + " want " + want})
	}
}

// DialStream dials ONE TCP stream to addr THROUGH the serving session.
// Self-loop targets are refused; failures feed metrics/failure class.
//
// F6: addr carries a resolved IP, so the guard compares it against the
// ACTIVE node's resolved IPs (cache built at session establishment) —
// comparing the IP against the node HOSTNAME, as before, was always false
// and the guard was dead. Domain-level bypass (BypassSuffixes, Mozilla/
// Fastly hosts) belongs to the scoped router / DNS layer BEFORE resolution;
// this in-code guard is the last-resort net for node-IP dials.
func (r *Runtime) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	host := addr.Addr().String()
	if IsBypassDomain(host) {
		r.recordDial(false)
		return nil, ErrFxvpnSelfLoop
	}
	if err := r.ensureSession(ctx); err != nil {
		r.recordDial(false)
		r.noteFailure(classifyServiceErr(err))
		return nil, err
	}
	r.mu.Lock()
	sess := r.session
	nodeHost := hostOf(r.sessionHost)
	nodeIPs := r.nodeIPs
	r.mu.Unlock()
	if sess == nil {
		r.recordDial(false)
		return nil, ErrNotListening
	}
	if nodeHost != "" && strings.EqualFold(host, nodeHost) {
		r.recordDial(false)
		return nil, ErrFxvpnSelfLoop
	}
	for _, ip := range nodeIPs {
		if ip == addr.Addr().Unmap() {
			r.recordDial(false)
			return nil, ErrFxvpnSelfLoop
		}
	}
	conn, err := sess.OpenTunnel(ctx, net.JoinHostPort(host, strconv.Itoa(int(addr.Port()))))
	if err != nil {
		r.recordDial(false)
		r.noteFailure(classifyServiceErr(err))
		return nil, err
	}
	r.atomicOK()
	// F7b: the relay feeds the byte counters (up/down) + /metrics gauge.
	return byteCountingConn{Conn: conn, rt: r}, nil
}

// Status snapshots runtime state for the GUI/API (Дополнение 3 shapes).
type Status struct {
	Enabled       bool                 `json:"enabled"`
	Running       bool                 `json:"running"`
	Listening     bool                 `json:"listening"`
	Transport     string               `json:"transport"`
	Carrier       string               `json:"carrier,omitempty"`
	SessionNode   string               `json:"session_node,omitempty"`
	Location      config.FxVPNLocation `json:"location"`
	PreferH3      bool                 `json:"prefer_h3"`
	Pool          fxvpn.PoolStatus     `json:"pool"`
	VerifiedExit  ExitView             `json:"verified_exit"`
	LastFailure   string               `json:"last_failure,omitempty"`
	DialOK        uint64               `json:"dial_ok"`
	DialFail      uint64               `json:"dial_fail"`
	BytesUp       uint64               `json:"bytes_up"`
	BytesDown     uint64               `json:"bytes_down"`
	Nested        bool                 `json:"nested"`
	RestartCapHit bool                 `json:"restart_cap_hit"`
	Events        []fxvpn.PoolEvent    `json:"events,omitempty"`
}

// Status implements the honest running/listening split:
//   - running: supervisor loop alive;
//   - listening: live session AND exit verified (or not yet probed).
func (r *Runtime) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	st := Status{
		Enabled:      r.cfg.Enabled,
		Running:      r.running && !r.stopped,
		Transport:    "tcp-only",
		Carrier:      r.carrier,
		SessionNode:  r.sessionHost,
		Location:     r.cfg.Location,
		PreferH3:     r.preferH3.Load(),
		Pool:         r.pool.Status(),
		VerifiedExit: r.exit,
		LastFailure:  r.lastFailure,
		DialOK:       atomic.LoadUint64(&r.dialOK),
		DialFail:     atomic.LoadUint64(&r.dialFail),
		BytesUp:      atomic.LoadUint64(&r.bytesUp),
		BytesDown:    atomic.LoadUint64(&r.bytesDown),
		Nested:       r.nested,
		Events:       append([]fxvpn.PoolEvent(nil), r.events...),
	}
	listening := false
	if s := r.session; s != nil && s.IsAlive() {
		listening = st.VerifiedExit.OK || st.VerifiedExit.CheckedAt.IsZero()
	}
	st.Listening = listening
	st.RestartCapHit = !r.guard.allowed()
	return st
}

// LocationsView normalizes the cached server list for the GUI dropdown
// (Дополнение 3): quarantined excluded upstream, REC/CatchAll included.
type LocationsView struct {
	FetchedAt time.Time     `json:"fetched_at"`
	Countries []CountryView `json:"countries"`
}

type CountryView struct {
	Code   string     `json:"code"`
	Name   string     `json:"name"`
	Cities []CityView `json:"cities"`
}

type CityView struct {
	Code  string     `json:"code"`
	Name  string     `json:"name"`
	Hosts []HostView `json:"hosts"`
}

type HostView struct {
	Hostname    string `json:"hostname"`
	Port        int    `json:"port"`
	Quarantined bool   `json:"quarantined,omitempty"`
}

// Locations serves the dropdown; the raw cache stays authoritative.
func (r *Runtime) Locations(ctx context.Context) (LocationsView, error) {
	sl, err := r.serverlist()
	if err != nil {
		return LocationsView{}, err
	}
	countries, _, gerr := sl.Get(ctx)
	if gerr != nil {
		return LocationsView{}, gerr
	}
	view := LocationsView{FetchedAt: sl.FetchedAt()}
	for _, c := range countries {
		cv := CountryView{Code: c.Code, Name: c.Name}
		for _, city := range c.Cities {
			cityV := CityView{Code: city.Code, Name: city.Name}
			for _, srv := range city.Servers {
				cityV.Hosts = append(cityV.Hosts, HostView{
					Hostname:    srv.Hostname,
					Port:        srv.Port,
					Quarantined: srv.Quarantined,
				})
			}
			cv.Cities = append(cv.Cities, cityV)
		}
		view.Countries = append(view.Countries, cv)
	}
	return view, nil
}

// SetLocation applies a validated desired location IN MEMORY and kicks one
// supervision cycle. Persistence of b4.json belongs to the generic config
// API (the GUI saves it there); this endpoint answers with the fresh status.
// Review F10: the rebuild is ADMINISTRATIVE — it bypasses the automatic
// restart cap so seven location changes per hour cannot brick the switch.
func (r *Runtime) SetLocation(loc config.FxVPNLocation) {
	r.mu.Lock()
	r.cfg.Location = loc
	r.adminRebuild = true
	// Force rebuild on next ensure: retire current session descriptor.
	if s := r.session; s != nil {
		_ = s.Close()
	}
	r.session = nil
	r.mu.Unlock()
}

// ValidateLocation checks a requested location against the cached list.
func (r *Runtime) ValidateLocation(ctx context.Context, loc config.FxVPNLocation) error {
	switch strings.ToLower(loc.Mode) {
	case "", "auto":
		return nil
	case "country":
		if strings.TrimSpace(loc.Country) == "" {
			return errors.New("country required for mode=country")
		}
	case "host":
		if strings.TrimSpace(loc.Host) == "" {
			return errors.New("host required for mode=host")
		}
	default:
		return fmt.Errorf("mode %q invalid (auto|country|host)", loc.Mode)
	}
	sl, err := r.serverlist()
	if err != nil {
		return err
	}
	countries, _, gerr := sl.Get(ctx)
	if gerr != nil {
		return gerr
	}
	switch strings.ToLower(loc.Mode) {
	case "country":
		for _, c := range countries {
			if strings.EqualFold(c.Code, loc.Country) {
				if loc.City == "" {
					return nil
				}
				for _, city := range c.Cities {
					if strings.EqualFold(city.Code, loc.City) {
						return nil
					}
				}
				return fmt.Errorf("city %q not found in %s", loc.City, loc.Country)
			}
		}
		return fmt.Errorf("country %q not in cached list", loc.Country)
	case "host":
		if _, ok := fxvpn.FindHost(countries, loc.Host); !ok {
			return fmt.Errorf("host %q not in cached list", loc.Host)
		}
	}
	return nil
}

// TestAccountInput is the accounts/test payload (Дополнение 3).
type TestAccountInput struct {
	Email        string `json:"email"`
	Password     string `json:"password,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Label        string `json:"label,omitempty"`
}

// TestAccountResult reports the credential check WITHOUT touching tunnels.
type TestAccountResult struct {
	OK         bool   `json:"ok"`
	NeedsCode  bool   `json:"needs_code,omitempty"`
	Error      string `json:"error,omitempty"`
	Class      string `json:"class,omitempty"`
	QuotaLeft  string `json:"quota_left,omitempty"`
	QuotaMax   string `json:"quota_max,omitempty"`
	QuotaReset string `json:"quota_reset,omitempty"`
	Subscribed *bool  `json:"subscribed,omitempty"`
}

// TestAccount checks credentials end-to-end through the RUNTIME control
// plane (same pins/jar/exit - challenge discipline) but never opens a
// data-plane session. Password-only logins that demand the emailed code
// answer needs_code=true instead of failing.
func (r *Runtime) TestAccount(ctx context.Context, in TestAccountInput) TestAccountResult {
	res := TestAccountResult{}
	var access string
	switch {
	case strings.TrimSpace(in.RefreshToken) != "":
		tok, err := r.poolRefreshForTest(ctx, in.RefreshToken)
		if err != nil {
			res.Error, res.Class = short(err), fxvpn.Classify(err)
			return res
		}
		access = tok
	case strings.TrimSpace(in.Password) != "":
		fxa := &fxvpn.FXA{CP: r.cp}
		login, err := fxa.Login(ctx, in.Email, in.Password)
		if err != nil {
			res.Error, res.Class = short(err), fxvpn.Classify(err)
			return res
		}
		if !login.Verified {
			res.NeedsCode = true
			res.OK = true // credentials accepted; code pending
			return res
		}
		tok, terr := fxa.OAuthToken(ctx, login.SessionToken)
		if terr != nil {
			res.Error, res.Class = short(terr), fxvpn.Classify(terr)
			return res
		}
		access = tok.AccessToken
	default:
		res.Error = "either refresh_token or password required"
		return res
	}

	g := &fxvpn.Guardian{CP: r.cp}
	pass, perr := g.FetchProxyPass(ctx, access)
	if perr != nil {
		var ti *fxvpn.TokenInvalidError
		if errors.As(perr, &ti) {
			if _, aerr := g.Activate(ctx, access); aerr == nil {
				pass, perr = g.FetchProxyPass(ctx, access)
			}
		}
		if perr != nil {
			res.Error, res.Class = short(perr), fxvpn.Classify(perr)
			return res
		}
	}
	res.OK = true
	res.QuotaLeft, res.QuotaMax, res.QuotaReset = pass.QuotaLeft, pass.QuotaMax, pass.QuotaReset
	if ent, serr := g.FetchUserInfo(ctx, access); serr == nil {
		res.Subscribed = &ent.Subscribed
	}
	return res
}

func (r *Runtime) poolRefreshForTest(ctx context.Context, rt string) (string, error) {
	tok, err := (&fxvpn.FXA{CP: r.cp}).RefreshToken(ctx, rt)
	if err != nil {
		return "", err
	}
	return tok.AccessToken, nil
}

// ---- supervisor + dial internals -------------------------------------------------

func (r *Runtime) now() time.Time { return time.Now() }

func (r *Runtime) serverlist() (*fxvpn.ServerlistCache, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sl == nil {
		sl, err := fxvpn.NewServerlistCache(r.cp, siblingPath(r.cfg.AccountsPath, "serverlist.json"))
		if err != nil {
			return nil, err
		}
		r.sl = sl
	}
	return r.sl, nil
}

func (r *Runtime) appendEvent(ev fxvpn.PoolEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	if len(r.events) > eventsRingCap {
		r.events = r.events[len(r.events)-eventsRingCap:]
	}
}

func (r *Runtime) noteFailure(class string) {
	if class == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastFailure = class
}

func (r *Runtime) atomicOK()   { r.recordDial(true) }
func (r *Runtime) atomicFail() { r.recordDial(false) }

// ---- small helpers ---------------------------------------------------------------

// classifyServiceErr maps service-level errors onto taxonomy classes.
func classifyServiceErr(err error) string {
	switch {
	case errors.Is(err, fxvpn.ErrPoolBlocked):
		return fxvpn.ClassQuotaExhausted
	case errors.Is(err, fxvpn.ErrNoServers):
		return fxvpn.ClassNoServerForLocation
	case errors.Is(err, fxvpn.ErrPinMismatch):
		return fxvpn.ClassAPIPinMismatch
	default:
		return fxvpn.Classify(err)
	}
}

func hostOf(hostport string) string {
	h, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return ""
	}
	return h
}

func short(err error) string {
	s := err.Error()
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
