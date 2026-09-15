// Package torservice assembles the E-TOR reserve tunnel (design
// tor-reserve-design.md): the external C-tor process supervised over the
// control protocol, the in-process PT proxy, the egress bridge, the bridge
// collection conveyor and the entry ladder, behind the reserve.Carrier
// contract (kind "tor", priority 5 — strictly the carrier of last resort).
//
// Service-level canon (protonservice/fxvpservice shape): Build wires
// components without touching the network; Start launches the supervisor
// tick; the states are honest (idle → binary-missing → bridges-wait →
// starting → bootstrapping → established, rotating/backoff on the sides);
// `enabled=false` is a complete no-op (zero goroutines, zero listeners —
// the caller never even Builds). Tor death NEVER tears the carrier
// registry entry down abruptly: Unregister happens at Stop, by design.
package torservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/dns"
	"github.com/daniellavrushin/b4/packetmark"
	"github.com/daniellavrushin/b4/transport/tor"
	"github.com/daniellavrushin/b4/transport/torsnowflake"
)

// Service-level constants (design §8).
const (
	superviseTick = 30 * time.Second
	eventsRingCap = 32

	// Liveness cadence (design §4.4): SOCKS5 CONNECT through tor every
	// 60s; 2 failures → SIGNAL ACTIVE + NEWNYM; 4 failures + 30s →
	// teardown + restart from the last working entry.
	livenessInterval    = 60 * time.Second
	livenessNEWNYMAfter = 2
	livenessTeardownAt  = 4
	livenessGrace       = 30 * time.Second

	// Exit probe cadence: never more often than 30 min.
	exitProbeInterval = 30 * time.Minute

	// Bridge strikes (design §8.3): 2 strikes → 300s cooldown.
	bridgeStrikeThreshold = 2
	bridgeStrikeCooldown  = 300 * time.Second

	// Sequential-ladder order (design §2: measured RF passability).
	ladderWebtunnel = "webtunnel"
	ladderObfs4     = "obfs4"
	ladderSnowflake = "snowflake"
	ladderVanilla   = "vanilla"
)

// LadderOrder is the auto-mode sequential pass order (measured RF
// passability, design §2 — webtunnel first, obfs4 never the head).
var LadderOrder = []string{ladderWebtunnel, ladderObfs4, ladderSnowflake, ladderVanilla}

// ProcessController abstracts the supervised tor process (tests: a
// controllable fake; production: *tor.ProcessHandle).
type ProcessController interface {
	PID() int
	Death() <-chan tor.ProcessDeath
	Stop(ctx context.Context, ctl tor.ControlClient)
}

// Options carries the test seams (nils get production defaults).
type Options struct {
	// Now injects the clock.
	Now func() time.Time
	// Spawn replaces the process spawn (fake-tor stand). nil = tor.SpawnTor.
	Spawn func(ctx context.Context, binaryPath, torrcPath, dataPath string) (ProcessController, error)
	// DialControl replaces the control connection (fake control scripts).
	DialControl func(ctx context.Context, network, addr string) (tor.ControlClient, error)
	// LivenessProbe replaces the SOCKS5-through-tor liveness check.
	LivenessProbe func(ctx context.Context, socksAddr string) error
	// ExitProbe replaces the check.torproject.org/api/ip probe through tor.
	ExitProbe func(ctx context.Context, socksAddr string) (ExitInfo, error)
	// Resolve overrides the DoH hostname resolver for the egress dialer.
	Resolve tor.ResolveFunc
	// SuperviseTick overrides the 30s cadence (tests). <=0 keeps default.
	SuperviseTick time.Duration
	// Bootstrap windows override (tests).
	Bootstrap tor.BootstrapConfig
	// CollectorFactory overrides the bridge conveyor construction (tests
	// inject httptest-only collectors — the consent rule: no live mirror
	// requests from unit tests). nil = the production conveyor.
	CollectorFactory func(store *tor.BridgesStore, dial tor.ProbeDial, now func() time.Time) *tor.Collector
}

// ExitInfo is the exit-probe observation.
type ExitInfo struct {
	IP      string `json:"ip,omitempty"`
	Country string `json:"country,omitempty"`
	IsTor   bool   `json:"is_tor"`
}

// State names (design §8.1).
const (
	StateIdle          = "idle"
	StateBinaryMissing = "binary-missing"
	StateBridgesWait   = "bridges-wait"
	StateStarting      = "starting"
	StateBootstrapping = "bootstrapping"
	StateEstablished   = "established"
	StateRotating      = "rotating"
	StateBackoff       = "backoff"
)

// Status is the API/status projection (TT8 consumes it).
type Status struct {
	Enabled    bool           `json:"enabled"`
	Running    bool           `json:"running"`
	Listening  bool           `json:"listening"`
	State      string         `json:"state"`
	Entry      EntryView      `json:"entry"`
	Bridges    BridgesView    `json:"bridges"`
	Bootstrap  BootstrapView  `json:"bootstrap"`
	Egress     EgressView     `json:"egress"`
	Exit       ExitView       `json:"exit"`
	Version    string         `json:"version,omitempty"`
	BaitActive bool           `json:"bait_active"`
	Events     []tor.TorEvent `json:"events,omitempty"`
	Hint       string         `json:"hint,omitempty"`
}

// EntryView projects the entry state.
type EntryView struct {
	Mode   string `json:"mode"`
	Active string `json:"active,omitempty"`
	Winner string `json:"winner,omitempty"`
}

// BridgesView projects the bridge set.
type BridgesView struct {
	Alive        int            `json:"alive"`
	ByTransport  map[string]int `json:"by_transport,omitempty"`
	FreshUntilMS int64          `json:"fresh_until_ms,omitempty"`
	Source       string         `json:"source,omitempty"`
	LastError    string         `json:"last_error,omitempty"`
}

// BootstrapView projects the bootstrap progress.
type BootstrapView struct {
	Progress int    `json:"progress"`
	Tag      string `json:"tag,omitempty"`
}

// EgressView projects the egress policy.
type EgressView struct {
	Through string `json:"through"`
	Bait    string `json:"bait_profile"`
}

// ExitView projects the last exit probe.
type ExitView struct {
	IP        string `json:"ip,omitempty"`
	Country   string `json:"country,omitempty"`
	IsTor     bool   `json:"is_tor"`
	CheckedAt string `json:"checked_at,omitempty"`
}

// Runtime is the assembled E-TOR service.
type Runtime struct {
	cfg  config.TorConfig
	opts Options

	store     *tor.BridgesStore
	entryMem  *tor.EntryMemory
	collector *tor.Collector
	dialer    *tor.Dialer

	egressBridge *tor.EgressBridge
	ptProxy      *tor.PTProxy
	snowflake    *torsnowflake.SnowflakeAdapter
	hostResolve  tor.ResolveFunc

	mu            sync.Mutex
	ctx           context.Context
	cancel        context.CancelFunc
	loopDone      chan struct{}
	running       bool
	stopped       bool
	state         string
	hint          string
	entry         string // current attempt entry
	activeSet     []tor.Bridge
	entryIdx      int // sequential pass position
	mixedTried    bool
	winner        string
	proc          ProcessController
	ctl           tor.ControlClient
	socksAddr     string
	bootstrap     tor.BootstrapPhase
	livenessFails int
	lastLiveness  time.Time
	newnymSent    bool
	lastExitProbe time.Time
	exit          ExitInfo
	exitAt        time.Time
	version       string
	confluxDone   bool
	strikes       map[string]int
	strikeUntil   map[string]time.Time
	restarts      []time.Time
	cooldown      time.Time
	events        []tor.TorEvent
	// scanning/nextScanAt gate the background relay scan (6h freshness).
	scanning   bool
	nextScanAt time.Time
	collecting bool
	// collectDone signals the async conveyor pass completion (Stop waits
	// on it so a temp-dir teardown never races an in-flight collection).
	collectDone     chan struct{}
	lastCollectFail string
}

// Build assembles the runtime (no network, no listeners yet — the honest
// disabled canon: the caller never Builds when !Enabled).
func Build(cfg *config.Config, opts Options) (*Runtime, error) {
	tc := cfg.System.Tor
	if !tc.Enabled {
		return nil, errors.New("torservice: build called with tor disabled")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.SuperviseTick <= 0 {
		opts.SuperviseTick = superviseTick
	}
	dataPath := tc.EffectiveDataPath()
	binaryPath := tc.EffectiveBinaryPath()

	store := tor.NewBridgesStore(dataPath)
	entryMem := tor.NewEntryMemory(dataPath)

	r := &Runtime{
		cfg:         tc,
		opts:        opts,
		store:       store,
		entryMem:    entryMem,
		state:       StateIdle,
		strikes:     map[string]int{},
		strikeUntil: map[string]time.Time{},
	}

	// The egress dialer: policies + self-loop set built at start (the
	// listeners do not exist yet).
	r.dialer = tor.NewDialer(tor.EgressPolicy{
		Through:     tc.EffectiveEgressThrough(),
		BaitProfile: tc.EffectiveBaitProfile(),
		Now:         opts.Now,
	}, nil, opts.Resolve, nil)
	if opts.Resolve == nil {
		r.hostResolve = torDoHResolve(opts.Now)
		r.dialer = tor.NewDialer(tor.EgressPolicy{
			Through:     tc.EffectiveEgressThrough(),
			BaitProfile: tc.EffectiveBaitProfile(),
			Now:         opts.Now,
		}, nil, r.hostResolve, nil)
	} else {
		r.hostResolve = opts.Resolve
	}

	// The collector over the egress dialer (bootstrap-source class for
	// its HTTP legs, probe class for the liveness dials).
	dial := func(ctx context.Context, class tor.ConnClass, host string, port uint16) (net.Conn, error) {
		return r.dialer.Dial(ctx, class, host, port)
	}
	if opts.CollectorFactory != nil {
		r.collector = opts.CollectorFactory(store, dial, opts.Now)
	} else {
		r.collector = tor.NewCollector(tor.CollectorOptions{
			Store: store,
			Dial:  dial,
			Now:   opts.Now,
		})
	}

	// The binary pre-check runs in PRODUCTION only (tests inject Spawn —
	// their stands are not binaries on disk). The honest binary-missing
	// state comes from the stat OR from the spawn failure, never an error
	// at Build (design §8.1).
	if opts.Spawn == nil {
		if _, err := os.Stat(binaryPath); err != nil {
			r.state = StateBinaryMissing
			r.hint = "opkg install tor (Entware) or set system.tor.binary_path"
		}
	}
	return r, nil
}

// torDoHResolve builds the production DoH resolver on the tor egress mark
// (the dns package imports classifier→config: wired HERE, not in the
// transport layer).
func torDoHResolve(now func() time.Time) tor.ResolveFunc {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		client := dns.MarkedDoHClient(int(packetmark.MarkTorEgress), 8*time.Second)
		defer client.CloseIdleConnections()
		var lastErr error
		for _, srv := range tor.DefaultEgressDoHServers {
			query := dns.BuildQuery(host, 0, 1) // A
			body, err := dns.ResolveDoH(ctx, client, srv, query)
			if err != nil {
				lastErr = err
				continue
			}
			ips := dns.ParseResponseIPs(body)
			out := make([]netip.Addr, 0, len(ips))
			for _, ip := range ips {
				if a, err := netip.ParseAddr(ip.String()); err == nil {
					out = append(out, a)
				}
			}
			if len(out) > 0 {
				return out, nil
			}
		}
		if lastErr == nil {
			lastErr = errors.New("no A records")
		}
		return nil, lastErr
	}
}

// Start launches the supervisor (idempotent).
func (r *Runtime) Start(ctx context.Context) error {
	if err := r.startListeners(ctx); err != nil {
		return err
	}
	r.mu.Lock()
	r.loopDone = make(chan struct{})
	r.mu.Unlock()
	go r.loop(r.ctx)
	r.appendEvent(tor.TorEvent{Name: tor.EventTorStarted, At: r.opts.Now()})
	return nil
}

// startListeners wires the loopback components WITHOUT the supervisor
// goroutine (tests drive ensure() directly for determinism; production
// Start adds the loop on top).
func (r *Runtime) startListeners(ctx context.Context) error {
	r.mu.Lock()
	if r.stopped || r.running {
		r.mu.Unlock()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.ctx = runCtx
	r.cancel = cancel
	r.running = true
	if r.state == StateIdle {
		r.state = StateStarting
	}
	// wire the loopback listeners (fail-closed: no listeners, no run)
	eb, err := tor.NewEgressBridge(r.dialer, func() []string {
		r.mu.Lock()
		defer r.mu.Unlock()
		var out []string
		for _, b := range r.activeSet {
			if b.Transport == "vanilla" {
				out = append(out, b.AddrPort)
			}
		}
		return out
	})
	if err != nil {
		cancel()
		r.running = false
		r.mu.Unlock()
		return fmt.Errorf("torservice: egress bridge: %w", err)
	}
	r.egressBridge = eb

	// PT proxy: snowflake adapter + hooks (process-global, owned here)
	r.snowflake = torsnowflake.NewSnowflakeAdapter(
		func(ctx context.Context, class tor.ConnClass, host string, port uint16) (net.Conn, error) {
			return r.dialer.Dial(ctx, class, host, port)
		}, torEgressMarkControl())
	registry := tor.NewPTRegistry(r.snowflake)
	pp, err := tor.NewPTProxy(registry, func() []tor.Bridge {
		r.mu.Lock()
		defer r.mu.Unlock()
		return append([]tor.Bridge(nil), r.activeSet...)
	}, func(ctx context.Context, class tor.ConnClass, host string, port uint16) (net.Conn, error) {
		return r.dialer.Dial(ctx, class, host, port)
	})
	if err != nil {
		eb.Stop()
		cancel()
		r.running = false
		r.mu.Unlock()
		return fmt.Errorf("torservice: pt proxy: %w", err)
	}
	r.ptProxy = pp

	// self-loop guard: egress bridge + PT proxy listeners
	loopSet := func() []string {
		var out []string
		if r.egressBridge != nil {
			out = append(out, r.egressBridge.LoopAddr())
		}
		if r.ptProxy != nil {
			out = append(out, r.ptProxy.LoopAddr())
		}
		if r.socksAddr != "" {
			out = append(out, r.socksAddr)
		}
		return out
	}
	r.dialer.SetLoops(loopSet)

	r.mu.Unlock()
	return nil
}

// Stop tears everything down in reverse start order (PT proxy after the
// process; the registry Unregister happens in the caller BEFORE Stop —
// design §9.3).
func (r *Runtime) Stop() {
	r.mu.Lock()
	if !r.running || r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	cancel := r.cancel
	proc := r.proc
	ctl := r.ctl
	eb := r.egressBridge
	pp := r.ptProxy
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if r.loopDone != nil {
		select {
		case <-r.loopDone:
		case <-time.After(10 * time.Second): // bounded: a stuck ensure() must not hang Stop forever
		}
	}
	// an in-flight collection pass must finish before a temp-dir teardown
	r.mu.Lock()
	collectDone := r.collectDone
	r.mu.Unlock()
	if collectDone != nil {
		select {
		case <-collectDone:
		case <-time.After(10 * time.Second):
		}
	}
	if proc != nil {
		proc.Stop(context.Background(), ctl) // graded ladder
	}
	if ctl != nil {
		_ = ctl.Close()
	}
	if pp != nil {
		pp.Stop() // PT proxy dies after tor (reverse order)
	}
	if eb != nil {
		eb.Stop()
	}
}

// loop is the supervisor: ensureBridges → ensureProcess → ensureBootstrap
// → ensureLiveness → ensureExitProbe → ensureConflux → exportState, tick
// 30s (+ death wakeups).
func (r *Runtime) loop(ctx context.Context) {
	if r.loopDone != nil {
		defer close(r.loopDone)
	}
	tick := time.NewTicker(r.opts.SuperviseTick)
	defer tick.Stop()
	r.ensure(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			r.ensure(ctx)
		case <-r.deathCh():
			r.handleDeath(ctx)
		}
	}
}

func (r *Runtime) deathCh() <-chan tor.ProcessDeath {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.proc == nil {
		return nil
	}
	return r.proc.Death()
}

// ensure runs one supervision pass.
func (r *Runtime) ensure(ctx context.Context) {
	// the backoff gate: NOTHING runs while the restart cooldown holds —
	// the honest backoff (design §8.2); when it lapses the ladder resumes.
	r.mu.Lock()
	if r.state == StateBackoff {
		if r.opts.Now().Before(r.cooldown) {
			r.mu.Unlock()
			return
		}
		r.state = StateStarting
	}
	r.mu.Unlock()
	r.ensureBridges(ctx)
	r.ensureProcess(ctx)
	r.ensureBootstrap(ctx)
	r.ensureLiveness(ctx)
	r.ensureExitProbe(ctx)
	r.ensureConflux(ctx)
	r.ensureRelayScan(ctx)
	r.exportState()
}
