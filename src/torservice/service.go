// Package torservice assembles the E-TOR reserve tunnel (design
// tor-reserve-design.md): the external C-tor process supervised over the
// control protocol, the in-process PT proxy, the egress bridge, the bridge
// collection conveyor and the entry ladder, behind the reserve.Carrier
// contract (kind "tor", priority 5 — strictly the carrier of last resort).
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

const (
	superviseTick = 30 * time.Second
	eventsRingCap = 32

	livenessInterval    = 60 * time.Second
	livenessNEWNYMAfter = 2
	livenessTeardownAt  = 4
	livenessGrace       = 30 * time.Second

	exitProbeInterval = 30 * time.Minute

	bridgeStrikeThreshold = 2
	bridgeStrikeCooldown  = 300 * time.Second

	ladderWebtunnel = "webtunnel"
	ladderObfs4     = "obfs4"
	ladderSnowflake = "snowflake"
	ladderVanilla   = "vanilla"
)

var LadderOrder = []string{ladderWebtunnel, ladderObfs4, ladderSnowflake, ladderVanilla}

type ProcessController interface {
	PID() int
	Death() <-chan tor.ProcessDeath
	Stop(ctx context.Context, ctl tor.ControlClient)
}

type Options struct {
	Now           func() time.Time
	Spawn         func(ctx context.Context, binaryPath, torrcPath, dataPath string) (ProcessController, error)
	DialControl   func(ctx context.Context, network, addr string) (tor.ControlClient, error)
	LivenessProbe func(ctx context.Context, socksAddr string) error
	ExitProbe     func(ctx context.Context, socksAddr string) (ExitInfo, error)
	Resolve       tor.ResolveFunc
	SuperviseTick time.Duration
	Bootstrap     tor.BootstrapConfig
	CollectorFactory func(store *tor.BridgesStore, dial tor.ProbeDial, now func() time.Time) *tor.Collector
}

type ExitInfo struct {
	IP      string `json:"ip,omitempty"`
	Country string `json:"country,omitempty"`
	IsTor   bool   `json:"is_tor"`
}

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
	Resources  ResourceView   `json:"resources"`
	BaitActive bool           `json:"bait_active"`
	Events     []tor.TorEvent `json:"events,omitempty"`
	Hint       string         `json:"hint,omitempty"`
}

type EntryView struct {
	Mode         string `json:"mode"`
	Active       string `json:"active,omitempty"`
	Winner       string `json:"winner,omitempty"`
	WinnerBridge string `json:"winner_bridge,omitempty"`
}

type BridgesView struct {
	Alive        int            `json:"alive"`
	ByTransport  map[string]int `json:"by_transport,omitempty"`
	FreshUntilMS int64          `json:"fresh_until_ms,omitempty"`
	Source       string         `json:"source,omitempty"`
	LastError    string         `json:"last_error,omitempty"`
}

type BootstrapView struct {
	Progress int    `json:"progress"`
	Tag      string `json:"tag,omitempty"`
}

type EgressView struct {
	Through string `json:"through"`
	Bait    string `json:"bait_profile"`
}

type ExitView struct {
	IP        string `json:"ip,omitempty"`
	Country   string `json:"country,omitempty"`
	IsTor     bool   `json:"is_tor"`
	CheckedAt string `json:"checked_at,omitempty"`
}

// ResourceView is an honest platform envelope. Cross-compilation only proves
// buildability; these fields expose the runtime constraints that matter on a
// Keenetic/MIPS target.
type ResourceView struct {
	RSSBytes              uint64 `json:"rss_bytes,omitempty"`
	FDUsed                int    `json:"fd_used,omitempty"`
	FDLimit               uint64 `json:"fd_limit,omitempty"`
	LowMemory             bool   `json:"low_memory"`
	SnowflakeDirectPacket bool   `json:"snowflake_direct_packet"`
	ConfluxUX             string `json:"conflux_ux,omitempty"`
}

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

	mu        sync.Mutex
	ctx       context.Context
	cancel    context.CancelFunc
	loopDone  chan struct{}
	running   bool
	stopped   bool
	retiring  bool
	state     string
	hint      string
	entry     string
	activeSet []tor.Bridge
	entryIdx  int
	mixedTried bool
	winner       string
	winnerBridge string
	proc          ProcessController
	ctl           tor.ControlClient
	socksAddr     string
	bootstrap     tor.BootstrapPhase
	livenessFails     int
	lastLiveness      time.Time
	livenessDeadSince time.Time
	newnymSent        bool
	lastExitProbe time.Time
	exit          ExitInfo
	exitAt        time.Time
	version       string
	confluxDone   bool
	confluxUX     string
	strikes       map[string]int
	strikeUntil   map[string]time.Time
	restarts      []time.Time
	cooldown      time.Time
	events        []tor.TorEvent
	scanning      bool
	nextScanAt    time.Time
	collecting    bool
	collectDone     chan struct{}
	lastCollectFail string
}

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

	r.dialer = tor.NewDialer(tor.EgressPolicy{
		Through: tc.EffectiveEgressThrough(), BaitProfile: tc.EffectiveBaitProfile(), Now: opts.Now,
	}, nil, opts.Resolve, nil)
	if opts.Resolve == nil {
		r.hostResolve = torDoHResolve(opts.Now)
		r.dialer = tor.NewDialer(tor.EgressPolicy{
			Through: tc.EffectiveEgressThrough(), BaitProfile: tc.EffectiveBaitProfile(), Now: opts.Now,
		}, nil, r.hostResolve, nil)
	} else {
		r.hostResolve = opts.Resolve
	}

	dial := func(ctx context.Context, class tor.ConnClass, host string, port uint16) (net.Conn, error) {
		return r.dialer.Dial(ctx, class, host, port)
	}
	if opts.CollectorFactory != nil {
		r.collector = opts.CollectorFactory(store, dial, opts.Now)
	} else {
		r.collector = tor.NewCollector(tor.CollectorOptions{Store: store, Dial: dial, Now: opts.Now})
	}

	if opts.Spawn == nil {
		if _, err := os.Stat(binaryPath); err != nil {
			r.state = StateBinaryMissing
			r.hint = "opkg install tor (Entware) or set system.tor.binary_path"
		}
	}
	return r, nil
}

func torDoHResolve(now func() time.Time) tor.ResolveFunc {
	return func(ctx context.Context, host string) ([]netip.Addr, error) {
		client := dns.MarkedDoHClient(int(packetmark.MarkTorEgress), 8*time.Second)
		defer client.CloseIdleConnections()
		var lastErr error
		for _, srv := range tor.DefaultEgressDoHServers {
			query := dns.BuildQuery(host, 0, 1)
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

	allowSnowflakePacket := !tor.IsPinnedCarrierPolicy(r.cfg.EffectiveEgressThrough())
	r.snowflake = torsnowflake.NewSnowflakeAdapterPolicy(
		func(ctx context.Context, class tor.ConnClass, host string, port uint16) (net.Conn, error) {
			return r.dialer.Dial(ctx, class, host, port)
		}, torEgressMarkControl(), allowSnowflakePacket)
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

func (r *Runtime) Stop() {
	r.mu.Lock()
	if !r.running || r.stopped {
		r.mu.Unlock()
		return
	}
	r.stopped = true
	cancel := r.cancel
	eb := r.egressBridge
	pp := r.ptProxy
	r.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if r.loopDone != nil {
		select {
		case <-r.loopDone:
		case <-time.After(10 * time.Second):
		}
	}
	r.mu.Lock()
	collectDone := r.collectDone
	r.mu.Unlock()
	if collectDone != nil {
		select {
		case <-collectDone:
		case <-time.After(10 * time.Second):
		}
	}

	// One retirement path for final shutdown and all runtime restarts: never
	// discard the ProcessController before the owned C-Tor has stopped.
	r.retireCurrentProcess("service-stop")
	if pp != nil {
		pp.Stop()
	}
	if eb != nil {
		eb.Stop()
	}

	r.mu.Lock()
	r.running = false
	r.mu.Unlock()
}

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
	if r.proc == nil || r.retiring {
		return nil
	}
	return r.proc.Death()
}

func (r *Runtime) ensure(ctx context.Context) {
	r.mu.Lock()
	if r.state == StateBackoff {
		if r.opts.Now().Before(r.cooldown) {
			r.mu.Unlock()
			return
		}
		r.state = StateStarting
	}
	if r.retiring {
		r.mu.Unlock()
		return
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
