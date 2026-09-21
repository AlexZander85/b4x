// Package vlessservice assembles the dependency-free VLESS(+REALITY) reserve
// engine (src/transport/vless) from the main config — the deliberately-thin
// "last mile" mirroring operaservice.
//
// Integration contract (design .ag/research/vless-tunnel-design.md §5/§6):
//
//   - role kind "vless": a userspace, TCP-only carrier. Consumers take
//     Runtime.DialStream and the scoped router treats it like every other
//     userspace carrier (routing.tunnel="vless").
//
//   - two speakers: the EXTERNAL helper's local SOCKS5 (client=helper) or the
//     in-process VLESS client (client=in-process, §8 V4: raw/tcp+tls+reality,
//     ws/httpupgrade). "auto" prefers in-process when a capable node exists.
//
//   - nodes come from inline config, the last-good disk cache (offline) and
//     the subscription refresh loop (bundled aggregators + own URLs).
//
//   - anti-loop: DialStream refuses dialing a configured node through itself.
//
//   - UDP fail-closed: SupportsUDP()==false and DialUDP returns
//     reserve.ErrCarrierNoUDP (UDP ASSOCIATE is a later phase).
package vlessservice

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/internal/socks"
	"github.com/daniellavrushin/b4/socks5"
	"github.com/daniellavrushin/b4/transport/vless"
)

// DialFunc is the base TCP dial shape shared with the other services.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// ErrVlessSelfLoop is returned when a consumer asks the vless tunnel to carry
// traffic addressed to one of its own configured nodes.
var ErrVlessSelfLoop = errors.New("vlessservice: refusing self-loop through the vless tunnel")

// Options assembles the runtime; zero values are valid.
type Options struct {
	// SocksDial overrides the SOCKS5 dialer built from system.vless.socks_addr
	// (tests / custom egress).
	SocksDial DialFunc
	// Nodes overrides the loaded inline node set (tests). nil => parse cfg.Nodes.
	Nodes []vless.Node
	// Carrier is the base-transport dial used for node dials (in-process
	// bootstrap-through-carrier) and for fetching subscriptions when the direct
	// egress is blocked (operaservice.BaseCarrierDial shape).
	Carrier DialFunc
	// HTTPClient overrides the subscription fetcher (tests).
	HTTPClient *http.Client
}

// Runtime owns one assembled VLESS transport for a config generation.
type Runtime struct {
	cfg        config.VLESSConfig
	socksDial  DialFunc // helper path: the helper's SOCKS5 inbound
	base       DialFunc // base-transport dial (bootstrap-through-carrier)
	httpClient *http.Client
	ring       *eventRing
	// helper is the supervised external helper process (V2). nil when the
	// helper is not managed (external operator / missing binary).
	helper *vless.Helper
	// helperKind is the helper dialect (for renderability checks; b4x-d0fw).
	helperKind vless.HelperKind
	// selector probes candidates and picks the active node (V2 seek + loc).
	selector *vless.Selector
	// stats is the persistent per-node outcome memory (b4x-d0fw).
	stats *vless.StatsStore

	// helperMu serialises render+start/restart of the managed helper.
	helperMu sync.Mutex
	// renderMu guards rendered, the identity of the node the helper last ran.
	renderMu sync.Mutex
	rendered string

	mu          sync.RWMutex
	inline      []vless.Node
	fetched     []vless.Node
	sourceState map[string]vless.SourceState
	sourcesRaw  []string
	sourcesRed  []string
	lastRefresh time.Time
	lastErr     string

	lifeMu  sync.Mutex
	started bool
	stopped bool
	cancel  context.CancelFunc
}

// Build validates the system.vless section and constructs the runtime WITHOUT
// network I/O or goroutines. It succeeds even when Enabled=false so the daemon
// gates on config itself (operaservice/warpservice parity).
func Build(cfg *config.Config, opts Options) (*Runtime, error) {
	vc := cfg.System.Vless.WithDefaults()
	helper, err := vless.NormalizeHelper(vc.Helper)
	if err != nil {
		return nil, fmt.Errorf("vlessservice: system.vless.helper: %w", err)
	}
	inline := opts.Nodes
	if inline == nil && len(vc.Nodes) > 0 {
		parsed, _ := vless.ParseMany(vc.Nodes)
		inline = parsed
	}
	// Last-good online asset (offline startup parity), including the per-source
	// ETag/Last-Modified state for the next conditional GET.
	var fetched []vless.Node
	var bySource map[string]vless.SourceState
	if cache, cerr := vless.LoadNodeCache(vc.EffectiveNodeCachePath()); cerr != nil {
		// A corrupt cache is not fatal: start empty and let refresh rebuild it.
		fetched = nil
	} else if cache != nil {
		fetched = cache.Nodes
		bySource = cache.BySource
	}
	nodes := vless.MergeNodes(inline, fetched)

	sources := vless.ResolveSources(vc.BundledSourcesEnabled(), vc.Subscriptions)
	mode := strings.ToLower(strings.TrimSpace(vc.Client))
	if mode == "" {
		mode = config.VLESSClientAuto
	}
	if mode == config.VLESSClientInProcess && firstInProcessNode(nodes) == nil && len(sources) == 0 {
		return nil, fmt.Errorf("vlessservice: client=in-process but no node uses an in-process transport and no subscriptions are configured")
	}

	var socksDial DialFunc = opts.SocksDial
	var socksErr error
	if socksDial == nil {
		if d, derr := socks.DialFunc(vc.SocksAddr); derr != nil {
			socksErr = derr
		} else {
			socksDial = d
		}
	}
	if socksErr != nil && mode != config.VLESSClientInProcess {
		return nil, fmt.Errorf("vlessservice: system.vless.socks_addr: %w", socksErr)
	}

	var helperProc *vless.Helper
	if vc.ManageHelper() && helper != vless.HelperExternal {
		bin := strings.TrimSpace(vc.HelperPath)
		if bin == "" {
			if p, lerr := exec.LookPath(helperBinaryName(helper)); lerr == nil {
				bin = p
			}
		}
		if bin != "" {
			dir := filepath.Dir(vc.IdentityPath)
			helperProc = vless.NewHelper(vless.HelperSpec{
				Kind:       helper,
				BinPath:    bin,
				ConfigPath: filepath.Join(dir, "helper-"+string(helper)+".json"),
				LogPath:    filepath.Join(dir, "helper-"+string(helper)+".log"),
				SocksAddr:  vc.SocksAddr,
				UDP:        vc.UDP,
				Mixed:      vc.Mixed,
			})
		}
	}

	statsPath := filepath.Join(filepath.Dir(vc.EffectiveNodeCachePath()), "stats.json")
	statsStore, _ := vless.LoadStats(statsPath) // missing/corrupt -> empty, never fatal

	rt := &Runtime{
		cfg:         vc,
		socksDial:   socksDial,
		base:        opts.Carrier,
		httpClient:  opts.HTTPClient,
		ring:        newEventRing(64),
		helper:      helperProc,
		helperKind:  helper,
		stats:       statsStore,
		inline:      inline,
		fetched:     fetched,
		sourceState: bySource,
		sourcesRaw:  sources,
	}
	rt.sourcesRed = redactAll(sources)
	prober := &vless.Prober{
		Stream:     rt.streamToNode,
		ServerName: "one.one.one.one",
		Insecure:   true, // trace target is a literal IP; geo is what matters
		Timeout:    8 * time.Second,
	}
	rt.selector = vless.NewSelector(vless.SeekConfig{
		Interval:     time.Duration(vc.SeekIntervalSec) * time.Second,
		Tolerance:    time.Duration(vc.SeekToleranceMs) * time.Millisecond,
		PreferNonRU:  vc.PreferNonRUEnabled(),
		CountryAllow: vc.CountryAllow,
		CountryDeny:  vc.CountryDeny,
		MaxParallel:  4,
		Pin:          vc.PinNode,
	}, prober)
	rt.selector.Stats = statsStore
	rt.selector.OnChange = rt.onActiveChange
	rt.selector.OnReady = rt.onActiveChange
	rt.ring.push("info", "assembled", fmt.Sprintf("client=%s helper=%s socks=%s nodes=%d sources=%d",
		mode, helper, vc.SocksAddr, len(nodes), len(sources)))
	if vc.ManageHelper() && helper != vless.HelperExternal && helperProc == nil {
		rt.ring.push("warn", "helper_binary_missing",
			fmt.Sprintf("helper %s not found; set system.vless.helper_path", helper))
	}
	return rt, nil
}

// helperBinaryName is the default PATH binary per helper kind.
func helperBinaryName(kind vless.HelperKind) string {
	switch kind {
	case vless.HelperSingbox:
		return "sing-box"
	case vless.HelperXray:
		return "xray"
	default:
		return ""
	}
}

// ensureHelper renders the helper config and spawns the helper on the
// selector's chosen node (or the first renderable one before the first probe),
// then waits for its SOCKS5 inbound. Safe to call repeatedly (idempotent).
func (r *Runtime) ensureHelper(ctx context.Context) {
	if r.helper == nil {
		return
	}
	node, ok := r.helperNode()
	if !ok {
		r.ring.push("warn", "helper_config", "no helper-renderable node")
		return
	}
	r.applyHelperNode(ctx, node)
}

// helperNode picks the node the managed helper should run: the selector's
// active choice when one exists, otherwise the first renderable candidate.
func (r *Runtime) helperNode() (vless.Node, bool) {
	if r.selector != nil {
		if a, ok := r.selector.Active(); ok {
			return a, true
		}
	}
	for _, n := range r.allNodes() {
		if _, err := vless.RenderWith(r.helperKind, n, vless.RenderOptions{SocksAddr: r.cfg.SocksAddr}); err == nil {
			return n, true
		}
	}
	return vless.Node{}, false
}

// applyHelperNode renders n and (re)starts the managed helper on it. A repeat
// for the node the helper already runs is a no-op.
func (r *Runtime) applyHelperNode(ctx context.Context, n vless.Node) {
	r.helperMu.Lock()
	defer r.helperMu.Unlock()
	if r.helper == nil {
		return
	}
	if r.renderedIdentity() == n.Identity() && r.helper.Status().Running {
		return
	}
	if err := r.helper.RenderWrite(n); err != nil {
		r.ring.push("warn", "helper_config", err.Error())
		return
	}
	r.setRenderedIdentity(n.Identity())
	if r.helper.Status().Running {
		if err := r.helper.Restart(ctx); err != nil {
			r.ring.push("warn", "helper_restart", err.Error())
			return
		}
	} else if err := r.helper.Start(ctx); err != nil {
		r.ring.push("warn", "helper_start", err.Error())
		return
	}
	if err := r.helper.WaitReady(ctx); err != nil {
		r.ring.push("warn", "helper_ready", err.Error())
		return
	}
	r.ring.push("info", "helper_ready", r.cfg.SocksAddr)
}

func (r *Runtime) renderedIdentity() string {
	r.renderMu.Lock()
	defer r.renderMu.Unlock()
	return r.rendered
}

func (r *Runtime) setRenderedIdentity(id string) {
	r.renderMu.Lock()
	r.rendered = id
	r.renderMu.Unlock()
}

func redactAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, vless.RedactURL(s))
	}
	return out
}

// Start arms the carrier and, when sources are configured, launches the
// subscription refresh loop. The config gate (system.vless.enabled) belongs to
// the caller.
func (r *Runtime) Start(ctx context.Context) error {
	r.lifeMu.Lock()
	if r.stopped {
		r.lifeMu.Unlock()
		return errors.New("vlessservice: runtime already stopped")
	}
	if r.started {
		r.lifeMu.Unlock()
		return nil
	}
	runCtx, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	r.started = true
	r.lifeMu.Unlock()

	r.mu.RLock()
	sources := append([]string(nil), r.sourcesRaw...)
	r.mu.RUnlock()
	if len(sources) > 0 {
		go r.refreshLoop(runCtx, sources)
	}
	if r.helper != nil {
		go r.ensureHelper(runCtx)
	}
	if r.selector != nil {
		r.selector.SetNodes(r.dialableNodes())
		go r.selector.Run(runCtx)
	}
	r.ring.push("info", "started", fmt.Sprintf("vless carrier armed (client=%s, sources=%d)", r.effectiveMode(), len(sources)))
	return nil
}

// streamToNode opens a raw stream to target through one node using the path
// that node would actually be dialed with (in-process when capable, else the
// helper's SOCKS5).
func (r *Runtime) streamToNode(ctx context.Context, n vless.Node, target netip.AddrPort) (net.Conn, error) {
	// Probe the candidate ITSELF. The in-process client carries raw/tcp, ws and
	// httpupgrade, so the selector ranks those candidates directly even when the
	// carrier ships traffic through the external helper (b4x-d0fw): otherwise
	// every probe would ride the active helper node and rank nothing.
	if vless.SupportsInProcess(n) {
		return (&vless.Dialer{Node: n, Base: r.base}).Dial(ctx, target)
	}
	if r.socksDial == nil {
		return nil, errors.New("vlessservice: no dialer for probe")
	}
	return r.socksDial(ctx, "tcp", target.String())
}

// dialableNodes restricts the candidate set to what the current mode can dial.
func (r *Runtime) dialableNodes() []vless.Node {
	nodes := r.allNodes()
	if r.modeFor(nodes) == config.VLESSClientHelper {
		return nodes
	}
	out := make([]vless.Node, 0, len(nodes))
	for _, n := range nodes {
		if vless.SupportsInProcess(n) {
			out = append(out, n)
		}
	}
	return out
}

// onActiveChange reacts to a selection change: the in-process path picks it up
// on the next dial; a managed helper is re-rendered and restarted.
func (r *Runtime) onActiveChange(n vless.Node) {
	r.ring.push("info", "node_rotate", activeAddr(&n))
	if r.helper == nil {
		return
	}
	go r.applyHelperNode(context.Background(), n)
}

// Stop tears the runtime down (no-op before Start).
func (r *Runtime) Stop() {
	r.lifeMu.Lock()
	defer r.lifeMu.Unlock()
	if !r.started || r.stopped {
		return
	}
	r.stopped = true
	if r.cancel != nil {
		r.cancel()
	}
	if r.helper != nil {
		r.helper.Stop()
	}
	r.ring.push("info", "stopped", "vless carrier stopped")
}

// refreshLoop runs the initial fetch and then re-fetches on the configured
// interval with +/-10% jitter (conditional-GET/ETag is a later refinement).
func (r *Runtime) refreshLoop(ctx context.Context, sources []string) {
	_ = r.refreshOnce(ctx, sources)
	interval := time.Duration(r.cfg.SubscriptionIntervalSec) * time.Second
	if interval < time.Minute {
		interval = time.Minute
	}
	span := int64(interval / 5)
	for {
		jitter := time.Duration(0)
		if span > 0 {
			jitter = time.Duration(rand.Int63n(span+1)) - interval/10
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval + jitter):
			_ = r.refreshOnce(ctx, sources)
		}
	}
}

// RefreshOnce runs one refresh pass now (HTTP manual-refresh / tests).
func (r *Runtime) RefreshOnce(ctx context.Context) error {
	r.mu.RLock()
	sources := append([]string(nil), r.sourcesRaw...)
	r.mu.RUnlock()
	if len(sources) == 0 {
		return nil
	}
	return r.refreshOnce(ctx, sources)
}

func (r *Runtime) refreshOnce(ctx context.Context, sources []string) error {
	rep := vless.RefreshWithState(ctx, r.httpClientOrDefault(), sources, r.sourceStateSnapshot(), vless.MaxNodes)
	r.mu.Lock()
	r.fetched = rep.Nodes
	r.sourceState = rep.BySource
	r.lastRefresh = rep.UpdatedAt
	r.lastErr = vless.SummarizeFailed(rep.Failed)
	r.mu.Unlock()

	cache := &vless.NodeCache{Nodes: rep.Nodes, Sources: rep.Sources, BySource: rep.BySource, UpdatedAt: rep.UpdatedAt}
	if err := cache.Save(r.cfg.EffectiveNodeCachePath()); err != nil {
		r.ring.push("warn", "cache_save", err.Error())
	}
	r.ring.push("info", "refresh", fmt.Sprintf("nodes=%d ok_sources=%d failed=%d",
		len(rep.Nodes), len(rep.Sources), len(rep.Failed)))
	if r.helper != nil {
		// A managed helper needs a node to render; start it once refresh has
		// produced a renderable one (idempotent if already running).
		go r.ensureHelper(ctx)
	}
	if r.selector != nil {
		r.selector.SetNodes(r.dialableNodes())
	}
	if r.lastErrString() != "" {
		return fmt.Errorf("vless: refresh partial: %s", r.lastErrString())
	}
	return nil
}

func (r *Runtime) lastErrString() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lastErr
}

// sourceStateSnapshot copies the per-source ETag/Last-Modified state for the
// conditional GET.
func (r *Runtime) sourceStateSnapshot() map[string]vless.SourceState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(r.sourceState) == 0 {
		return nil
	}
	out := make(map[string]vless.SourceState, len(r.sourceState))
	for k, v := range r.sourceState {
		out[k] = v
	}
	return out
}

// httpClientOrDefault returns the subscription HTTP client: an injected one
// (tests) or a client whose dialer rides the base carrier when present.
func (r *Runtime) httpClientOrDefault() *http.Client {
	if r.httpClient != nil {
		return r.httpClient
	}
	tr := &http.Transport{}
	if r.base != nil {
		tr.DialContext = r.base
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: tr}
}

// Status is the honest snapshot for the status endpoint and the tunnels pane.
type Status struct {
	Enabled       bool                `json:"enabled"`
	Running       bool                `json:"running"`
	Client        string              `json:"client"` // effective: in-process | helper
	Helper        string              `json:"helper"`
	SocksAddr     string              `json:"socks_addr"`
	Transport     string              `json:"transport"` // constant "tcp-only" in V1
	NodeCount     int                 `json:"node_count"`
	ActiveNode    string              `json:"active_node,omitempty"`
	IdentityPath  string              `json:"identity_path"`
	NodeCachePath string              `json:"node_cache_path"`
	Sources       []string            `json:"sources,omitempty"` // redacted
	LastRefresh   time.Time           `json:"last_refresh,omitempty"`
	LastError     string              `json:"last_error,omitempty"`
	HelperProcess *vless.HelperStatus `json:"helper_process,omitempty"`
	Events        []Event             `json:"events,omitempty"`
}

// Status snapshots the runtime.
func (r *Runtime) Status() Status {
	r.lifeMu.Lock()
	running := r.started && !r.stopped
	r.lifeMu.Unlock()

	nodes := r.allNodes()
	r.mu.RLock()
	sources := append([]string(nil), r.sourcesRed...)
	lastRefresh := r.lastRefresh
	lastErr := r.lastErr
	r.mu.RUnlock()

	var helperProc *vless.HelperStatus
	if r.helper != nil {
		s := r.helper.Status()
		helperProc = &s
	}
	return Status{
		Enabled:       r.cfg.Enabled,
		Running:       running,
		HelperProcess: helperProc,
		Client:        r.modeFor(nodes),
		ActiveNode:    r.activeNodeAddr(nodes),
		Helper:        r.cfg.Helper,
		SocksAddr:     r.cfg.SocksAddr,
		Transport:     "tcp-only",
		NodeCount:     len(nodes),
		IdentityPath:  r.cfg.IdentityPath,
		NodeCachePath: r.cfg.EffectiveNodeCachePath(),
		Sources:       sources,
		LastRefresh:   lastRefresh,
		LastError:     lastErr,
		Events:        r.ring.snapshot(),
	}
}

// Nodes returns a copy of the merged node set (diagnostics/tests).
func (r *Runtime) Nodes() []vless.Node { return r.allNodes() }

func (r *Runtime) allNodes() []vless.Node {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return vless.MergeNodes(r.inline, r.fetched)
}

// effectiveMode resolves the client mode from the configured value and the
// current node set ("auto" prefers in-process when a capable node exists).
func (r *Runtime) effectiveMode() string { return r.modeFor(r.allNodes()) }

func (r *Runtime) modeFor(nodes []vless.Node) string {
	switch strings.ToLower(strings.TrimSpace(r.cfg.Client)) {
	case config.VLESSClientInProcess:
		return config.VLESSClientInProcess
	case config.VLESSClientHelper:
		return config.VLESSClientHelper
	default:
		if firstInProcessNode(nodes) != nil {
			return config.VLESSClientInProcess
		}
		return config.VLESSClientHelper
	}
}

func firstInProcessNode(nodes []vless.Node) *vless.Node {
	for i := range nodes {
		if vless.SupportsInProcess(nodes[i]) {
			return &nodes[i]
		}
	}
	return nil
}

// DialStream dials ONE TCP stream to addr (the reserve.Carrier contract):
// through the in-process client when the mode/node allows, else through the
// helper's SOCKS5 inbound. Self-loop targets are refused.
func (r *Runtime) DialStream(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	nodes := r.allNodes()
	if isSelfLoop(nodes, addr) {
		return nil, ErrVlessSelfLoop
	}
	if r.modeFor(nodes) == config.VLESSClientInProcess {
		if n := r.pickInProcess(nodes); n != nil {
			conn, err := (&vless.Dialer{Node: *n, Base: r.base}).Dial(ctx, addr)
			if err == nil {
				return conn, nil
			}
			r.ring.push("warn", "dial_fail", "in-process "+activeAddr(n)+": "+err.Error())
			if r.socksDial == nil {
				return nil, err
			}
			// Never silent: log the fallback, then try the helper's SOCKS5.
			r.ring.push("info", "dial_fallback", "helper SOCKS5 after in-process failure")
		} else if r.socksDial == nil {
			return nil, errors.New("vlessservice: no in-process node available")
		}
	}
	if r.socksDial == nil {
		return nil, errors.New("vlessservice: no dialer configured")
	}
	conn, err := r.socksDial(ctx, "tcp", addr.String())
	if err != nil {
		r.ring.push("warn", "dial_fail", err.Error())
		return nil, err
	}
	return conn, nil
}

// pickInProcess prefers the selector's active node when it is in-process
// capable, else falls back to the first capable node.
func (r *Runtime) pickInProcess(nodes []vless.Node) *vless.Node {
	if r.selector != nil {
		if a, ok := r.selector.Active(); ok && vless.SupportsInProcess(a) {
			return &a
		}
	}
	return firstInProcessNode(nodes)
}

// isSelfLoop reports whether addr is one of the configured node addresses.
func isSelfLoop(nodes []vless.Node, addr netip.AddrPort) bool {
	target := addr.Addr().Unmap()
	for _, n := range nodes {
		ip, err := netip.ParseAddr(strings.TrimSpace(n.Host))
		if err != nil {
			continue
		}
		if ip.Unmap() == target {
			return true
		}
	}
	return false
}

// dialUDP opens a UDP ASSOCIATE through the helper's SOCKS5 inbound to addr
// (V3). The returned net.Conn is a connected datagram socket: Write sends one
// datagram to addr, Read receives one reply.
func (r *Runtime) dialUDP(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	parsed, err := socks.ParseAddr(r.cfg.SocksAddr)
	if err != nil {
		return nil, fmt.Errorf("vlessservice: system.vless.socks_addr: %w", err)
	}
	u, err := socks5.DialUpstreamUDP(ctx, socks5.ClientConfig{
		Host:     parsed.Host,
		Port:     parsed.Port,
		Username: parsed.User,
		Password: parsed.Pass,
		Timeout:  10 * time.Second,
	}, addr.Addr().AsSlice(), int(addr.Port()))
	if err != nil {
		r.ring.push("warn", "udp_dial_fail", err.Error())
		return nil, err
	}
	return &udpConn{u: u, remote: net.UDPAddrFromAddrPort(addr)}, nil
}

// udpConn adapts socks5.UDPUpstream to net.Conn. UDPUpstream.Read expects a
// buffer large enough for the SOCKS5 UDP header + datagram, so the adapter
// drains whole datagrams into an internal buffer and serves any read size.
type udpConn struct {
	u      *socks5.UDPUpstream
	remote net.Addr
	rbuf   []byte
}

func (c *udpConn) Read(p []byte) (int, error) {
	for len(c.rbuf) == 0 {
		buf := make([]byte, 65535)
		n, err := c.u.Read(buf)
		if err != nil {
			return 0, err
		}
		c.rbuf = buf[:n]
	}
	n := copy(p, c.rbuf)
	c.rbuf = c.rbuf[n:]
	return n, nil
}
func (c *udpConn) Write(p []byte) (int, error) { return c.u.Write(p) }
func (c *udpConn) Close() error                { return c.u.Close() }
func (c *udpConn) LocalAddr() net.Addr         { return vlessUDPAddr("local") }
func (c *udpConn) RemoteAddr() net.Addr        { return c.remote }
func (c *udpConn) SetDeadline(t time.Time) error {
	return c.u.SetReadDeadline(t)
}
func (c *udpConn) SetReadDeadline(t time.Time) error { return c.u.SetReadDeadline(t) }
func (c *udpConn) SetWriteDeadline(time.Time) error  { return nil }

type vlessUDPAddr string

func (a vlessUDPAddr) Network() string { return "udp" }
func (a vlessUDPAddr) String() string  { return string(a) }

// activeNodeAddr reports the selected node endpoint (selector first, else the
// first in-process candidate) for status.
func (r *Runtime) activeNodeAddr(nodes []vless.Node) string {
	if r.selector != nil {
		if a, ok := r.selector.Active(); ok {
			return activeAddr(&a)
		}
	}
	return activeAddr(firstInProcessNode(nodes))
}

// activeAddr renders the in-process node endpoint for status.
func activeAddr(n *vless.Node) string {
	if n == nil {
		return ""
	}
	return net.JoinHostPort(n.Host, strconv.Itoa(int(n.Port)))
}
