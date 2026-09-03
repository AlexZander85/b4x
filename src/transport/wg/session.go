// WG session lifecycle (design §4): tunnel + device + bind assembly, Noise
// handshake wait, data-plane trust gate, establishment, stall watchdog with
// structural restart. One goroutine owns the lifecycle; Stop() cancels it.
// Teardown follows the sing-box discipline: watchdog stops first, then
// device Down -> Close (our Bind.Close is idempotent).
package transportwg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	twarp "github.com/daniellavrushin/b4/transport/warp"
)

// SessionState is the externally visible lifecycle phase.
type SessionState string

const (
	StateIdle        SessionState = "idle"
	StateStarting    SessionState = "starting"
	StateProving     SessionState = "trust-gate"
	StateEstablished SessionState = "established"
	StateRestarting  SessionState = "restarting"
	StateClosed      SessionState = "closed"
)

// SessionEvent is one taxonomy trace point (prefix wg_/awg_ per design §8).
type SessionEvent struct {
	Name   string
	Class  FailureClass
	Reason string
}

// SessionCallbacks receive lifecycle events; every callback must be safe for
// concurrent use and non-blocking. OnEstablished fires ONLY after the trust
// gate passed — route/camouflage consumers must key on it exclusively.
type SessionCallbacks struct {
	OnEvent       func(SessionEvent)
	OnEstablished func()
	OnLost        func(Failure)
}

// HealthConfig carries the timing posture; zero values map to defaults.
type HealthConfig struct {
	HandshakeTimeout time.Duration // default 10 s
	Gate             TrustGate
	Watchdog         WatchdogConfig
	RestartBackoff   time.Duration // default 1 s (exponential base)
	RestartCap       RestartCapConfig
	KeepaliveSec     uint16 // default 25 (NAT/CGNAT)
}

func (h *HealthConfig) fillDefaults() {
	if h.HandshakeTimeout == 0 {
		h.HandshakeTimeout = 10 * time.Second
	}
	if h.RestartBackoff == 0 {
		h.RestartBackoff = time.Second
	}
	if h.KeepaliveSec == 0 {
		h.KeepaliveSec = 25
	}
	// PATCH-04: derive the default RXIdle from the session keepalive —
	// max(30s, 3x keepalive). Keepalives are outbound-only (the peer does
	// not answer them), so a fixed 10s RXIdle guaranteed restart cycles for
	// nested pairs (outer keepalive 5s, inner 20s): 25s -> 75s, 5s -> 30s,
	// 20s -> 60s. An EXPLICIT RXIdle in the config always wins.
	if h.Watchdog.RXIdle == 0 {
		h.Watchdog.RXIdle = max(30*time.Second, 3*time.Duration(h.KeepaliveSec)*time.Second)
	}
	h.RestartCap.fillDefaults()
	h.Watchdog.fillDefaults()
}

// RestartCapConfig bounds restart storms (design §10 tail; PATCH-03): an
// endpoint that cannot hold a generation burns its budget and the session
// goes TERMINAL instead of cycling forever.
type RestartCapConfig struct {
	// MaxPerHour bounds restarts per rolling Window: 0 = default (6),
	// -1 = explicit off (tests / supervisor-managed scenarios).
	MaxPerHour int
	// Window is the rolling window; default 1h.
	Window time.Duration
	// OnExhausted is an optional structural notification fired when the
	// cap closes the session (the wg_restart_cap_exhausted event and the
	// terminal OnLost fire regardless).
	OnExhausted func(gen uint64)
}

func (c *RestartCapConfig) fillDefaults() {
	if c.MaxPerHour == 0 {
		c.MaxPerHour = 6
	}
	if c.Window <= 0 {
		c.Window = time.Hour
	}
}

// enabled reports whether the cap governs restarts (-1 = off).
func (c *RestartCapConfig) enabled() bool { return c.MaxPerHour > 0 }

// SessionConfig assembles everything the session needs to build itself.
type SessionConfig struct {
	Ident        *Identity
	Profile      Profile
	Endpoint     string // "host:port" of the edge
	ListenFwMark uint32
	SockOpts     SocketOptions
	Tunnel       TunnelConfig
	Health       HealthConfig
	Callbacks    SessionCallbacks
	// MaxGenerations bounds restart cycles: 0 (default) = unlimited;
	// 1 = single-shot establishment (seek-ladder attempts).
	MaxGenerations int
	// VerboseDiagnostics routes per-generation device logs to stdout
	// (debug aid; production keeps the silent logger).
	VerboseDiagnostics bool
	// KernelUp / KernelDown are the kernel-TUN PBR hooks (review P2 stage
	// в, design §7 "kernel-TUN PBR — основной путь роутера"): in ModeKernel
	// establishGeneration calls KernelUp with the ACTUAL device name right
	// after the TUN is created and BEFORE the trust gate (the gate's raw
	// probe path needs the addressing/route up); teardown calls KernelDown.
	// The hooks own the kernel wiring (addresses, policy rule, table
	// default) and must be idempotent; nil = plain kernel TUN with no
	// kernel wiring (the owner manages routing externally).
	KernelUp   func(device string) error
	KernelDown func(device string)
	// I1Regen, when non-nil, wires the per-handshake InitPacket
	// regeneration seam of the vendored amneziawg-go device (review P3,
	// stage PT-obf1): for every SendHandshakeInitiation the device calls
	// it with the 0-based I-slot and re-materializes the returned chain
	// spec ("" = keep the static IpcSet chain). The proton QUIC family
	// uses it to render a FRESH QUIC Initial (new DCID + randomness) on
	// every handshake instead of re-sending one identical 1250-byte
	// datagram - the static-DCID replay signature. Must be fast and
	// non-blocking; read-only after NewSession.
	I1Regen func(slot int) string
}

// Session owns one logical WG connection across restarts (generation bump on
// every teardown). It implements the supervisor contract of design §4:
// handshake budget -> trust gate -> established -> watchdog -> restart.
type Session struct {
	cfg SessionConfig

	// endpointAP is the parsed cfg.Endpoint (ip:port). Resolved ONCE in
	// NewSession so the lifecycle goroutine never re-parses config input
	// (PATCH-02: a malformed endpoint is a construction-time structural
	// rejection, not a goroutine panic).
	endpointAP netip.AddrPort

	// restart telemetry (PATCH-03): the wg layer has no metrics pipeline;
	// structural events plus these atomics are the composed surface.
	restartTotal  atomic.Int64
	lastBackoffMS atomic.Int64
	// genEstablished flips true when the CURRENT generation reached
	// StateEstablished — a successful generation resets the restart
	// backoff ladder (design §10: consecutive-failure growth only).
	genEstablished atomic.Bool
	// restartStamps is the rolling restart window (cap bookkeeping);
	// guarded by mu, only touched from the run goroutine + Stop.
	restartStamps []time.Time
	// randF is the jitter source hook (tests pin it for determinism).
	randF func() float64

	// kernelDev is the ACTUAL kernel-TUN device name of the live generation
	// (kernel mode only, set by establishGeneration, cleared by teardown).
	kernelDev string
	// countersOverride lets tests script counter samples (same-package hook;
	// production leaves it nil and the sampler reads IpcGet).
	countersOverride CountersFunc

	// newTunnelFn defaults to NewTunnel; tests override it with a channel
	// backend (same-package hook, production code never sets it).
	newTunnelFn func(TunnelConfig) (*Tunnel, error)

	mu     sync.Mutex
	state  SessionState
	gen    uint64
	cancel context.CancelFunc
	done   chan struct{}
	dev    *device.Device
	bind   *Bind
	tun    *Tunnel
}

// NewSession validates identity/config coherence without touching network.
func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.Ident == nil {
		return nil, newFailure(ClassParamRejected, "nil-identity", nil)
	}
	if err := cfg.Ident.Validate(); err != nil {
		return nil, err
	}
	if cfg.Endpoint == "" {
		return nil, newFailure(ClassParamRejected, "empty-endpoint", nil)
	}
	// PATCH-02 (WG MAJOR 2): the endpoint must be a literal ip:port.
	// Hostnames (e.g. directory endpoints like engage.cloudflareclient.com:2408)
	// are the CALLER's responsibility to resolve (endpoints.go already does);
	// a non-parsable endpoint is a structural param rejection here — never
	// a MustParse panic inside the lifecycle goroutine.
	ap, err := netip.ParseAddrPort(strings.TrimSpace(cfg.Endpoint))
	if err != nil {
		return nil, newFailure(ClassParamRejected, "endpoint", fmt.Errorf(
			"endpoint %q is not ip:port (hostnames must be resolved by the caller): %w", cfg.Endpoint, err))
	}
	return &Session{cfg: cfg, endpointAP: ap, state: StateIdle, randF: mathrand.Float64}, nil
}

// State returns the current lifecycle phase.
func (s *Session) State() SessionState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// Generation increments on every teardown/restart cycle.
func (s *Session) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen
}

// Tunnel snapshots the live generation's tunnel device (nil-safe; nil when
// no generation is currently assembled). Consumers of the Backend-B nested
// carrier grab the OUTER tunnel's netstack from here right after
// OnEstablished fires, when the owning generation is guaranteed alive.
func (s *Session) Tunnel() *Tunnel {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.tun
}

// Start launches the lifecycle goroutine. Idempotent while running.
func (s *Session) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cancel != nil {
		return fmt.Errorf("transportwg: session already running")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.done = make(chan struct{})
	s.state = StateStarting
	go s.run(ctx)
	return nil
}

// Stop tears the session down synchronously.
func (s *Session) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	done := s.done
	s.cancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

func (s *Session) emit(ev SessionEvent) {
	if cb := s.cfg.Callbacks.OnEvent; cb != nil {
		cb(ev)
	}
}

// run is the supervisor loop: assemble -> handshake -> gate -> established,
// restart on any structural failure until ctx dies, MaxGenerations ends, or
// the restart cap (design §10, PATCH-03) closes the session terminally.
func (s *Session) run(ctx context.Context) {
	defer func() {
		s.teardown()
		s.mu.Lock()
		s.state = StateClosed
		s.mu.Unlock()
		close(s.done)
	}()
	gens := 0
	base := s.cfg.Health.RestartBackoff
	if base <= 0 {
		base = time.Second
	}
	backoff := base
	capCfg := s.cfg.Health.RestartCap
	capCfg.fillDefaults()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if s.cfg.MaxGenerations > 0 && gens >= s.cfg.MaxGenerations {
			return
		}
		gens++
		s.mu.Lock()
		s.gen++
		gen := s.gen
		s.mu.Unlock()
		s.genEstablished.Store(false)

		f := s.establishGeneration(ctx)
		if f != nil && !errors.Is(f.Err, context.Canceled) {
			s.emit(SessionEvent{Name: "wg_lost", Class: f.Class, Reason: f.Reason})
			if cb := s.cfg.Callbacks.OnLost; cb != nil {
				cb(*f)
			}
		}
		s.teardown()

		if ctx.Err() != nil {
			return
		}
		if s.cfg.MaxGenerations > 0 && gens >= s.cfg.MaxGenerations {
			return
		}

		// PATCH-03: the backoff ladder grows on CONSECUTIVE failures
		// and resets after any successful (established) generation.
		if s.genEstablished.Load() {
			backoff = base
		} else {
			backoff = min(backoff*2, maxRestartBackoff)
		}

		// PATCH-03: sliding-window restart cap. Before spending the
		// next restart, prune the window and go TERMINAL when the
		// budget is exhausted — the session must not cycle forever.
		if capCfg.enabled() {
			s.pruneRestartStamps(time.Now().Add(-capCfg.Window))
			s.mu.Lock()
			n := len(s.restartStamps)
			s.mu.Unlock()
			if n >= capCfg.MaxPerHour {
				reason := fmt.Sprintf("gen=%d restarts=%d window=%s", gen, n, capCfg.Window)
				s.emit(SessionEvent{Name: "wg_restart_cap_exhausted", Class: ClassRestartCapExhausted, Reason: reason})
				if cb := s.cfg.Callbacks.OnLost; cb != nil {
					cb(*newFailure(ClassRestartCapExhausted, "restart-cap-exhausted", nil))
				}
				if capCfg.OnExhausted != nil {
					capCfg.OnExhausted(gen)
				}
				return
			}
		}

		s.mu.Lock()
		s.state = StateRestarting
		s.mu.Unlock()
		s.emit(SessionEvent{Name: "wg_restarting", Reason: fmt.Sprintf("gen=%d", gen)})

		delay := s.applyJitter(backoff)
		s.lastBackoffMS.Store(delay.Milliseconds())
		s.emit(SessionEvent{Name: "wg_restart_backoff",
			Reason: fmt.Sprintf("gen=%d backoff_ms=%d", gen, delay.Milliseconds())})

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		s.mu.Lock()
		s.restartStamps = append(s.restartStamps, time.Now())
		s.mu.Unlock()
		s.restartTotal.Add(1)
	}
}

// maxRestartBackoff is the exponential-ladder ceiling (design §10: 60 s).
const maxRestartBackoff = 60 * time.Second

// pruneRestartStamps drops restart stamps older than the cutoff (PATCH-03).
func (s *Session) pruneRestartStamps(cutoff time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.restartStamps[:0]
	for _, st := range s.restartStamps {
		if st.After(cutoff) {
			kept = append(kept, st)
		}
	}
	s.restartStamps = kept
}

// applyJitter widens d by ±20% (design §10 anti-thundering-herd):
// [0.8d; 1.2d], sourced from the injectable rand hook.
func (s *Session) applyJitter(d time.Duration) time.Duration {
	r := 0.0
	if s.randF != nil {
		r = s.randF()
	}
	factor := 0.8 + 0.4*r
	return time.Duration(float64(d) * factor)
}

// RestartTotal reports how many restarts this session performed (PATCH-03
// telemetry; the structural events remain the primary observability).
func (s *Session) RestartTotal() int64 { return s.restartTotal.Load() }

// LastBackoffMS reports the most recent restart delay in milliseconds.
func (s *Session) LastBackoffMS() int64 { return s.lastBackoffMS.Load() }

// establishGeneration builds one device generation and drives it to
// Established, then blocks until stall or ctx death. Returns a failure when
// the generation died (nil only when ctx was cancelled while established).
func (s *Session) establishGeneration(ctx context.Context) *Failure {
	s.setState(StateStarting)

	newTun := s.newTunnelFn
	if newTun == nil {
		newTun = NewTunnel
	}
	tunRes, err := newTun(s.cfg.Tunnel)
	if err != nil {
		return newFailure(ClassParamRejected, "tunnel", err)
	}
	bind := NewBind(s.cfg.SockOpts)
	hook, err := s.cfg.Ident.DatagramHookOrNil()
	if err != nil {
		return newFailure(ClassReservedInvalid, "hook-derivation", err)
	}
	if hook != nil {
		bind.SetDatagramHook(hook)
	}
	s.emit(SessionEvent{Name: "wg_device_assembling"})

	var dlog *device.Logger
	if s.cfg.VerboseDiagnostics {
		dlog = device.NewLogger(device.LogLevelVerbose, fmt.Sprintf("wggen%d: ", s.gen))
	} else {
		dlog = DeviceLogger(nil)
	}
	dev := device.NewDevice(tunRes.Device, bind, dlog)
	if s.cfg.I1Regen != nil {
		dev.InitPacketSpecFunc = s.cfg.I1Regen
	}
	// Kernel-TUN PBR hook (review P2 stage в): the wiring MUST be up
	// before the gate — the raw probe path rides the kernel addressing.
	// The ACTUAL device name is passed (the kernel may diverge from the
	// hint, the nested/E4 lesson); a failed wiring is a structural
	// rejection, never a half-routed session.
	if s.cfg.Tunnel.Mode == ModeKernel && s.cfg.KernelUp != nil {
		devName := s.cfg.Tunnel.InterfaceName
		if tunRes.Device != nil {
			if n, nerr := tunRes.Device.Name(); nerr == nil && n != "" {
				devName = n
			}
		}
		if uerr := s.cfg.KernelUp(devName); uerr != nil {
			return newFailure(ClassParamRejected, "kernel-up", uerr)
		}
		s.kernelDev = devName
	}
	s.mu.Lock()
	s.dev, s.bind, s.tun = dev, bind, tunRes
	s.mu.Unlock()

	ipc, err := s.buildIPC()
	if err != nil {
		return newFailure(ClassJunkProfileFailed, "ipc-render", err)
	}
	if err := dev.IpcSet(ipc); err != nil {
		s.emitIPCSetFailed(s.Generation(), ipc, err) // PATCH-11: effective-config dump (scrubbed)
		return newFailure(ClassParamRejected, "ipc-set", err)
	}
	if err := dev.Up(); err != nil {
		return newFailure(ClassParamRejected, "device-up", err)
	}
	s.emit(SessionEvent{Name: "wg_handshake_wait"})

	// Bootstrap traffic: queue one health probe so the device has outbound
	// data to protect. This is what actually triggers the Noise handshake —
	// persistent-keepalone timers do not initiate without an established
	// keypair, so a fresh generation would otherwise stay silent forever.
	gate := s.cfg.Health.Gate
	gate.LocalV4 = localV4Of(s.cfg.Ident)
	gate.fillDefaults()
	// PATCH-10 (A5): netstack production sessions attach the built-in trace
	// probe when the wiring flag is on — an on-path injector that forges DNS
	// replies with the correct TXID still fails the /cdn-cgi/trace check.
	// CI fixtures and the seek ladder leave the flag off (no HTTP surface /
	// budget); the kernel-TUN probe stays a field-layer concern.
	if gate.E2EProbeEnabled && gate.E2EProbe == nil && tunRes.Netstack != nil {
		gate.E2EProbe = NetstackE2EProbe(nsTCPDial(tunRes.Netstack), localV4Of(s.cfg.Ident))
	}
	if err := s.bootstrapThrough(tunRes, gateBootstrapPacket(gate)); err != nil {
		return newFailure(ClassStallRX, "bootstrap-inject", err)
	}

	if f := s.waitHandshake(ctx, dev); f != nil {
		return f
	}
	s.emit(SessionEvent{Name: "wg_handshake_ok"})

	gctx, gcancel := context.WithCancel(ctx)
	defer gcancel()

	s.setState(StateProving)
	rt := s.roundTripper(tunRes)
	gate.LocalV4 = localV4Of(s.cfg.Ident)

	// Pre-gate counter snapshot: on gate failure the delta classifies the
	// outcome — tx growth with rx pinned at zero is the AWG version-mismatch
	// signature ("92 B received / 20 KB sent" family), not a plain stall.
	pre, preErr := s.countersSampler(dev)(ctx)
	if err := gate.Verify(gctx, rt); err != nil {
		var f *Failure
		if errors.As(err, &f) {
			// Upgrade rule: ONLY a junk-bearing (non-vanilla) profile whose
			// tx grows while rx stays zero is the AWG parameter-disagreement
			// signature. A vanilla profile failing the gate means the
			// endpoint itself is dead/DPI'd — plain stall class.
			if f.Class == ClassStallRX && !s.cfg.Profile.VanillaSafe() && preErr == nil {
				if post, e := s.countersSampler(dev)(ctx); e == nil {
					txDelta := post.TxBytes - pre.TxBytes
					rxDelta := post.RxBytes - pre.RxBytes
					sigTX := gate.SigMinTX
					if sigTX == 0 {
						sigTX = DefaultGateSigMinTX
					}
					if txDelta >= sigTX && rxDelta == 0 {
						return &Failure{
							Class:  ClassVersionMismatch,
							Reason: "92b-20kb-gate",
							Err:    f,
						}
					}
				}
			}
			return f
		}
		return newFailure(ClassStallRX, "gate", err)
	}
	s.emit(SessionEvent{Name: "wg_gate_passed"})

	stallCh := make(chan Failure, 1)
	wdCfg := s.cfg.Health.Watchdog
	wdCfg.OnStall = func(f Failure) {
		select {
		case stallCh <- f:
		default:
		}
	}
	liveWd := NewWatchdog(wdCfg)
	go liveWd.Run(gctx, s.countersSampler(dev))
	s.setState(StateEstablished)
	s.emit(SessionEvent{Name: "wg_established"})
	s.genEstablished.Store(true)
	if cb := s.cfg.Callbacks.OnEstablished; cb != nil {
		cb()
	}

	select {
	case <-ctx.Done():
		return nil
	case f := <-stallCh:
		return &f
	}
}

func (s *Session) setState(st SessionState) {
	s.mu.Lock()
	s.state = st
	s.mu.Unlock()
}

// buildIPC renders the IpcSet string from identity+profile+endpoint.
func (s *Session) buildIPC() (string, error) {
	c := Config{
		PrivateKey: s.cfg.Ident.PrivateKey,
		FWMark:     s.cfg.ListenFwMark,
		Profile:    s.cfg.Profile,
		Peers: []PeerConfig{{
			PublicKey: s.cfg.Ident.PeerPublicKey,
			Endpoint:  s.endpointAP, // parsed+validated in NewSession (PATCH-02)
			// PATCH-23/NIT5: the default route is declared EXPLICITLY —
			// empty AllowedIPs is now a validation error.
			AllowedIPs: []netip.Prefix{
				netip.PrefixFrom(netip.AddrFrom4([4]byte{0, 0, 0, 0}), 0),
				netip.PrefixFrom(netip.AddrFrom16([16]byte{}), 0),
			},
			PersistentKeepaliveSec: s.cfg.Health.KeepaliveSec,
		}},
	}
	return c.IPCString()
}

// roundTripper picks the gate IO implementation per TUN mode.
func (s *Session) roundTripper(t *Tunnel) DNSRoundTripper {
	if t.Netstack != nil {
		return NewNetstackRoundTripper(nsUDPDial(t.Netstack), localV4Of(s.cfg.Ident))
	}
	return &RawTUNRoundTripper{Inject: t.Inject, Capture: t.Capture}
}

// bootstrapThrough pushes the handshake-triggering probe using whichever
// surface the TUN mode provides: raw injection (kernel/channel) or a real
// UDP write through the gvisor stack (netstack).
func (s *Session) bootstrapThrough(t *Tunnel, pkt []byte) error {
	switch {
	case t.Inject != nil:
		return t.Inject(pkt)
	case t.Netstack != nil:
		rt := &NetstackRoundTripper{NS: nsUDPDial(t.Netstack), Local: localV4Of(s.cfg.Ident)}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		conn, err := rt.NS(ctx, "udp", "8.8.8.8:53")
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close() }()
		const dnsPayloadOffset = 28
		if len(pkt) <= dnsPayloadOffset {
			return errors.New("transportwg: bootstrap probe too short")
		}
		_, err = conn.Write(pkt[dnsPayloadOffset:])
		return err
	default:
		return errors.New("transportwg: no bootstrap surface for this TUN mode")
	}
}

// nsUDPDial adapts netstack.Net.DialContext to the udpConn surface.
func nsUDPDial(ns *netstack.Net) func(ctx context.Context, network, address string) (udpConn, error) {
	return func(ctx context.Context, network, address string) (udpConn, error) {
		c, err := ns.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		uc, ok := c.(udpConn)
		if !ok {
			return nil, fmt.Errorf("netstack conn does not expose UDP surface")
		}
		return uc, nil
	}
}

// gateBootstrapPacket builds the one probe packet queued right after Up():
// it forces the handshake and doubles as the first data packet. Its qname
// carries the bootstrap. label so wire-level consumers (and tests) can tell
// it apart from trust-gate probes — user buffered packets still flush at
// keypair establishment BEFORE any gate probe is sent.
func gateBootstrapPacket(gate TrustGate) []byte {
	gate.fillDefaults()
	gate.QName = bootstrapQNameLabel + gate.QName
	p, err := twarp.NewDNSProbe(gate.LocalV4, gate.DNSServer, gate.QName)
	if err != nil {
		panic("transportwg: bootstrap probe build: " + err.Error())
	}
	return p.Packet
}

// waitHandshake polls IpcGet for a completed handshake.
func (s *Session) waitHandshake(ctx context.Context, dev *device.Device) *Failure {
	s.cfg.Health.fillDefaults()
	deadline := time.Now().Add(s.cfg.Health.HandshakeTimeout)
	for {
		if deviceHandshakeEstablished(dev) {
			return nil
		}
		if time.Now().After(deadline) {
			return newFailure(ClassHandshakeTimeout, "handshake-budget-exhausted", nil)
		}
		select {
		case <-ctx.Done():
			return newFailure(ClassHandshakeTimeout, "cancelled", ctx.Err())
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// countersSampler parses rx_bytes/tx_bytes out of IpcGet; the test override
// takes precedence when installed.
func (s *Session) countersSampler(dev *device.Device) CountersFunc {
	if s.countersOverride != nil {
		return s.countersOverride
	}
	return func(ctx context.Context) (CounterSample, error) {
		state, err := dev.IpcGet()
		if err != nil {
			return CounterSample{}, err
		}
		var sample CounterSample
		sample.Time = time.Now()
		for _, ln := range strings.Split(state, "\n") {
			if v, ok := strings.CutPrefix(ln, "rx_bytes="); ok {
				sample.RxBytes, _ = strconv.ParseUint(v, 10, 64)
			} else if v, ok := strings.CutPrefix(ln, "tx_bytes="); ok {
				sample.TxBytes, _ = strconv.ParseUint(v, 10, 64)
			}
		}
		return sample, nil
	}
}

// SessionTelemetry is the parsed per-peer transfer snapshot of one session
// (PATCH-28, N-5: per-layer handshake/RX/TX for the composed Status views).
type SessionTelemetry struct {
	// HandshakeUnix is the last completed handshake as a unix timestamp
	// (0 = never established).
	HandshakeUnix int64
	RXBytes       uint64
	TXBytes       uint64
}

// Telemetry parses the first peer's counters out of the live IpcGet dump.
// Errors degrade to a zero-value telemetry (never blocks the caller).
func (s *Session) Telemetry() SessionTelemetry {
	dump, err := s.IPCSnapshot()
	if err != nil {
		return SessionTelemetry{}
	}
	return ParseWGTelemetry(dump)
}

// ParseWGTelemetry extracts the per-peer handshake stamp and transfer
// counters from a wg IpcGet dump (first peer wins; the nested runtimes
// compose exactly one peer per session). Both key spellings are accepted:
// upstream wireguard-go ships transfer_rx_bytes/transfer_tx_bytes while the
// vendored amneziawg-go v3 UAPI emits rx_bytes/tx_bytes (uapi.go:212).
func ParseWGTelemetry(dump string) SessionTelemetry {
	var t SessionTelemetry
	for _, line := range strings.Split(dump, "\n") {
		name, value, found := cutLine(line)
		if !found {
			continue
		}
		switch name {
		case "last_handshake_time_sec":
			if t.HandshakeUnix == 0 {
				t.HandshakeUnix, _ = strconv.ParseInt(value, 10, 64)
			}
		case "transfer_rx_bytes", "rx_bytes":
			if t.RXBytes == 0 {
				t.RXBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		case "transfer_tx_bytes", "tx_bytes":
			if t.TXBytes == 0 {
				t.TXBytes, _ = strconv.ParseUint(value, 10, 64)
			}
		}
	}
	return t
}

func cutLine(line string) (name, value string, ok bool) {
	for i := 0; i < len(line); i++ {
		if line[i] == '=' {
			return line[:i], line[i+1:], true
		}
	}
	return "", "", false
}

// IPCSnapshot returns the live IpcGet dump of the current generation,
// SCRUBBED of secret key material (PATCH-14/B10: keys never travel in
// dumps — the first diagnostic call must not be the leak). Empty string +
// error when no device is up.
func (s *Session) IPCSnapshot() (string, error) {
	s.mu.Lock()
	dev := s.dev
	s.mu.Unlock()
	if dev == nil {
		return "", fmt.Errorf("transportwg: session has no live device")
	}
	dump, err := dev.IpcGet()
	if err != nil {
		return "", err
	}
	return ScrubIPC(dump), nil
}

// ScrubIPC masks secret lines (private_key, preshared_key) in an IpcGet /
// rendered IpcSet dump: every secret value is replaced with a stable 12
// hex-char sha256 prefix so dumps stay correlatable without ever carrying
// key material (B10 red line: keys never travel in logs/dumps/events).
// All other lines pass through verbatim.
func ScrubIPC(dump string) string {
	if dump == "" {
		return dump
	}
	lines := strings.Split(dump, "\n")
	for i, line := range lines {
		name, value, ok := cutLine(line)
		if !ok || (name != "private_key" && name != "preshared_key") {
			continue
		}
		sum := sha256.Sum256([]byte(value))
		lines[i] = name + "=sha256:" + hex.EncodeToString(sum[:])[:12]
	}
	return strings.Join(lines, "\n")
}

// emitIPCSetFailed reports a failed IpcSet with the EFFECTIVE rendered
// config attached (PATCH-11/B9, sing-box diagnostic pattern): field config
// rejections arrive with gen + scrubbed render + error, not just a bare
// upstream message.
func (s *Session) emitIPCSetFailed(gen uint64, ipc string, err error) {
	s.emit(SessionEvent{
		Name:   "wg_ipc_set_failed",
		Class:  ClassParamRejected,
		Reason: fmt.Sprintf("gen=%d err=%v config=%q", gen, err, ScrubIPC(ipc)),
	})
}

// teardown stops and closes the current generation's resources.
func (s *Session) teardown() {
	s.mu.Lock()
	dev := s.dev
	s.dev, s.bind, s.tun = nil, nil, nil
	kernelDev := s.kernelDev
	s.kernelDev = ""
	down := s.cfg.KernelDown
	s.mu.Unlock()
	// Kernel wiring down BEFORE the device disappears: the rule/table pins
	// reference the interface name, and the PBR owner must see it alive.
	if down != nil && kernelDev != "" {
		down(kernelDev)
	}
	if dev != nil {
		_ = dev.Down()
		dev.Close()
	}
}

// deviceHandshakeEstablished reads IpcGet last_handshake_time_sec.
func deviceHandshakeEstablished(dev *device.Device) bool {
	state, err := dev.IpcGet()
	if err != nil {
		return false
	}
	return strings.Contains(state, "last_handshake_time_sec=") &&
		!strings.Contains(state, "last_handshake_time_sec=0")
}

func localV4Of(id *Identity) [4]byte {
	addr := netip.MustParseAddr(id.AssignedV4)
	return addr.As4()
}

// nsTCPDial adapts the netstack's DialContext to the E2E trace dial seam.
func nsTCPDial(ns *netstack.Net) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return ns.DialContext(ctx, network, addr)
	}
}
