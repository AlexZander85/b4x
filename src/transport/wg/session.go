// WG session lifecycle (design §4): tunnel + device + bind assembly, Noise
// handshake wait, data-plane trust gate, establishment, stall watchdog with
// structural restart. One goroutine owns the lifecycle; Stop() cancels it.
// Teardown follows the sing-box discipline: watchdog stops first, then
// device Down -> Close (our Bind.Close is idempotent).
package transportwg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"sync"
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
	RestartBackoff   time.Duration // default 1 s
	KeepaliveSec     uint16        // default 25 (NAT/CGNAT)
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
	h.Watchdog.fillDefaults()
}

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
	return &Session{cfg: cfg, endpointAP: ap, state: StateIdle}, nil
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
// restart on any structural failure until ctx dies or MaxGenerations ends.
func (s *Session) run(ctx context.Context) {
	defer func() {
		s.teardown()
		s.mu.Lock()
		s.state = StateClosed
		s.mu.Unlock()
		close(s.done)
	}()
	gens := 0
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
		s.mu.Lock()
		s.state = StateRestarting
		s.mu.Unlock()
		s.emit(SessionEvent{Name: "wg_restarting", Reason: fmt.Sprintf("gen=%d", gen)})

		select {
		case <-ctx.Done():
			return
		case <-time.After(s.cfg.Health.RestartBackoff):
		}
	}
}

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
	s.mu.Lock()
	s.dev, s.bind, s.tun = dev, bind, tunRes
	s.mu.Unlock()

	ipc, err := s.buildIPC()
	if err != nil {
		return newFailure(ClassJunkProfileFailed, "ipc-render", err)
	}
	if err := dev.IpcSet(ipc); err != nil {
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
	pre, preOK := s.countersSampler(dev)(ctx)
	if err := gate.Verify(gctx, rt); err != nil {
		var f *Failure
		if errors.As(err, &f) {
			// Upgrade rule: ONLY a junk-bearing (non-vanilla) profile whose
			// tx grows while rx stays zero is the AWG parameter-disagreement
			// signature. A vanilla profile failing the gate means the
			// endpoint itself is dead/DPI'd — plain stall class.
			if f.Class == ClassStallRX && !s.cfg.Profile.VanillaSafe() && preOK == nil {
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
			PublicKey:              s.cfg.Ident.PeerPublicKey,
			Endpoint:               s.endpointAP, // parsed+validated in NewSession (PATCH-02)
			AllowedIPs:             nil,          // default route through the tunnel
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

// IPCSnapshot returns the live IpcGet dump of the current generation
// (empty string + error when no device is up).
func (s *Session) IPCSnapshot() (string, error) {
	s.mu.Lock()
	dev := s.dev
	s.mu.Unlock()
	if dev == nil {
		return "", fmt.Errorf("transportwg: session has no live device")
	}
	return dev.IpcGet()
}

// teardown stops and closes the current generation's resources.
func (s *Session) teardown() {
	s.mu.Lock()
	dev := s.dev
	s.dev, s.bind, s.tun = nil, nil, nil
	s.mu.Unlock()
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
