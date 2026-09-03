// E7 wiring tests: Backend-B dial plumbing, TUN pump (ICMP TooBig + stall
// watchdog), control-flow guard, enrollment hostlist contract.
package transportwarp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ---- BLOCKED_CARRIER: structural layer classification (owner decision) ----

func TestBlockedCarrierLayerClassification(t *testing.T) {
	// Carrier absence is a STRUCTURAL blocked state, distinct from network
	// failures; diagnostics classify via errors.Is.
	if !errors.Is(ErrHTTPSNotWired, ErrBlockedCarrier) {
		t.Fatal("https probe slot does not classify as BLOCKED_CARRIER")
	}
	if !errors.Is(ErrDoHNotWired, ErrBlockedCarrier) {
		t.Fatal("doh slot does not classify as BLOCKED_CARRIER")
	}
	// Backend-B composition without a carrier fails at CONFIG time.
	cfg := validNestedConfig()
	cfg.BaseInterface = ""
	cfg.Backend = BackendBProxy
	if err := cfg.Validate(); !errors.Is(err, ErrBlockedCarrier) {
		t.Fatalf("backend-b without carrier = %v, want ErrBlockedCarrier", err)
	}
}

// ---- Backend B: SessionConfig.DialFunc routes the raw TCP through the adapter ----

func TestBackendBDialFuncRoutesThroughAdapter(t *testing.T) {
	h := newGeoHarness(t)

	// The endpoint in the config is a TEST-NET address nothing dials
	// directly; the adapter serves the connection from the real fixture
	// listener. A successful validated session therefore proves the whole
	// control stream flowed through the StreamDialer.
	bogus := netip.MustParseAddrPort("192.0.2.10:443")

	var mu sync.Mutex
	var dialed []netip.AddrPort
	sd := StreamDialerFunc(func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		mu.Unlock()
		// Simulate a base-tunnel carrier: connect to the REAL edge fixture.
		d := net.Dialer{Timeout: 2 * time.Second}
		return d.DialContext(ctx, "tcp", h.fs.ln.Addr().String())
	})

	privB64, _, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParseClientKeyB64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	cfg := SessionConfig{
		Endpoint:        bogus,
		ClientKey:       priv,
		Pin:             h.fs.pinPub(),
		LocalV4:         [4]byte{172, 16, 0, 2},
		ValidateWindow:  200 * time.Millisecond,
		ProbeInterval:   5 * time.Millisecond,
		HandshakeBudget: 2 * time.Second,
		DialFunc:        BackendBDialFunc(sd),
	}
	sess, res, err := DialSession(context.Background(), cfg)
	if err != nil {
		t.Fatalf("dial through adapter: %v (class %s)", err, res.FailureClass)
	}
	defer sess.Close()
	if err := sess.ValidateDataPlane(context.Background()); err != nil {
		t.Fatalf("validate: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(dialed) != 1 || dialed[0] != bogus {
		t.Fatalf("adapter dialed %v, want exactly [%s]", dialed, bogus)
	}
}

func TestTunnelGeoTransportHTTPSExchangeSlot(t *testing.T) {
	h := newGeoHarness(t)

	if _, err := h.tr.HTTPSExchange(context.Background(), "https://1.1.1.1/cdn-cgi/trace"); !errors.Is(err, ErrHTTPSNotWired) {
		t.Fatalf("unwired slot = %v", err)
	}
	called := 0
	h.tr.WithHTTPSExchange(func(ctx context.Context, url string) ([]byte, error) {
		called++
		return []byte("ip=81.2.3.4\nloc=DE\nwarp=on\n"), nil
	})
	body, err := h.tr.HTTPSExchange(context.Background(), "https://1.1.1.1/cdn-cgi/trace")
	if err != nil || called != 1 || body == nil {
		t.Fatalf("wired slot = %q, %v (calls %d)", body, err, called)
	}

	p := NewCFTraceProvider("cf-trace")
	res, err := p.Probe(context.Background(), h.tr)
	if err != nil {
		t.Fatal(err)
	}
	wanted, herr := HashPublicIP(netip.AddrFrom4([4]byte{81, 2, 3, 4}))
	if herr != nil {
		t.Fatal(herr)
	}
	if res.Country != "DE" || res.PublicIPHash != wanted {
		t.Fatalf("trace provider result %+v", res)
	}
	// Fail-closed posture on non-WARP trace bodies.
	h.tr.WithHTTPSExchange(func(ctx context.Context, url string) ([]byte, error) {
		return []byte("ip=81.2.3.4\nloc=DE\nwarp=off\n"), nil
	})
	if _, err := p.Probe(context.Background(), h.tr); !errors.Is(err, ErrTraceNotWARP) {
		t.Fatalf("warp=off must fail closed, got %v", err)
	}
}

// ---- Pump: round trip, ICMP TooBig synthesis, stall watchdog ----

type memTUN struct {
	mu      sync.Mutex
	out     chan []byte // read by pump (device outbound)
	in      chan []byte // written by pump (device inbound)
	closed  chan struct{}
	once    sync.Once
	readCtx context.Context
}

func newMemTUN() *memTUN {
	return &memTUN{out: make(chan []byte, 16), in: make(chan []byte, 16), closed: make(chan struct{})}
}

func (t *memTUN) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p := <-t.out:
		return p, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.closed:
		return nil, ErrTUNClosed
	}
}

func (t *memTUN) WritePacket(pkt []byte) error {
	select {
	case t.in <- pkt:
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("inbound queue full")
	}
}

func (t *memTUN) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

type fakePumpSession struct {
	mu       sync.Mutex
	inbox    [][]byte // packets the session received (uplink)
	closed   bool
	readable chan []byte
	done     chan struct{}
	failBig  int // MTU used to decide ErrPacketTooBig
}

func newFakePumpSession(mtu int) *fakePumpSession {
	return &fakePumpSession{readable: make(chan []byte, 16), done: make(chan struct{}), failBig: mtu}
}

func (s *fakePumpSession) WritePacket(pkt []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	if len(pkt) > s.failBig {
		return ErrPacketTooBig
	}
	s.inbox = append(s.inbox, pkt)
	return nil
}

func (s *fakePumpSession) ReadPacket(ctx context.Context) ([]byte, error) {
	select {
	case p := <-s.readable:
		return p, nil
	case <-s.done:
		return nil, ErrSessionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *fakePumpSession) Done() <-chan struct{} { return s.done }

func (s *fakePumpSession) uplinkCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.inbox)
}

func TestPumpRoundTripAndICMPTooBig(t *testing.T) {
	tun := newMemTUN()
	sess := newFakePumpSession(100)

	ctx, cancel := context.WithCancel(context.Background())
	reasonCh := make(chan string, 1)
	go func() { reasonCh <- Pump(ctx, PumpConfig{Session: sess, TUN: tun, MTU: 100}) }()
	defer cancel()

	normal := make([]byte, 60)
	tun.out <- normal
	waitUntil(t, "uplink delivered", func() bool { return sess.uplinkCount() == 1 })

	oversized := make([]byte, 200) // > MTU 100, valid IPv4 header start
	oversized[0] = 0x45
	copy(oversized[12:20], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	tun.out <- oversized
	waitUntil(t, "icmp too big synthesized", func() bool {
		select {
		case pkt := <-tun.in:
			if len(pkt) < 20+8 || pkt[9] != 1 { // proto ICMP
				return false
			}
			icmp := pkt[20:]
			if icmp[0] != 3 || icmp[1] != 4 {
				t.Errorf("icmp type/code = %d/%d", icmp[0], icmp[1])
				return true
			}
			if got := binary.BigEndian.Uint16(icmp[6:8]); got != ICMPTunnelMTU {
				t.Errorf("advertised mtu = %d", got)
			}
			if string(icmp[8:8+20]) != string(oversized[:20]) {
				t.Error("embedded original header mismatch")
			}
			sum := checksum32(icmp)
			if fold(sum) != 0xffff {
				t.Error("icmp checksum invalid")
			}
			ipSum := checksum32(pkt[:20])
			if fold(ipSum) != 0xffff {
				t.Error("outer ip checksum invalid")
			}
			// ICMP error src/dst semantics
			if string(pkt[12:16]) != string(oversized[16:20]) || string(pkt[16:20]) != string(oversized[12:16]) {
				t.Error("icmp outer addresses not reversed")
			}
			return true
		default:
			return false
		}
	})
}

func TestPumpStallWatchdog(t *testing.T) {
	tun := newMemTUN()
	sess := newFakePumpSession(1280)

	stalls := 0
	stallDone := make(chan struct{})
	var once sync.Once
	onStall := func() {
		once.Do(func() {
			stalls++
			close(stallDone)
		})
	}

	reasonCh := make(chan string, 1)
	go func() {
		reasonCh <- Pump(context.Background(), PumpConfig{
			Session:             sess,
			TUN:                 tun,
			DownlinkIdleTimeout: 80 * time.Millisecond,
			StallCheckEvery:     15 * time.Millisecond,
			OnStall:             onStall,
		})
	}()

	select {
	case r := <-reasonCh:
		if r != "stall" {
			t.Fatalf("reason = %q", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pump did not report stall")
	}
	<-stallDone
	if stalls != 1 {
		t.Fatalf("OnStall fired %d times", stalls)
	}
}

func TestPumpTerminationReasons(t *testing.T) {
	// Session lost: closing the fake session unblocks downlink and reports.
	tun := newMemTUN()
	sess := newFakePumpSession(1280)
	reasonCh := make(chan string, 1)
	go func() {
		reasonCh <- Pump(context.Background(), PumpConfig{Session: sess, TUN: tun})
	}()
	sess.mu.Lock()
	close(sess.done)
	sess.mu.Unlock()
	select {
	case r := <-reasonCh:
		if r != "session-lost" {
			t.Fatalf("unexpected reason %q", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no termination after session close")
	}

	// Parent cancel: clean stop.
	tun2 := newMemTUN()
	sess2 := newFakePumpSession(1280)
	ctx, cancel := context.WithCancel(context.Background())
	reasonCh2 := make(chan string, 1)
	go func() { reasonCh2 <- Pump(ctx, PumpConfig{Session: sess2, TUN: tun2}) }()
	cancel()
	select {
	case r := <-reasonCh2:
		if r != "stop" {
			t.Fatalf("want stop, got %q", r)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("pump ignored parent cancel")
	}
}

// ---- ControlFlowGuard ----

type recordingApplier struct {
	mu    sync.Mutex
	calls []struct {
		set    string
		add    []string
		remove []string
	}
	failuresLeft int
	errFail      error
}

func (r *recordingApplier) Apply(set string, add, remove []netip.Addr) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failuresLeft > 0 {
		r.failuresLeft--
		return r.errFail
	}
	call := struct {
		set    string
		add    []string
		remove []string
	}{set: set}
	for _, a := range add {
		call.add = append(call.add, a.String())
	}
	for _, a := range remove {
		call.remove = append(call.remove, a.String())
	}
	r.calls = append(r.calls, call)
	return nil
}

func (r *recordingApplier) snapshot() []struct {
	set    string
	add    []string
	remove []string
} {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]struct {
		set    string
		add    []string
		remove []string
	}(nil), r.calls...)
}

func TestControlFlowGuardExclusionLifecycle(t *testing.T) {
	applier := &recordingApplier{}
	ip1 := netip.MustParseAddr("162.159.198.7")
	connected := false
	var connMu sync.Mutex
	log := &eventLogGuard{}

	g, err := NewControlFlowGuard(ControlFlowGuardConfig{
		SetName:       "b4_warp_ctl",
		Apply:         applier,
		ControlIPs:    func() []netip.Addr { return []netip.Addr{ip1} },
		Connected:     func() bool { connMu.Lock(); defer connMu.Unlock(); return connected },
		InstanceID:    "inst-base",
		PollInterval:  10 * time.Millisecond,
		ReassertEvery: 500 * time.Millisecond,
		Sink:          log.sink,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := g.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer g.Stop()

	waitUntil(t, "start authorization emitted", func() bool { return log.count(EvCamouflageAuthorized) >= 1 })

	connMu.Lock()
	connected = true
	connMu.Unlock()
	waitUntil(t, "exclusion applied", func() bool {
		return g.Status().Excluding && len(g.Status().AppliedAddrs) == 1
	})
	waitUntil(t, "cutoff emitted", func() bool { return log.count(EvCamouflageCutoff) >= 1 })
	if st := g.Status(); st.Cutoffs != 1 {
		t.Fatalf("cutoffs = %d", st.Cutoffs)
	}

	connMu.Lock()
	connected = false
	connMu.Unlock()
	waitUntil(t, "exclusion removed", func() bool {
		return !g.Status().Excluding && len(g.Status().AppliedAddrs) == 0
	})
	waitUntil(t, "re-arm authorized", func() bool { return log.count(EvCamouflageAuthorized) >= 2 })

	auth := g.Status().LastAuthorization
	if auth.Purpose != "camouflage" || auth.InstanceID != "inst-base" || !auth.Valid(genOf(nil), genOf(nil)) {
		t.Fatalf("last authorization = %+v", auth)
	}
}

func TestControlFlowGuardReassertAndRetries(t *testing.T) {
	applier := &recordingApplier{failuresLeft: 2, errFail: errors.New("ipset busy")}
	ip1 := netip.MustParseAddr("162.159.198.7")
	g, err := NewControlFlowGuard(ControlFlowGuardConfig{
		SetName:       "b4_warp_ctl",
		Apply:         applier,
		ControlIPs:    func() []netip.Addr { return []netip.Addr{ip1} },
		Connected:     func() bool { return true },
		PollInterval:  5 * time.Millisecond,
		ReassertEvery: 40 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	defer g.Stop()

	waitUntil(t, "applied despite initial failures", func() bool {
		st := g.Status()
		return st.ApplyErrors == 2 && len(st.AppliedAddrs) == 1
	})
	// Reassert cadence produces repeated identical adds while connected.
	waitUntil(t, "reassert ticks", func() bool {
		n := 0
		for _, c := range applier.snapshot() {
			if len(c.add) == 1 && c.add[0] == ip1.String() {
				n++
			}
		}
		return n >= 3
	})
}

func TestNewControlFlowGuardRejectsBadConfig(t *testing.T) {
	okIPs := func() []netip.Addr { return nil }
	base := ControlFlowGuardConfig{
		SetName:    "set",
		Apply:      SetApplierFunc(func(string, []netip.Addr, []netip.Addr) error { return nil }),
		ControlIPs: okIPs,
		Connected:  func() bool { return false },
	}
	if _, err := NewControlFlowGuard(base); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	noSet := base
	noSet.SetName = ""
	if _, err := NewControlFlowGuard(noSet); !errors.Is(err, ErrGuardConfig) {
		t.Fatalf("missing set accepted")
	}
	noApply := base
	noApply.Apply = nil
	if _, err := NewControlFlowGuard(noApply); !errors.Is(err, ErrGuardConfig) {
		t.Fatalf("nil applier accepted")
	}
}

// ---- enrollment hostlist contract ----

func TestEnrollmentHostlistContract(t *testing.T) {
	empty := MissingWarpControlDomains(nil)
	if len(empty) != len(WarpControlDomains()) {
		t.Fatalf("empty catalog missing = %v", empty)
	}
	full := MergeWarpControlDomains([]string{"youtube.com"})
	if m := MissingWarpControlDomains(full); len(m) != 0 {
		t.Fatalf("merged catalog still missing %v", m)
	}
	// Subdomain coverage both directions counts as covered.
	sub := []string{"edge.api.cloudflareclient.com"}
	if m := MissingWarpControlDomains(sub); len(m) != len(WarpControlDomains())-1 {
		t.Fatalf("subdomain not credited: %v", m)
	}
	// Enrollment API host is part of the canonical set (z2k #16).
	found := false
	for _, d := range WarpControlDomains() {
		if d == EnrollHostAPI {
			found = true
		}
	}
	if !found {
		t.Fatal("enrollment api host missing from canonical set")
	}
}

// eventLogGuard collects guard events (mirrors nonru eventLog shape).
type eventLogGuard struct {
	mu  sync.Mutex
	evs []GuardEvent
}

func (l *eventLogGuard) sink(ev GuardEvent) {
	l.mu.Lock()
	l.evs = append(l.evs, ev)
	l.mu.Unlock()
}

func (l *eventLogGuard) count(name string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.evs {
		if e.Name == name {
			n++
		}
	}
	return n
}
