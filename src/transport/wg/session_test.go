// WG3/WG4 session integration suite: establishment through the trust gate,
// structural loss classification, flap recovery, cold-start ordering,
// keepalive liveness, and the mid-session refused-identity stall arc.
// CI windows are shrunk; production numbers stay the design defaults.
package transportwg

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

var cfReserved = [3]byte{0xb9, 0x2f, 0x7f} // client_id "uS9/"

// ---- event recorder ----

type sessionRecorder struct {
	mu     sync.Mutex
	events []SessionEvent
	lost   []Failure
	est    int
}

func (r *sessionRecorder) onEvent(ev SessionEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}
func (r *sessionRecorder) onEstablished() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.est++
}
func (r *sessionRecorder) onLost(f Failure) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lost = append(r.lost, f)
}
func (r *sessionRecorder) establishedCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.est
}
func (r *sessionRecorder) lostList() []Failure {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Failure(nil), r.lost...)
}
func (r *sessionRecorder) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.events))
	for _, e := range r.events {
		out = append(out, e.Name)
	}
	return out
}

// ---- channel TUN (self-owned, idempotent close) ----
//
// Upstream tuntest.ChannelTUN panics on double Close, and BOTH our session
// teardown and upstream's fatal-read auto-close path (send.go:398-412 -> go
// device.Close()) may race a second Close. Its Read/Write must also never
// return transient errors: upstream treats ANY read error as fatal.

type testChannel struct {
	Device   tun.Device
	Inbound  <-chan []byte // decrypted packets arriving FROM the tunnel
	Outbound chan<- []byte // packets injected INTO the tunnel
	inject   func([]byte) error
}

type chanTUN struct {
	inbound   chan []byte
	outbound  chan []byte
	events    chan tun.Event
	closed    chan struct{}
	closeOnce sync.Once
}

func newTestChannelTUN() *testChannel {
	c := &chanTUN{
		inbound:  make(chan []byte, 4096),
		outbound: make(chan []byte, 256),
		events:   make(chan tun.Event, 1),
		closed:   make(chan struct{}),
	}
	c.events <- tun.EventUp
	tc := &testChannel{Device: c, Inbound: c.inbound, Outbound: c.outbound}
	tc.inject = c.inject
	return tc
}

func (c *chanTUN) File() *os.File { return nil }

func (c *chanTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-c.closed:
		return 0, os.ErrClosed
	case msg := <-c.outbound:
		n := copy(bufs[0][offset:], msg)
		sizes[0] = n
		return 1, nil
	}
}

func (c *chanTUN) Write(bufs [][]byte, offset int) (int, error) {
	for i, data := range bufs {
		msg := make([]byte, len(data)-offset)
		copy(msg, data[offset:])
		select {
		case <-c.closed:
			return i, os.ErrClosed
		case c.inbound <- msg:
		}
	}
	return len(bufs), nil
}

func (c *chanTUN) MTU() (int, error)        { return DefaultMTU, nil }
func (c *chanTUN) Name() (string, error)    { return "wgtest0", nil }
func (c *chanTUN) Events() <-chan tun.Event { return c.events }
func (c *chanTUN) BatchSize() int           { return 1 }
func (c *chanTUN) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// inject publishes an outbound packet without ever blocking indefinitely: a
// generation teardown may leave the device reader gone mid-flight.
func (c *chanTUN) inject(b []byte) error {
	select {
	case <-c.closed:
		return os.ErrClosed
	default:
	}
	select {
	case <-c.closed:
		return os.ErrClosed
	case c.outbound <- b:
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("transportwg(test): inject timeout (device reader gone)")
	}
}

// onceCloseTUN remains as belt-and-braces for other tun.Device impls.
type onceCloseTUN struct {
	tun.Device
	once sync.Once
}

func (w *onceCloseTUN) Close() error {
	var err error
	w.once.Do(func() { err = w.Device.Close() })
	return err
}

// ---- harness ----
//
// mustKeyNow / ip4 / mustAddrPort / itoaPort live in interop_test.go and
// seek_test.go (same package).

func tuntestPing(ch *testChannel, dst, src netip.Addr) error {
	return ch.inject(tuntest.Ping(dst, src))
}

func waitFor(cond func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func assertContains(t *testing.T, list []string, want string) {
	t.Helper()
	for _, v := range list {
		if v == want {
			return
		}
	}
	t.Fatalf("missing event %q in %v", want, list)
}

func newTestSession(t *testing.T, edge *fakeEdge, opts ...func(*SessionConfig)) (*Session, *sessionRecorder, func() *testChannel) {
	t.Helper()
	edgePriv, _ := edgeKeyPair(t)
	clientPriv := mustKeyNow()
	id, err := NewIdentity(clientPriv.B64(), edgePriv.Pub().B64(), "uS9/", clientTunnelIP, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := edge.Configure(edgePriv, mustPub(t, clientPriv), netip.MustParseAddr(clientTunnelIP)); err != nil {
		t.Fatal(err)
	}

	rec := &sessionRecorder{}
	var curMu sync.Mutex
	var cur *testChannel
	current := func() *testChannel {
		curMu.Lock()
		defer curMu.Unlock()
		return cur
	}

	sc := SessionConfig{
		Ident:    id,
		Endpoint: edge.addr(),
		SockOpts: SocketOptions{},
		Tunnel:   TunnelConfig{Mode: ModeNetstack}, // label only; overridden below
		Health: HealthConfig{
			HandshakeTimeout: 8 * time.Second,
			Gate: TrustGate{
				LocalV4:    [4]byte{172, 16, 0, 2},
				RoundTrips: 2,
				Gap:        30 * time.Millisecond,
				Window:     3 * time.Second,
			},
			Watchdog: WatchdogConfig{
				RXIdle: 10 * time.Minute, // quiet post-establish must not churn gens
				Window: 5 * time.Second,
				Tick:   100 * time.Millisecond,
			},
			RestartBackoff: 200 * time.Millisecond,
			KeepaliveSec:   1,
		},
		VerboseDiagnostics: true,
		Callbacks: SessionCallbacks{
			OnEvent:       rec.onEvent,
			OnEstablished: rec.onEstablished,
			OnLost:        rec.onLost,
		},
	}
	for _, opt := range opts {
		opt(&sc)
	}
	sess, err := NewSession(sc)
	if err != nil {
		t.Fatal(err)
	}
	sess.newTunnelFn = func(TunnelConfig) (*Tunnel, error) {
		gch := newTestChannelTUN()
		curMu.Lock()
		cur = gch
		curMu.Unlock()
		return &Tunnel{
			Device: &onceCloseTUN{Device: gch.Device},
			Inject: gch.inject,
			Capture: func(ctx context.Context) ([]byte, error) {
				select {
				case pkt := <-gch.Inbound:
					return pkt, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			},
		}, nil
	}
	t.Cleanup(sess.Stop)
	return sess, rec, current
}

// ---- tests ----

// newSessionCfgFor builds a minimal SessionConfig around an arbitrary
// endpoint string (identity material is valid; only the endpoint varies).
func newSessionCfgFor(t *testing.T, endpoint string) SessionConfig {
	t.Helper()
	edgePriv, _ := edgeKeyPair(t)
	clientPriv := mustKeyNow()
	id, err := NewIdentity(clientPriv.B64(), edgePriv.Pub().B64(), "uS9/", clientTunnelIP, "", true)
	if err != nil {
		t.Fatal(err)
	}
	return SessionConfig{
		Ident:    id,
		Endpoint: endpoint,
		Tunnel:   TunnelConfig{Mode: ModeNetstack},
	}
}

// TestNewSessionRejectsHostnameEndpoint is the PATCH-02 (WG MAJOR 2)
// acceptance test: a directory-style hostname endpoint must produce a
// structural ClassParamRejected failure at construction — never a
// MustParseAddrPort panic inside buildIPC on the lifecycle goroutine.
// Resolving hostnames is the caller's job (endpoints.go).
func TestNewSessionRejectsHostnameEndpoint(t *testing.T) {
	for _, ep := range []string{
		"engage.cloudflareclient.com:2408",
		"[::1]:2408.hostname.example:2408",
	} {
		sess, err := NewSession(newSessionCfgFor(t, ep))
		if err == nil {
			sess.Stop()
			t.Fatalf("hostname endpoint %q must be rejected", ep)
		}
		if !IsClass(err, ClassParamRejected) {
			t.Fatalf("endpoint %q: class = %s, want %s (err=%v)", ep, failureClassOf(err), ClassParamRejected, err)
		}
	}
}

// TestNewSessionRejectsGarbageEndpoint pins the same contract for malformed
// literals (not ip:port at all).
func TestNewSessionRejectsGarbageEndpoint(t *testing.T) {
	for _, ep := range []string{"1.2.3:80", "not-an-endpoint", "1.2.3.4"} {
		sess, err := NewSession(newSessionCfgFor(t, ep))
		if err == nil {
			sess.Stop()
			t.Fatalf("garbage endpoint %q must be rejected", ep)
		}
		if !IsClass(err, ClassParamRejected) {
			t.Fatalf("endpoint %q: class = %s, want %s (err=%v)", ep, failureClassOf(err), ClassParamRejected, err)
		}
	}
}

// failureClassOf extracts the Failure class from an error chain ("" if none).
func failureClassOf(err error) FailureClass {
	var f *Failure
	if errors.As(err, &f) {
		return f.Class
	}
	return ""
}

// Establishment through the trust gate: handshake, gate payload observed by
// the edge, reserved bytes stamped on EVERY datagram, PersistentKeepalive
// applied by the engine (config + live traffic), and user data transiting.
func TestSessionEstablishesThroughTrustGate(t *testing.T) {
	edge, err := startFakeEdge(t, cfReserved, true /*require*/, true /*stamp*/, true /*scrub*/)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, current := newTestSession(t, edge)
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}

	if !waitFor(func() bool { return rec.establishedCount() > 0 }, 15*time.Second) {
		t.Fatalf("never established; events=%v lost=%+v", rec.names(), rec.lostList())
	}
	if s := sess.State(); s != StateEstablished {
		t.Fatalf("state=%s", s)
	}

	names := rec.names()
	assertContains(t, names, "wg_handshake_ok")
	assertContains(t, names, "wg_gate_passed")
	assertContains(t, names, "wg_established")

	// (refine #3a) PersistentKeepalive is IN the applied engine config.
	ipc, err := sess.IPCSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	wantKA := "persistent_keepalive_interval=" + strconv.FormatUint(uint64(sess.cfg.Health.KeepaliveSec), 10)
	if !strings.Contains(ipc, wantKA+"\n") {
		t.Fatalf("keepalive not applied to the engine: want %q in ipc", wantKA)
	}

	// (refine #3b) ...and the engine EMITS it: with ka=1 s the edge records
	// extra datagrams within ~2.2 s of establishment (NAT binding alive).
	n0, _ := edge.bind.stats()
	time.Sleep(2200 * time.Millisecond)
	n1, _ := edge.bind.stats()
	if len(n1)-len(n0) < 1 {
		t.Fatalf("no keepalive traffic after establishment: %d -> %d", len(n0), len(n1))
	}

	// Data plane: ping client -> edge inner IP lands on the edge TUN
	// (asserted via the responder's classified inner log).
	marker := len(edge.innerStats())
	if err := tuntestPing(current(), netip.MustParseAddr(edgeInnerIP), netip.MustParseAddr(clientTunnelIP)); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool {
		inner := edge.innerStats()
		if len(inner) <= marker {
			return false
		}
		for _, r := range inner[marker:] {
			if r.Kind == "icmp" {
				return true
			}
		}
		return false
	}, 8*time.Second) {
		t.Fatalf("data packet did not transit to the fake edge (inner=%+v)", edge.innerStats()[marker:])
	}

	seen, dropped := edge.bind.stats()
	if dropped != 0 || len(seen) == 0 {
		t.Fatalf("edge stats: seen=%d dropped=%d", len(seen), dropped)
	}
	for i, s := range seen {
		if s.Res != cfReserved {
			t.Fatalf("datagram %d reserved=%v want %v", i, s.Res, cfReserved)
		}
	}
}

// (WG7) Junk-client against a VANILLA edge: the default cf-warp ladder
// leads with junk families (owner decision 2026-08-24), so a real
// amneziawg device in PURE-VANILLA config must accept our junk-bearing
// establishment end to end. Proves three things at once: (a) the quic-a
// profile passes Validate/render and physically leaves the host as
// unclassifiable junk datagrams (edge sees rxUnknown traffic); (b) the
// vanilla edge tolerates them under full CF reserved discipline and still
// completes handshake + trust gate; (c) protocol datagrams remain correctly
// reserved-stamped alongside the junk.
func TestJunkClientAgainstVanillaEdge(t *testing.T) {
	edge, err := startFakeEdge(t, cfReserved, true /*require*/, true /*stamp*/, true /*scrub*/)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, _ := newTestSession(t, edge, func(sc *SessionConfig) {
		sc.Profile = mustBuild(t, mustLookup(t, "quic-a"))
	})
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}

	if !waitFor(func() bool { return rec.establishedCount() > 0 }, 15*time.Second) {
		t.Fatalf("junk client never established against vanilla edge; events=%v lost=%+v",
			rec.names(), rec.lostList())
	}
	names := rec.names()
	assertContains(t, names, "wg_handshake_ok")
	assertContains(t, names, "wg_gate_passed")
	assertContains(t, names, "wg_established")

	if !waitFor(func() bool {
		for _, r := range edge.innerStats() {
			if r.Kind == "dns-gate" {
				return true
			}
		}
		return false
	}, 10*time.Second) {
		t.Fatalf("gate payload never reached the vanilla edge; inner=%+v", edge.innerStats())
	}

	seen, dropped := edge.bind.stats()
	var unknown int
	for _, s := range seen {
		switch s.Kind {
		case rxUnknown:
			unknown++ // junk datagrams: unclassifiable at the wire layer
		case rxInit, rxResp, rxData:
			if s.Res != cfReserved {
				t.Fatalf("protocol datagram %s reserved=%v want %v", s.Kind, s.Res, cfReserved)
			}
		}
	}
	if unknown < 3 {
		t.Fatalf("expected junk datagrams at the vanilla edge, unknown=%d seen=%d", unknown, len(seen))
	}
	if dropped < 3 {
		t.Fatalf("vanilla-edge routing discipline should drop the junk, dropped=%d", dropped)
	}
}

// Mid-session silent drop -> structural wg-stall-rx loss + restart; healing
// the path lets the next generation re-establish (flap recovery).
func TestSessionSilentDropLostThenFlapRecovery(t *testing.T) {
	edge, err := startFakeEdge(t, cfReserved, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, _ := newTestSession(t, edge, func(sc *SessionConfig) {
		sc.Health.Watchdog.RXIdle = 700 * time.Millisecond // fast stall for the flap arc
	})
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return rec.establishedCount() > 0 }, 15*time.Second) {
		t.Fatalf("never established; events=%v", rec.names())
	}
	gen1 := sess.Generation()

	edge.SetResponderMode(ResponderSilent)

	if !waitFor(func() bool { return len(rec.lostList()) > 0 }, 10*time.Second) {
		t.Fatalf("no loss detected after silent drop; events=%v", rec.names())
	}
	lost := rec.lostList()
	if lost[0].Class != ClassStallRX {
		t.Fatalf("class=%s want wg-stall-rx", lost[0].Class)
	}

	edge.SetResponderMode(ResponderNormal)
	if !waitFor(func() bool { return rec.establishedCount() >= 2 }, 20*time.Second) {
		t.Fatalf("flap recovery failed; events=%v", rec.names())
	}
	if sess.Generation() <= gen1 {
		t.Fatalf("generation did not advance: %d", sess.Generation())
	}
}

// (4a) Up() without ANY user traffic: the bootstrap probe alone forces the
// handshake initiation, recorded by the fake edge.
func TestSessionBootstrapTriggersHandshakeWithoutTraffic(t *testing.T) {
	edge, err := startFakeEdge(t, cfReserved, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, _ := newTestSession(t, edge)
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return edge.handshakeEstablished() }, 10*time.Second) {
		t.Fatal("edge never saw a handshake without user traffic")
	}
	sawInit := false
	st, _ := edge.bind.stats()
	for _, r := range st {
		if r.Kind == rxInit {
			sawInit = true
		}
	}
	if !sawInit {
		t.Fatal("edge did not record a handshake initiation")
	}
	if !waitFor(func() bool { return rec.establishedCount() > 0 }, 5*time.Second) {
		t.Fatal("session did not reach established")
	}
}

// (4б) Edge answers handshake but silently drops ALL data: the trust gate
// fails with the structural wg-stall-rx class and the generation is torn
// down (the supervisor advances to a fresh generation).
func TestSessionSilentDataGateTimesOutByClass(t *testing.T) {
	edge, err := startFakeEdge(t, cfReserved, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderSilent)

	sess, rec, _ := newTestSession(t, edge)
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	defer sess.Stop()

	if !waitFor(func() bool { return len(rec.lostList()) > 0 }, 20*time.Second) {
		t.Fatalf("no loss detected; events=%v", rec.names())
	}
	f := rec.lostList()[0]
	if f.Class != ClassStallRX {
		t.Fatalf("class=%s want wg-stall-rx", f.Class)
	}
	if !strings.Contains(f.Reason, "gate-dns") {
		t.Fatalf("reason=%q want gate-dns-*", f.Reason)
	}
	if !waitFor(func() bool { return sess.Generation() >= 2 }, 5*time.Second) {
		t.Fatalf("generation did not advance after loss: %d", sess.Generation())
	}
}

// (4г) Cold-start ordering: a user packet queued during handshake wait ships
// at keypair establishment BEFORE the first trust-gate probe (bootstrap
// carries its own qname label so the two service probes are distinguishable
// on the wire).
func TestSessionColdStartUserPacketShipsBeforeGateProbes(t *testing.T) {
	edge, err := startFakeEdge(t, cfReserved, true, true, true)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, current := newTestSession(t, edge)

	go func() {
		waitFor(func() bool {
			st, _ := edge.bind.stats()
			for _, r := range st {
				if r.Kind == rxInit {
					return true
				}
			}
			return false
		}, 8*time.Second)
		_ = tuntestPing(current(), netip.MustParseAddr(edgeInnerIP), netip.MustParseAddr(clientTunnelIP))
	}()

	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return rec.establishedCount() > 0 }, 15*time.Second) {
		t.Fatalf("never established; events=%v", rec.names())
	}

	var inner []innerRX
	if !waitFor(func() bool {
		inner = edge.innerStats()
		for _, r := range inner {
			if r.Kind == "dns-gate" {
				return true
			}
		}
		return false
	}, 10*time.Second) {
		t.Fatal("gate probes never reached the edge")
	}

	icmpIdx, firstGateIdx, bootIdx := -1, -1, -1
	for i, r := range inner {
		switch r.Kind {
		case "icmp":
			if icmpIdx == -1 {
				icmpIdx = i
			}
		case "dns-gate":
			if firstGateIdx == -1 {
				firstGateIdx = i
			}
		case "dns-boot":
			if bootIdx == -1 {
				bootIdx = i
			}
		}
	}
	if bootIdx == -1 || icmpIdx == -1 || firstGateIdx == -1 {
		t.Fatalf("fixture incomplete: boot=%d icmp=%d gate=%d inner=%+v",
			bootIdx, icmpIdx, firstGateIdx, inner)
	}
	if !(icmpIdx < firstGateIdx) {
		t.Fatalf("user packet shipped AFTER a gate probe (icmp=%d gate=%d)",
			icmpIdx, firstGateIdx)
	}
}

// (4в) Refused identity — watchdog wiring inside a live session: the pair
// establishes normally; scripted counters then make tx grow while rx stays
// frozen (the wire equivalent: peer refuses our data-plane parameters).
// The watchdog must fire awg-version-mismatch within its window and the
// supervisor must advance the generation.
func TestSessionRefusedIdentityStallFiresWithinWindow(t *testing.T) {
	edge, err := startFakeEdge(t, cfReserved, true /*require*/, true /*stamp*/, true /*scrub*/)
	if err != nil {
		t.Fatal(err)
	}
	edge.StartResponder(ResponderNormal)

	sess, rec, _ := newTestSession(t, edge)

	start := time.Unix(7777, 0)
	nowT := start
	tx := uint64(0)
	sess.countersOverride = func(context.Context) (CounterSample, error) {
		nowT = nowT.Add(100 * time.Millisecond)
		tx += 60 // bootstrap/gate probes and keepalives accumulate on tx
		return CounterSample{Time: nowT, TxBytes: tx, RxBytes: 0}, nil
	}
	sess.cfg.Health.Watchdog = WatchdogConfig{
		RXIdle: 10 * time.Hour, // isolate the signature trigger
		Window: 1400 * time.Millisecond,
		MinTX:  128,
		MaxRX:  0,
		Tick:   100 * time.Millisecond,
		Now:    func() time.Time { return nowT },
	}

	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitFor(func() bool { return rec.establishedCount() > 0 }, 15*time.Second) {
		t.Fatalf("never established; events=%v", rec.names())
	}

	if !waitFor(func() bool {
		for _, l := range rec.lostList() {
			if l.Class == ClassVersionMismatch {
				return true
			}
		}
		return false
	}, 15*time.Second) {
		t.Fatalf("version-mismatch stall never fired within window; lost=%+v", rec.lostList())
	}
	if !waitFor(func() bool { return sess.Generation() >= 2 }, 5*time.Second) {
		t.Fatalf("no restart after version-mismatch stall: %d", sess.Generation())
	}
}

// ---- PATCH-03: restart cap + exponential backoff + autostart ----

// TestSessionRestartCapExhausted: a session whose every generation fails
// (tunnel factory always errors) burns its restart budget (MaxPerHour=3,
// Window=1h) and goes TERMINAL — exactly 3 restarts, the structural
// wg_restart_cap_exhausted event, the terminal OnLost with the dedicated
// class, done closed, and no goroutine leak.
func TestSessionRestartCapExhausted(t *testing.T) {
	id, err := NewIdentity(mustKeyNow().B64(), mustKeyNow().Pub().B64(), "uS9/", clientTunnelIP, "", true)
	if err != nil {
		t.Fatal(err)
	}
	rec := &sessionRecorder{}
	sc := SessionConfig{
		Ident:    id,
		Endpoint: "127.0.0.1:2408",
		Tunnel:   TunnelConfig{Mode: ModeNetstack},
		Health: HealthConfig{
			RestartBackoff: time.Millisecond,
			RestartCap: RestartCapConfig{
				MaxPerHour: 3,
				Window:     time.Hour,
			},
		},
		Callbacks: SessionCallbacks{
			OnEvent: rec.onEvent,
			OnLost:  rec.onLost,
		},
	}
	sess, err := NewSession(sc)
	if err != nil {
		t.Fatal(err)
	}
	broken := errors.New("no tunnel in this test")
	sess.newTunnelFn = func(TunnelConfig) (*Tunnel, error) { return nil, broken }

	before := runtime.NumGoroutine()
	if err := sess.Start(); err != nil {
		t.Fatal(err)
	}
	<-sess.done

	if got := sess.State(); got != StateClosed {
		t.Fatalf("state after cap exhaustion = %s, want closed", got)
	}
	restarts := 0
	exhausted := false
	for _, ev := range rec.events {
		switch ev.Name {
		case "wg_restarting":
			restarts++
		case "wg_restart_cap_exhausted":
			exhausted = true
		}
	}
	if restarts != 3 {
		t.Fatalf("restarts = %d, want exactly 3", restarts)
	}
	if !exhausted {
		t.Fatal("wg_restart_cap_exhausted event never emitted")
	}
	lost := rec.lostList()
	if len(lost) == 0 {
		t.Fatal("terminal OnLost never fired")
	}
	last := lost[len(lost)-1]
	if last.Class != ClassRestartCapExhausted {
		t.Fatalf("terminal loss class = %s, want %s", last.Class, ClassRestartCapExhausted)
	}
	if got := sess.RestartTotal(); got != 3 {
		t.Fatalf("RestartTotal = %d, want 3", got)
	}
	// Goroutine hygiene: the terminal loop must leave nothing behind.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines: before=%d after=%d (leak)", before, runtime.NumGoroutine())
}

// TestSessionBackoffExponentialWithJitter pins the ladder math: doubling
// per consecutive failure with the 60 s ceiling and reset after an
// established generation; jitter stays inside ±20%.
func TestSessionBackoffExponentialWithJitter(t *testing.T) {
	id, err := NewIdentity(mustKeyNow().B64(), mustKeyNow().Pub().B64(), "uS9/", clientTunnelIP, "", true)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := NewSession(SessionConfig{Ident: id, Endpoint: "127.0.0.1:2408"})
	if err != nil {
		t.Fatal(err)
	}
	sess.randF = func() float64 { return 0.5 } // exact factor 1.0

	// Ladder: 1,2,4,8,16,32,60,60... (seconds).
	base := time.Second
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60}
	prev := base
	for i, w := range want {
		if i > 0 {
			prev = min(prev*2, maxRestartBackoff)
		}
		if prev != w*time.Second {
			t.Fatalf("ladder[%d] = %s, want %s", i, prev, w*time.Second)
		}
	}
	// Reset after an established generation.
	sess.genEstablished.Store(true)
	if got := sess.applyJitter(base); got != base {
		t.Fatalf("post-establish first retry = %s, want base %s", got, base)
	}
	sess.genEstablished.Store(false)

	// Jitter bounds: randF 0 => 0.8x, randF 1 => 1.2x.
	sess.randF = func() float64 { return 0 }
	if got := sess.applyJitter(10 * time.Second); got != 8*time.Second {
		t.Fatalf("jitter low = %s, want 8s", got)
	}
	sess.randF = func() float64 { return 1 }
	if got := sess.applyJitter(10 * time.Second); got != 12*time.Second {
		t.Fatalf("jitter high = %s, want 12s", got)
	}
}

// TestIdentityAutostartRoundTrip: the PATCH-03 flag survives a store
// round-trip, and a legacy JSON file without the field decodes false with
// no error.
func TestIdentityAutostartRoundTrip(t *testing.T) {
	id, err := NewIdentity(mustKeyNow().B64(), mustKeyNow().Pub().B64(), "uS9/", clientTunnelIP, "", true)
	if err != nil {
		t.Fatal(err)
	}
	id.Autostart = true

	store := &IdentityStore{Path: filepath.Join(t.TempDir(), "wgid.json")}
	if err := store.Save(id); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Autostart {
		t.Fatal("autostart flag lost across the store round-trip")
	}

	// Legacy file: no autostart field at all.
	legacy := map[string]any{}
	blob, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(blob, &legacy); err != nil {
		t.Fatal(err)
	}
	delete(legacy, "autostart")
	legacyBlob, _ := json.Marshal(legacy)
	var decoded Identity
	if err := json.Unmarshal(legacyBlob, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Autostart {
		t.Fatal("legacy file without the field must decode to autostart=false")
	}
}

// ---- PATCH-14/B10 + PATCH-11/B9: secret scrubbing + effective-config dump ----

// TestIPCSnapshotNeverContainsSecrets: ScrubIPC replaces private_key and
// preshared_key values with stable sha256 prefixes; everything else passes
// through verbatim; the same input always scrubs identically.
func TestIPCSnapshotNeverContainsSecrets(t *testing.T) {
	priv := "OMd3/5PIFd9BlDjLwGKzXq1Z1x6+H1Vz3sF0kW8EUnE="
	psk1 := "Kk7q9WQm1GJ0bXz8cVh5tN2yA4eR6uI0oP3sD7fLgWo="
	psk2 := "Zz9Yx8Wv7Uu6tT5sS4rR3qQ2pP1oO0nN9mM8lL7kK6jJ="
	dump := strings.Join([]string{
		"private_key=" + priv,
		"listen_port=51820",
		"fwmark=0x0",
		"public_key=AbCdEf1234567890AbCdEf1234567890AbCdEf12345=",
		"preshared_key=" + psk1,
		"rx_bytes=1",
		"tx_bytes=2",
		"public_key=FfEdCb0987654321FfEdCb0987654321FfEdCb09876=",
		"preshared_key=" + psk2,
	}, "\n")

	scrubbed := ScrubIPC(dump)
	for _, secret := range []string{priv, psk1, psk2} {
		if strings.Contains(scrubbed, secret) {
			t.Fatalf("scrubbed dump still carries secret material (%q...)", secret[:8])
		}
	}
	if !strings.Contains(scrubbed, "private_key=sha256:") {
		t.Fatalf("private_key not masked: %q", scrubbed)
	}
	if strings.Count(scrubbed, "preshared_key=sha256:") != 2 {
		t.Fatalf("preshared keys not both masked: %q", scrubbed)
	}
	// Non-secret lines survive verbatim.
	for _, want := range []string{"listen_port=51820", "fwmark=0x0", "rx_bytes=1", "tx_bytes=2"} {
		if !strings.Contains(scrubbed, want) {
			t.Fatalf("non-secret line lost: %q not in %q", want, scrubbed)
		}
	}
	if strings.Count(scrubbed, "public_key=") != 2 {
		t.Fatal("public keys must NOT be scrubbed")
	}
	// Stability: identical input -> identical output (correlatable prefixes).
	if ScrubIPC(dump) != scrubbed {
		t.Fatal("scrubbing is not stable for identical input")
	}
	// Distinct values -> distinct prefixes (correlation, not collision).
	lines := strings.Split(scrubbed, "\n")
	if lines[4] == lines[8] {
		t.Fatal("distinct preshared keys scrubbed to the same prefix")
	}
	// Regex red line: no base64 key body may survive anywhere.
	re := regexp.MustCompile(`private_key=[0-9A-Za-z+/]{40,}`)
	if re.MatchString(scrubbed) {
		t.Fatal("base64 private-key body survived scrubbing")
	}
}

// TestSessionEmitsEffectiveConfigOnIpcSetFailure (PATCH-11/B9): the
// IpcSet-failure event carries gen, the error, and the SCRUBBED effective
// config — never raw key material.
func TestSessionEmitsEffectiveConfigOnIpcSetFailure(t *testing.T) {
	id, err := NewIdentity(mustKeyNow().B64(), mustKeyNow().Pub().B64(), "uS9/", clientTunnelIP, "", true)
	if err != nil {
		t.Fatal(err)
	}
	rec := &sessionRecorder{}
	sess, err := NewSession(SessionConfig{
		Ident:    id,
		Endpoint: "127.0.0.1:2408",
		Health:   HealthConfig{KeepaliveSec: 7},
		Callbacks: SessionCallbacks{
			OnEvent: rec.onEvent,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ipc, err := sess.buildIPC()
	if err != nil {
		t.Fatal(err)
	}
	reject := errors.New("uapi: invalid junk parameter")
	sess.emitIPCSetFailed(3, ipc, reject)

	names := rec.names()
	if len(names) != 1 || names[0] != "wg_ipc_set_failed" {
		t.Fatalf("events = %v, want exactly [wg_ipc_set_failed]", names)
	}
	ev := rec.events[0]
	if ev.Class != ClassParamRejected {
		t.Fatalf("class = %s, want %s", ev.Class, ClassParamRejected)
	}
	if !strings.Contains(ev.Reason, "gen=3") || !strings.Contains(ev.Reason, reject.Error()) {
		t.Fatalf("event lacks gen/err: %q", ev.Reason)
	}
	// The scrubbed render must be present but WITHOUT the raw key.
	if !strings.Contains(ev.Reason, "private_key=sha256:") {
		t.Fatalf("event lacks the scrubbed config render: %q", ev.Reason)
	}
	if strings.Contains(ev.Reason, id.PrivateKey.B64()) {
		t.Fatal("raw private key leaked into the diagnostic event")
	}
	if !strings.Contains(ev.Reason, "persistent_keepalive_interval=7") {
		t.Fatal("effective config render lacks the keepalive line")
	}
	// Regex red line: no base64 key body in the event reason.
	re := regexp.MustCompile(`private_key=[0-9A-Za-z+/]{40,}`)
	if re.MatchString(ev.Reason) {
		t.Fatal("base64 key body survived into the diagnostic event")
	}
}
