package nested

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	twg "github.com/daniellavrushin/b4/transport/wg"
)

func validPair() PairConfig {
	return PairConfig{
		Outer: LayerSpec{
			Kind: KindMasqueH2, IdentitySlot: SlotPrimary,
			ProfileID: "cf-warp/vanilla-off", Endpoint: netip.MustParseAddrPort("162.159.192.1:443"),
		},
		Inner: LayerSpec{
			Kind: KindAWG, IdentitySlot: SlotSecondary,
			ProfileID: "awg/quic-a", Endpoint: netip.MustParseAddrPort("10.66.66.1:51820"),
		},
	}
}

func TestPairConfigValidateTable(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*PairConfig)
		wantErr error
	}{
		{"happy-m+w", func(*PairConfig) {}, nil},
		{"happy-w-w", func(p *PairConfig) {
			p.Outer.Kind = KindAWG
			p.Outer.Endpoint = netip.MustParseAddrPort("162.159.193.10:2408")
		}, nil},
		{"bad-inner-kind", func(p *PairConfig) { p.Inner.Kind = "vless" }, ErrBadKind},
		{"inner-slot-primary", func(p *PairConfig) { p.Inner.IdentitySlot = SlotPrimary }, ErrBadSlot},
		{"edge-collision", func(p *PairConfig) {
			p.Inner.Endpoint = netip.MustParseAddrPort("162.159.192.1:51820")
		}, ErrEdgeCollision},
		{"mtu-over-cap", func(p *PairConfig) { p.Inner.MTU = 1280 }, nil}, // see explicit test below
		{"bad-failure-mode", func(p *PairConfig) { p.FailureMode = "best-effort" }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validPair()
			tc.mutate(&cfg)
			err := cfg.Validate()
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("validate err = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && err != nil &&
				tc.name != "mtu-over-cap" && tc.name != "bad-failure-mode" {
				t.Fatalf("validate unexpected error: %v", err)
			}
		})
	}

	// Explicit expectations for the two table entries asserted by content.
	mtu := validPair()
	mtu.Inner.MTU = 1400
	if err := mtu.Validate(); err == nil || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("mtu cap err = %v", err)
	}
	fm := validPair()
	fm.FailureMode = "best-effort"
	if err := fm.Validate(); err == nil || !strings.Contains(err.Error(), "failure_mode") {
		t.Fatalf("failure_mode err = %v", err)
	}
}

func TestResolveCarrierAutoRules(t *testing.T) {
	// MASQUE outer always resolves to the datagram plane.
	mw := validPair()
	got, err := ResolveCarrier(mw, false)
	if err != nil || got != CarrierDatagram {
		t.Fatalf("masque auto = %v/%v, want datagram", got, err)
	}

	// AWG outer resolves by its data-plane mode.
	ww := validPair()
	ww.Outer.Kind = KindAWG
	if got, _ = ResolveCarrier(ww, true); got != CarrierKernelRoute {
		t.Fatalf("kernel awg outer = %v, want kernel-route", got)
	}
	if got, _ = ResolveCarrier(ww, false); got != CarrierNetstack {
		t.Fatalf("netstack awg outer = %v, want netstack", got)
	}

	// Explicit modes pass through.
	ww.Carrier = CarrierNetstack
	if got, _ = ResolveCarrier(ww, true); got != CarrierNetstack {
		t.Fatalf("explicit passthrough = %v", got)
	}
}

func TestForwarderSeamAdaptsCarrier(t *testing.T) {
	rec := &recordCarrier{}
	seam := ForwarderSeam(rec)

	if _, err := seam(context.Background(), "tcp", "10.0.0.1:53"); err == nil {
		t.Fatal("seam must reject non-udp networks")
	}
	sess, err := seam(context.Background(), "udp", "203.0.113.9:51820")
	if err != nil {
		t.Fatalf("seam dial: %v", err)
	}
	if rec.dialed != "203.0.113.9:51820" {
		t.Fatalf("dialed = %q", rec.dialed)
	}
	if _, err := sess.Write([]byte("x")); err != nil {
		t.Fatalf("write through seam: %v", err)
	}
}

type recordCarrier struct {
	dialed string
}

func (r *recordCarrier) DialUDPThrough(_ context.Context, dst netip.AddrPort) (UDPSession, error) {
	r.dialed = dst.String()
	return nopSession{}, nil
}

type nopSession struct{}

func (nopSession) Write(b []byte) (int, error) { return len(b), nil }
func (nopSession) Read(b []byte) (int, error)  { return 0, nil }
func (nopSession) Close() error                { return nil }

func TestCarrierDialFuncParsesNumericEndpoint(t *testing.T) {
	var mu sync.Mutex
	var dialed netip.AddrPort
	carrier := fakeTCPCarrier{onDial: func(dst netip.AddrPort) {
		mu.Lock()
		dialed = dst
		mu.Unlock()
	}}
	fn := CarrierDialFunc(carrier)

	conn, err := fn(context.Background(), "tcp", "162.159.198.1:443")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	_ = conn.Close()
	mu.Lock()
	defer mu.Unlock()
	if dialed.String() != "162.159.198.1:443" {
		t.Fatalf("carrier received %v", dialed)
	}
	if _, err := fn(context.Background(), "udp", "162.159.198.1:443"); err == nil {
		t.Fatal("non-tcp must be rejected")
	}
}

type fakeTCPCarrier struct{ onDial func(netip.AddrPort) }

func (f fakeTCPCarrier) InjectUDPDatagram(netip.AddrPort, []byte) error { return nil }
func (f fakeTCPCarrier) DialTCPThrough(_ context.Context, dst netip.AddrPort) (net.Conn, error) {
	f.onDial(dst)
	c1, c2 := net.Pipe()
	go func() { _ = c2.Close() }()
	return c1, nil
}
func (f fakeTCPCarrier) ProofSnapshot() (string, bool) { return "test", true }

// ---- PATCH-07 (MAJOR-5): M+W outer gate + pair gauge over the poller ----

// setPlaneHeld flips the fake plane's RouteHeld (test seam for the poller).
func setPlaneHeld(p *fakePlane, held bool) {
	p.mu.Lock()
	p.routeHeld = held
	p.mu.Unlock()
}

// testInnerIdentity fabricates a structurally valid AWG identity (throwaway
// keys; the unit stand never completes a handshake - the poller's gate and
// gauge transitions are what is pinned here).
func testInnerIdentity() *twg.Identity {
	priv := twg.Key{1}
	peer := twg.Key{200}
	for i := 1; i < 32; i++ {
		priv[i] = byte(i)
		peer[i] = byte(200 - i)
	}
	return &twg.Identity{
		PrivateKey:    priv,
		PeerPublicKey: peer,
		ClientID:      "AAA", // decodes to a non-empty <=3-byte client id
		AssignedV4:    "10.66.66.2",
		CFWarp:        true,
	}
}

// TestMasqueAwgOuterGateAndPairGauge pins the M+W capture points: the outer
// gate closes on the RouteHeld rising edge witnessed by the poller (armed at
// Start only when the plane was down), re-arms on loss (repair gate), and
// the pair gauge tracks the up/down transitions without drift.
func TestMasqueAwgOuterGateAndPairGauge(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a loopback-forwarded inner session; skipped in -short")
	}
	plane := newFakePlane()
	m := &Metrics{}
	rt, err := NewMasqueAwgRuntime(MasqueAwgConfig{
		Pair:         validPair(),
		Plane:        plane,
		LocalV4:      localV4(),
		InnerIdent:   testInnerIdentity(),
		PollInterval: 5 * time.Millisecond,
		Metrics:      m,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer rt.Stop()

	// Parent not held: nothing gated, nothing active.
	if got := m.PairActive.Load(); got != 0 {
		t.Fatalf("pair active before parent = %d, want 0", got)
	}

	// Parent up: the held edge closes the outer gate (measured from Start,
	// a few poll ticks) and the pair gauge rises with the started child.
	setPlaneHeld(plane, true)
	deadline := time.Now().Add(3 * time.Second)
	for m.PairActive.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatalf("pair gauge never rose after parent up (outer=%dms)", m.OuterGateMS.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	first := m.OuterGateMS.Load()
	if first > 10 {
		t.Fatalf("first outer gate = %dms, want a near-immediate edge (< 10ms)", first)
	}

	// Parent lost: gauge drops; the outer gate re-arms for the repair.
	setPlaneHeld(plane, false)
	deadline = time.Now().Add(3 * time.Second)
	for m.PairActive.Load() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("pair gauge never dropped on parent loss")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // inflate the armed repair gate

	// Repair: a NEW outer-gate value lands (re-armed on the loss edge).
	setPlaneHeld(plane, true)
	deadline = time.Now().Add(3 * time.Second)
	for m.PairActive.Load() != 1 {
		if time.Now().After(deadline) {
			t.Fatal("pair gauge never rose again after repair")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := m.OuterGateMS.Load(); got < 40 {
		t.Fatalf("repair outer gate = %dms, want >= 40ms (first was %dms)", got, first)
	}
}

// ---- PATCH-17 (M-4): post-connect edge-collision fact-check ----

func TestEdgeCollisionPostConnectUnit(t *testing.T) {
	sameIP := edgeCollision(edgeWitness{ip: "1.2.3.4", colo: "A"}, edgeWitness{ip: "1.2.3.4"})
	if !sameIP {
		t.Fatal("same-ip witnesses must collide")
	}
	sameColo := edgeCollision(edgeWitness{ip: "1.2.3.4", colo: "TEST"}, edgeWitness{ip: "5.6.7.8", colo: "TEST"})
	if !sameColo {
		t.Fatal("same-colo witnesses must collide")
	}
	distinct := edgeCollision(edgeWitness{ip: "1.2.3.4", colo: "AAA"}, edgeWitness{ip: "5.6.7.8", colo: "BBB"})
	if distinct {
		t.Fatal("distinct witnesses must not collide")
	}
	// Empty facts never collide (a layer without telemetry cannot lie).
	emptyOK := edgeCollision(edgeWitness{ip: "1.2.3.4"}, edgeWitness{ip: "5.6.7.8"})
	if emptyOK {
		t.Fatal("missing colo must not collide on the empty side")
	}
}

// TestWgMasqueEdgeCollisionPostConnectDetected runs the fact-check through
// the W+M wiring: outer/inner witnesses land via onParentUp, the inner colo
// arrives through the sink bridge, and the collision emits once per
// generation with the post-connect reason prefix.
func TestWgMasqueEdgeCollisionPostConnectDetected(t *testing.T) {
	fr := newFakeRoutes()
	log := &wmEventLog{}
	rt := newWMKernelRuntimeMetrics(t, fr, log, &Metrics{})

	// Established pair: both ip witnesses recorded (outer + inner endpoints
	// differ by config, so no collision yet).
	rt.onParentUp()
	if n := log.count(ClassEdgeCollision); n != 0 {
		t.Fatalf("pre-collision events = %d, want 0", n)
	}

	// The inner lands on the SAME physical edge as the outer: the colo
	// telemetry arrives through the sink bridge — the fact-check fires.
	rt.mu.Lock()
	rt.outerWitness.colo = "TEST"
	rt.innerWitness.colo = "TEST"
	rt.checkEdgeCollisionLocked(rt.parentGen)
	rt.mu.Unlock()
	if n := log.count(ClassEdgeCollision); n != 1 {
		t.Fatalf("collision events = %d, want 1", n)
	}
	evs := func() []Event { log.mu.Lock(); defer log.mu.Unlock(); return append([]Event(nil), log.ev...) }()
	found := false
	for _, ev := range evs {
		if ev.Class == ClassEdgeCollision && strings.HasPrefix(ev.Reason, "post-connect:") {
			found = true
		}
	}
	if !found {
		t.Fatal("collision reason lacks the post-connect: prefix")
	}

	// Consume-once per generation: a duplicate check must not re-emit.
	rt.mu.Lock()
	rt.checkEdgeCollisionLocked(rt.parentGen)
	rt.mu.Unlock()
	if n := log.count(ClassEdgeCollision); n != 1 {
		t.Fatalf("duplicate collision events = %d, want still 1", n)
	}

	// Distinct facts: no collision on the next generation.
	rt.mu.Lock()
	rt.outerWitness, rt.innerWitness = edgeWitness{ip: "1.1.1.1", colo: "AAA"}, edgeWitness{ip: "2.2.2.2", colo: "BBB"}
	rt.checkEdgeCollisionLocked(rt.parentGen + 1)
	rt.mu.Unlock()
	if n := log.count(ClassEdgeCollision); n != 1 {
		t.Fatalf("distinct-fact events = %d, want still 1", n)
	}
	rt.Stop()
}

// ---- PATCH-08/E3: child retry while the parent is alive ----

// TestMasqueAwgRuntimeRetriesChildAfterFailedStart: two injected child-start
// failures, then success — the poller retries with the backoff ladder and
// the link reaches "up" without any parent flap (red before the patch: one
// failed startChild left a dead child until the next parent flap).
func TestMasqueAwgRuntimeRetriesChildAfterFailedStart(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a loopback-forwarded inner session; skipped in -short")
	}
	plane := newFakePlane()
	rt, err := NewMasqueAwgRuntime(MasqueAwgConfig{
		Pair:         validPair(),
		Plane:        plane,
		LocalV4:      localV4(),
		InnerIdent:   testInnerIdentity(),
		PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	rt.retryBase = 20 * time.Millisecond
	rt.retryCap = 60 * time.Millisecond

	attempts := 0
	rt.startChildFn = func(gen uint64) error {
		attempts++
		if attempts <= 2 {
			return errors.New("injected child-start failure")
		}
		return rt.startChild(gen)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer rt.Stop()
	setPlaneHeld(plane, true)

	deadline := time.Now().Add(3 * time.Second)
	for {
		if link, _, _ := rt.Status(); link == "up" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("link never reached up; attempts=%d", attempts)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3 (two failures then success)", attempts)
	}
}

// TestMasqueAwgRuntimeBackoffCapsAndFlapResets: with a permanently failing
// child start the attempt intervals double up to the cap; a parent flap
// resets the ladder to the base.
func TestMasqueAwgRuntimeBackoffCapsAndFlapResets(t *testing.T) {
	plane := newFakePlane()
	rt, err := NewMasqueAwgRuntime(MasqueAwgConfig{
		Pair:         validPair(),
		Plane:        plane,
		LocalV4:      localV4(),
		InnerIdent:   testInnerIdentity(),
		PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	base := 60 * time.Millisecond
	cap := 180 * time.Millisecond
	rt.retryBase = base
	rt.retryCap = cap

	var mu sync.Mutex
	var stamps []time.Time
	rt.startChildFn = func(uint64) error {
		mu.Lock()
		stamps = append(stamps, time.Now())
		mu.Unlock()
		return errors.New("always fails")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer rt.Stop()
	setPlaneHeld(plane, true)

	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(stamps)
		mu.Unlock()
		if n >= 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d attempts within deadline", n)
		}
		time.Sleep(5 * time.Millisecond)
	}

	mu.Lock()
	deltas := make([]time.Duration, 0, len(stamps)-1)
	for i := 1; i < len(stamps); i++ {
		deltas = append(deltas, stamps[i].Sub(stamps[i-1]))
	}
	mu.Unlock()

	// Ladder: ~base, ~2*base, ~cap (3rd doubling hits the cap), ~cap...
	if deltas[0] < base*3/4 || deltas[0] > base*3+40*time.Millisecond {
		t.Fatalf("delta[0] = %s, want ~%s", deltas[0], base)
	}
	if deltas[1] < deltas[0]*3/2 {
		t.Fatalf("delta[1] = %s, want growth beyond delta[0]=%s", deltas[1], deltas[0])
	}
	for i := 2; i < len(deltas); i++ {
		if deltas[i] > cap+80*time.Millisecond {
			t.Fatalf("delta[%d] = %s exceeds cap %s (plus slop)", i, deltas[i], cap)
		}
	}

	// Parent flap resets the ladder: drop the plane, re-raise, the next
	// attempt lands at ~base again.
	setPlaneHeld(plane, false)
	time.Sleep(40 * time.Millisecond)
	mu.Lock()
	before := len(stamps)
	mu.Unlock()
	setPlaneHeld(plane, true)
	deadline = time.Now().Add(3 * time.Second)
	for {
		mu.Lock()
		n := len(stamps)
		mu.Unlock()
		if n > before {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no attempt after the parent flap")
		}
		time.Sleep(5 * time.Millisecond)
	}
	mu.Lock()
	flapDelta := stamps[before].Sub(stamps[before-1])
	mu.Unlock()
	if flapDelta > base*3+80*time.Millisecond {
		t.Fatalf("post-flap delta = %s, want ~base %s (ladder was not reset)", flapDelta, base)
	}
}

// TestMasqueAwgRuntimeRetryNoGoroutineLeak: Stop while the retry ladder is
// active leaves no goroutines behind (NumGoroutine delta, per DoD item 3).
func TestMasqueAwgRuntimeRetryNoGoroutineLeak(t *testing.T) {
	plane := newFakePlane()
	rt, err := NewMasqueAwgRuntime(MasqueAwgConfig{
		Pair:         validPair(),
		Plane:        plane,
		LocalV4:      localV4(),
		InnerIdent:   testInnerIdentity(),
		PollInterval: 5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	rt.retryBase = 10 * time.Millisecond
	rt.retryCap = 20 * time.Millisecond
	rt.startChildFn = func(uint64) error { return errors.New("always fails") }

	ctx, cancel := context.WithCancel(context.Background())
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	setPlaneHeld(plane, true)
	time.Sleep(100 * time.Millisecond) // a few failed attempts

	base := runtime.NumGoroutine()
	rt.Stop()
	cancel()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= base {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutine leak: base=%d now=%d", base, runtime.NumGoroutine())
}
