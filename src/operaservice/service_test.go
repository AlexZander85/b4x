package operaservice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	opera "github.com/daniellavrushin/b4/transport/opera"
)

// testClient builds an opera client wired to the shared seStand fixture
// (declared in transport/opera tests — replicated minimal stand here).
// To keep operaservice self-contained we drive a real client against a
// local fake API built on the same shapes as the engine tests.
func newFakeAPI(t *testing.T) (*seStandLite, string) {
	t.Helper()
	s := newSEStandLite(t)
	return s, s.srv.URL
}

// ---------------------------------------------------------------------------
// Anti-loop helpers.
// ---------------------------------------------------------------------------

func TestIsBypassDomain(t *testing.T) {
	for _, ok := range []string{"api2.sec-tunnel.com", "eu0.sec-tunnel.com", "SEC-TUNNEL.COM", "a.b.sec-tunnel.com.", "sec-tunnel.com"} {
		if !IsBypassDomain(ok) {
			t.Fatalf("IsBypassDomain(%q) = false", ok)
		}
	}
	for _, no := range []string{"sec-tunnel.com.evil.tld", "notsec-tunnel.com", "", "example.com"} {
		if IsBypassDomain(no) {
			t.Fatalf("IsBypassDomain(%q) = true", no)
		}
	}
}

func TestRefuseNodeSelfLoop(t *testing.T) {
	entry := opera.SEIPEntry{IP: "77.111.244.3", Ports: []uint16{443}}
	self, _ := netip.ParseAddr("77.111.244.3")
	other, _ := netip.ParseAddr("1.2.3.4")
	if !refuseNodeSelfLoop(entry, self) {
		t.Fatal("self dial not detected")
	}
	if refuseNodeSelfLoop(entry, other) {
		t.Fatal("innocent target flagged")
	}

	// IPv4-mapped IPv6 form of the same address must also match.
	mapped := netip.AddrFrom16(self.As16())
	if !refuseNodeSelfLoop(entry, mapped) {
		t.Fatal("mapped self dial not detected")
	}
}

// ---------------------------------------------------------------------------
// Failover dialer (bootstrap-through-carrier).
// ---------------------------------------------------------------------------

func TestFailoverDialerDirectFirstCarrierSecond(t *testing.T) {
	directErr := errors.New("direct blocked")
	carrierHits := 0
	fd := failoverDialer(
		func(ctx context.Context, network, addr string) (net.Conn, error) { return nil, directErr },
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			carrierHits++
			return nil, nil
		},
	)
	if _, err := fd(context.Background(), "tcp", "api2.sec-tunnel.com:443"); err != nil {
		t.Fatalf("failover failed: %v", err)
	}
	if carrierHits != 1 {
		t.Fatalf("carrier path not taken: hits=%d", carrierHits)
	}

	// Direct success short-circuits the carrier.
	fd2 := failoverDialer(
		func(ctx context.Context, network, addr string) (net.Conn, error) { return nil, nil },
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("fallback must not fire")
		},
	)
	if _, err := fd2(context.Background(), "tcp", "x:1"); err != nil {
		t.Fatalf("direct path broke: %v", err)
	}

	// Nil direct + nil carrier => plain net dialer passthrough.
	if fd3 := failoverDialer(nil, nil); fd3 == nil {
		t.Fatal("nil composition produced nil")
	}
}

func TestFailoverDialerBothFailAggregates(t *testing.T) {
	fd := failoverDialer(
		func(ctx context.Context, network, addr string) (net.Conn, error) { return nil, errors.New("direct down") },
		func(ctx context.Context, network, addr string) (net.Conn, error) { return nil, errors.New("carrier down") },
	)
	_, err := fd(context.Background(), "tcp", "x:1")
	if err == nil || !strings.Contains(err.Error(), "direct down") || !strings.Contains(err.Error(), "carrier down") {
		t.Fatalf("aggregate error = %v", err)
	}
}

// ---------------------------------------------------------------------------
// Runtime assembly + StreamDialer contract.
// ---------------------------------------------------------------------------

func TestBuildDisabledSucceedsAndStatusHonest(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Opera.Enabled = false
	rt, err := Build(cfg, Options{})
	if err != nil {
		t.Fatalf("build disabled: %v", err)
	}
	st := rt.Status()
	if st.Enabled {
		t.Fatalf("enabled mismatch: %+v", st)
	}
	if rt.SupportsUDP() {
		t.Fatal("opera must report UDP-unsupported (fail-closed honesty)")
	}
	if st.Transport != "tcp-only" {
		t.Fatalf("transport honesty: %q", st.Transport)
	}
}

func TestBuildInvalidRegionRejectedEvenDisabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Opera.Region = "RU"
	if _, err := Build(cfg, Options{}); err == nil || !strings.Contains(err.Error(), "whitelist") {
		t.Fatalf("err = %v, want whitelist rejection", err)
	}
}

func TestDialStreamContractAndSelfLoopGuard(t *testing.T) {
	stand, base := newFakeAPI(t)
	_ = stand // API exercised via client below; snapshot asserted in SetRegion test
	slot := t.TempDir() + "/identity.json"
	client := newEngineClient(t, base, slot)
	if err := client.EnsureSession(context.Background()); err != nil {
		t.Fatalf("ensure session: %v", err)
	}

	cfg := &config.Config{}
	cfg.System.Opera.Enabled = true
	cfg.System.Opera.IdentityPath = slot
	rt, err := Build(cfg, Options{Client: client})
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	// Prime supervisor state without Run(): adopt nodes via one Tick.
	supTickOnce(rt)

	// Self-loop refused.
	self, _ := netip.ParseAddrPort("77.111.244.3:443")
	if _, err := rt.DialStream(context.Background(), self); !errors.Is(err, ErrOperaSelfLoop) {
		t.Fatalf("self-loop err = %v, want ErrOperaSelfLoop", err)
	}

	// Innocent numeric target reaches the underlying node dialer (fails at
	// TCP level against 127.0.0.1 closed port, but NOT with self-loop).
	innocent, _ := netip.ParseAddrPort("127.0.0.1:1")
	_, err = rt.DialStream(context.Background(), innocent)
	if err == nil || errors.Is(err, ErrOperaSelfLoop) {
		t.Fatalf("innocent target err = %v, want non-self-loop failure", err)
	}

	// Bootstrap-pending runtime has no active node.
	emptyCfg := &config.Config{}
	emptyCfg.System.Opera.Enabled = true
	emptyRt, err := Build(emptyCfg, Options{Client: newEngineClient(t, base, t.TempDir()+"/id.json")})
	if err != nil {
		t.Fatalf("empty build: %v", err)
	}
	if _, err := emptyRt.DialStream(context.Background(), innocent); err == nil ||
		!strings.Contains(err.Error(), "no active node") {
		t.Fatalf("pending dial err = %v", err)
	}
}

func TestSetRegionKeepsDeviceIdentity(t *testing.T) {
	stand, base := newFakeAPI(t)
	slot := t.TempDir() + "/identity.json"
	client := newEngineClient(t, base, slot)
	ctx := context.Background()
	if err := client.EnsureSession(ctx); err != nil {
		t.Fatalf("register: %v", err)
	}
	registrationsBefore := countPath(stand, "/v4/register_device")

	cfg := &config.Config{}
	cfg.System.Opera.Enabled = true
	cfg.System.Opera.IdentityPath = slot
	rt, err := Build(cfg, Options{
		Client:     client,
		Supervisor: func(c *opera.Client) (*opera.HealthSupervisor, error) {
			hc := opera.DefaultHealthConfig("EU")
			return opera.NewHealthSupervisor(c, hc)
		},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// Prime the supervisor so sessionOK=true before the region command.
	supTickOnce(rt)
	if err := rt.SetRegion("AS"); err != nil {
		t.Fatalf("set region: %v", err)
	}
	st := rt.Status()
	if st.DesiredRegion != "AS" {
		t.Fatalf("post-switch status: %+v", st)
	}
	if got := countPath(stand, "/v4/register_device"); got != registrationsBefore {
		t.Fatalf("region switch re-registered device (%d -> %d)", registrationsBefore, got)
	}
	if n := countGeoRequestsLite(stand, "AS"); n == 0 {
		t.Fatal("no AS discover issued after region switch")
	}
	if err := rt.SetRegion("RU"); err == nil {
		t.Fatal("RU accepted")
	}
}

// Start/Stop idempotence (warpservice parity).
func TestStartStopLifecycle(t *testing.T) {
	stand, base := newFakeAPI(t)
	slot := t.TempDir() + "/identity.json"
	cfg := &config.Config{}
	cfg.System.Opera.Enabled = true
	cfg.System.Opera.IdentityPath = slot
	rt, err := Build(cfg, Options{Client: newEngineClient(t, base, slot)})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := rt.Start(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := rt.Start(ctx); err != nil {
		t.Fatal("double start must be a no-op success")
	}
	rt.Stop()
	rt.Stop() // idempotent
	if err := rt.Start(ctx); err == nil {
		t.Fatal("start after stop must fail")
	}
	_ = stand
}

// supTickOnce primes supervisor state (bootstrap + deep probe) without the
// Run loop — deterministic for contract tests.
func supTickOnce(rt *Runtime) { rt.sup.Tick(time.Now()) }

// ---------------------------------------------------------------------------
// Review E-OPERA H2: negative cache + timed direct stage (§6: carrier
// preferred path — direct dead => dial via carrier in well under a second).
// ---------------------------------------------------------------------------

func TestFailoverNegativeCacheSkipsDeadDirect(t *testing.T) {
	directHits := 0
	carrierHits := 0
	fd := newFailoverDial(
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			directHits++
			return nil, errors.New("direct blocked")
		},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			carrierHits++
			return nil, nil
		},
	)

	// Two consecutive direct failures arm the negative cache.
	for i := 0; i < 2; i++ {
		if _, err := fd.Dial(context.Background(), "tcp", "x:1"); err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
	}
	if directHits != 2 || carrierHits != 2 {
		t.Fatalf("arm phase: direct=%d carrier=%d", directHits, carrierHits)
	}

	// Within the TTL the direct stage must not be contacted at all.
	if _, err := fd.Dial(context.Background(), "tcp", "x:1"); err != nil {
		t.Fatalf("cached dial: %v", err)
	}
	if directHits != 2 || carrierHits != 3 {
		t.Fatalf("TTL phase: direct=%d carrier=%d, want direct untouched", directHits, carrierHits)
	}

	// Past the TTL the direct stage is re-probed (self-heal window).
	fd.mu.Lock()
	fd.directDeadUntil = fd.now().Add(-time.Second)
	fd.mu.Unlock()
	if _, err := fd.Dial(context.Background(), "tcp", "x:1"); err != nil {
		t.Fatalf("post-TTL dial: %v", err)
	}
	if directHits != 3 || carrierHits != 4 {
		t.Fatalf("post-TTL: direct=%d carrier=%d", directHits, carrierHits)
	}
}

func TestFailoverDirectHealThroughSelfProbe(t *testing.T) {
	directOK := false
	fd := newFailoverDial(
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !directOK {
				return nil, errors.New("still blocked")
			}
			return nil, nil
		},
		func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("carrier down too")
		},
	)
	// Arm the negative cache.
	for i := 0; i < 2; i++ {
		_, _ = fd.Dial(context.Background(), "tcp", "x:1")
	}
	// Direct heals: carrier-first dial fails, self-heal probe succeeds.
	directOK = true
	conn, err := fd.Dial(context.Background(), "tcp", "x:1")
	if err != nil || conn != nil {
		t.Fatalf("heal dial: conn=%v err=%v", conn, err)
	}
	// Success re-arms the direct stage: next dial goes direct-first.
	if !fd.directAlive() {
		t.Fatal("direct stage not re-armed after self-heal")
	}
}

// TestFailoverDirectDialHasTimeout: the zero-config direct stage must carry
// the 5s hard cap (review H2a) — never the naked net.Dialer{}.
func TestFailoverDirectDialHasTimeout(t *testing.T) {
	fd := newFailoverDial(nil, nil)
	// The default dialer is not directly observable through the DialFunc;
	// assert via the constant contract and by construction the Build path
	// uses newFailoverDial (single source of truth).
	if directDialTimeout != 5*time.Second {
		t.Fatalf("directDialTimeout = %v, want 5s", directDialTimeout)
	}
	if fd.direct == nil {
		t.Fatal("default direct dialer missing")
	}
}

// ---------------------------------------------------------------------------
// Review E-OPERA M3: observability wiring.
// ---------------------------------------------------------------------------

// TestBuildHooksWired: the assembled runtime must install the observability
// hooks (events ring, probe/discover counters) — the "silent transport"
// regression guard.
func TestBuildHooksWired(t *testing.T) {
	rt, err := Build(&config.Config{}, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rt.ring == nil {
		t.Fatal("event ring not wired")
	}
	st := rt.Status()
	if st.Events == nil {
		t.Fatal("Status must expose the events slice")
	}
}

// TestEventRingBounded: the tail never grows past the cap (proton parity).
func TestEventRingBounded(t *testing.T) {
	ring := &eventRing{}
	for i := 0; i < eventsRingCap*3; i++ {
		ring.append("x", "y")
	}
	if got := len(ring.snapshot()); got != eventsRingCap {
		t.Fatalf("ring len = %d, want %d", got, eventsRingCap)
	}
}

// ---------------------------------------------------------------------------
// Review E-OPERA OP-M3: bait handle honesty.
// ---------------------------------------------------------------------------

// TestBaitHandleHonesty: the bait handle starts inactive and flips only on
// the tables-layer confirmation; nil (not configured) stays inactive.
func TestBaitHandleHonesty(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Opera.Masquerade.TTLFake = false
	rt, err := Build(cfg, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rt.nfqBait != nil {
		t.Fatal("bait handle created without ttl_fake")
	}
	if rt.Status().Masquerade.TTLFakeActive {
		t.Fatal("TTLFakeActive without config")
	}

	cfg2 := &config.Config{}
	cfg2.System.Opera.Masquerade.TTLFake = true
	rt2, err := Build(cfg2, Options{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if rt2.nfqBait == nil {
		t.Fatal("bait handle missing with ttl_fake")
	}
	if rt2.Status().Masquerade.TTLFakeActive {
		t.Fatal("TTLFakeActive before the tables layer confirmed the rule")
	}
	rt2.SetBaitActive(true)
	if !rt2.Status().Masquerade.TTLFakeActive {
		t.Fatal("TTLFakeActive must follow the tables confirmation")
	}
	rt2.SetBaitActive(false)
	if rt2.Status().Masquerade.TTLFakeActive {
		t.Fatal("TTLFakeActive must clear on teardown")
	}
}
