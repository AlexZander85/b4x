package opera

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fake prober + injectable clock.
// ---------------------------------------------------------------------------

type probeCall struct {
	node string
	deep bool
}

type fakeProber struct {
	mu    sync.Mutex
	cheap func(entry SEIPEntry) error
	deep  func(entry SEIPEntry) error
	calls []probeCall
}

func (p *fakeProber) ProbeCheap(_ context.Context, e SEIPEntry) error {
	p.mu.Lock()
	p.calls = append(p.calls, probeCall{node: e.NetAddr(), deep: false})
	fn := p.cheap
	p.mu.Unlock()
	if fn != nil {
		return fn(e)
	}
	return nil
}

func (p *fakeProber) ProbeDeep(_ context.Context, e SEIPEntry) error {
	p.mu.Lock()
	p.calls = append(p.calls, probeCall{node: e.NetAddr(), deep: true})
	fn := p.deep
	p.mu.Unlock()
	if fn != nil {
		return fn(e)
	}
	return nil
}

func (p *fakeProber) set(cheap, deep func(SEIPEntry) error) {
	p.mu.Lock()
	p.cheap, p.deep = cheap, deep
	p.mu.Unlock()
}

func (p *fakeProber) log() []probeCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]probeCall(nil), p.calls...)
}

type testClock struct{ t time.Time }

func (c *testClock) Now() time.Time { return c.t }

var healthBase = time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)

func newTestSupervisor(t *testing.T, stand *seStand, region string) (*HealthSupervisor, *fakeProber, *testClock) {
	t.Helper()
	slot := &IdentityStore{Path: slotPath(t)}
	c := newTestClient(t, stand.endpoints(), slot, "health")
	cfg := DefaultHealthConfig(region)
	clk := &testClock{t: healthBase}
	cfg.Now = clk.Now
	sup, err := NewHealthSupervisor(c, cfg)
	if err != nil {
		t.Fatalf("NewHealthSupervisor: %v", err)
	}
	pb := &fakeProber{}
	sup.SetProber(pb)
	return sup, pb, clk
}

// ---------------------------------------------------------------------------
// Scenarios.
// ---------------------------------------------------------------------------

func TestHealthBootstrapLifecycleRunningListening(t *testing.T) {
	stand := newSEStand(t)
	sup, pb, clk := newTestSupervisor(t, stand, "EU")

	// First tick: bootstrap + deep probe immediately due -> full pipeline
	// verified in one step.
	sup.Tick(clk.t)
	st := sup.Status()
	if !st.Running || !st.Listening {
		t.Fatalf("after bootstrap: running=%v listening=%v, want true/true", st.Running, st.Listening)
	}
	if st.CachedNodes != 2 || st.ActiveNode != "77.111.244.3:443" {
		t.Fatalf("cache=%d active=%q", st.CachedNodes, st.ActiveNode)
	}

	// Deep failure clears listening but keeps running ("process alive,
	// port closed" family — design §4).
	pb.set(nil, func(e SEIPEntry) error { return fmt.Errorf("deep dead") })
	clk.t = clk.t.Add(sup.cfg.DeepInterval + time.Second)
	sup.Tick(clk.t)
	st = sup.Status()
	if st.Running != true || st.Listening != false || st.LastVerdict != ProbeFail {
		t.Fatalf("after deep fail: %+v", st)
	}
}

func TestHealthRotationAcrossCacheThenRediscover(t *testing.T) {
	stand := newSEStand(t)
	sup, pb, clk := newTestSupervisor(t, stand, "EU")
	sup.Tick(clk.t) // bootstrap + first deep OK

	pb.set(func(e SEIPEntry) error { return fmt.Errorf("node dead") },
		func(e SEIPEntry) error { return fmt.Errorf("node dead") })

	discoverBefore := sup.Status().DiscoverCalls
	// FailureLimit=3 per candidate: node0 x3 -> rotate -> node1 x3 ->
	// exhausted -> rediscover EU -> adopt from idx0.
	for i := 0; i < 6; i++ {
		clk.t = clk.t.Add(time.Minute)
		sup.Tick(clk.t)
	}
	calls := pb.log()
	var seq []string
	for _, cl := range calls {
		seq = append(seq, cl.node)
	}
	// Bootstrap deep OK on n0, then FailureLimit(3) fails on n0 -> rotate ->
	// 3 fails on n1 -> exhausted -> rediscover adopts cache (no probe in
	// that same tick).
	want := []string{
		"77.111.244.3:443",
		"77.111.244.3:443", "77.111.244.3:443", "77.111.244.3:443",
		"77.111.244.9:8443", "77.111.244.9:8443", "77.111.244.9:8443",
	}
	if strings.Join(seq, "|") != strings.Join(want, "|") {
		t.Fatalf("rotation sequence:\n got %v\nwant %v", seq, want)
	}
	if got := sup.Status().DiscoverCalls; got != discoverBefore+1 {
		t.Fatalf("discover calls delta = %d, want 1", got-discoverBefore)
	}
}

func TestHealthAlternateEUtoAMAndDesiredReturn(t *testing.T) {
	stand := newSEStand(t)
	sup, pb, clk := newTestSupervisor(t, stand, "EU")
	sup.Tick(clk.t)

	// Everything fails AND the API stopped serving the EU region (801).
	pb.set(func(e SEIPEntry) error { return fmt.Errorf("dead") },
		func(e SEIPEntry) error { return fmt.Errorf("dead") })
	stand.setKnobs(false, false, false, true)

	// Burn through cache: 2 candidates x FailureLimit(3).
	for i := 0; i < 6; i++ {
		clk.t = clk.t.Add(time.Minute)
		sup.Tick(clk.t)
	}
	// Exhausted -> rediscover EU fails (801) -> alternate AM attempted,
	// also 801 -> region committed to AM anyway (Nova parity), retry scheduled.
	st := sup.Status()
	if st.Region != "AM" || st.DesiredRegion != "EU" {
		t.Fatalf("region=%q desired=%q, want AM/EU", st.Region, st.DesiredRegion)
	}
	if st.NextDesiredRetry.IsZero() {
		t.Fatal("desired-region retry not scheduled")
	}

	// API recovers; after the backoff instant the supervisor returns to EU,
	// and the retry machinery clears (Nova begin_desired_retry parity).
	stand.setKnobs(false, false, false, false)
	amAttempts := countGeoRequests(stand, "AM")
	clk.t = st.NextDesiredRetry.Add(time.Second)
	sup.Tick(clk.t)
	st = sup.Status()
	if st.Region != "EU" {
		t.Fatalf("did not return to desired region: %+v", st)
	}
	if !st.NextDesiredRetry.IsZero() {
		t.Fatal("retry instant not cleared after return")
	}
	if got := countGeoRequests(stand, "EU"); got <= amAttempts {
		t.Fatal("no fresh EU discover after retry instant")
	}
}

func TestHealthNonEUDesiredRetriedInPlace(t *testing.T) {
	stand := newSEStand(t)
	sup, pb, clk := newTestSupervisor(t, stand, "AS")
	sup.Tick(clk.t)

	pb.set(func(e SEIPEntry) error { return fmt.Errorf("dead") },
		func(e SEIPEntry) error { return fmt.Errorf("dead") })
	stand.setKnobs(false, false, false, true) // AS discover now 801

	for i := 0; i < 6; i++ {
		clk.t = clk.t.Add(time.Minute)
		sup.Tick(clk.t)
	}
	st := sup.Status()
	if st.Region != "AS" {
		t.Fatalf("non-EU desired must retry in place, got region=%q", st.Region)
	}
	if st.NextDesiredRetry.IsZero() {
		t.Fatal("retry not scheduled")
	}
}

func TestHealthRestartCapAndCooldown(t *testing.T) {
	stand := newSEStand(t)
	sup, _, clk := newTestSupervisor(t, stand, "EU")
	sup.Tick(clk.t) // healthy bootstrap

	// Credentials die server-side at refresh time.
	stand.setKnobs(true, false, false, false)
	clk.t = clk.t.Add(sup.cfg.RefreshEvery + time.Second)
	sup.Tick(clk.t) // refresh refused -> recovery #1 (refused too)

	// Every later tick retries registration while refused; cap at 6/hour.
	for i := 0; i < 12; i++ {
		clk.t = clk.t.Add(time.Minute)
		sup.Tick(clk.t)
	}
	st := sup.Status()
	if st.RestartsLastHour != sup.cfg.RestartCapPerHour {
		t.Fatalf("restarts=%d, want capped at %d", st.RestartsLastHour, sup.cfg.RestartCapPerHour)
	}
	if st.CooldownUntil.IsZero() || st.Running {
		t.Fatalf("cooldown/running wrong: %+v", st)
	}

	// API heals; still inside the sliding hour window -> cap holds.
	stand.setKnobs(false, false, false, false)
	clk.t = clk.t.Add(sup.cfg.Cooldown + time.Minute)
	sup.Tick(clk.t)
	if st2 := sup.Status(); st2.Running {
		t.Fatal("cap must hold within one hour even after cooldown expires")
	}

	// Window slides past the burst -> recovery allowed and succeeds.
	clk.t = clk.t.Add(time.Hour)
	sup.Tick(clk.t)
	st3 := sup.Status()
	if !st3.Running || st3.RestartsLastHour != 1 {
		t.Fatalf("post-window recovery: running=%v restarts=%d", st3.Running, st3.RestartsLastHour)
	}
}

func TestHealthJWTRefreshCadence(t *testing.T) {
	stand := newSEStand(t)
	sup, _, clk := newTestSupervisor(t, stand, "EU")
	sup.Tick(clk.t)

	genBefore := stand.generateCalls()
	clk.t = clk.t.Add(sup.cfg.RefreshEvery - time.Minute)
	sup.Tick(clk.t)
	if stand.generateCalls() != genBefore {
		t.Fatal("refresh fired before cadence")
	}
	clk.t = clk.t.Add(2 * time.Minute)
	sup.Tick(clk.t)
	if stand.generateCalls() != genBefore+1 {
		t.Fatal("refresh did not fire at cadence")
	}
}

func TestHealthCantBindDoesNotRotate(t *testing.T) {
	stand := newSEStand(t)
	sup, pb, clk := newTestSupervisor(t, stand, "EU")
	sup.Tick(clk.t)

	setupErr := fmt.Errorf("%w: no auth provider", errSetup)
	pb.set(func(e SEIPEntry) error { return setupErr }, func(e SEIPEntry) error { return setupErr })
	before := pb.log()

	for i := 0; i < 10; i++ {
		clk.t = clk.t.Add(time.Minute)
		sup.Tick(clk.t)
	}
	st := sup.Status()
	if st.ConsecFails != 0 || st.LastVerdict != ProbeCantBind {
		t.Fatalf("cant-bind leaked into rotation counters: %+v", st)
	}
	if st.CachedNodes != 2 || sup.idx != 0 {
		t.Fatalf("candidate rotated on cant-bind: idx=%d", sup.idx)
	}
	if len(pb.log())-len(before) != 10 {
		t.Fatal("probes stopped unexpectedly")
	}
}

func TestHealthDegradedOnPinMismatchStopsTicks(t *testing.T) {
	stand := newSEStand(t)
	sup, pb, clk := newTestSupervisor(t, stand, "EU")
	sup.Tick(clk.t)

	sup.noteAPIFailure(newFailure(ClassAPIPinMismatch, "api key changed", nil), clk.t)
	st := sup.Status()
	if st.Degraded != string(ClassAPIPinMismatch) {
		t.Fatalf("degraded=%q", st.Degraded)
	}

	n := len(pb.log())
	clk.t = clk.t.Add(time.Hour)
	sup.Tick(clk.t)
	if len(pb.log()) != n {
		t.Fatal("ticks continued after terminal degradation")
	}
}

func TestProbeVerdictClassification(t *testing.T) {
	if v := probeVerdictOf(nil); v != ProbeOK {
		t.Fatalf("nil => %v", v)
	}
	if v := probeVerdictOf(fmt.Errorf("%w: guard", errSetup)); v != ProbeCantBind {
		t.Fatalf("setup => %v", v)
	}
	wrapped := fmt.Errorf("outer: %w", fmt.Errorf("%w: inner", errSetup))
	if v := probeVerdictOf(wrapped); v != ProbeCantBind {
		t.Fatalf("wrapped setup => %v", v)
	}
	if v := probeVerdictOf(errors.New("net timeout")); v != ProbeFail {
		t.Fatalf("plain => %v", v)
	}
}

func TestDefaultHealthConfigValues(t *testing.T) {
	cfg := DefaultHealthConfig("eu")
	if cfg.Region != "eu" { // resolve normalizes
		t.Logf("pre-resolve region %q", cfg.Region)
	}
	if err := cfg.resolve(); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cfg.Region != "EU" {
		t.Fatalf("region normalized to %q", cfg.Region)
	}
	if cfg.FailureLimit != 3 || cfg.RestartCapPerHour != 6 ||
		cfg.Cooldown != 300*time.Second || cfg.RefreshEvery != 4*time.Hour ||
		cfg.RetryBase != 300*time.Second || cfg.RetryMax != 1800*time.Second {
		t.Fatalf("defaults drifted: %+v", cfg)
	}
	if _, err := NormalizeRegion(cfg.Region); err != nil {
		t.Fatal("whitelist rejected default")
	}
}

func countGeoRequests(stand *seStand, region string) int {
	n := 0
	for _, r := range stand.snapshot() {
		if r.Path == "/v4/discover" && r.Form.Get("requested_geo") == fmt.Sprintf("%q,,", region) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Review E-OPERA C2 / §6: wedged-node regression tests.
// ---------------------------------------------------------------------------

// wedgedNodeListener accepts TCP and NEVER answers — the silent-node
// pathology that used to pin HandshakeContext forever (C2).
func wedgedNodeListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("wedged listener: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		conns := make([]net.Conn, 0, 8)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			conns = append(conns, c) // hold, never read/write, never close
			select {
			case <-done:
				return
			default:
			}
		}
	}()
	return ln.Addr().String()
}

// TestHealthWedgedNodeTickReturnsInBudget: a node that accepts TCP and
// stays silent must not pin the supervisor — Tick returns within the probe
// budget, the verdict is a bounded ProbeFail, and Status() answers WHILE
// the probe is still in flight (mutex-free I/O discipline).
func TestHealthWedgedNodeTickReturnsInBudget(t *testing.T) {
	stand := newSEStand(t)
	sup, _, clk := newTestSupervisor(t, stand, "EU")

	budget := 300 * time.Millisecond
	sup.cfg.ProbeBudgetDeep = budget
	sup.cfg.ProbeBudgetCheap = budget

	// Bootstrap through the healthy stand, then aim the cache at the wedge.
	sup.Tick(clk.t)
	if st := sup.Status(); !st.Running {
		t.Fatalf("bootstrap failed: %+v", st)
	}
	wedge := wedgedNodeListener(t)
	host, portStr, _ := net.SplitHostPort(wedge)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	sup.mu.Lock()
	sup.nodes = []SEIPEntry{{Geo: SEGeoEntry{CountryCode: "NL"}, IP: host, Ports: []uint16{port}}}
	sup.idx = 0
	sup.mu.Unlock()
	// Real network probes: the fake prober ignores ctx deadlines, but the
	// wedged-node pathology lives in the REAL dial/TLS path.
	sup.SetProber(defaultProber{c: sup.c, control: sup.cfg.ControlTarget})

	// Fire the next tick on a goroutine and check Status() responsiveness
	// while the (wedged) deep probe is still running.
	clk.t = clk.t.Add(sup.cfg.DeepInterval + time.Second)
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		sup.Tick(clk.t)
		done <- time.Since(start)
	}()
	time.Sleep(budget / 4)
	stCh := make(chan HealthStatus, 1)
	go func() {
		start := time.Now()
		st := sup.Status()
		_ = time.Since(start)
		stCh <- st
	}()
	select {
	case <-stCh:
		// Status() answered during the in-flight wedged probe — the C2
		// mutex discipline holds.
	case <-time.After(2 * budget):
		t.Fatal("Status() blocked while a wedged probe held the tick")
	}
	select {
	case elapsed := <-done:
		if elapsed > 4*budget {
			t.Fatalf("tick took %v, want <= ~%v (probe budget)", elapsed, budget)
		}
		st := sup.Status()
		if st.LastVerdict != ProbeFail {
			t.Fatalf("verdict = %v, want ProbeFail (bounded, classified)", st.LastVerdict)
		}
		if st.LastError == "" {
			t.Fatal("wedged probe must surface an error string")
		}
	case <-time.After(4 * budget):
		t.Fatal("Tick never returned from the wedged probe — C2 regression")
	}
}

// TestHealthRunCancelAbortsProbe: cancelling the Run context aborts an
// in-flight wedged probe (C2c: Stop must not orphan the handshake).
func TestHealthRunCancelAbortsProbe(t *testing.T) {
	stand := newSEStand(t)
	sup, _, clk := newTestSupervisor(t, stand, "EU")
	budget := 5 * time.Second
	sup.cfg.ProbeBudgetDeep = budget
	sup.cfg.ProbeBudgetCheap = budget

	sup.Tick(clk.t)
	wedge := wedgedNodeListener(t)
	host, portStr, _ := net.SplitHostPort(wedge)
	var port uint16
	fmt.Sscanf(portStr, "%d", &port)
	sup.mu.Lock()
	sup.nodes = []SEIPEntry{{Geo: SEGeoEntry{CountryCode: "NL"}, IP: host, Ports: []uint16{port}}}
	sup.idx = 0
	sup.mu.Unlock()
	sup.SetProber(defaultProber{c: sup.c, control: sup.cfg.ControlTarget})

	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan struct{})
	go func() { sup.Run(ctx); close(runDone) }()

	// Run's first tick probes the wedge in the background; cancel must
	// return the loop promptly (well under the full budget).
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel — C2c regression")
	}
}

// ---------------------------------------------------------------------------
// Review E-OPERA H3/M4: persistent discover cache + 801 fallback.
// ---------------------------------------------------------------------------

func newTestSupervisorWithCache(t *testing.T, stand *seStand, region string) (*HealthSupervisor, *fakeProber, *testClock, *NodeCache) {
	t.Helper()
	slot := &IdentityStore{Path: slotPath(t)}
	c := newTestClient(t, stand.endpoints(), slot, "health-cache")
	cfg := DefaultHealthConfig(region)
	clk := &testClock{t: healthBase}
	cfg.Now = clk.Now
	cache := &NodeCache{Path: filepath.Join(t.TempDir(), "nodecache.json")}
	cfg.NodeCache = cache
	sup, err := NewHealthSupervisor(c, cfg)
	if err != nil {
		t.Fatalf("NewHealthSupervisor: %v", err)
	}
	pb := &fakeProber{}
	sup.SetProber(pb)
	return sup, pb, clk, cache
}

// TestHealthDiscoverCachePersistedAndSourcedLive: a successful discover
// persists the offline asset and the status reports the live source.
func TestHealthDiscoverCachePersistedAndSourcedLive(t *testing.T) {
	stand := newSEStand(t)
	sup, _, clk, cache := newTestSupervisorWithCache(t, stand, "EU")

	sup.Tick(clk.t)
	if st := sup.Status(); st.NodesSource != "live" || st.CachedNodes != 2 {
		t.Fatalf("source=%q nodes=%d, want live/2", st.NodesSource, st.CachedNodes)
	}
	rec, err := cache.Load()
	if err != nil {
		t.Fatalf("cache load: %v", err)
	}
	if rec.Region != "EU" || len(rec.Entries) != 2 {
		t.Fatalf("cached record region=%q entries=%d", rec.Region, len(rec.Entries))
	}
}

// TestHealth801FallsBackToCache: design §2 item 5 — discover answering 801
// must not empty the data plane when a cached list exists (M4).
func TestHealth801FallsBackToCache(t *testing.T) {
	stand := newSEStand(t)
	sup, pb, clk, _ := newTestSupervisorWithCache(t, stand, "EU")
	sup.Tick(clk.t) // healthy bootstrap, cache written

	// Cache dies with the process — the supervisor keeps the live copy; a
	// fresh supervisor instance simulates the reboot-from-cache scenario.
	stand.setKnobs(false, false, false, true) // discover now 801
	clk.t = clk.t.Add(sup.cfg.DeepInterval + time.Minute)
	pb.set(func(e SEIPEntry) error { return fmt.Errorf("dead") },
		func(e SEIPEntry) error { return fmt.Errorf("dead") })
	// Burn the cache: 2 candidates x FailureLimit(3) -> rotate -> discover 801.
	for i := 0; i < 6; i++ {
		clk.t = clk.t.Add(time.Minute)
		sup.Tick(clk.t)
	}
	st := sup.Status()
	// Rotation hit the exhausted cache + 801 rediscover: with the offline
	// asset the EU list must be re-adopted instead of scheduling a retry.
	if st.Region != "EU" {
		t.Fatalf("region = %q, want EU (cache fallback must keep the region)", st.Region)
	}
	if st.NextDesiredRetry.Unix() > 0 && !st.NextDesiredRetry.IsZero() {
		t.Fatalf("retry scheduled despite usable cache: %v", st.NextDesiredRetry)
	}
}

// TestHealthOfflineBootFromCache: a reboot with a dead API but a fresh
// cache boots the data plane from the offline asset (H3).
func TestHealthOfflineBootFromCache(t *testing.T) {
	stand := newSEStand(t)
	slotFile := slotPath(t)
	slot := &IdentityStore{Path: slotFile}
	cachePath := filepath.Join(t.TempDir(), "nodecache.json")
	cache := &NodeCache{Path: cachePath}
	clk := &testClock{t: healthBase}

	build := func(device string) *HealthSupervisor {
		c := newTestClient(t, stand.endpoints(), slot, device)
		cfg := DefaultHealthConfig("EU")
		cfg.Now = clk.Now
		cfg.NodeCache = cache
		sup, err := NewHealthSupervisor(c, cfg)
		if err != nil {
			t.Fatalf("supervisor: %v", err)
		}
		pb := &fakeProber{}
		sup.SetProber(pb)
		return sup
	}

	// First run: healthy bootstrap writes the identity and the cache.
	build("health-first").Tick(clk.t)
	if _, err := os.Stat(slotFile); err != nil {
		t.Fatalf("identity slot missing after first run: %v", err)
	}
	if _, err := os.Stat(cachePath); err != nil {
		t.Fatalf("cache missing after first run: %v", err)
	}
	if _, lerr := (&IdentityStore{Path: slotFile}).Load(); lerr != nil {
		t.Fatalf("identity slot not loadable after first run: %v", lerr)
	}

	// Reboot with the API dead (malformed replies) and a fresh supervisor
	// sharing the persisted identity + cache file.
	stand.setKnobs(false, false, true, false)
	clk.t = healthBase.Add(time.Hour) // well within the cache trust TTL
	rebooted := build("health-reboot")
	rebooted.Tick(clk.t)

	st := rebooted.Status()
	if st.CachedNodes != 2 || st.NodesSource != "cache" {
		t.Fatalf("offline boot: nodes=%d source=%q lastErr=%q running=%v, want 2/cache",
			st.CachedNodes, st.NodesSource, st.LastError, st.Running)
	}
}

// TestNodeCacheCorruptQuarantined: a tampered cache file is quarantined
// (identity-slot canon), never fatal.
func TestNodeCacheCorruptQuarantined(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nodecache.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	cache := &NodeCache{Path: path}
	if _, err := cache.Load(); !errors.Is(err, ErrNodeCacheCorrupt) {
		t.Fatalf("err = %v, want corrupt", err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatal("corrupt file not quarantined")
	}
}

// ---------------------------------------------------------------------------
// Review E-OPERA M1/M2 + §6: 407-on-CONNECT -> refresh -> capped re-register.
// ---------------------------------------------------------------------------

// errConnect407 mimics the data-plane refusal shape DialContext produces
// (structured class + HTTP status).
func errConnect407() error {
	return newFailureStatus(ClassDataPlaneConnectRefused,
		"connect through node to target: 407 Proxy Authentication Required",
		http.StatusProxyAuthRequired, nil)
}

// TestProbe407PullsRefreshForwardNotRotation: a 407 is a credential
// rejection — the node cache must not rotate and the JWT refresh must fire
// on the NEXT tick regardless of the 4h cadence (review M1+M2).
func TestProbe407PullsRefreshForwardNotRotation(t *testing.T) {
	stand := newSEStand(t)
	sup, pb, clk := newTestSupervisor(t, stand, "EU")
	sup.Tick(clk.t) // healthy bootstrap

	pb.set(func(e SEIPEntry) error { return errConnect407() },
		func(e SEIPEntry) error { return errConnect407() })
	genBefore := stand.generateCalls()
	clk.t = clk.t.Add(time.Minute)
	sup.Tick(clk.t)

	st := sup.Status()
	if st.ConsecFails != 0 || sup.idx != 0 {
		t.Fatalf("407 leaked into rotation counters: fails=%d idx=%d", st.ConsecFails, sup.idx)
	}

	// The refresh pulls forward IN THE SAME TICK (pipeline: probe -> 407 ->
	// refresh): generate_password fires even though the 4h cadence is
	// nowhere near due.
	if stand.generateCalls() != genBefore+1 {
		t.Fatalf("refresh after 407 did not fire (gen=%d, want %d)", stand.generateCalls(), genBefore+1)
	}
	if sup.authRejected || !sup.refreshRetryAt.IsZero() {
		t.Fatalf("successful refresh did not clear the 407 state: flag=%v retryAt=%v",
			sup.authRejected, sup.refreshRetryAt)
	}
}

// TestRefreshFailureBacksOffThenRetries: a failed refresh retries on the
// exponential backoff (60s, doubling) instead of disappearing for 4h
// (review M1).
func TestRefreshFailureBacksOffThenRetries(t *testing.T) {
	stand := newSEStand(t)
	sup, pb, clk := newTestSupervisor(t, stand, "EU")
	sup.Tick(clk.t) // healthy bootstrap

	// First refresh attempt fails with a transient (network) error.
	pb.set(nil, nil)                          // probes fine; the failure is injected via the stand
	stand.setKnobs(false, false, true, false) // malformed replies = transient
	sup.authRejected = true                   // force a refresh attempt now
	clk.t = clk.t.Add(time.Minute)
	sup.Tick(clk.t)
	if sup.refreshRetryAt.IsZero() {
		t.Fatal("failed refresh scheduled no backoff retry")
	}
	firstRetry := sup.refreshRetryAt
	if !clk.t.Before(firstRetry) {
		t.Fatalf("retry instant %v not in the future relative to %v", firstRetry, clk.t)
	}

	// Still inside the backoff: no second attempt.
	genAfterFirst := stand.generateCalls()
	clk.t = clk.t.Add(30 * time.Second)
	sup.Tick(clk.t)
	if stand.generateCalls() != genAfterFirst {
		t.Fatal("refresh retried inside the backoff window")
	}

	// Backoff elapsed: the retry fires and succeeds (knobs healed).
	stand.setKnobs(false, false, false, false)
	clk.t = firstRetry.Add(time.Second)
	sup.Tick(clk.t)
	if stand.generateCalls() != genAfterFirst+1 {
		t.Fatalf("backoff retry did not fire (gen=%d)", stand.generateCalls())
	}
	if !sup.refreshRetryAt.IsZero() || sup.refreshFailRound != 0 {
		t.Fatalf("success did not reset the backoff: retryAt=%v round=%d",
			sup.refreshRetryAt, sup.refreshFailRound)
	}
}

// TestProbe407ThenRefusedRefreshCapsReRegister (review §6 third test): the
// full chain — 407 on CONNECT -> immediate refresh -> refresh refused ->
// credsDead -> capped re-register (<=6/hour).
func TestProbe407ThenRefusedRefreshCapsReRegister(t *testing.T) {
	stand := newSEStand(t)
	sup, pb, clk := newTestSupervisor(t, stand, "EU")
	sup.Tick(clk.t) // healthy bootstrap

	// 407 on both probe levels: credentials rejected by the node. The
	// refresh fires in the same tick (knobs still healthy) and succeeds.
	pb.set(func(e SEIPEntry) error { return errConnect407() },
		func(e SEIPEntry) error { return errConnect407() })
	clk.t = clk.t.Add(time.Minute)
	sup.Tick(clk.t)

	// Next tick: the node still answers 407, but now the REFRESH hits a
	// refusing API — creds die, recovery engages in the same tick.
	stand.setKnobs(true, false, false, false)
	clk.t = clk.t.Add(time.Minute)
	sup.Tick(clk.t) // 407 -> refresh refused -> credsDead -> recover attempt #1
	if st := sup.Status(); st.RestartsLastHour != 1 {
		t.Fatalf("restarts=%d, want the first capped re-register to have fired", st.RestartsLastHour)
	}

	// Subsequent ticks retry the registration while refused; cap at 6/hour.
	for i := 0; i < 8; i++ {
		clk.t = clk.t.Add(time.Minute)
		sup.Tick(clk.t)
	}
	st := sup.Status()
	if st.RestartsLastHour != sup.cfg.RestartCapPerHour {
		t.Fatalf("restarts=%d, want capped at %d", st.RestartsLastHour, sup.cfg.RestartCapPerHour)
	}
	if st.Running {
		t.Fatal("must stay unbootstrapped while the API refuses and the cap holds")
	}
}
