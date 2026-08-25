package opera

import (
	"context"
	"errors"
	"fmt"
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
