package transportwarp

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"
)

// ---- harness ----

type supHarness struct {
	api  *fakeAPI
	mq   *fakeServer
	rec  *Reconciler
	tmpl SessionConfig

	mu     sync.Mutex
	sleeps []time.Duration

	sinkMu   sync.Mutex
	sinkSeen []SupervisorEvent
	onEvent  func(SupervisorEvent) // optional test hook, called under sinkMu
}

func (h *supHarness) recordSleep(_ context.Context, d time.Duration) error {
	h.mu.Lock()
	h.sleeps = append(h.sleeps, d)
	h.mu.Unlock()
	return nil
}

func (h *supHarness) recordedSleeps() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]time.Duration(nil), h.sleeps...)
}

func (h *supHarness) sink(ev SupervisorEvent) {
	h.sinkMu.Lock()
	h.sinkSeen = append(h.sinkSeen, ev)
	hook := h.onEvent
	h.sinkMu.Unlock()
	if hook != nil {
		hook(ev)
	}
}

func (h *supHarness) events() []SupervisorEvent {
	h.sinkMu.Lock()
	defer h.sinkMu.Unlock()
	return append([]SupervisorEvent(nil), h.sinkSeen...)
}

func (h *supHarness) eventNames() []string {
	evs := h.events()
	out := make([]string, 0, len(evs))
	for _, e := range evs {
		out = append(out, e.Name)
	}
	return out
}

func countName(names []string, name string) int {
	n := 0
	for _, v := range names {
		if v == name {
			n++
		}
	}
	return n
}

func newSupHarness(t *testing.T) *supHarness {
	t.Helper()
	h := &supHarness{api: newFakeAPI(t)}
	srv := h.api.start()
	// The MASQUE endpoint must present EXACTLY the key the registration API
	// pinned in peers[0].public_key — otherwise every supervisor dial fails
	// pin verification by construction.
	h.mq = newFakeServerWithKey(t, h.api.key)
	dir := t.TempDir()
	store := &IdentityStore{Path: dir + "/identity.json"}
	cli := &EnrollClient{
		BaseURL: srv.URL + "/v0a4471",
		Sleep:   func(context.Context, time.Duration) error { return nil },
	}
	h.rec = &Reconciler{API: cli, Store: store, MinEnrollInterval: time.Millisecond}
	h.tmpl = SessionConfig{Endpoint: h.mq.addr()}
	return h
}

func (h *supHarness) newSupervisor(t *testing.T, mutate func(*SupervisorConfig)) *Supervisor {
	t.Helper()
	cfg := SupervisorConfig{
		Template:   h.tmpl,
		Reconciler: h.rec,
		Sleep:      h.recordSleep,
		Sink:       h.sink,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	sup, err := NewSupervisor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return sup
}

// waitFor polls cond until true or the deadline passes.
func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", what)
}

func hasState(t *testing.T, sup *Supervisor, want SupervisorState) bool {
	t.Helper()
	return sup.Snapshot().State == want
}

// ---- scenarios ----

// Happy path: provision -> connect -> validate -> masque_connected with the
// route held; §62.1 event sequence is emitted.
func TestSupervisorConnectsAndHoldsRoute(t *testing.T) {
	h := newSupHarness(t)
	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.HealthInterval = time.Hour // no probes in this scenario
	})
	ctx := context.Background()
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "masque_connected state", func() bool {
		st := sup.Snapshot()
		return st.State == StateConnected && st.RouteHeld
	})

	names := h.eventNames()
	if countName(names, EvSessionGenerationStarted) == 0 ||
		countName(names, EvMasqueConnected) == 0 || len(names) < 2 {
		t.Fatalf("event sequence incomplete: %v", names)
	}
	if names[0] != EvSessionGenerationStarted {
		t.Fatalf("first event = %s, want %s", names[0], EvSessionGenerationStarted)
	}
	if i := indexOf(names, EvMasqueConnected); i < indexOf(names, EvSessionGenerationStarted) {
		t.Fatalf("connected must follow generation start: %v", names)
	}
	post, _, _, _, _ := h.api.counters()
	if post != 1 {
		t.Fatalf("exactly one provisioning expected, post=%d", post)
	}

	_ = sup.Restart(true) // clean teardown path
	sup.Stop()
	if st := sup.Snapshot(); st.State != StateStopped {
		t.Fatalf("state after stop = %s", st.State)
	}
}

func indexOf(names []string, name string) int {
	for i, v := range names {
		if v == name {
			return i
		}
	}
	return -1
}

// apiCounters snapshots the fake registration API request counters so a test
// can assert an exact-zero delta across a phase.
type apiCounters struct {
	post, patch, get, account, del int
}

func counterSnapshot(api *fakeAPI) apiCounters {
	post, patch, get, account, del := api.counters()
	return apiCounters{post, patch, get, account, del}
}

func diffCounters(before apiCounters, api *fakeAPI) apiCounters {
	now := counterSnapshot(api)
	return apiCounters{
		post:    now.post - before.post,
		patch:   now.patch - before.patch,
		get:     now.get - before.get,
		account: now.account - before.account,
		del:     now.del - before.del,
	}
}

// DeferRevalidation: a locally valid stored identity is trusted for the
// FIRST connect with ZERO registration/revalidation API traffic and the
// revalidation-deferred event is emitted. Field finding 2026-08-25: networks
// that SNI-filter api.cloudflareclient.com otherwise deadlock Ensure-at-start
// before the tunnel — which may itself restore API reachability — comes up.
func TestSupervisorDeferredRevalidationSkipsAPI(t *testing.T) {
	h := newSupHarness(t)
	ctx := context.Background()

	seed := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.HealthInterval = time.Hour
	})
	if err := seed.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "provisioning connect", func() bool {
		st := seed.Snapshot()
		return st.State == StateConnected && st.RouteHeld
	})
	seed.Stop()

	apiBefore := counterSnapshot(h.api)
	namesBefore := len(h.eventNames())

	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.HealthInterval = time.Hour
		c.DeferRevalidation = true
	})
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sup.Stop()
	waitFor(t, 5*time.Second, "deferred connect", func() bool {
		st := sup.Snapshot()
		return st.State == StateConnected && st.RouteHeld
	})

	if got := diffCounters(apiBefore, h.api); got != (apiCounters{}) {
		t.Fatalf("deferred run touched the API: %+v", got)
	}
	names := h.eventNames()[namesBefore:]
	if countName(names, EvIdentityRevalidationDeferred) == 0 {
		t.Fatalf("revalidation-deferred event missing: %v", names)
	}
	if countName(names, EvMasqueConnected) == 0 {
		t.Fatalf("masque_connected must still fire: %v", names)
	}
}

// Corrupt store + DeferRevalidation falls through to the standard Ensure
// path: provisioning happens exactly as without the flag.
func TestDeferredRevalidationFallsBackOnCorruptStore(t *testing.T) {
	h := newSupHarness(t)
	if err := os.WriteFile(h.rec.Store.Path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.HealthInterval = time.Hour
		c.DeferRevalidation = true
	})
	ctx := context.Background()
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer sup.Stop()
	waitFor(t, 5*time.Second, "fallback provisioning connect", func() bool {
		st := sup.Snapshot()
		return st.State == StateConnected && st.RouteHeld
	})
	post, _, _, _, _ := h.api.counters()
	if post != 1 {
		t.Fatalf("fallback must provision exactly once, post=%d", post)
	}
}

// Storm guard: a dead endpoint produces bounded reconnect pacing — the
// backoff series grows exactly per design and the registration API is NOT
// hammered during the storm (identity reused across attempts).
func TestStormGuardBoundedReconnectPace(t *testing.T) {
	h := newSupHarness(t)
	// Dead endpoint: nothing listens here (port 1 on loopback).
	h.tmpl.Endpoint = netip.MustParseAddrPort("127.0.0.1:1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const targetRejects = 3
	var mu sync.Mutex
	rejects := 0
	h.onEvent = func(ev SupervisorEvent) {
		if ev.Name == EvMasqueRejected {
			mu.Lock()
			rejects++
			n := rejects
			mu.Unlock()
			if n == targetRejects {
				cancel()
			}
		}
	}

	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.InitialBackoff = time.Second // addendum numbers; Sleep is virtual-instant
		c.MaxBackoff = 30 * time.Second
	})

	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 10*time.Second, "paced retries", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return rejects >= targetRejects
	})
	cancel() // hook already cancelled at target; belt and braces
	sup.Stop()

	sleeps := h.recordedSleeps()
	if len(sleeps) < targetRejects {
		var dump string
		for _, e := range h.events() {
			dump += fmt.Sprintf("\n  %s class=%q status=%d detail=%q", e.Name, e.FailureClass, e.Status, e.Detail)
		}
		t.Fatalf("expected >= %d paced retries, got sleeps %v; events:%s", targetRejects, sleeps, dump)
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	for i, w := range want {
		if sleeps[i] != w {
			t.Fatalf("backoff[%d] = %v, want %v (series %v)", i, sleeps[i], w, sleeps)
		}
	}
	post, _, _, _, _ := h.api.counters()
	if post != 1 {
		t.Fatalf("storm must not re-register: post=%d", post)
	}
	names := h.eventNames()
	if countName(names, EvReconnectScheduled) < targetRejects {
		t.Fatalf("reconnect_scheduled events missing: %v", names)
	}
}

func netipAddrPort(s string) (ap struct{}) {
	panic("unused helper") // replaced below
}

// Wake-up first-packet fix: a packet written while disconnected is buffered,
// flushed right after the next validated connect, and received by the peer;
// overwritten buffers count as dropped wake-ups.
func TestWakeUpFirstPacketFix(t *testing.T) {
	h := newSupHarness(t)
	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.HealthInterval = time.Hour
	})
	ctx := context.Background()
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "initial connection", func() bool {
		return hasState(t, sup, StateConnected)
	})

	// Kick the session down; the loop will reconnect with a 1s virtual
	// backoff. During the outage window, write wake-up packets.
	if err := sup.Restart(true); err != nil {
		t.Fatal(err)
	}
	wake1 := []byte{0x45, 0x01, 0xAA, 0xBB}
	wake2 := []byte{0x45, 0x01, 0xCC, 0xDD}
	if err := sup.WritePacket(wake1); err != nil {
		t.Fatal(err)
	}
	if err := sup.WritePacket(wake2); err != nil { // latest wins; wake1 dropped
		t.Fatal(err)
	}
	if st := sup.Snapshot(); !st.PendingPacket || st.DroppedWakeups != 1 {
		t.Fatalf("pending buffer state wrong: %+v", st)
	}

	waitFor(t, 5*time.Second, "reconnect after kick", func() bool {
		return hasState(t, sup, StateConnected)
	})

	// The flushed packet must reach the fake server (echoed back too).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got := h.mq.receivedPayloads()
		if len(got) > 0 {
			last := got[len(got)-1]
			if equalBytes(last, wake2) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	got := h.mq.receivedPayloads()
	found := false
	for _, p := range got {
		if equalBytes(p, wake2) {
			found = true
		}
	}
	if !found {
		t.Fatalf("wake-up packet never delivered; server saw %d payloads", len(got))
	}
	if !equalBytes(got[len(got)-1], wake2) {
		t.Fatalf("last payload = %x, want echo of %x", got[len(got)-1], wake2)
	}
	sup.Stop()
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Fail-open: when the data plane dies mid-session, three consecutive failed
// health probes release the route IMMEDIATELY, tear the session down, and
// the loop keeps reconnecting in background.
func TestFailOpenOnHealthStreak(t *testing.T) {
	h := newSupHarness(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.HealthInterval = 20 * time.Millisecond
		c.ProbeTimeout = 60 * time.Millisecond
		c.HealthFailureLimit = 3
	})
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	// Wait for a VALIDATED connection before flipping behavior: dropping
	// data earlier would fail ValidateDataPlane instead of the health loop.
	waitFor(t, 5*time.Second, "initial validated connection", func() bool {
		return hasState(t, sup, StateConnected) && sup.Snapshot().RouteHeld
	})
	// Silent-DPI class: control accepted, data swallowed.
	h.mq.setBehavior(200, true, false, 0)

	waitFor(t, 5*time.Second, "fail-open route release", func() bool {
		evs := h.events()
		for _, e := range evs {
			if e.Name == EvRouteReleasedFailOpen {
				return true
			}
		}
		return false
	})
	if st := sup.Snapshot(); st.RouteHeld {
		t.Fatal("route must be released (fail-open)")
	}
	names := h.eventNames()
	if countName(names, EvKeepaliveFailed) < 3 {
		t.Fatalf("three keepalive failures expected, got %v", names)
	}

	// Recovery: restore the echo server; route must be held again.
	h.mq.setBehavior(200, false, false, 0)
	waitFor(t, 8*time.Second, "route recovery after heal", func() bool {
		return sup.Snapshot().RouteHeld && hasState(t, sup, StateConnected)
	})
	sup.Stop()
}

// Identity blocked (throttle): while Ensure reports a cooldown, the
// supervisor must not dial the MASQUE endpoint at all and must pace its next
// identity attempt until ThrottleUntil.
func TestIdentityBlockedNoDialing(t *testing.T) {
	h := newSupHarness(t)
	h.api.postStatusDef = 429
	h.api.retryAfter = "120"

	unblocked := make(chan struct{})
	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.Sleep = func(sctx context.Context, d time.Duration) error {
			h.recordSleep(sctx, d)
			select {
			case <-unblocked:
				return nil
			case <-sctx.Done():
				return sctx.Err()
			}
		}
	})
	ctx := context.Background()
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 3*time.Second, "identity-blocked event", func() bool {
		return countName(h.eventNames(), EvIdentityBlocked) > 0
	})
	if conns, _ := h.mq.counters(); conns != 0 {
		t.Fatalf("no MASQUE dialing allowed while identity blocked, connects=%d", conns)
	}
	sleeps := h.recordedSleeps()
	if len(sleeps) == 0 {
		t.Fatal("no identity-cooldown wait recorded")
	}
	// With the harness floor at 1ms, the capped Retry-After (120s -> 30s)
	// dominates: the first wait must be the server-honored cap, not a bare
	// retry tick.
	if sleeps[0] < 25*time.Second || sleeps[0] > MaxRetryAfterCap+2*time.Second {
		t.Fatalf("first wait must be the capped Retry-After (~30s), got %v", sleeps[0])
	}

	close(unblocked) // let the clock move: subsequent rounds proceed
	sup.Stop()
}

// Restart kicks are cooldown-paced; force bypasses.
func TestRestartCooldown(t *testing.T) {
	h := newSupHarness(t)
	base := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	clock := base
	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.HealthInterval = time.Hour
		c.Now = func() time.Time { return clock }
	})
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "connection", func() bool {
		return hasState(t, sup, StateConnected)
	})
	if err := sup.Restart(false); err != nil {
		t.Fatalf("first kick must pass: %v", err)
	}
	if err := sup.Restart(false); err == nil {
		t.Fatal("second immediate kick must hit the cooldown")
	}
	if err := sup.Restart(true); err != nil {
		t.Fatalf("force bypasses cooldown: %v", err)
	}
	sup.Stop()
}

// Backoff series unit semantics including the stable-run reset (z2k #14 /
// addendum §19 reset_after_stable=60s).
func TestBackoffSeriesAndStableReset(t *testing.T) {
	cfg := SupervisorConfig{InitialBackoff: time.Second, MaxBackoff: 30 * time.Second, ResetAfterStable: 60 * time.Second}
	b := backoffSeq{cfg: &cfg}
	series := []time.Duration{}
	for i := 0; i < 6; i++ {
		series = append(series, b.next())
	}
	expect := []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second,
		8 * time.Second, 16 * time.Second, 30 * time.Second,
	}
	for i := range expect {
		if series[i] != expect[i] {
			t.Fatalf("series[%d]=%v want %v (%v)", i, series[i], expect[i], series)
		}
	}
	// Cap holds.
	if b.next() != 30*time.Second {
		t.Fatal("cap must hold at MaxBackoff")
	}
	// Stable run resets; short run does not.
	b.observeLifetime(61 * time.Second)
	if b.next() != time.Second {
		t.Fatal("stable lifetime must reset the series")
	}
	b.next()
	b.next()
	b.observeLifetime(59 * time.Second)
	if b.next() != 8*time.Second {
		t.Fatalf("short lifetime must keep the series advancing, got %v", b.next())
	}
}
