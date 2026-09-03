package transportwarp

// EH5 tests: the fake-QUIC bootstrap cover WITHOUT real NFQ — profile
// conformance to the Nova pattern, arm/release lifecycle, fail-closed
// behavior on applier failure, and ladder integration (arm before H3 dial,
// release strictly after the trust gate).

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ---- profile conformance (prompt EH5: юнит соответствия профилю) ----

func TestFakeQUICProfileConformsToNovaPattern(t *testing.T) {
	p := DefaultFakeQUICCoverProfile()
	if err := p.Validate(); err != nil {
		t.Fatalf("default profile must conform: %v", err)
	}
	if len(p.Ports) != 7 {
		t.Fatalf("ports = %d, want the 7-port catalog set", len(p.Ports))
	}
	for i, port := range p.Ports {
		if port != Ports[i] {
			t.Fatalf("port[%d]=%d drifts from catalog %d", i, port, Ports[i])
		}
	}
	if p.FakeBinRepeats != 6 {
		t.Fatalf("fake_bin_repeats = %d, want 6", p.FakeBinRepeats)
	}
	if !p.AutoTTL {
		t.Fatal("autottl must be on")
	}
	if p.SetNameV4 == "" || p.SetNameV6 == "" || p.SetNameV4 == p.SetNameV6 {
		t.Fatalf("set names = %q/%q", p.SetNameV4, p.SetNameV6)
	}
}

func TestFakeQUICProfileRejectsDrift(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*FakeQUICProfile)
	}{
		{"repeats drifted", func(p *FakeQUICProfile) { p.FakeBinRepeats = 5 }},
		{"port dropped", func(p *FakeQUICProfile) { p.Ports = p.Ports[:6] }},
		{"port swapped", func(p *FakeQUICProfile) { p.Ports[0] = 80 }},
		{"autottl off", func(p *FakeQUICProfile) { p.AutoTTL = false }},
		{"empty v4 set", func(p *FakeQUICProfile) { p.SetNameV4 = "" }},
		{"same sets", func(p *FakeQUICProfile) { p.SetNameV6 = p.SetNameV4 }},
	}
	for _, c := range cases {
		p := DefaultFakeQUICCoverProfile()
		c.mutate(&p)
		if err := p.Validate(); err == nil {
			t.Errorf("%s: drift accepted", c.name)
		}
	}
}

// ---- lifecycle without NFQ ----

type stubCoverApplier struct {
	mu          sync.Mutex
	active      bool
	activations int
	v4, v6      []netip.Prefix
	failArm     bool
	lastSets    [2]string
}

func (s *stubCoverApplier) Activate(setV4, setV6 string, v4, v6 []netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failArm {
		return errors.New("injected applier failure")
	}
	s.active = true
	s.activations++
	s.v4, s.v6 = v4, v6
	s.lastSets = [2]string{setV4, setV6}
	return nil
}

func (s *stubCoverApplier) Deactivate(setV4, setV6 string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = false
	return nil
}

func newTestCover(t *testing.T, mutate func(*FakeQUICCoverConfig)) (*FakeQUICCover, *stubCoverApplier) {
	t.Helper()
	ap := &stubCoverApplier{}
	cfg := FakeQUICCoverConfig{Profile: DefaultFakeQUICCoverProfile(), Apply: ap}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := NewFakeQUICCover(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, ap
}

func TestFakeQUICCoverLifecycle(t *testing.T) {
	var events []string
	c, ap := newTestCover(t, func(cfg *FakeQUICCoverConfig) {
		cfg.Sink = func(ev GuardEvent) { events = append(events, ev.Name) }
	})

	// Arm → coverage active with BOTH families of the versioned map.
	if err := c.Arm(); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if !ap.active || len(ap.v4) == 0 || len(ap.v6) == 0 {
		t.Fatalf("coverage incomplete: active=%v v4=%v v6=%v", ap.active, ap.v4, ap.v6)
	}
	for _, p := range append(append([]netip.Prefix{}, ap.v4...), ap.v6...) {
		found := false
		for _, cat := range h2GatewayCIDRs {
			if cat == p {
				found = true
			}
		}
		if !found {
			t.Fatalf("cover prefix %s outside the versioned map", p)
		}
	}
	if ap.lastSets[0] != DefaultFakeQUICCoverSetV4 || ap.lastSets[1] != DefaultFakeQUICCoverSetV6 {
		t.Fatalf("sets = %v", ap.lastSets)
	}
	// Idempotent re-arm inside one window.
	if err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	if ap.activations != 1 {
		t.Fatalf("activations = %d, want 1 (idempotent)", ap.activations)
	}

	// Release strictly on terminal outcome; double release is a no-op.
	c.Release("validated")
	if ap.active {
		t.Fatal("coverage must drop after release")
	}
	c.Release("validated")
	st := c.Status()
	if st.Releases != 1 || st.Arms != 1 || st.Armed {
		t.Fatalf("status = %+v", st)
	}
	if len(events) != 2 || events[0] != EvFakeQUICCoverArmed || events[1] != EvFakeQUICCoverReleased {
		t.Fatalf("events = %v", events)
	}
}

func TestFakeQUICCoverArmFailureIsStructural(t *testing.T) {
	c, _ := newTestCover(t, func(cfg *FakeQUICCoverConfig) {
		cfg.Apply = &stubCoverApplier{failArm: true}
	})
	err := c.Arm()
	if err == nil {
		t.Fatalf("arm failure must surface, got nil")
	}
	if st := c.Status(); st.Armed || st.ApplyErrors != 1 {
		t.Fatalf("status = %+v", st)
	}
}

func TestFakeQUICCoverRejectsInvalidProfile(t *testing.T) {
	p := DefaultFakeQUICCoverProfile()
	p.FakeBinRepeats = 7
	if _, err := NewFakeQUICCover(FakeQUICCoverConfig{Profile: p, Apply: &stubCoverApplier{}}); err == nil {
		t.Fatal("drifted profile must not construct")
	}
}

// ---- ladder integration ----

// Cover arms BEFORE every H3 attempt and releases on each terminal outcome;
// a validated H3 session releases AFTER the trust gate; an applier failure
// skips to H2 for the generation WITHOUT poisoning the cooldown gate.
func TestLadderCoverIntegration(t *testing.T) {
	h := newSupHarness(t)
	scfg := ladderKeyMaterial(t, h)

	ap := &stubCoverApplier{}
	cover, err := NewFakeQUICCover(FakeQUICCoverConfig{Profile: DefaultFakeQUICCoverProfile(), Apply: ap})
	if err != nil {
		t.Fatal(err)
	}

	// Case 1: H3 dies after arming → released on the terminal outcome,
	// switch event present, H2 generation proceeds covered-or-not.
	d1, _ := newTestLadder(t, func(c *LadderConfig) {
		c.Cover = cover
		c.DialH3 = func(context.Context, H3SessionConfig) (*H3Session, H3ConnectResult, error) {
			_ = cover.Arm() // real flow arms inside tryH3; fixture mirrors it
			return nil, H3ConnectResult{FailureClass: FailureUDPEgressBlocked}, errors.New("udp-egress-blocked: injected")
		}
	})
	ctx := context.Background()
	sess1, att1, derr := d1.Dial(ctx, scfg)
	if derr != nil {
		t.Fatalf("h2 fallback: %v", derr)
	}
	sess1.Close()
	_ = att1
	if cover.Status().Armed {
		t.Fatal("cover must release on h3 terminal outcome")
	}

	// Case 2: validated H3 → release happens via ObserveValidation(success).
	d2, _ := newTestLadder(t, func(c *LadderConfig) {
		c.Cover = cover
	})
	if err := cover.Arm(); err != nil {
		t.Fatal(err)
	}
	if evs := d2.ObserveValidation(TransportH3, nil); len(evs) != 0 {
		t.Fatalf("validated observation must be silent, got %+v", evs)
	}
	if cover.Status().Armed {
		t.Fatal("validated trust gate must release the cover (§C.4)")
	}

	// Case 3: applier failure → NO network verdict, NO gate poisoning:
	// straight H2 this generation, zero switch events, next Dial retries H3.
	failCover, _ := NewFakeQUICCover(FakeQUICCoverConfig{
		Profile: DefaultFakeQUICCoverProfile(),
		Apply:   &stubCoverApplier{failArm: true},
	})
	h3Calls := 0
	d3, _ := newTestLadder(t, func(c *LadderConfig) {
		c.Cover = failCover
		c.DialH3 = func(context.Context, H3SessionConfig) (*H3Session, H3ConnectResult, error) {
			h3Calls++
			return nil, H3ConnectResult{}, errors.New("must not dial under broken cover")
		}
	})
	sess3, att3, derr3 := d3.Dial(ctx, scfg)
	if derr3 != nil || sess3 == nil {
		t.Fatalf("broken cover must land on H2: %v", derr3)
	}
	sess3.Close()
	if att3.Transport != TransportH2 || len(att3.Events) != 0 {
		t.Fatalf("case3 attempt = %q %+v", att3.Transport, att3.Events)
	}
	if m := d3.Metrics(); m.H3Blocked || m.Switches != 0 {
		t.Fatalf("gate poisoned by local cover failure: %+v", m)
	}
	_ = h3Calls // must stay 0 while the cover is broken
}

// ---- PATCH-23 (M-15): release retry + escalation ----

// flakyCoverApplier fails Deactivate a fixed number of times, then succeeds.
type flakyCoverApplier struct {
	stubCoverApplier
	mu       sync.Mutex
	failLeft int
	calls    int
}

func (f *flakyCoverApplier) Deactivate(setV4, setV6 string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.failLeft > 0 {
		f.failLeft--
		return errors.New("nft panic: ruleset busy")
	}
	return nil
}

// Calls returns the Deactivate call count (race-safe for test polling).
func (f *flakyCoverApplier) Calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// guardEvents is a mutex-guarded GuardEvent collector (the retry loop emits
// from a background goroutine).
type guardEvents struct {
	mu  sync.Mutex
	evs []GuardEvent
}

func (g *guardEvents) add(ev GuardEvent) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.evs = append(g.evs, ev)
}

func (g *guardEvents) count(name string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, ev := range g.evs {
		if ev.Name == name {
			n++
		}
	}
	return n
}

func newFlakyCover(t *testing.T, failLeft int) (*FakeQUICCover, *flakyCoverApplier, *guardEvents) {
	t.Helper()
	prof := DefaultFakeQUICCoverProfile()
	applier := &flakyCoverApplier{failLeft: failLeft}
	events := &guardEvents{}
	c, err := NewFakeQUICCover(FakeQUICCoverConfig{
		Profile:                  prof,
		Apply:                    applier,
		Sink:                     events.add,
		ReleaseRetryEvery:        5 * time.Millisecond,
		ReleaseRetryFastAttempts: 3,
		ReleaseRetrySlowEvery:    20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return c, applier, events
}

// TestReleaseRetriesUntilSuccess: two failed Deactivates, then the retry
// loop clears the sets; exactly one escalation (the initial failure), the
// fast retries stay quiet, and the final Deactivate succeeded.
func TestReleaseRetriesUntilSuccess(t *testing.T) {
	c, applier, events := newFlakyCover(t, 2)
	if err := c.Arm(); err != nil {
		t.Fatalf("arm: %v", err)
	}
	c.Release("test-done")

	deadline := time.After(3 * time.Second)
	for {
		st := c.Status()
		if !st.Armed && applier.Calls() >= 3 && events.count(EvFakeQUICCoverReleased) >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("retry never cleared: status=%+v calls=%d", c.Status(), applier.Calls())
		case <-time.After(5 * time.Millisecond):
		}
	}
	time.Sleep(50 * time.Millisecond) // settle: no further retries may arrive
	st := c.Status()
	if st.ReleaseRetries != 2 {
		t.Fatalf("ReleaseRetries = %d, want 2", st.ReleaseRetries)
	}
	if n := events.count(EvFakeQUICCoverReleaseFailed); n != 1 {
		t.Fatalf("escalations = %d, want exactly 1 (initial failure)", n)
	}
	if calls := applier.Calls(); calls < 3 {
		t.Fatalf("Deactivate calls = %d, want >= 3 (initial + 2 retries)", calls)
	}
}

// TestReleaseEscalatesWhenPersistent: a permanently failing applier drives
// escalations at the discharged cadence; a new Arm() cancels the retry loop
// (no goroutine leak, no events after the re-arm).
func TestReleaseEscalatesWhenPersistent(t *testing.T) {
	c, applier, events := newFlakyCover(t, 1<<30) // never succeeds
	if err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	c.Release("test-stuck")

	deadline := time.After(3 * time.Second)
	for events.count(EvFakeQUICCoverReleaseFailed) < 2 {
		select {
		case <-deadline:
			t.Fatal("escalations never reached the discharged cadence")
		case <-time.After(5 * time.Millisecond):
		}
	}
	// Re-arm cancels the retry loop.
	if err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // a leaked loop would keep retrying/escalating
	base := events.count(EvFakeQUICCoverReleaseFailed)
	time.Sleep(100 * time.Millisecond)
	if got := events.count(EvFakeQUICCoverReleaseFailed); got != base {
		t.Fatalf("retry loop survived Arm(): escalations %d -> %d", base, got)
	}
	t.Logf("total Deactivate calls before re-arm: %d", applier.Calls())
}
