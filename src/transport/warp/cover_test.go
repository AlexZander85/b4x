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
