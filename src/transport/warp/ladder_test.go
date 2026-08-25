package transportwarp

// EH3 ladder tests: switch classes, anti-oscillation gate, cooldown return,
// pin-mismatch fail-closed, silent-drop marking, and the end-to-end
// supervisor acceptance criterion (N ticks with live H2 + dead H3 ⇒ exactly
// ONE transport_switched).

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// ladderKeyMaterial fills the shared endpoint profile with usable identity
// material (the supervisor normally injects these per-generation).
func ladderKeyMaterial(t *testing.T, h *supHarness) SessionConfig {
	t.Helper()
	privB64, _, err := GenerateClientKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParseClientKeyB64(privB64)
	if err != nil {
		t.Fatal(err)
	}
	scfg := h.tmpl
	scfg.ClientKey = priv
	scfg.Pin = &h.api.key.PublicKey
	scfg.LocalV4 = [4]byte{172, 16, 0, 2}
	return scfg
}

type h3AttemptCounter struct {
	n atomic.Int32
}

func (c *h3AttemptCounter) fail(class string) func(context.Context, H3SessionConfig) (*H3Session, H3ConnectResult, error) {
	return func(context.Context, H3SessionConfig) (*H3Session, H3ConnectResult, error) {
		c.n.Add(1)
		res := H3ConnectResult{FailureClass: class, DurationMS: 5}
		return nil, res, errors.New(class + ": injected")
	}
}

func newTestLadder(t *testing.T, mutate func(*LadderConfig)) (*H3FirstDialer, *LadderConfig) {
	t.Helper()
	cfg := LadderConfig{}
	if mutate != nil {
		mutate(&cfg)
	}
	d, err := NewH3FirstDialer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return d, &cfg
}

// Confirmed egress-block ⇒ immediate H2 fallback with EXACTLY ONE switch
// event; subsequent generations go straight to H2 (zero H3 contacts, zero
// events) while the cooldown window lives.
func TestLadderUDPEgressBlockedSwitchesToH2Once(t *testing.T) {
	h := newSupHarness(t)
	scfg := ladderKeyMaterial(t, h)

	var ctr h3AttemptCounter
	base := time.Date(2026, 8, 25, 12, 0, 0, 0, time.UTC)
	clock := base
	d, _ := newTestLadder(t, func(c *LadderConfig) {
		c.DialH3 = ctr.fail(FailureUDPEgressBlocked)
		c.Now = func() time.Time { return clock }
	})

	ctx := context.Background()

	// Generation 1: H3 dies (egress-blocked) ⇒ one switch event, H2 lives.
	sess, att, err := d.Dial(ctx, scfg)
	if err != nil {
		t.Fatalf("H2 fallback dial: %v", err)
	}
	defer sess.Close()
	if att.Transport != TransportH2 {
		t.Fatalf("transport = %q, want h2", att.Transport)
	}
	if n := len(att.Events); n != 1 || att.Events[0].Name != EvTransportSwitched {
		t.Fatalf("events = %+v, want exactly one %s", att.Events, EvTransportSwitched)
	}
	ev := att.Events[0]
	if ev.FailureClass != FailureUDPEgressBlocked || ev.Detail != "from=h3 to=h2 reason=udp-egress-blocked" {
		t.Fatalf("switch event payload wrong: %+v", ev)
	}
	vctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	if verr := sess.ValidateDataPlane(vctx); verr != nil {
		t.Fatalf("fallback H2 session failed trust gate: %v", verr)
	}

	// Generations 2..N within the cooldown: straight to H2, ZERO H3 contact,
	// ZERO events — the anti-oscillation core.
	for tick := 2; tick <= 6; tick++ {
		s2, att2, err := d.Dial(ctx, scfg)
		if err != nil {
			t.Fatalf("tick %d: %v", tick, err)
		}
		s2.Close()
		if att2.Transport != TransportH2 || len(att2.Events) != 0 {
			t.Fatalf("tick %d: transport=%q events=%v", tick, att2.Transport, att2.Events)
		}
	}
	if got := ctr.n.Load(); got != 1 {
		t.Fatalf("H3 contacted %d times across 6 ticks, want exactly 1", got)
	}
	if m := d.Metrics(); !m.H3Blocked || m.FallbackToH2 != 1 || m.Switches != 1 || m.H3DialTotal[FailureUDPEgressBlocked] != 1 {
		t.Fatalf("metrics = %+v", m)
	}

	// Cooldown expiry inside the supervisor cycle: H3 is tried AGAIN, fails
	// again (one more switch), and the generation still lands on live H2.
	clock = base.Add(301 * time.Second)
	sess3, att3, err := d.Dial(ctx, scfg)
	if err != nil {
		t.Fatalf("post-cooldown generation must land on H2: %v", err)
	}
	defer sess3.Close()
	if att3.Transport != TransportH2 || len(att3.Events) != 1 ||
		att3.Events[0].FailureClass != FailureUDPEgressBlocked {
		t.Fatalf("post-cooldown attempt = %q %+v", att3.Transport, att3.Events)
	}
	if got := ctr.n.Load(); got != 2 {
		t.Fatalf("post-cooldown H3 attempts = %d, want 2", got)
	}
	if m := d.Metrics(); m.Switches != 2 || m.FallbackToH2 != 2 {
		t.Fatalf("metrics = %+v", m)
	}
}

// TLS-alert handshake failures belong to the confirmed family: switch once,
// then stay on H2 until the cooldown expires.
func TestLadderHandshakeFailSwitchesToH2(t *testing.T) {
	h := newSupHarness(t)
	scfg := ladderKeyMaterial(t, h)
	var ctr h3AttemptCounter
	d, _ := newTestLadder(t, func(c *LadderConfig) {
		c.DialH3 = ctr.fail(FailureTLSAlert)
	})

	ctx := context.Background()
	sess, att, err := d.Dial(ctx, scfg)
	if err != nil {
		t.Fatalf("H2 fallback: %v", err)
	}
	defer sess.Close()
	if len(att.Events) != 1 || att.Events[0].FailureClass != FailureTLSAlert {
		t.Fatalf("events = %+v", att.Events)
	}
	s2, att2, err := d.Dial(ctx, scfg)
	if err != nil || len(att2.Events) != 0 || att2.Transport != TransportH2 {
		t.Fatalf("tick2 must be silent H2: err=%v events=%v", err, att2.Events)
	}
	s2.Close()
	if got := ctr.n.Load(); got != 1 {
		t.Fatalf("H3 attempts = %d, want 1", got)
	}
}

// H3 success sticks: every generation keeps using H3, no switch events ever.
func TestLadderH3SuccessSticks(t *testing.T) {
	h := newSupHarness(t) // profile carries key material
	scfg := ladderKeyMaterial(t, h)
	// The edge MUST present the pinned key (api.key), not a stranger key.
	e := newFakeH3EdgeWithKey(t, h.api.key)

	calls := 0
	d, _ := newTestLadder(t, func(c *LadderConfig) {
		c.DialH3 = func(_ context.Context, hcfg H3SessionConfig) (*H3Session, H3ConnectResult, error) {
			calls++
			// Fixture wiring: the real carrier dials the loopback edge.
			hcfg.Endpoint = netipMustAddrPort(e.addr)
			hcfg.HandshakeBudget = 3 * time.Second
			hcfg.ValidateWindow = 900 * time.Millisecond
			hcfg.ProbeInterval = 100 * time.Millisecond
			return DialH3Session(context.Background(), hcfg)
		}
	})

	ctx := context.Background()
	for gen := 1; gen <= 3; gen++ {
		sess, att, err := d.Dial(ctx, scfg)
		if err != nil {
			t.Fatalf("gen %d: %v", gen, err)
		}
		if att.Transport != TransportH3 || len(att.Events) != 1 || att.Events[0].Name != EvH3Negotiated {
			t.Fatalf("gen %d: transport=%q events=%v", gen, att.Transport, att.Events)
		}
		if att.Result.Colo != "TST" {
			t.Fatalf("gen %d: colo lost on the unified result (%+v)", gen, att.Result)
		}
		sess.Close()
	}
	if calls != 3 {
		t.Fatalf("H3 dials = %d, want 3 (success must stick)", calls)
	}
	if m := d.Metrics(); m.H3Blocked || m.H3DialTotal["ok"] != 3 {
		t.Fatalf("metrics = %+v", m)
	}
}

// Pin mismatch is fail-closed: NO H2 attempt, NO switch, and H3 stays the
// preference for the next generation.
func TestLadderPinMismatchDoesNotSwitch(t *testing.T) {
	h := newSupHarness(t)
	scfg := ladderKeyMaterial(t, h)
	var ctr h3AttemptCounter
	h2Calls := 0
	d, _ := newTestLadder(t, func(c *LadderConfig) {
		c.DialH3 = ctr.fail(FailureTLSPin)
		c.DialH2 = func(context.Context, SessionConfig) (*Session, ConnectResult, error) {
			h2Calls++
			return nil, ConnectResult{}, errors.New("h2 must not be attempted")
		}
	})

	ctx := context.Background()
	for gen := 1; gen <= 2; gen++ {
		sess, att, evErr := d.Dial(ctx, scfg)
		if sess != nil || evErr == nil {
			t.Fatalf("gen %d: pin verdict must fail the generation", gen)
		}
		_ = sess
		if att.Transport != TransportH3 || len(att.Events) != 0 {
			t.Fatalf("gen %d: transport=%q events=%v", gen, att.Transport, att.Events)
		}
	}
	if h2Calls != 0 {
		t.Fatalf("H2 attempted %d times on pin mismatch — masking forbidden", h2Calls)
	}
	if got := ctr.n.Load(); got != 2 {
		t.Fatalf("H3 attempts = %d, want 2 (preference preserved)", got)
	}
	if m := d.Metrics(); m.FallbackToH2 != 0 || m.Switches != 0 {
		t.Fatalf("metrics = %+v", m)
	}
}

// Validation-timeout on an H3 session is the §6 handshake-ok-but-silent
// case: the NEXT generation goes to H2 with one switch event.
func TestLadderSilentDropMarksAndSwitchesNextGeneration(t *testing.T) {
	h := newSupHarness(t)
	scfg := ladderKeyMaterial(t, h)
	var ctr h3AttemptCounter
	d, _ := newTestLadder(t, func(c *LadderConfig) {
		c.DialH3 = ctr.fail(FailureUDPEgressBlocked) // reused after the mark
	})
	ctx := context.Background()

	// Supervisor reports an H3 validation timeout.
	evs := d.ObserveValidation(TransportH3, ErrValidationTimeout)
	if len(evs) != 1 || evs[0].Name != EvTransportSwitched || evs[0].FailureClass != FailureValidation {
		t.Fatalf("observe-validation events = %+v", evs)
	}
	// Passed H2 validations are ladder-neutral.
	if evs := d.ObserveValidation(TransportH2, nil); len(evs) != 0 {
		t.Fatalf("h2 observation must be neutral, got %+v", evs)
	}
	// Next generation: straight to H2 without touching H3.
	sess, att, err := d.Dial(ctx, scfg)
	if err != nil {
		t.Fatalf("post-mark H2 dial: %v", err)
	}
	defer sess.Close()
	if att.Transport != TransportH2 || len(att.Events) != 0 {
		t.Fatalf("post-mark generation wrong: %q %+v", att.Transport, att.Events)
	}
	if got := ctr.n.Load(); got != 0 {
		t.Fatalf("blocked H3 was contacted (%d)", got)
	}
}

// classifyProbeError: the three reachability classes over synthetic inputs.
func TestProbeClassification(t *testing.T) {
	cases := []struct {
		err  error
		want ReachabilityClass
	}{
		{&quic.VersionNegotiationError{Ours: []quic.Version{quic.Version1}}, ReachReachable},
		{&quic.StatelessResetError{}, ReachReachable},
		{errors.New("tls: handshake failure"), ReachReachable},
		{errors.New("remote error: tls: bad certificate"), ReachReachable},
		{&quic.IdleTimeoutError{}, ReachBlackhole},
		{&quic.HandshakeTimeoutError{}, ReachBlackhole},
		{context.DeadlineExceeded, ReachBlackhole},
		{errors.New("dial udp 162.159.198.1:443: connect: connection refused"), ReachRefused},
		{errors.New("read: connection reset by peer"), ReachRefused},
	}
	for i, c := range cases {
		if got := classifyProbeError(c.err); got != c.want {
			t.Errorf("case %d (%v): got %s want %s", i, c.err, got, c.want)
		}
	}
}

// The live probe distinguishes an answering edge from a blackhole, and a
// closed port is never reported reachable (the prompt-mandated distinction:
// reachability ≠ handshake-failure ≠ egress block).
func TestProbeUDPReachabilityLiveVsBlackhole(t *testing.T) {
	h := newDiscHarness(t, 1)
	key := h.tmpl.ClientKey

	// Live edge: the pinned handshake completes ⇒ reachable.
	e := newFakeH3EdgeWithKey(t, h.api.key)
	liveCfg := SessionConfig{
		Endpoint:  netipMustAddrPort(e.addr),
		SNI:       DefaultSNI,
		ClientKey: key,
		Pin:       e.pinPub(),
	}
	class, err := ProbeUDPReachability(context.Background(), liveCfg, 2500*time.Millisecond)
	if err != nil || class != ReachReachable {
		t.Fatalf("live edge probe = %s %v, want reachable", class, err)
	}

	// Blackhole fixture: occupy a UDP port, then release it — nothing listens.
	dead, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := dead.LocalAddr().(*net.UDPAddr).Port
	dead.Close()
	deadCfg := SessionConfig{
		Endpoint:  netip.MustParseAddrPort("127.0.0.1:" + strconv.Itoa(port)),
		SNI:       DefaultSNI,
		ClientKey: key,
		Pin:       e.pinPub(),
	}
	start := time.Now()
	class, perr := ProbeUDPReachability(context.Background(), deadCfg, 700*time.Millisecond)
	if class != ReachBlackhole || perr == nil {
		t.Fatalf("blackhole probe = %s %v, want blackhole+err", class, perr)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("probe must stay fast, took %v", elapsed)
	}
}

// ACCEPTANCE (prompt EH3): N ticks with a LIVE H2 edge and a DEAD H3 edge
// produce exactly ONE transport_switched — no per-tick oscillation.
func TestSupervisorLadderNoOscillationAcrossTicks(t *testing.T) {
	h := newSupHarness(t)
	var ctr h3AttemptCounter
	lad, _ := newTestLadder(t, func(c *LadderConfig) {
		c.DialH3 = ctr.fail(FailureUDPEgressBlocked)
	})
	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.Dialer = lad
		c.HealthInterval = time.Hour // sessions live until kicked
	})
	ctx := context.Background()
	if err := sup.Start(ctx); err != nil {
		t.Fatal(err)
	}

	const ticks = 5
	for tick := 1; tick <= ticks; tick++ {
		waitFor(t, 5*time.Second, "connected generation", func() bool {
			return hasState(t, sup, StateConnected) && sup.Snapshot().RouteHeld
		})
		if tick == ticks {
			break
		}
		// Anchor on the disconnect EVENT: Snapshot can show stale
		// Connected/RouteHeld while the kicked session is still unwinding.
		before := countName(h.eventNames(), EvMasqueDisconnected)
		if err := sup.Restart(true); err != nil { // force: bypass kick cooldown
			t.Fatal(err)
		}
		waitFor(t, 5*time.Second, "disconnect observed", func() bool {
			return countName(h.eventNames(), EvMasqueDisconnected) >= before+1
		})
	}

	names := h.eventNames()
	if n := countName(names, EvTransportSwitched); n != 1 {
		t.Fatalf("transport_switched across %d ticks = %d, want exactly 1 (%v)", ticks, n, names)
	}
	if countName(names, EvMasqueConnected) != ticks {
		t.Fatalf("connected events = %d, want %d", countName(names, EvMasqueConnected), ticks)
	}
	if st := sup.Snapshot(); st.LastTransport != TransportH2 || !st.RouteHeld {
		t.Fatalf("status = %+v", st)
	}
	if got := ctr.n.Load(); got != 1 {
		t.Fatalf("H3 contacted %d times, want exactly 1", got)
	}
	// Connected events carry the carrier explicitly.
	for _, ev := range h.events() {
		if ev.Name == EvMasqueConnected && ev.Detail != "transport=h2" {
			t.Fatalf("connected detail = %q", ev.Detail)
		}
	}
	sup.Stop()
}

// EH4: cf-warp-colo parsed on the H3 CONNECT response reaches the trace
// payload exactly like the H2 path — EvMasqueConnected carries it and the
// unified result keeps one shape per phase.
func TestSupervisorH3ColoFlowsToTraceEvent(t *testing.T) {
	h := newSupHarness(t)
	e := newFakeH3EdgeWithKey(t, h.api.key)

	d, _ := newTestLadder(t, func(c *LadderConfig) {
		c.DialH3 = func(_ context.Context, hcfg H3SessionConfig) (*H3Session, H3ConnectResult, error) {
			hcfg.Endpoint = netipMustAddrPort(e.addr)
			hcfg.HandshakeBudget = 3 * time.Second
			hcfg.ValidateWindow = 900 * time.Millisecond
			hcfg.ProbeInterval = 100 * time.Millisecond
			return DialH3Session(context.Background(), hcfg)
		}
	})
	sup := h.newSupervisor(t, func(c *SupervisorConfig) {
		c.Dialer = d
		c.HealthInterval = time.Hour
	})
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, "h3 connection", func() bool {
		st := sup.Snapshot()
		return st.State == StateConnected && st.LastTransport == TransportH3
	})

	var connected *SupervisorEvent
	for i, ev := range h.events() {
		if ev.Name == EvMasqueConnected {
			connected = &h.events()[i]
		}
	}
	if connected == nil || connected.Colo != "TST" || connected.Detail != "transport=h3" {
		t.Fatalf("connected event = %+v", connected)
	}
	if st := sup.Snapshot(); st.LastColo != "TST" {
		t.Fatalf("status colo = %q", st.LastColo)
	}
	sup.Stop()
}
