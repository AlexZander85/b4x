package nested

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	twarp "github.com/daniellavrushin/b4/transport/warp"
	twg "github.com/daniellavrushin/b4/transport/wg"
)

func validWMPair() PairConfig {
	return PairConfig{
		Outer: LayerSpec{
			Kind: KindAWG, IdentitySlot: SlotPrimary,
			ProfileID: "awg/quic-a", Endpoint: netip.MustParseAddrPort("162.159.193.10:2408"),
		},
		Inner: LayerSpec{
			Kind: KindMasqueH2, IdentitySlot: SlotSecondary,
			ProfileID: "cf-warp/vanilla-off", Endpoint: netip.MustParseAddrPort("162.159.192.1:443"),
		},
	}
}

// wmTestIdentity builds a structurally valid throwaway identity for tests
// that never touch the wire (PATCH-02/E10: zero identities are now rejected
// at construction, so fixtures must carry a parseable AssignedV4).
func wmTestIdentity(t *testing.T) *twg.Identity {
	t.Helper()
	priv, pub := genWGPair(t)
	id, err := twg.NewIdentity(priv, pub, "AAAA", "10.77.0.2", "", false)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// TestWgMasqueValidateRejectsZeroAssignedV4 is the PATCH-02/E10 acceptance
// test: a W+M config whose outer identity carries no parseable AssignedV4
// must be rejected at Validate time, never panic later on Start.
func TestWgMasqueValidateRejectsZeroAssignedV4(t *testing.T) {
	cfg := WgMasqueConfig{
		Pair:          validWMPair(),
		OuterIdent:    &twg.Identity{}, // empty AssignedV4
		InnerEnroll:   &twarp.EnrollClient{},
		InnerSlotPath: "/tmp/secondary.json",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("zero AssignedV4 must be rejected by WgMasqueConfig.Validate")
	}
	if _, err := NewWgMasqueRuntime(cfg); err == nil {
		t.Fatal("zero AssignedV4 must be rejected at construction")
	}
}

func TestWgMasqueValidateTable(t *testing.T) {
	base := func() WgMasqueConfig {
		return WgMasqueConfig{
			Pair:          validWMPair(),
			OuterIdent:    wmTestIdentity(t),
			InnerEnroll:   &twarp.EnrollClient{},
			InnerSlotPath: "/tmp/secondary.json",
		}
	}

	c0 := base()
	if err := c0.Validate(); err != nil {
		t.Fatalf("happy config rejected: %v", err)
	}

	wm := base()
	wm.Pair.Outer.Kind = KindMasqueH2 // M+W declared here, runtime is W+M
	if err := wm.Validate(); err == nil {
		t.Fatal("masque outer must be rejected by the w+m runtime")
	}

	noIdent := base()
	noIdent.OuterIdent = nil
	if err := noIdent.Validate(); err == nil {
		t.Fatal("missing outer identity must be rejected")
	}

	kernHalf := base()
	kernHalf.OuterKernelTUN = true
	if err := kernHalf.Validate(); err == nil {
		t.Fatal("kernel mode without device/runner must be rejected")
	}

	kernStray := base()
	kernStray.KernelDevice = "wg0" // but OuterKernelTUN=false
	if err := kernStray.Validate(); err == nil {
		t.Fatal("stray kernel fields without kernel mode must be rejected")
	}

	noSlot := base()
	noSlot.InnerEnroll = nil
	if err := noSlot.Validate(); err == nil {
		t.Fatal("secondary slot enrollment is mandatory (red line #3)")
	}
	noPath := base()
	noPath.InnerSlotPath = ""
	if err := noPath.Validate(); err == nil {
		t.Fatal("secondary store path is mandatory")
	}
}

func TestWgMasqueRuntimeConstruction(t *testing.T) {
	cfg := WgMasqueConfig{Pair: validWMPair()}
	if _, err := NewWgMasqueRuntime(cfg); err == nil {
		t.Fatal("missing identity/enrollment must be rejected at construction")
	}

	ok := WgMasqueConfig{
		Pair:          validWMPair(),
		OuterIdent:    wmTestIdentity(t),
		InnerEnroll:   &twarp.EnrollClient{},
		InnerSlotPath: t.TempDir() + "/secondary.json",
	}
	rt, err := NewWgMasqueRuntime(ok)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	link, gen, child := rt.Status()
	if link != "waiting-parent" || gen != 0 || child {
		t.Fatalf("initial status = %s/%d/%v", link, gen, child)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = ctx
	// NOTE: full Start() requires a live AWG edge (outer session dial);
	// that coverage belongs to the field/integration stand - construction
	// and parent-link contracts are what unit CI pins down here.
}

func TestDialerWithMSSPreservesBase(t *testing.T) {
	d := &net.Dialer{Timeout: 3 * time.Second}
	got := DialerWithMSS(d, 1200)
	if got == d {
		t.Fatal("expected a wrapped dialer when mss>0")
	}
	same := DialerWithMSS(d, 0)
	if same != d {
		t.Fatal("mss<=0 must return the base dialer unchanged")
	}
	fresh := DialerWithMSS(nil, 0)
	if fresh == nil || fresh.Timeout != 5*time.Second {
		t.Fatal("nil base with mss<=0 must yield the default dialer")
	}
}

// ---- PATCH-04: single live carrier across outer reconnects ----

// wmEventLog collects runtime events (mutex-guarded: assertion loops emit
// from goroutines).
type wmEventLog struct {
	mu sync.Mutex
	ev []Event
}

func (l *wmEventLog) add(ev Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.ev = append(l.ev, ev)
}

func (l *wmEventLog) count(class string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.ev {
		if e.Class == class {
			n++
		}
	}
	return n
}

// newWMKernelRuntime builds a kernel-mode W+M runtime over a fake route
// table. The inner enrollment points at a dead loopback port so the inner
// start fails fast WITHOUT any external traffic; the carrier lifecycle under
// test is independent of the inner outcome.
func newWMKernelRuntime(t *testing.T, fr *fakeRoutes, log *wmEventLog) *WgMasqueRuntime {
	t.Helper()
	cfg := WgMasqueConfig{
		Pair:           validWMPair(),
		OuterIdent:     wmTestIdentity(t),
		InnerEnroll:    &twarp.EnrollClient{BaseURL: "http://127.0.0.1:1"},
		InnerSlotPath:  t.TempDir() + "/secondary.json",
		OuterKernelTUN: true,
		KernelDevice:   "wgout",
		KernelRunner:   fr.run,
		OnEvent:        log.add,
	}
	rt, err := NewWgMasqueRuntime(cfg)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	rt.assertInterval = 50 * time.Millisecond
	return rt
}

// TestWgMasqueKernelCarrierSurvivesOuterGenerations is the PATCH-07/E2
// acceptance test: the kernel route carrier is built ONCE per runtime and
// survives outer generations — no teardown/rebuild churn, no repeated
// route-show snapshots (provenance stays with the single carrier), and the
// final Stop restores the ORIGINAL foreign route verbatim.
func TestWgMasqueKernelCarrierSurvivesOuterGenerations(t *testing.T) {
	fr := newFakeRoutes()
	dst := validWMPair().Inner.Endpoint.Addr().String() // the pin target the runtime actually owns
	// Foreign route present BEFORE the first pin: the final Stop must
	// restore it verbatim (first-generation prev survives reconnects).
	fr.showPre[dst] = dst + " via 10.7.7.1 dev wan0"

	log := &wmEventLog{}
	rt := newWMKernelRuntime(t, fr, log)

	// Generation 1: fresh carrier pins the route on the outer device.
	rt.onParentUp()
	if !fr.has("-4", dst, "wgout") {
		t.Fatal("gen1: route not pinned on the outer device")
	}
	showsAfterGen1 := fr.count("route show")

	// Generations 2 and 3 (outer reconnects): the SAME carrier serves —
	// no teardown event, no new Setup snapshot (show count unchanged),
	// pin ownership undisturbed.
	rt.onParentUp()
	rt.onParentUp()
	if n := log.count("wg_nested_carrier_replaced"); n != 0 {
		t.Fatalf("carrier_replaced events = %d, want 0 (single carrier)", n)
	}
	if got := fr.count("route show"); got != showsAfterGen1 {
		t.Fatalf("route show calls grew %d -> %d across generations (carrier was rebuilt)", showsAfterGen1, got)
	}
	if !fr.has("-4", dst, "wgout") {
		t.Fatal("pin lost across generations")
	}

	// Final Stop: the ORIGINAL foreign route comes back, not our pin.
	rt.Stop()
	if !fr.has("-4", dst, "wan0") {
		t.Fatalf("final restore must return the foreign route, table=%v", fr.lines)
	}
	if fr.has("-4", dst, "wgout") {
		t.Fatal("our pin survived Stop: ownership leak")
	}
}

// TestWgMasqueForeignRouteProvenanceAcrossGenerations is the end-to-end
// E1+E2 acceptance: two outer generations over a pre-existing foreign /32,
// then Stop — the foreign route must come back verbatim, our pin gone.
func TestWgMasqueForeignRouteProvenanceAcrossGenerations(t *testing.T) {
	fr := newFakeRoutes()
	dst := validWMPair().Inner.Endpoint.Addr().String()
	fr.showPre[dst] = dst + " via 10.7.7.1 dev wan0"

	rt := newWMKernelRuntime(t, fr, &wmEventLog{})

	rt.onParentUp()
	rt.onParentUp() // second generation reuses the single carrier
	rt.Stop()

	if !fr.has("-4", dst, "wan0") {
		t.Fatalf("foreign route not restored verbatim, table=%v", fr.lines)
	}
	if fr.has("-4", dst, "wgout") {
		t.Fatal("pin survived Stop across generations")
	}
}

// TestWgMasqueNoDuplicateRouteLostAfterWipe pins the wipe->repair cycle on
// the SINGLE runtime carrier (PATCH-07/E2): exactly one route-lost event
// and one repair per episode — there is no second emitter at all anymore.
func TestWgMasqueNoDuplicateRouteLostAfterWipe(t *testing.T) {
	fr := newFakeRoutes()
	dst := validWMPair().Inner.Endpoint.Addr().String()
	fr.showPre[dst] = dst + " via 10.7.7.1 dev wan0"

	log := &wmEventLog{}
	rt := newWMKernelRuntime(t, fr, log)

	rt.onParentUp()
	lostBase := log.count(ClassCarrierRouteLost)
	if lostBase != 0 {
		t.Fatalf("pre-wipe route-lost events = %d, want 0", lostBase)
	}

	// Wipe the pin (steal the route to a foreign device): exactly ONE
	// route-lost from the live gen2 carrier, then pin-restored.
	fr.mu.Lock()
	fr.lines[key("-4", dst)] = dst + " dev wan0"
	fr.mu.Unlock()

	deadline := time.After(3 * time.Second)
	for log.count(ClassPinRestored) == 0 {
		select {
		case <-deadline:
			t.Fatal("pin-restored never arrived after wipe")
		case <-time.After(10 * time.Millisecond):
		}
	}
	// Settle window: a duplicate emitter would add more route-lost events
	// within a couple of ticks (none can exist with a single carrier).
	time.Sleep(200 * time.Millisecond)
	if n := log.count(ClassCarrierRouteLost); n != 1 {
		t.Fatalf("route-lost events after wipe = %d, want exactly 1", n)
	}
	if !fr.has("-4", dst, "wgout") {
		t.Fatal("route not repaired back onto the outer device")
	}
	rt.Stop()
}

// PATCH-05 (M-12): watch must wait on the RUNTIME-derived context, not the
// caller's parent — Stop closes done even when the parent lives on, and the
// goroutine never outlives the runtime.
func TestWgMasqueStopClosesWatchWithoutParentCancel(t *testing.T) {
	cfg := WgMasqueConfig{
		Pair:          validWMPair(),
		OuterIdent:    wmTestIdentity(t),
		InnerEnroll:   &twarp.EnrollClient{},
		InnerSlotPath: t.TempDir() + "/secondary.json",
	}
	rt, err := NewWgMasqueRuntime(cfg)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()
	// Start bookkeeping exactly as Start does (unit CI has no live outer
	// edge; the watch contract is what is pinned here).
	ctx, cancel := context.WithCancel(parent)
	rt.cancel = cancel
	rt.mu.Lock()
	rt.cancelCtx = ctx
	rt.mu.Unlock()
	go rt.watch()

	rt.Stop() // cancels the runtime context, bounded-waits for done
	select {
	case <-rt.done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed by Stop: watch goroutine leaked")
	}
	select {
	case <-parent.Done():
		t.Fatal("parent context must stay alive across Stop")
	default:
	}
	rt.Stop() // idempotent
}

// ---- PATCH-07 (E4): kernel device-name contract ----

// TestWgMasqueInterfaceNameHintPassed is the PATCH-07/E4 acceptance test:
// in kernel mode the OUTER TunnelConfig carries InterfaceName == KernelDevice
// so the TUN is created under the name the route pins will own.
func TestWgMasqueInterfaceNameHintPassed(t *testing.T) {
	fr := newFakeRoutes()
	rt := newWMKernelRuntime(t, fr, &wmEventLog{})
	defer rt.Stop()

	outerV4 := netip.MustParseAddr("10.77.0.2")
	tc := rt.outerTunnelConfig(twg.ModeKernel, outerV4)
	if tc.InterfaceName != "wgout" {
		t.Fatalf("kernel-mode InterfaceName = %q, want the KernelDevice hint %q", tc.InterfaceName, "wgout")
	}
	// Netstack mode stays clean: the hint is a kernel-only knob.
	tcNS := rt.outerTunnelConfig(twg.ModeNetstack, outerV4)
	if tcNS.InterfaceName != "" {
		t.Fatalf("netstack-mode InterfaceName = %q, want empty", tcNS.InterfaceName)
	}
}

// TestResolveKernelDevicePinsActualName is the PATCH-07/E4 second half: the
// pin follows the ACTUAL device name, with divergence flagged for events.
func TestResolveKernelDevicePinsActualName(t *testing.T) {
	dev, diverged := resolveKernelDevice("wgout", "tun42")
	if dev != "tun42" || !diverged {
		t.Fatalf("resolve = (%q, %v), want (tun42, true)", dev, diverged)
	}
	dev, diverged = resolveKernelDevice("wgout", "wgout")
	if dev != "wgout" || diverged {
		t.Fatalf("resolve = (%q, %v), want (wgout, false)", dev, diverged)
	}
	dev, diverged = resolveKernelDevice("wgout", "")
	if dev != "wgout" || diverged {
		t.Fatalf("resolve = (%q, %v), want (wgout, false)", dev, diverged)
	}
}

// TestWgMasqueKernelPinsActualDeviceName drives the carrier construction
// through the runtime: without a live outer (unit CI) the hint is used and
// no mismatch is emitted; the resolve contract (actual wins + divergence
// flag) is pinned by TestResolveKernelDevicePinsActualName.
func TestWgMasqueKernelPinsActualDeviceName(t *testing.T) {
	fr := newFakeRoutes()
	log := &wmEventLog{}
	rt := newWMKernelRuntime(t, fr, log)
	defer rt.Stop()

	rt.onParentUp()
	dst := validWMPair().Inner.Endpoint.Addr().String()
	if !fr.has("-4", dst, "wgout") {
		t.Fatal("pin must use the configured hint when no actual device is known")
	}
	if n := log.count("wg_nested_kernel_device_mismatch"); n != 0 {
		t.Fatalf("mismatch events = %d, want 0 (no divergence in unit fixture)", n)
	}
}

func TestMetricsSnapshotAndExportLoop(t *testing.T) {
	m := &Metrics{}
	m.RouteLostTotal.Add(2)
	m.RepinTotal.Add(1)
	m.ObserveGate("inner", 1500*time.Millisecond)

	snap := map[string]float64{}
	for _, s := range m.Snapshot() {
		if s.Name == SeriesLayerGateSeconds && s.Labels["layer"] == "inner" {
			snap[s.Name+"|inner"] = s.Value
			continue
		}
		snap[s.Name] = s.Value
	}
	if snap[SeriesRouteLost] != 2 || snap[SeriesRepinTotal] != 1 {
		t.Fatalf("counters wrong: %v", snap)
	}
	if snap[SeriesLayerGateSeconds+"|inner"] != 1.5 {
		t.Fatalf("inner gate seconds wrong: %v", snap)
	}

	// ExportLoop: ten ticks must reach the sink.
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan MetricSample, 64)
	ExportLoop(ctx, m, 20*time.Millisecond, func(s MetricSample) { got <- s })
	deadline := time.After(3 * time.Second)
	n := 0
	for n < 10 {
		select {
		case <-got:
			n++
		case <-deadline:
			t.Fatalf("export loop starved after %d samples", n)
		}
	}
	cancel()
}

// ---- PATCH-07 (MAJOR-5): per-layer gate latency reaches the Metrics ----

// newWMKernelRuntimeMetrics is newWMKernelRuntime with a Metrics surface.
func newWMKernelRuntimeMetrics(t *testing.T, fr *fakeRoutes, log *wmEventLog, m *Metrics) *WgMasqueRuntime {
	t.Helper()
	cfg := WgMasqueConfig{
		Pair:           validWMPair(),
		OuterIdent:     wmTestIdentity(t),
		InnerEnroll:    &twarp.EnrollClient{BaseURL: "http://127.0.0.1:1"},
		InnerSlotPath:  t.TempDir() + "/secondary.json",
		OuterKernelTUN: true,
		KernelDevice:   "wgout",
		KernelRunner:   fr.run,
		OnEvent:        log.add,
		Metrics:        m,
	}
	rt, err := NewWgMasqueRuntime(cfg)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	rt.assertInterval = 50 * time.Millisecond
	return rt
}

// TestWgMasqueGateLatencyWiring pins the design 62.9 capture points: the
// outer gate closes in onParentUp (armed at Start, re-armed on parent loss),
// the inner gate closes on the generation's first warp_masque_connected via
// the sink bridge, observe is consume-once, and nil Metrics stays a no-op.
func TestWgMasqueGateLatencyWiring(t *testing.T) {
	fr := newFakeRoutes()
	log := &wmEventLog{}
	m := &Metrics{}
	rt := newWMKernelRuntimeMetrics(t, fr, log, m)

	// Outer gate: armed -> onParentUp closes it with a real duration.
	rt.armOuterGate()
	time.Sleep(25 * time.Millisecond)
	rt.onParentUp()
	first := m.OuterGateMS.Load()
	if first < 20 {
		t.Fatalf("outer gate = %dms, want >= 20ms", first)
	}

	// Consume-once: a disarmed observe (duplicate callback, late
	// generation) must not overwrite the last observed value.
	time.Sleep(25 * time.Millisecond)
	rt.onParentUp()
	if got := m.OuterGateMS.Load(); got != first {
		t.Fatalf("disarmed observe overwrote the outer gate: %d -> %d", first, got)
	}

	// Inner gate: noise must not close it; the connected event does;
	// every event still reaches the operator sink verbatim.
	sinkGot := make(chan twarp.SupervisorEvent, 4)
	rt.cfg.InnerSink = func(ev twarp.SupervisorEvent) { sinkGot <- ev }
	rt.armInnerGate()
	time.Sleep(25 * time.Millisecond)
	bridge := rt.innerSinkBridge()
	bridge(twarp.SupervisorEvent{Name: twarp.EvMasqueRejected})
	select {
	case ev := <-sinkGot:
		if ev.Name != twarp.EvMasqueRejected {
			t.Fatalf("bridge forwarded %s, want verbatim %s", ev.Name, twarp.EvMasqueRejected)
		}
	case <-time.After(time.Second):
		t.Fatal("bridge lost the forwarded event")
	}
	if inner := m.InnerGateMS.Load(); inner != 0 {
		t.Fatalf("non-connected event closed the inner gate: %dms", inner)
	}
	bridge(twarp.SupervisorEvent{Name: twarp.EvMasqueConnected})
	if inner := m.InnerGateMS.Load(); inner < 20 {
		t.Fatalf("inner gate = %dms, want >= 20ms", inner)
	}
	select {
	case ev := <-sinkGot:
		if ev.Name != twarp.EvMasqueConnected {
			t.Fatalf("connected event arrived as %s", ev.Name)
		}
	case <-time.After(time.Second):
		t.Fatal("connected event never reached the operator sink")
	}

	// Nil Metrics: the whole gate path must stay a no-op surface.
	rt2 := newWMKernelRuntime(t, fr, log)
	rt2.armOuterGate()
	rt2.onParentUp() // must not panic with a nil Metrics surface
	rt2.Stop()

	rt.Stop()
}

// TestWgMasquePairActiveGauge pins the gauge transitions: up on the first
// establishment, guarded against double-count and double-drop across
// reconnects, losses and Stop.
func TestWgMasquePairActiveGauge(t *testing.T) {
	fr := newFakeRoutes()
	log := &wmEventLog{}
	m := &Metrics{}
	rt := newWMKernelRuntimeMetrics(t, fr, log, m)

	rt.onParentUp()
	if got := m.PairActive.Load(); got != 1 {
		t.Fatalf("pair active after up = %d, want 1", got)
	}
	rt.onParentUp() // re-establishment must not double-count
	if got := m.PairActive.Load(); got != 1 {
		t.Fatalf("pair active after re-establishment = %d, want 1", got)
	}
	rt.onParentLost(twg.Failure{Class: "probe-loss"})
	if got := m.PairActive.Load(); got != 0 {
		t.Fatalf("pair active after parent loss = %d, want 0", got)
	}
	rt.onParentLost(twg.Failure{Class: "probe-loss"}) // double loss: guarded
	if got := m.PairActive.Load(); got != 0 {
		t.Fatalf("pair active after double loss = %d, want 0", got)
	}
	rt.onParentUp()
	if got := m.PairActive.Load(); got != 1 {
		t.Fatalf("pair active after repair = %d, want 1", got)
	}
	rt.Stop()
	if got := m.PairActive.Load(); got != 0 {
		t.Fatalf("pair active after Stop = %d, want 0", got)
	}
}

// ---- PATCH-07 (M-14): child lifecycle taxonomy ----

// TestWgMasqueChildTaxonomySeparatesRouteIncidents pins the class split:
// start failures emit wg_nested_child_start_failed, parent loss emits
// wg_nested_child_invalidated, and only a genuine route wipe produces
// nested/carrier-route-lost — with the Metrics counters split accordingly.
func TestWgMasqueChildTaxonomySeparatesRouteIncidents(t *testing.T) {
	fr := newFakeRoutes()
	log := &wmEventLog{}
	m := &Metrics{}
	rt := newWMKernelRuntimeMetrics(t, fr, log, m)
	// Production-style counter wiring: the wiring layer wraps OnEvent with
	// CountingEvents; replicate that here to pin the counter separation.
	rt.cfg.OnEvent = CountingEvents(m, log.add)
	rt.cfg.FamilyPolicy = FamilyPolicy{RequireV4: true}

	dst := validWMPair().Inner.Endpoint.Addr().String()

	// Start failure: the mandatory pin cannot land (add AND its replace
	// fallback both fail), so the carrier build fails — a child-start
	// outcome, never a route-lost.
	fr.failAdd[dst] = true
	fr.failReplace[dst] = true
	rt.onParentUp()
	if n := log.count(ClassChildStartFailed); n != 1 {
		t.Fatalf("child-start-failed events = %d, want 1", n)
	}
	if n := log.count(ClassCarrierRouteLost); n != 0 {
		t.Fatalf("route-lost leaked from a start failure: %d", n)
	}
	fr.failAdd[dst] = false
	fr.failReplace[dst] = false

	// Healthy generation, then parent loss: child-invalidated, not route-lost.
	rt.onParentUp()
	rt.onParentLost(twg.Failure{Class: "probe-loss"})
	if n := log.count(ClassChildInvalidated); n != 1 {
		t.Fatalf("child-invalidated events = %d, want 1", n)
	}

	// Genuine route incident: wipe → exactly one route-lost, then restored.
	rt.onParentUp()
	if !fr.has("-4", dst, "wgout") {
		t.Fatal("gen3: route not pinned before the wipe")
	}
	fr.mu.Lock()
	fr.lines[key("-4", dst)] = dst + " dev wan0"
	fr.mu.Unlock()
	deadline := time.After(3 * time.Second)
	for log.count(ClassPinRestored) == 0 {
		select {
		case <-deadline:
			t.Fatal("pin-restored never arrived after wipe")
		case <-time.After(10 * time.Millisecond):
		}
	}

	// Counter separation (Metrics via CountingEvents + Snapshot series).
	if got := m.ChildStartFailedTotal.Load(); got != 1 {
		t.Fatalf("ChildStartFailedTotal = %d, want 1", got)
	}
	if got := m.ChildInvalidatedTotal.Load(); got != 1 {
		t.Fatalf("ChildInvalidatedTotal = %d, want 1", got)
	}
	if got := m.RouteLostTotal.Load(); got != 1 {
		t.Fatalf("RouteLostTotal = %d, want 1", got)
	}
	snap := map[string]float64{}
	for _, s := range m.Snapshot() {
		snap[s.Name] = s.Value
	}
	if snap[SeriesChildStartFailed] != 1 || snap[SeriesChildInvalidated] != 1 || snap[SeriesRouteLost] != 1 {
		t.Fatalf("snapshot series wrong: %v", snap)
	}
	rt.Stop()
}
