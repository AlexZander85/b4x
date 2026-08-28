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

func TestWgMasqueValidateTable(t *testing.T) {
	base := func() WgMasqueConfig {
		return WgMasqueConfig{
			Pair:          validWMPair(),
			OuterIdent:    &twg.Identity{},
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
		OuterIdent:    &twg.Identity{},
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
		OuterIdent:     &twg.Identity{},
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

func TestWgMasqueCarrierTornDownAcrossGenerations(t *testing.T) {
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

	// Generation 2 (outer reconnect): the old carrier must be torn down
	// (terminal record) before the new one builds.
	rt.onParentUp()
	if n := log.count("wg_nested_carrier_replaced"); n != 1 {
		t.Fatalf("carrier_replaced events = %d, want exactly 1", n)
	}
	if !fr.has("-4", dst, "wgout") {
		t.Fatal("gen2: route not re-pinned by the new carrier")
	}

	// Old assertion loop must be DEAD: after the gen2 teardown its journal
	// freezes. Wait several ticks and confirm no foreign-restore churn from
	// the dead carrier (its Restore already ran exactly once: the pin
	// stays ours and no extra route-lost can come from the dead side).
	lostBefore := log.count(ClassCarrierRouteLost)
	time.Sleep(200 * time.Millisecond)
	if got := log.count(ClassCarrierRouteLost); got != lostBefore {
		t.Fatalf("dead carrier still asserting: route-lost %d -> %d", lostBefore, got)
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

func TestWgMasqueNoDuplicateRouteLostAfterReconnect(t *testing.T) {
	fr := newFakeRoutes()
	dst := validWMPair().Inner.Endpoint.Addr().String()
	fr.showPre[dst] = dst + " via 10.7.7.1 dev wan0"

	log := &wmEventLog{}
	rt := newWMKernelRuntime(t, fr, log)

	rt.onParentUp()
	rt.onParentUp() // reconnect: gen2 carrier is the only live one
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
	// Settle window: a duplicate emitter (dead gen1 carrier) would add more
	// route-lost events within a couple of ticks.
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
		OuterIdent:    &twg.Identity{},
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
