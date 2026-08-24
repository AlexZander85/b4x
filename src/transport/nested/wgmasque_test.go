package nested

import (
	"context"
	"net"
	"net/netip"
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
