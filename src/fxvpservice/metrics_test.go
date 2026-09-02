package fxvpservice

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/daniellavrushin/b4/config"
	"github.com/daniellavrushin/b4/observability"
	fxvpn "github.com/daniellavrushin/b4/transport/fxvpn"
)

func fxGaugeValue(t *testing.T, name, labelKey, labelVal string) (uint64, bool) {
	t.Helper()
	for _, g := range observability.Default().Metrics.Snapshot(time.Now()).Gauges {
		if g.Name != name {
			continue
		}
		if v, ok := g.Labels[labelKey]; ok && v == labelVal {
			return g.Value, true
		}
	}
	return 0, false
}

func fxDialCounter(t *testing.T, result string) uint64 {
	t.Helper()
	for _, c := range observability.Default().Metrics.Snapshot(time.Now()).Counters {
		if c.Name == observability.MetricFxvpnDialTotal && c.Labels["result"] == result {
			return c.Value
		}
	}
	return 0
}

// The pool state vector exports EVERY lifecycle state (zeros included for a
// stable vector); the quota gauge stays ABSENT while the quota is unknown;
// dial counters track recordDial outcomes 1:1.
func TestFxvpnMetricsExport(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "accounts.json")
	store := fxvpn.NewAccountStore(storePath)
	if err := store.Save(&fxvpn.AccountsFile{Accounts: []fxvpn.Account{
		{Email: "a@example.com", RefreshToken: "rt-a", Label: "acc-a"},
		{Email: "b@example.com", Password: "pw-b"},
	}}); err != nil {
		t.Fatalf("save store: %v", err)
	}

	cfg := &config.Config{}
	rt, err := Build(cfg, Options{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	pool, err := fxvpn.NewPool(store, &fxvpn.FXA{}, &fxvpn.Guardian{}, fxvpn.PoolConfig{})
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	rt.pool = pool

	rt.exportPoolMetrics()

	got, ok := fxGaugeValue(t, observability.MetricFxvpnPoolState, "state", string(fxvpn.StateProvisioning))
	if !ok || got != 2 {
		t.Fatalf("pool_state provisioning = %d (present=%t), want 2", got, ok)
	}
	got, ok = fxGaugeValue(t, observability.MetricFxvpnPoolState, "state", string(fxvpn.StateActive))
	if !ok || got != 0 {
		t.Fatalf("pool_state active = %d (present=%t), want explicit zero", got, ok)
	}
	if _, present := fxGaugeValue(t, observability.MetricFxvpnQuotaRemainingBytes, "account", "active"); present {
		t.Fatal("quota gauge must stay absent while quota is unknown")
	}

	// Dial counters mirror the runtime atomics.
	beforeOK, beforeFail := fxDialCounter(t, "ok"), fxDialCounter(t, "fail")
	rt.recordDial(true)
	rt.recordDial(false)
	rt.recordDial(false)
	if got := fxDialCounter(t, "ok") - beforeOK; got != 1 {
		t.Fatalf("dial ok delta = %d, want 1", got)
	}
	if got := fxDialCounter(t, "fail") - beforeFail; got != 2 {
		t.Fatalf("dial fail delta = %d, want 2", got)
	}
	if rt.Status().DialFail != 2 { // fresh runtime: atomics were 0 before deltas
		t.Fatalf("status dial_fail out of sync: %d", rt.Status().DialFail)
	}
}

// poolStateCounts is pure: per-state counts plus the ACTIVE account quota.
func TestPoolStateCountsReduction(t *testing.T) {
	st := fxvpn.PoolStatus{Views: []fxvpn.AccountView{
		{Label: "a", State: fxvpn.StateStandby, QuotaLeft: 1, Active: false},
		{Label: "b", State: fxvpn.StateActive, QuotaLeft: 42_000_000_000, Active: true},
		{Label: "c", State: fxvpn.StateExhausted, QuotaLeft: 0, Active: false},
	}}
	counts, activeLeft := poolStateCounts(st)
	if counts[fxvpn.StateStandby] != 1 || counts[fxvpn.StateActive] != 1 || counts[fxvpn.StateExhausted] != 1 {
		t.Fatalf("counts = %+v", counts)
	}
	if counts[fxvpn.StateBanned] != 0 {
		t.Fatalf("missing states must read as zero, got %+v", counts)
	}
	if activeLeft != 42_000_000_000 {
		t.Fatalf("activeLeft = %d", activeLeft)
	}

	counts, activeLeft = poolStateCounts(fxvpn.PoolStatus{})
	if len(counts) != 0 || activeLeft != -1 {
		t.Fatalf("empty pool reduction = %+v, %d", counts, activeLeft)
	}
}

// TestFxvpnBytesCounter pins review F7b: relay bytes land in the shared
// registry counter fxvpn_bytes_total{dir=up|down} and the Status totals.
func TestFxvpnBytesCounter(t *testing.T) {
	observability.Default().Metrics.Reset()
	t.Cleanup(func() { observability.Default().Metrics.Reset() })

	cfg := &config.Config{}
	rt, err := Build(cfg, Options{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rt.recordBytes(true, 128)
	rt.recordBytes(true, 64)
	rt.recordBytes(false, 4096)

	up, okUp := fxCounterValue(t, observability.MetricFxvpnBytesTotal, "dir", "up")
	down, okDown := fxCounterValue(t, observability.MetricFxvpnBytesTotal, "dir", "down")
	if !okUp || up != 192 {
		t.Fatalf("bytes up = %d (present=%t), want 192", up, okUp)
	}
	if !okDown || down != 4096 {
		t.Fatalf("bytes down = %d (present=%t), want 4096", down, okDown)
	}
	st := rt.Status()
	if st.BytesUp != 192 || st.BytesDown != 4096 {
		t.Fatalf("status bytes = %d/%d", st.BytesUp, st.BytesDown)
	}
}

func fxCounterValue(t *testing.T, name, labelKey, labelVal string) (uint64, bool) {
	t.Helper()
	for _, c := range observability.Default().Metrics.Snapshot(time.Now()).Counters {
		if c.Name != name {
			continue
		}
		if v, ok := c.Labels[labelKey]; ok && v == labelVal {
			return c.Value, true
		}
	}
	return 0, false
}

// TestFxvpnMasqueradeGauges pins FX-M4: the nested/bait rungs are exported
// as gauges (observable switches — §7.8.3) and the Status view carries the
// masquerade summary.
func TestFxvpnMasqueradeGauges(t *testing.T) {
	observability.Default().Metrics.Reset()
	t.Cleanup(func() { observability.Default().Metrics.Reset() })

	cfg := &config.Config{}
	rt, err := Build(cfg, Options{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	rt.exportPoolMetrics()

	if v, ok := fxGaugeValueNoLabels(t, observability.MetricFxvpnNested); !ok || v != 0 {
		t.Fatalf("fxvpn_nested = %d (present=%t), want 0", v, ok)
	}
	// Bait not configured: the gauge reports 0 (explicit zero, not absent —
	// the series must not disappear between scrapes).
	if v, ok := fxGaugeValueNoLabels(t, observability.MetricFxvpnBaitActive); !ok || v != 0 {
		t.Fatalf("fxvpn_bait_active = %d (present=%t), want explicit 0", v, ok)
	}

	st := rt.Status()
	if st.Masquerade.Profile != "firefox" || st.Masquerade.Fingerprint != "firefox" {
		t.Fatalf("default masquerade view = %+v", st.Masquerade)
	}
	if !st.Masquerade.HelloShaping || st.Masquerade.PreflightFake {
		t.Fatalf("default masquerade view = %+v (bait is config-gated)", st.Masquerade)
	}
}

func fxGaugeValueNoLabels(t *testing.T, name string) (uint64, bool) {
	t.Helper()
	for _, g := range observability.Default().Metrics.Snapshot(time.Now()).Gauges {
		if g.Name == name {
			return g.Value, true
		}
	}
	return 0, false
}
