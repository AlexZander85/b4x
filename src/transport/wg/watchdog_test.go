package transportwg

import (
	"context"
	"testing"
	"time"
)

// TestWatchdogVersionMismatchSignature feeds the classic "92B/20KB" shape:
// tx grows past 4096 B while rx stays under 1024 B across a full window.
func TestWatchdogVersionMismatchSignature(t *testing.T) {
	now := time.Unix(0, 0)
	wd := NewWatchdog(WatchdogConfig{
		RXIdle: 10 * time.Second,
		Window: 120 * time.Second,
		Tick:   time.Second,
		Now:    func() time.Time { return now },
	})
	var fired *Failure
	wd.cfg.OnStall = func(f Failure) { fired = &f }

	t0 := now
	for i := 0; i <= 130; i++ { // 131 s of samples
		now = t0.Add(time.Duration(i) * time.Second)
		tx := uint64(i) * 200 // ~200 B/s => crosses 4096 at ~21 s
		rx := uint64(i % 3)   // jitter below MaxRX
		wd.Feed(CounterSample{Time: now, RxBytes: rx, TxBytes: tx})
		if wd.Fired() {
			break
		}
	}
	if !wd.Fired() || fired == nil {
		t.Fatal("version-mismatch signature never fired")
	}
	if fired.Class != ClassVersionMismatch {
		t.Fatalf("class=%s want awg-version-mismatch", fired.Class)
	}

	// Edge-triggered: further bad samples must not refire until Rearm.
	wd.Feed(CounterSample{Time: t0.Add(200 * time.Second), RxBytes: 1, TxBytes: 1 << 20})
	fired = nil
	wd.Rearm()
	now = t0.Add(300 * time.Second)
	wd.Feed(CounterSample{Time: now, RxBytes: 2, TxBytes: DefaultStallMinTX + 5000})
}

// TestWatchdogRxIdle fires wg-stall-rx once rx freezes beyond RXIdle.
func TestWatchdogRxIdle(t *testing.T) {
	start := time.Unix(100, 0)
	nowT := start
	wd := NewWatchdog(WatchdogConfig{
		RXIdle: 10 * time.Second,
		Window: 120 * time.Second,
		Tick:   time.Second,
		Now:    func() time.Time { return nowT },
	})
	var class FailureClass
	wd.cfg.OnStall = func(f Failure) { class = f.Class }

	rx, tx := uint64(1000), uint64(2000)
	wd.Feed(CounterSample{Time: nowT, RxBytes: rx, TxBytes: tx}) // anchor
	for i := 1; i <= 11; i++ {
		nowT = start.Add(time.Duration(i) * time.Second)
		tx += 40 // keepalive-ish tx growth, rx frozen
		wd.Feed(CounterSample{Time: nowT, RxBytes: rx, TxBytes: tx})
	}
	if !wd.Fired() {
		t.Fatal("rx-idle never fired")
	}
	if class != ClassStallRX {
		t.Fatalf("class=%s want wg-stall-rx", class)
	}
}

// TestWatchdogQuietKeepsAlive proves quiet traffic never trips either
// trigger. PATCH-04 semantics: an idle client (NO outbound growth) over a
// quiet edge (sparse inbound replies) must NOT restart — with no tx growth
// the rx-idle trigger cannot fire at all, regardless of the inbound cadence.
func TestWatchdogQuietKeepsAlive(t *testing.T) {
	start := time.Unix(500, 0)
	nowT := start
	wd := NewWatchdog(WatchdogConfig{
		RXIdle: 10 * time.Second,
		Window: 120 * time.Second,
		Tick:   time.Second,
		Now:    func() time.Time { return nowT },
	})
	wd.cfg.OnStall = func(Failure) { t.Fatal("watchdog fired on healthy quiet traffic") }
	rx, tx := uint64(0), uint64(0)
	for i := 0; i < 300; i++ { // 5 minutes of healthy idle-with-keepalive
		nowT = start.Add(time.Duration(i) * time.Second)
		if i%30 == 0 && i > 0 {
			rx += 32 // passive keepalive replies ~32 B / 30 s (quiet edge)
		}
		wd.Feed(CounterSample{Time: nowT, RxBytes: rx, TxBytes: tx})
	}
	if wd.Fired() {
		t.Fatal("fired flag set on healthy feed")
	}
}

// ---- PATCH-04: tx-gating + derived RXIdle ----

// TestWatchdogQuietIdleWithoutTxIsNotStall: rx AND tx both frozen — the
// session is legitimately quiet, no restart (red before the tx-gate:
// the rx-idle trigger fired at RXIdle regardless of tx).
func TestWatchdogQuietIdleWithoutTxIsNotStall(t *testing.T) {
	start := time.Unix(700, 0)
	nowT := start
	wd := NewWatchdog(WatchdogConfig{
		RXIdle: 10 * time.Second,
		Window: 120 * time.Second,
		Tick:   time.Second,
		Now:    func() time.Time { return nowT },
	})
	wd.cfg.OnStall = func(Failure) { t.Fatal("quiet idle must not be classified as a stall") }

	rx, tx := uint64(1000), uint64(2000)
	for i := 0; i <= 60; i++ { // 60 s of total silence
		nowT = start.Add(time.Duration(i) * time.Second)
		wd.Feed(CounterSample{Time: nowT, RxBytes: rx, TxBytes: tx})
	}
	if wd.Fired() {
		t.Fatal("fired on quiet idle")
	}
}

// TestWatchdogIdleWithTxAndDeadRxFires: rx frozen, tx growing — the classic
// dead tunnel while the user still writes; the old detection must be
// preserved by the tx-gate (fires when rx idle exceeds RXIdle).
func TestWatchdogIdleWithTxAndDeadRxFires(t *testing.T) {
	start := time.Unix(800, 0)
	nowT := start
	wd := NewWatchdog(WatchdogConfig{
		RXIdle: 10 * time.Second,
		Window: 120 * time.Second,
		Tick:   time.Second,
		Now:    func() time.Time { return nowT },
	})
	var class FailureClass
	wd.cfg.OnStall = func(f Failure) { class = f.Class }

	rx, tx := uint64(5000), uint64(5000)
	wd.Feed(CounterSample{Time: nowT, RxBytes: rx, TxBytes: tx}) // anchor
	for i := 1; i <= 11; i++ {
		nowT = start.Add(time.Duration(i) * time.Second)
		tx += 1500 // user traffic keeps flowing outward
		wd.Feed(CounterSample{Time: nowT, RxBytes: rx, TxBytes: tx})
	}
	if !wd.Fired() {
		t.Fatal("dead tunnel with live tx must fire the rx-idle trigger")
	}
	if class != ClassStallRX {
		t.Fatalf("class=%s want wg-stall-rx", class)
	}
}

// TestNestedKeepaliveDerivesRXIdle pins the PATCH-04 derivation:
// RXIdle = max(30s, 3x keepalive) for keepalive 5/20/25 => 30/60/75 s,
// and an explicit RXIdle always wins.
func TestNestedKeepaliveDerivesRXIdle(t *testing.T) {
	cases := []struct {
		keep uint16
		want time.Duration
	}{
		{5, 30 * time.Second},  // W+M outer
		{20, 60 * time.Second}, // M+W inner
		{25, 75 * time.Second}, // default
	}
	for _, tc := range cases {
		h := HealthConfig{KeepaliveSec: tc.keep}
		h.fillDefaults()
		if h.Watchdog.RXIdle != tc.want {
			t.Fatalf("keepalive %ds: RXIdle = %s, want %s", tc.keep, h.Watchdog.RXIdle, tc.want)
		}
	}
	// Explicit config wins over the derivation.
	h := HealthConfig{KeepaliveSec: 25, Watchdog: WatchdogConfig{RXIdle: 42 * time.Second}}
	h.fillDefaults()
	if h.Watchdog.RXIdle != 42*time.Second {
		t.Fatalf("explicit RXIdle overwritten: %s", h.Watchdog.RXIdle)
	}
}

// TestWatchdogStartupBurstDoesNotFireVersionMismatch guards the full-window
// coverage requirement.
func TestWatchdogStartupBurstDoesNotFireVersionMismatch(t *testing.T) {
	start := time.Unix(900, 0)
	nowT := start
	wd := NewWatchdog(WatchdogConfig{
		RXIdle: 10 * time.Hour, // idle trigger disabled: this test targets the window guard
		Window: 120 * time.Second,
		Tick:   time.Second,
		Now:    func() time.Time { return nowT },
	})
	wd.cfg.OnStall = func(Failure) { t.Fatal("fired on startup burst") }
	// 60 s of heavy tx with zero rx: window not yet saturated.
	for i := 0; i <= 60; i++ {
		nowT = start.Add(time.Duration(i) * time.Second)
		wd.Feed(CounterSample{Time: nowT, TxBytes: uint64(i) * 1000})
	}
	if wd.Fired() {
		t.Fatal("premature version-mismatch fire")
	}
}

// TestWatchdogVersionMismatchSignatureJittered is the PATCH-01 acceptance
// test: the classic mismatch shape on a 1 s grid where even samples carry
// +10..+50 ms of real-clock jitter. Before the eviction-margin fix the
// span>=Window requirement was unreachable (red); after it the signature
// fires for any jitter <= 2*Tick (green).
func TestWatchdogVersionMismatchSignatureJittered(t *testing.T) {
	shifts := []time.Duration{10 * time.Millisecond, 25 * time.Millisecond, 50 * time.Millisecond}
	for _, jitter := range shifts {
		jitter := jitter
		t.Run("jitter="+jitter.String(), func(t *testing.T) {
			now := time.Unix(0, 0)
			wd := NewWatchdog(WatchdogConfig{
				RXIdle: 10 * time.Second,
				Window: 120 * time.Second,
				Tick:   time.Second,
				Now:    func() time.Time { return now },
			})
			var fired *Failure
			wd.cfg.OnStall = func(f Failure) { fired = &f }

			t0 := now
			for i := 0; i <= 140; i++ { // 141 s of samples
				stamp := t0.Add(time.Duration(i) * time.Second)
				if i%2 == 0 && i > 0 {
					stamp = stamp.Add(jitter) // even samples late by jitter
				}
				now = stamp
				tx := uint64(i) * 200 // ~200 B/s => crosses 4096 at ~21 s
				rx := uint64(i % 3)   // jitter below MaxRX
				wd.Feed(CounterSample{Time: now, RxBytes: rx, TxBytes: tx})
				if wd.Fired() {
					break
				}
			}
			if !wd.Fired() || fired == nil {
				t.Fatalf("version-mismatch signature never fired with jitter %s", jitter)
			}
			if fired.Class != ClassVersionMismatch {
				t.Fatalf("class=%s want awg-version-mismatch", fired.Class)
			}
		})
	}
}

// TestWatchdogEvictionMarginProperty pins the eviction margin: a sample
// stamped exactly now-Window must survive eviction and remain evaluable —
// the margin (2*Tick) exists precisely so boundary-spanning samples are
// never dropped before the span check runs.
func TestWatchdogEvictionMarginProperty(t *testing.T) {
	nowT := time.Unix(1000, 0)
	wd := NewWatchdog(WatchdogConfig{
		RXIdle: 10 * time.Hour, // isolate trigger 2
		Window: 120 * time.Second,
		Tick:   time.Second,
		Now:    func() time.Time { return nowT },
	})
	wd.cfg.OnStall = func(Failure) {}

	// Anchor at t=0.
	wd.Feed(CounterSample{Time: nowT, RxBytes: 0, TxBytes: 0})
	// Advance 120 s with tx growth; then evaluate at exactly t=120 s.
	for i := 1; i <= 119; i++ {
		nowT = time.Unix(1000+int64(i), 0)
		wd.Feed(CounterSample{Time: nowT, TxBytes: uint64(i) * 100})
	}
	// The boundary sample: exactly Window (120 s) after the anchor.
	boundary := time.Unix(1120, 0)
	nowT = boundary
	wd.Feed(CounterSample{Time: boundary, TxBytes: 119 * 100})

	// The anchor (stamped exactly now-Window) must still be retained.
	wd.mu.Lock()
	retained := len(wd.samples) > 0 && wd.samples[0].Time.Equal(time.Unix(1000, 0))
	span := wd.samples[len(wd.samples)-1].Time.Sub(wd.samples[0].Time)
	wd.mu.Unlock()
	if !retained {
		t.Fatal("boundary sample (now-Window) was evicted: margin missing")
	}
	if span < wd.cfg.Window {
		t.Fatalf("retained span %s < Window %s: span check would be unreachable", span, wd.cfg.Window)
	}
}

// TestWatchdogRealTickerSmoke runs the mismatch signature against a real
// ticker (no mock clock) to confirm the margin does not eat the window on
// genuine scheduler jitter. Tuned to finish in ~3 s.
func TestWatchdogRealTickerSmoke(t *testing.T) {
	wd := NewWatchdog(WatchdogConfig{
		RXIdle: 10 * time.Hour, // isolate trigger 2
		Window: 1500 * time.Millisecond,
		MinTX:  2048,
		MaxRX:  64,
		Tick:   200 * time.Millisecond,
	})
	fired := make(chan Failure, 1)
	wd.cfg.OnStall = func(f Failure) {
		select {
		case fired <- f:
		default:
		}
	}

	var tx uint64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // stop the sampler goroutine before goleak inspects
	go wd.Run(ctx, func(context.Context) (CounterSample, error) {
		tx += 512
		return CounterSample{Time: time.Now(), TxBytes: tx}, nil
	})

	select {
	case f := <-fired:
		if f.Class != ClassVersionMismatch {
			t.Fatalf("class=%s want awg-version-mismatch", f.Class)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("version-mismatch signature never fired on real ticker")
	}
}
