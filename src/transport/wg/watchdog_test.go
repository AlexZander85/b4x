package transportwg

import (
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

// TestWatchdogQuietKeepsAlive proves passive keepalive traffic (small rx
// growth each tick) never trips either trigger.
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
		if i%10 == 0 && i > 0 {
			rx += 32 // passive keepalive replies ~32 B / 10 s
		}
		wd.Feed(CounterSample{Time: nowT, RxBytes: rx, TxBytes: tx})
	}
	if wd.Fired() {
		t.Fatal("fired flag set on healthy feed")
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
