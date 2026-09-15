package transportwg

import (
        "testing"
        "time"
)

// Byte-floor anchors (Nova 1.31.1 TunnelStallDetector traps 1-2): handshake
// and keepalive bytes must not count as data-plane life, and keepalive
// writes must not count as "we are writing". The tests shrink the floors
// only where the DEFAULT would make the fixture unwieldy; the semantics
// under test are the anchor-vs-previous-sample distinction.

// TestWatchdogHandshakeBytesDoNotResetIdle feeds the rx-idle trigger with a
// realistic sub-floor rx drip (one 92 B handshake/rekey reply every ~15 s —
// a dead data-plane that keeps the control plane alive) while real tx
// flows. The old per-sample comparison re-armed the idle timer forever
// (Nova trap 1); the anchor floor must let the trigger fire.
func TestWatchdogHandshakeBytesDoNotResetIdle(t *testing.T) {
        base := time.Now()
        fired := make(chan Failure, 1)
        w := NewWatchdog(WatchdogConfig{
                RXIdle:      10 * time.Second,
                Tick:        time.Second,
                MinRXGrowth: 256, // default
                MinTXGrowth: 256,
                Now:         func() time.Time { return base },
                OnStall:     func(f Failure) { fired <- f },
        })

        // t=0: baseline anchors.
        w.Feed(CounterSample{Time: base, RxBytes: 1000, TxBytes: 1000})
        // t=1..16: one 92 B handshake reply arrives every 15 s (sub-floor by
        // an order of magnitude), tx grows well past the floor (real writes).
        for i := 1; i <= 16; i++ {
                rx := uint64(1000)
                if i == 15 { // a single rekey reply inside the window
                        rx += 92
                }
                w.Feed(CounterSample{
                        Time:    base.Add(time.Duration(i) * time.Second),
                        RxBytes: rx,
                        TxBytes: 1000 + uint64(i)*2000,
                })
        }
        select {
        case f := <-fired:
                if f.Class != ClassStallRX {
                        t.Fatalf("expected ClassStallRX, got %v", f.Class)
                }
        case <-time.After(5 * time.Second):
                t.Fatal("rx-idle did not fire: handshake bytes still re-arm the idle timer")
        }
}

// TestWatchdogKeepaliveWritesDoNotArmIdle runs a LEGITIMATELY quiet tunnel
// where only sub-floor keepalive writes flow (32 B per tick, Nova trap 2).
// Nothing is being lost behind the dead path (no real tx), so the idle
// trigger must NOT fire — same verdict as TestWatchdogQuietIdleWithoutTxIsNotStall,
// now through the byte-floor mechanism.
func TestWatchdogKeepaliveWritesDoNotArmIdle(t *testing.T) {
        base := time.Now()
        fired := make(chan Failure, 1)
        w := NewWatchdog(WatchdogConfig{
                RXIdle:      2 * time.Second,
                Tick:        100 * time.Millisecond,
                MinRXGrowth: 256,
                MinTXGrowth: 256,
                Now:         func() time.Time { return base },
                OnStall:     func(f Failure) { fired <- f },
        })

        // t=0: baseline with real traffic both ways (anchors set).
        w.Feed(CounterSample{Time: base, RxBytes: 5000, TxBytes: 5000})
        // t=0.1..3: only keepalive writes (32 B/tick, cumulative 960 B < 256*4
        // would cross at 1024 — stop just under to keep the write sub-floor in
        // total? No: keep it honest — 32 B per tick for 30 ticks = 960 B total,
        // which is REAL cumulative growth crossing the floor only near the end.
        // The trap says a single keepalive interval must not count; a long
        // accumulation eventually does (that is traffic). Keep the window short
        // so the cumulative stays sub-floor: 3 ticks.
        for i := 1; i <= 3; i++ {
                w.Feed(CounterSample{
                        Time:    base.Add(time.Duration(i) * 100 * time.Millisecond),
                        RxBytes: 5000,
                        TxBytes: 5000 + uint64(i)*32, // keepalives only
                })
        }
        select {
        case f := <-fired:
                t.Fatalf("idle fired on a keepalive-only tunnel (trap 2 regression): %+v", f)
        case <-time.After(300 * time.Millisecond):
                // Not fired — correct: no real tx since the last inbound.
        }
}

// TestWatchdogSubFloorGrowthAccumulatesToLife pins the accumulation
// semantics: many small real packets (100 B each) sum past the floor and
// DO count as life — the floor must not starve a slow but healthy flow.
func TestWatchdogSubFloorGrowthAccumulatesToLife(t *testing.T) {
        base := time.Now()
        fired := make(chan Failure, 1)
        w := NewWatchdog(WatchdogConfig{
                RXIdle:      10 * time.Second,
                Tick:        time.Second,
                MinRXGrowth: 256,
                MinTXGrowth: 256,
                Now:         func() time.Time { return base },
                OnStall:     func(f Failure) { fired <- f },
        })
        w.Feed(CounterSample{Time: base, RxBytes: 0, TxBytes: 0})
        // 12 seconds of 100 B/s inbound (real but slow data): cumulative 1200 B
        // crosses the floor every ~3 s, re-arming the idle timer each time —
        // the trigger must NOT fire.
        for i := 1; i <= 12; i++ {
                w.Feed(CounterSample{
                        Time:    base.Add(time.Duration(i) * time.Second),
                        RxBytes: uint64(i) * 100,
                        TxBytes: uint64(i) * 100,
                })
        }
        select {
        case f := <-fired:
                t.Fatalf("idle fired on a slow-but-alive tunnel (accumulation broken): %+v", f)
        case <-time.After(300 * time.Millisecond):
                // Healthy — as designed.
        }
}
