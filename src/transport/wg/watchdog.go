// Stall watchdog (design §4; zapret-gui rx-stall + warp-socks/Aether
// health-lineage). Two structural triggers over the peer counters:
//
//  1. rx idle: no growth of rx_bytes for RXIdle (default 10 s) —
//     "last_valid_rx > 10 s = dead" (Aether health task).
//  2. version-mismatch signature: tx grew >= MinTX (4096 B) while rx grew
//     <= MaxRX (1024 B) across the rolling Window (120 s) — the classic
//     "92 B received / 20 KB sent" AWG parameter disagreement. The 1 KB
//     floor keeps passive keepalive traffic (~32 B / 10 s) out of the trap.
//
// Detection is edge-triggered: one callback per armed period; the session
// re-arms after a successful restart.
package transportwg

import (
	"context"
	"sync"
	"time"
)

// Watchdog defaults (research §2 numbers).
const (
	DefaultRXIdle       = 10 * time.Second
	DefaultStallWindow  = 120 * time.Second
	DefaultStallMinTX   = 4096
	DefaultStallMaxRX   = 1024
	defaultWatchdogTick = time.Second
)

// CounterSample is one snapshot of the peer transfer counters.
type CounterSample struct {
	Time    time.Time
	RxBytes uint64
	TxBytes uint64
}

// CountersFunc samples the live counters (IpcGet rx_bytes/tx_bytes).
type CountersFunc func(context.Context) (CounterSample, error)

// WatchdogConfig carries the thresholds; zero values map to defaults so
// tests can shrink the windows without touching production numbers.
//
// Structural invariant: trigger 2 (version-mismatch) evicts samples with a
// Window+2*Tick margin, so the Window value must always stay smaller than
// the eviction horizon. Shrinking the margin below 2*Tick (or removing it)
// makes the `span >= Window` check unreachable on real clocks and deadens
// the trigger — see the eviction comment in Feed.
//
// PATCH-04 note (field measurement gate): the DEFAULT RXIdle is derived
// from the session keepalive (max(30s, 3x keepalive)) by
// HealthConfig.fillDefaults; an explicit RXIdle always wins. The first
// field smoke MUST measure the actual inbound cadence of CF-WG edges
// (sampler events) before any AGGRESSIVE RXIdle is shipped — see the
// LivenessProbe reservation below.
type WatchdogConfig struct {
	RXIdle  time.Duration
	Window  time.Duration
	MinTX   uint64
	MaxRX   uint64
	Tick    time.Duration
	Now     func() time.Time // injectable clock
	OnStall func(Failure)

	// LivenessProbe is a RESERVED interface (PATCH-04, design §4 field
	// tail): a future self-liveness probe (e.g. DNS round-trip under
	// RXIdle) to distinguish "tunnel dead" from "edge legitimately
	// quiet". NIL by default and NOT consulted by the current detection
	// — wiring it is a field-stage decision, not a code-stage guess.
	LivenessProbe func(ctx context.Context) error
}

func (c *WatchdogConfig) fillDefaults() {
	if c.RXIdle == 0 {
		c.RXIdle = DefaultRXIdle
	}
	if c.Window == 0 {
		c.Window = DefaultStallWindow
	}
	if c.MinTX == 0 {
		c.MinTX = DefaultStallMinTX
	}
	if c.MaxRX == 0 {
		c.MaxRX = DefaultStallMaxRX
	}
	if c.Tick == 0 {
		c.Tick = defaultWatchdogTick
	}
	if c.Now == nil {
		c.Now = time.Now
	}
}

// Watchdog consumes counter samples and fires structural stall failures.
type Watchdog struct {
	cfg WatchdogConfig

	mu      sync.Mutex
	samples []CounterSample
	lastRx  time.Time // time of the last sample where rx grew
	lastTx  time.Time // time of the last sample where tx grew (PATCH-04)
	fired   bool
}

// NewWatchdog arms a watchdog. onStall must be non-nil.
func NewWatchdog(cfg WatchdogConfig) *Watchdog {
	cfg.fillDefaults()
	return &Watchdog{cfg: cfg}
}

// Feed records one sample and runs detection.
func (w *Watchdog) Feed(s CounterSample) {
	w.cfg.fillDefaults()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fired {
		return // edge-triggered until Rearm
	}

	if n := len(w.samples); n > 0 {
		if s.RxBytes > w.samples[n-1].RxBytes {
			w.lastRx = s.Time // anchor: last observed inbound growth
		}
		if s.TxBytes > w.samples[n-1].TxBytes {
			w.lastTx = s.Time // anchor: last observed outbound growth
		}
	} else {
		w.lastRx = s.Time
		w.lastTx = s.Time
	}
	w.samples = append(w.samples, s)
	now := s.Time

	// Trigger 1: no inbound growth for RXIdle — the tunnel went silent
	// (design §4 "нет входящих >10 с"; the health probes keep the tunnel
	// from being legitimately quiet).
	//
	// PATCH-04 tx-gating: idle counts ONLY when outbound traffic exists
	// since the last inbound — a session that neither reads NOR writes
	// is legitimately quiet (nothing can be lost behind a dead path),
	// while "we are writing and nothing comes back" is the stall
	// signature. NAT-keepalives requiring no response are exactly why
	// pure idle must not restart the session; the truly-dead tunnel
	// (with user tx flowing) is still caught, and trigger 2 covers the
	// write-heavy mismatch signature.
	if now.Sub(w.lastRx) > w.cfg.RXIdle && w.lastTx.After(w.lastRx) {
		w.fire(*newFailure(ClassStallRX, "rx-idle-exceeded", nil))
		return
	}

	// Trigger 2: rolling version-mismatch signature.
	//
	// Invariant: the eviction window MUST be wider than the span window
	// checked below. Evicting at exactly -Window makes the
	// `span >= Window` requirement unreachable on real clocks (it would
	// demand nanosecond-exact equality between the oldest surviving
	// sample and the cut line), which silently kills this trigger — the
	// 2*Tick margin absorbs scheduler/ticker jitter so samples with an
	// effective span of Window-epsilon .. Window+2Tick stay evaluable.
	cut := now.Add(-w.cfg.Window - 2*w.cfg.Tick)
	kept := w.samples[:0]
	for _, sm := range w.samples {
		if !sm.Time.Before(cut) {
			kept = append(kept, sm)
		}
	}
	w.samples = kept
	if len(w.samples) < 2 {
		return
	}
	first := w.samples[0]
	last := w.samples[len(w.samples)-1]
	txDelta := last.TxBytes - first.TxBytes
	rxDelta := last.RxBytes - first.RxBytes
	if txDelta >= w.cfg.MinTX && rxDelta <= w.cfg.MaxRX &&
		last.Time.Sub(first.Time) >= w.cfg.Window {
		// The full-window coverage requirement keeps startup bursts from
		// firing before any reply had a fair chance.
		w.fire(*newFailure(ClassVersionMismatch, "tx-grows-rx-flat", nil))
	}
}

// Rearm re-enables detection after a restart (fresh counters, fresh window).
func (w *Watchdog) Rearm() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.fired = false
	w.samples = nil
	w.lastRx = time.Time{}
	w.lastTx = time.Time{}
}

// Fired reports whether the watchdog already fired (test introspection).
func (w *Watchdog) Fired() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.fired
}

func (w *Watchdog) fire(f Failure) {
	w.fired = true
	if w.cfg.OnStall != nil {
		// Contract: the callback must be non-blocking; the session uses it
		// to tear down and restart on its own goroutine.
		w.cfg.OnStall(f)
	}
}

// Run feeds the watchdog from sampleFn every Tick until ctx is done.
func (w *Watchdog) Run(ctx context.Context, sampleFn CountersFunc) {
	t := time.NewTicker(w.cfg.Tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s, err := sampleFn(ctx)
			if err != nil {
				continue // transient sampling failure is not a stall signal
			}
			w.Feed(s)
		}
	}
}
