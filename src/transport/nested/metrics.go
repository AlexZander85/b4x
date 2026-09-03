// Observability (N4, design 5): structured event classes already live on
// every carrier; this file adds the counter surface and the per-layer gate
// latency capture points. Counters are plain atomics - the wiring layer
// exports them; the package stays dependency-free.
package nested

import (
	"sync/atomic"
	"time"
)

// Metrics is one composition's counter block. All fields are safe for
// concurrent use; zero value is ready.
type Metrics struct {
	// PairActive tracks up-down transitions of composed pairs (gauge).
	PairActive atomic.Int64
	// RepinTotal counts nested/pin-restored events (design 5).
	RepinTotal atomic.Uint64
	// RouteLostTotal counts nested/carrier-route-lost events.
	RouteLostTotal atomic.Uint64
	// EdgeCollisionTotal counts config-time nested/edge-collision rejects.
	EdgeCollisionTotal atomic.Uint64
	// ChildStartFailedTotal counts wg_nested_child_start_failed events
	// (PATCH-07, M-14: separated from route incidents).
	ChildStartFailedTotal atomic.Uint64
	// ChildInvalidatedTotal counts wg_nested_child_invalidated events
	// (PATCH-07, M-14: separated from route incidents).
	ChildInvalidatedTotal atomic.Uint64
	// OuterGateMS / InnerGateMS hold the LAST observed trust-gate duration
	// per layer in milliseconds (per-layer attribution, design 62.9:
	// without it no claim about "the price of nesting" is allowed).
	OuterGateMS atomic.Int64
	InnerGateMS atomic.Int64
}

// Observe classifies one composition event into counters.
func (m *Metrics) Observe(ev Event) {
	if m == nil {
		return
	}
	switch ev.Class {
	case ClassPinRestored:
		m.RepinTotal.Add(1)
	case ClassCarrierRouteLost:
		m.RouteLostTotal.Add(1)
	case ClassEdgeCollision:
		m.EdgeCollisionTotal.Add(1)
	case ClassChildStartFailed:
		m.ChildStartFailedTotal.Add(1)
	case ClassChildInvalidated:
		m.ChildInvalidatedTotal.Add(1)
	}
}

// ObserveGate records one layer's gate duration.
func (m *Metrics) ObserveGate(layer string, d time.Duration) {
	if m == nil {
		return
	}
	switch layer {
	case "outer":
		m.OuterGateMS.Store(d.Milliseconds())
	case "inner":
		m.InnerGateMS.Store(d.Milliseconds())
	}
}

// ---- MAJOR-5: gate-stamp helpers shared by both composition runtimes ----
//
// The gate stamps live on the runtimes as atomic unix-nano counters (0 =
// disarmed) because OnEstablished callbacks and supervisor sinks fire on
// foreign goroutines; the gate math itself never touches the runtime mutex.
// Observe is consume-once: a gate closes exactly once per establishment and
// a repeat (duplicate callback, late generation) cannot overwrite the last
// observed value.

// gateArm starts a gate measurement (stamp = now).
func gateArm(stamp *atomic.Int64) { stamp.Store(time.Now().UnixNano()) }

// gateDisarm cancels an in-flight measurement (generation died before its
// trust gate closed; no attribution is allowed to a dead generation).
func gateDisarm(stamp *atomic.Int64) { stamp.Store(0) }

// gateObserve closes the gate: the armed stamp converts to a duration and
// lands on the layer series; disarmed stamps are ignored.
func gateObserve(stamp *atomic.Int64, m *Metrics, layer string) {
	if start := stamp.Swap(0); start != 0 {
		m.ObserveGate(layer, time.Since(time.Unix(0, start)))
	}
}

// PairGaugeMove adjusts the pair-active gauge by one guarded transition
// (nil-safe: runtimes hold a nil surface when Metrics is not wired).
func (m *Metrics) PairGaugeMove(delta int64) {
	if m == nil {
		return
	}
	m.PairActive.Add(delta)
}

// CountingEvents wraps an OnEvent callback with Metrics classification.
func CountingEvents(m *Metrics, next func(Event)) func(Event) {
	return func(ev Event) {
		m.Observe(ev)
		if next != nil {
			next(ev)
		}
	}
}
