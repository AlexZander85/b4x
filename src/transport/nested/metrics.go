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

// CountingEvents wraps an OnEvent callback with Metrics classification.
func CountingEvents(m *Metrics, next func(Event)) func(Event) {
	return func(ev Event) {
		m.Observe(ev)
		if next != nil {
			next(ev)
		}
	}
}
