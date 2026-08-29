// Metrics export (E-NM tail #3): the design 5 series names leave this
// package through an injectable sample sink; adapting them to the
// src/warp TracePipeline envelope stays with the integration layer (same
// decision as E7 for supervisor events - engines stay pipeline-free).
package nested

import (
	"context"
	"time"
)

// MetricSample is one named series point.
type MetricSample struct {
	Name   string
	Value  float64
	Labels map[string]string
}

// MetricSink receives exported samples; must be non-blocking.
type MetricSink func(MetricSample)

// Design-series names (warp-nested-matrix-design.md 5).
const (
	SeriesPairActive    = "nested_pair_active"
	SeriesRepinTotal    = "nested_repin_total"
	SeriesRouteLost     = "nested_carrier_route_lost_total"
	SeriesEdgeCollision = "nested_edge_collision_total"
	// PATCH-07 (M-14): child-lifecycle counters, kept separate from the
	// route-incident series so route diagnostics never absorb start noise.
	SeriesChildStartFailed = "nested_child_start_failed_total"
	SeriesChildInvalidated = "nested_child_invalidated_total"
	// SeriesLayerGateSeconds carries label layer=outer|inner.
	SeriesLayerGateSeconds = "nested_layer_gate_duration_seconds"
)

// Snapshot renders the current counters as design-named samples.
func (m *Metrics) Snapshot() []MetricSample {
	if m == nil {
		return nil
	}
	out := []MetricSample{
		{Name: SeriesPairActive, Value: float64(m.PairActive.Load())},
		{Name: SeriesRepinTotal, Value: float64(m.RepinTotal.Load())},
		{Name: SeriesRouteLost, Value: float64(m.RouteLostTotal.Load())},
		{Name: SeriesEdgeCollision, Value: float64(m.EdgeCollisionTotal.Load())},
		{Name: SeriesChildStartFailed, Value: float64(m.ChildStartFailedTotal.Load())},
		{Name: SeriesChildInvalidated, Value: float64(m.ChildInvalidatedTotal.Load())},
	}
	if v := m.OuterGateMS.Load(); v >= 0 {
		out = append(out, MetricSample{Name: SeriesLayerGateSeconds,
			Value: float64(v) / 1000, Labels: map[string]string{"layer": "outer"}})
	}
	if v := m.InnerGateMS.Load(); v >= 0 {
		out = append(out, MetricSample{Name: SeriesLayerGateSeconds,
			Value: float64(v) / 1000, Labels: map[string]string{"layer": "inner"}})
	}
	return out
}

// Export publishes ONE snapshot into sink (call from integration tickers or
// use ExportLoop).
func (m *Metrics) Export(sink MetricSink) {
	if sink == nil {
		return
	}
	for _, s := range m.Snapshot() {
		sink(s)
	}
}

// ExportLoop publishes a snapshot every interval until ctx is done.
func ExportLoop(ctx context.Context, m *Metrics, interval time.Duration, sink MetricSink) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.Export(sink)
			}
		}
	}()
}
