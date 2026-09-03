package observability

import (
	"testing"
	"time"
)

func gaugeKey(g MetricSample) string {
	k := g.Name
	for key, v := range g.Labels {
		k += "{" + key + "=" + v + "}"
	}
	return k
}

// Set must REPLACE the value of a gauge series (never accumulate) and live
// in a namespace separate from same-named counters.
func TestGaugeSetReplacesAndResets(t *testing.T) {
	r := NewMetricsRegistry(64)
	r.Set("g_one", map[string]string{"k": "v"}, 10)
	r.Set("g_one", map[string]string{"k": "v"}, 7)
	r.Set("g_two", nil, 3)

	snap := r.Snapshot(time.Unix(10, 0))
	if len(snap.Gauges) != 2 {
		t.Fatalf("gauges = %d, want 2", len(snap.Gauges))
	}
	values := map[string]uint64{}
	for _, g := range snap.Gauges {
		values[gaugeKey(g)] = g.Value
	}
	if got := values["g_one{k=v}"]; got != 7 {
		t.Fatalf("g_one{k=v} = %d, want 7 (Set must replace)", got)
	}
	if got := values["g_two"]; got != 3 {
		t.Fatalf("g_two = %d, want 3", got)
	}

	// Counters and gauges are separate namespaces even for identical labels.
	r.Inc("g_one", map[string]string{"k": "v"}, 1)
	snap = r.Snapshot(time.Unix(11, 0))
	for _, c := range snap.Counters {
		if c.Name == "g_one" && c.Value != 1 {
			t.Fatalf("counter g_one = %d, want 1", c.Value)
		}
	}
	for _, g := range snap.Gauges {
		if g.Name == "g_one" && g.Value != 7 {
			t.Fatalf("gauge g_one drifted to %d, want 7", g.Value)
		}
	}

	r.Reset()
	if got := len(r.Snapshot(time.Unix(12, 0)).Gauges); got != 0 {
		t.Fatalf("gauges after reset = %d, want 0", got)
	}
}

// Gauges respect maxSeries together with counters and histograms.
func TestGaugeMaxSeriesBound(t *testing.T) {
	r := NewMetricsRegistry(2)
	r.Set("a", nil, 1)
	r.Set("b", nil, 1)
	r.Set("c", nil, 1) // over budget: dropped
	if got := len(r.Snapshot(time.Unix(13, 0)).Gauges); got != 2 {
		t.Fatalf("gauges = %d, want 2 (maxSeries bound)", got)
	}
}

// Snapshot copies gauge label maps (no aliasing of the caller's map).
func TestGaugeLabelsAreCopied(t *testing.T) {
	r := NewMetricsRegistry(8)
	labels := map[string]string{"state": "active"}
	r.Set("g", labels, 5)
	labels["state"] = "changed"
	for _, g := range r.Snapshot(time.Unix(14, 0)).Gauges {
		if g.Name == "g" && g.Labels["state"] != "active" {
			t.Fatalf("gauge labels alias caller map: %+v", g.Labels)
		}
	}
}
