package dnspath

import "time"

// HealthAxis is one monitoring health axis (addendum §79).
type HealthAxis string

const (
	AxisTransport  HealthAxis = "transport_health"
	AxisCorrectness HealthAxis = "correctness_health"
	AxisControl    HealthAxis = "control_health"
	AxisLatency    HealthAxis = "latency_health"
	AxisResource   HealthAxis = "resource_health"
	AxisBackend    HealthAxis = "backend_health"
	AxisFreshness  HealthAxis = "profile_freshness"
	AxisFallback   HealthAxis = "fallback_readiness"
)

// AxisState is the per-axis verdict.
type AxisState string

const (
	AxisHealthy  AxisState = "healthy"
	AxisDegraded AxisState = "degraded"
	AxisFailed   AxisState = "failed"
	AxisUnknown  AxisState = "unknown"
)

// HealthReport is the composed health view. Overall green requires a
// compatible composition of axes, never a single transport ping (§79).
type HealthReport struct {
	Axes    map[HealthAxis]AxisState `json:"axes"`
	Overall AxisState                `json:"overall"`
	Reason  string                   `json:"reason,omitempty"`
}

// ComposeHealth combines axis states into the overall verdict.
func ComposeHealth(axes map[HealthAxis]AxisState) HealthReport {
	r := HealthReport{Axes: axes, Overall: AxisHealthy}
	degraded := false
	for axis, st := range axes {
		switch st {
		case AxisFailed:
			r.Overall = AxisFailed
			r.Reason = string(axis) + " failed"
			return r
		case AxisDegraded:
			degraded = true
		case AxisUnknown:
			// unknown freshness/fallback readiness forbids green
			if axis == AxisFreshness || axis == AxisFallback || axis == AxisCorrectness {
				degraded = true
			}
		}
	}
	if degraded {
		r.Overall = AxisDegraded
	}
	return r
}

// FailureRecord is one aggregated monitoring failure signal (§80).
type FailureRecord struct {
	PathFamily   DNSPathFamily
	Kind         string // timeout | contradiction | crash | cache_anomaly | control_failure
	Count        int
	FirstSeen    time.Time
	LastSeen     time.Time
}

// RecurrenceTracker aggregates passive failure recurrence. It initiates
// bounded ABD requests but never changes bindings itself (§80, ADR-ADNS-010).
type RecurrenceTracker struct {
	records map[string]*FailureRecord
	// Threshold is the persistent-failure count that justifies a bounded
	// diagnosis request; a single transient timeout never triggers (§53).
	Threshold int
}

func NewRecurrenceTracker(threshold int) *RecurrenceTracker {
	if threshold <= 0 {
		threshold = 3
	}
	return &RecurrenceTracker{records: map[string]*FailureRecord{}, Threshold: threshold}
}

// Record adds one failure observation and reports whether the persistent
// threshold has been reached for this path/kind.
func (t *RecurrenceTracker) Record(family DNSPathFamily, kind string, now time.Time) bool {
	key := string(family) + "/" + kind
	rec, ok := t.records[key]
	if !ok {
		rec = &FailureRecord{PathFamily: family, Kind: kind, FirstSeen: now}
		t.records[key] = rec
	}
	rec.Count++
	rec.LastSeen = now
	return rec.Count >= t.Threshold
}

// Reset clears recurrence after successful revalidation.
func (t *RecurrenceTracker) Reset(family DNSPathFamily, kind string) {
	delete(t.records, string(family)+"/"+kind)
}

// Snapshot returns a copy of current records.
func (t *RecurrenceTracker) Snapshot() []FailureRecord {
	out := make([]FailureRecord, 0, len(t.records))
	for _, r := range t.records {
		out = append(out, *r)
	}
	return out
}
