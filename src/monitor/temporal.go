package monitor

import (
	"sort"
	"sync"
	"time"
)

// TemporalConfig bounds the amount of evidence retained for a scope.  The
// accumulator is deliberately a short-lived helper; callers must create a
// new instance when the scope or configuration generation changes.
type TemporalConfig struct {
	BucketWidth           time.Duration
	HalfLife              time.Duration
	MaxBuckets            int
	FailureToDegraded     int
	FailuresToFailing     int
	SuccessesToRecovering int
	SuccessesToHealthy    int
	MinFailureSeparation  time.Duration
}

func DefaultTemporalConfig() TemporalConfig {
	return TemporalConfig{BucketWidth: time.Minute, HalfLife: 10 * time.Minute,
		MaxBuckets: 30, FailureToDegraded: 2, FailuresToFailing: 3,
		SuccessesToRecovering: 1, SuccessesToHealthy: 2,
		MinFailureSeparation: 10 * time.Second}
}

type TemporalEvidenceBucket struct {
	Start, End                                   time.Time
	ObservationCount, SuccessCount, FailureCount uint32
	DistinctSources, DistinctEndpoints           uint16
	DistinctFlows, DistinctFingerprints          uint16
	DistinctWANIntervals                         uint16
}

type TemporalSnapshot struct {
	State                               HealthState
	Buckets                             []TemporalEvidenceBucket
	WeightedFailures, WeightedSuccesses float64
	Recurrence, Independence            float64
	LastFailure, LastSuccess            time.Time
}

type temporalBucketState struct {
	TemporalEvidenceBucket
	sources, endpoints, flows, fingerprints, wanIntervals map[string]struct{}
}

// TemporalAccumulator provides recurrence, independence, decay, and
// hysteresis without making an action decision or changing configuration.
type TemporalAccumulator struct {
	mu                       sync.Mutex
	cfg                      TemporalConfig
	buckets                  []temporalBucketState
	state                    HealthState
	lastFailure, lastSuccess time.Time
}

func NewTemporalAccumulator(cfg TemporalConfig) *TemporalAccumulator {
	d := DefaultTemporalConfig()
	if cfg.BucketWidth <= 0 {
		cfg.BucketWidth = d.BucketWidth
	}
	if cfg.HalfLife <= 0 {
		cfg.HalfLife = d.HalfLife
	}
	if cfg.MaxBuckets <= 0 {
		cfg.MaxBuckets = d.MaxBuckets
	}
	if cfg.FailureToDegraded <= 0 {
		cfg.FailureToDegraded = d.FailureToDegraded
	}
	if cfg.FailuresToFailing <= 0 {
		cfg.FailuresToFailing = d.FailuresToFailing
	}
	if cfg.SuccessesToRecovering <= 0 {
		cfg.SuccessesToRecovering = d.SuccessesToRecovering
	}
	if cfg.SuccessesToHealthy <= 0 {
		cfg.SuccessesToHealthy = d.SuccessesToHealthy
	}
	if cfg.MinFailureSeparation <= 0 {
		cfg.MinFailureSeparation = d.MinFailureSeparation
	}
	return &TemporalAccumulator{cfg: cfg, state: HealthUnknown}
}

// Add records one passive observation.  Identity dimensions are supplied by
// the caller so the accumulator does not infer authority from packet fields.
func (a *TemporalAccumulator) Add(o MonitorObservation, sourceFamily, endpoint, flow, fingerprint, wanInterval string, success bool) {
	if a == nil || o.ObservedAt.IsZero() {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trimLocked(o.ObservedAt)
	start := o.ObservedAt.Truncate(a.cfg.BucketWidth)
	var b *temporalBucketState
	if len(a.buckets) == 0 || !a.buckets[len(a.buckets)-1].Start.Equal(start) {
		a.buckets = append(a.buckets, temporalBucketState{TemporalEvidenceBucket: TemporalEvidenceBucket{Start: start, End: start.Add(a.cfg.BucketWidth)}, sources: map[string]struct{}{}, endpoints: map[string]struct{}{}, flows: map[string]struct{}{}, fingerprints: map[string]struct{}{}, wanIntervals: map[string]struct{}{}})
		b = &a.buckets[len(a.buckets)-1]
	} else {
		b = &a.buckets[len(a.buckets)-1]
	}
	b.ObservationCount++
	if success {
		b.SuccessCount++
		a.lastSuccess = o.ObservedAt
	} else {
		b.FailureCount++
		if a.lastFailure.IsZero() || o.ObservedAt.After(a.lastFailure) {
			a.lastFailure = o.ObservedAt
		}
	}
	if sourceFamily != "" {
		b.sources[sourceFamily] = struct{}{}
	}
	if endpoint != "" {
		b.endpoints[endpoint] = struct{}{}
	}
	if flow != "" {
		b.flows[flow] = struct{}{}
	}
	if fingerprint != "" {
		b.fingerprints[fingerprint] = struct{}{}
	}
	if wanInterval != "" {
		b.wanIntervals[wanInterval] = struct{}{}
	}
	b.DistinctSources = uint16(len(b.sources))
	b.DistinctEndpoints = uint16(len(b.endpoints))
	b.DistinctFlows = uint16(len(b.flows))
	b.DistinctFingerprints = uint16(len(b.fingerprints))
	b.DistinctWANIntervals = uint16(len(b.wanIntervals))
	a.transitionLocked()
}

func (a *TemporalAccumulator) trimLocked(now time.Time) {
	cutoff := now.Add(-a.cfg.HalfLife * 4)
	for len(a.buckets) > a.cfg.MaxBuckets || (len(a.buckets) > 0 && a.buckets[0].End.Before(cutoff)) {
		a.buckets = a.buckets[1:]
	}
}

func (a *TemporalAccumulator) transitionLocked() {
	var f, s int
	for _, b := range a.buckets {
		f += int(b.FailureCount)
		s += int(b.SuccessCount)
	}
	switch a.state {
	case HealthUnknown, HealthHealthy, HealthRecovered:
		if f >= a.cfg.FailuresToFailing {
			a.state = HealthFailing
		} else if f >= a.cfg.FailureToDegraded {
			a.state = HealthDegraded
		}
	case HealthDegraded:
		if f >= a.cfg.FailuresToFailing {
			a.state = HealthFailing
		} else if s >= a.cfg.SuccessesToRecovering {
			a.state = HealthRecovering
		}
	case HealthFailing:
		if s >= a.cfg.SuccessesToRecovering {
			a.state = HealthRecovering
		}
	case HealthRecovering:
		if s >= a.cfg.SuccessesToHealthy {
			a.state = HealthHealthy
		}
	}
}

func (a *TemporalAccumulator) Snapshot(now time.Time) TemporalSnapshot {
	if a == nil {
		return TemporalSnapshot{State: HealthUnknown}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.trimLocked(now)
	if len(a.buckets) == 0 {
		return TemporalSnapshot{State: a.state}
	}
	weightedF, weightedS := 0.0, 0.0
	var failureEvents int
	families, endpoints, flows, fingerprints, wan := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	for _, b := range a.buckets {
		age := now.Sub(b.End)
		if age < 0 {
			age = 0
		}
		weight := 1.0
		if a.cfg.HalfLife > 0 {
			weight = 1 / (1 + age.Hours()/(a.cfg.HalfLife.Hours()))
		}
		weightedF += float64(b.FailureCount) * weight
		weightedS += float64(b.SuccessCount) * weight
		failureEvents += int(b.FailureCount)
		for k := range b.sources {
			families[k] = struct{}{}
		}
		for k := range b.endpoints {
			endpoints[k] = struct{}{}
		}
		for k := range b.flows {
			flows[k] = struct{}{}
		}
		for k := range b.fingerprints {
			fingerprints[k] = struct{}{}
		}
		for k := range b.wanIntervals {
			wan[k] = struct{}{}
		}
	}
	recurrence := 0.0
	if failureEvents > 1 {
		recurrence = float64(failureEvents-1) / float64(failureEvents)
	}
	independentDimensions := len(families) + len(endpoints) + len(flows) + len(fingerprints) + len(wan)
	independence := 0.0
	if independentDimensions > 0 {
		independence = float64(independentDimensions) / float64(independentDimensions+1)
	}
	// Keep a stable, chronological copy for consumers; no mutable maps escape.
	buckets := make([]TemporalEvidenceBucket, len(a.buckets))
	for i := range a.buckets {
		buckets[i] = a.buckets[i].TemporalEvidenceBucket
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].Start.Before(buckets[j].Start) })
	return TemporalSnapshot{State: a.state, Buckets: buckets, WeightedFailures: weightedF, WeightedSuccesses: weightedS, Recurrence: recurrence, Independence: independence, LastFailure: a.lastFailure, LastSuccess: a.lastSuccess}
}

// FirstBucketStart is useful for diagnostics without exposing internal state.
func (a *TemporalAccumulator) FirstBucketStart() time.Time {
	s := a.Snapshot(time.Now())
	if len(s.Buckets) == 0 {
		return time.Time{}
	}
	return s.Buckets[0].Start
}
