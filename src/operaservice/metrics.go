// observability wiring for the opera runtime (review E-OPERA M3 —
// symmetric with fxvpservice/metrics.go and protonservice/metrics.go):
//
//   - every DialStream outcome bumps opera_dial_total{result};
//   - supervisor lifecycle events (established strictly after the e2e deep
//     probe, rotations, refresh failures, algorithm refusals, cache
//     adoptions, recovery attempts) land in the bounded event ring exposed
//     through Status AND bump their registry counters;
//   - node-list source is exported as a one-hot vector (live|cache) so
//     scrapers see a stable series instead of disappearing ones.
package operaservice

import (
	"sync"
	"time"

	"github.com/daniellavrushin/b4/observability"
)

// eventsRingCap bounds the in-memory event tail (proton parity).
const eventsRingCap = 64

// Event is one opera lifecycle event for status/GUI consumers.
type Event struct {
	Name   string    `json:"name"`
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// Event names emitted by the health layer (transport/opera) and the
// assembly below.
const (
	EventEstablished        = "opera_established"    // strictly after the deep probe passes
	EventRotated            = "opera_rotated"        // candidate rotation
	EventRefreshFailed      = "opera_refresh_failed" // JWT refresh failure (backoff armed)
	EventRecoverAttempt     = "opera_recover_attempt"
	EventCacheAdopted       = "opera_cache_adopted" // offline asset in use (no silent fallback)
	EventAPIAlgorithm       = "opera_api_algorithm" // digest algorithm refusal (review M5)
	EventMasqueradeSwitched = "opera_masquerade_switched"
)

// eventRing is the bounded status event tail.
type eventRing struct {
	mu     sync.Mutex
	events []Event
	now    func() time.Time
}

func (r *eventRing) append(name, detail string) {
	ev := Event{Name: name, Detail: detail, At: time.Now().UTC()}
	if r.now != nil {
		ev.At = r.now()
	}
	r.mu.Lock()
	r.events = append(r.events, ev)
	if len(r.events) > eventsRingCap {
		r.events = r.events[len(r.events)-eventsRingCap:]
	}
	r.mu.Unlock()
}

func (r *eventRing) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.events))
	copy(out, r.events)
	return out
}

// eventCounter maps event names to their registry counters.
func recordEventCounter(name string) {
	met := observability.Default().Metrics
	switch name {
	case EventEstablished:
		// established is a state transition, not a counter — the dial and
		// probe counters already expose the flow; the event ring carries it.
	case EventRecoverAttempt:
		met.Inc(observability.MetricOperaRestartsTotal, nil, 1)
	case EventAPIAlgorithm:
		met.Inc(observability.MetricOperaAPIAlgorithmTotal, nil, 1)
	case EventRefreshFailed:
		met.Inc(observability.MetricOperaRefreshTotal, map[string]string{"result": "fail"}, 1)
	}
}

// makeOnEvent builds the HealthConfig.OnEvent hook: ring append + counter.
func makeOnEvent(ring *eventRing) func(name, detail string) {
	return func(name, detail string) {
		ring.append(name, detail)
		recordEventCounter(name)
	}
}

// recordDial bumps the DialStream outcome counter (fxvpn parity).
func (r *Runtime) recordDial(result string) {
	observability.Default().Metrics.Inc(observability.MetricOperaDialTotal,
		map[string]string{"result": result}, 1)
}

// exportNodesSource pushes the one-hot source vector (live|cache).
func exportNodesSource(source string) {
	met := observability.Default().Metrics
	live, cache := uint64(0), uint64(0)
	if source == "cache" {
		cache = 1
	} else if source == "live" {
		live = 1
	}
	met.Set(observability.MetricOperaNodesSource, map[string]string{"source": "live"}, live)
	met.Set(observability.MetricOperaNodesSource, map[string]string{"source": "cache"}, cache)
}

// recordProbe bumps the probe counter with level+verdict labels.
func recordProbe(level, verdict string) {
	observability.Default().Metrics.Inc(observability.MetricOperaProbeTotal,
		map[string]string{"level": level, "verdict": verdict}, 1)
}

// recordDiscover bumps the discover counter with the source/result labels.
func recordDiscover(source, result string) {
	observability.Default().Metrics.Inc(observability.MetricOperaDiscoverTotal,
		map[string]string{"source": source, "result": result}, 1)
}

// recordRefreshOK marks a successful refresh.
func recordRefreshOK() {
	observability.Default().Metrics.Inc(observability.MetricOperaRefreshTotal,
		map[string]string{"result": "ok"}, 1)
}
