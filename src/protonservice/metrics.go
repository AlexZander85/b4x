// metrics.go: /metrics export for the proton runtime (E-PROTON design §8,
// patch-plan §7.3; the fxvpservice/metrics.go pattern). Counters mirror the
// runtime bookkeeping so the registry and the status view never diverge;
// the zero-value series are exported too so scrapers observe a stable
// vector.
package protonservice

import (
	"sync"

	"github.com/daniellavrushin/b4/observability"
	"github.com/daniellavrushin/b4/transport/proton"
)

// metricsState caches the "exported once" flags for the zero series.
type metricsState struct {
	mu        sync.Mutex
	zeroSeeds map[string]bool
}

var protonMetrics = &metricsState{zeroSeeds: make(map[string]bool)}

// recordHandshake bumps the handshake counters AND the shared registry
// counter (the runtime bookkeeping and /metrics never diverge).
func (r *Runtime) exportHandshake(ok bool) {
	res := "fail"
	if ok {
		res = "ok"
	}
	observability.Default().Metrics.Inc(observability.MetricProtonHandshakeTotal,
		map[string]string{"result": res}, 1)
}

// recordRegistration is called ONLY from the boot registration and the
// owner's manual reissue (the zero-tolerance rule).
func (r *Runtime) exportRegistration() {
	observability.Default().Metrics.Inc(observability.MetricProtonRegistrationTotal,
		map[string]string{}, 1)
}

// recordSeek exports one seek-ladder attempt.
func (r *Runtime) exportSeek(profileID, result string) {
	observability.Default().Metrics.Inc(observability.MetricProtonProfileSeekTotal,
		map[string]string{"profile": profileID, "result": result}, 1)
}

// exportState pushes the snapshot gauges: the node source vector and the
// certificate validity stamp.
func (r *Runtime) exportState() {
	met := observability.Default().Metrics
	source := r.list.Snapshot()
	for _, s := range []string{proton.SourceLiveV2, proton.SourceLiveV1, proton.SourceAsset, proton.SourceStale, proton.SourceMemCache} {
		v := uint64(0)
		if s == source {
			v = 1
		}
		met.Set(observability.MetricProtonNodesSource, map[string]string{"source": s}, v)
	}
	if id := r.currentIdentityPtr(); id != nil && id.CertExpiresAt > 0 {
		met.Set(observability.MetricProtonCertValidUntilSeconds,
			map[string]string{}, uint64(id.CertExpiresAt))
	}
}
