package leaktest

import (
        "testing"

        "go.uber.org/goleak"
)

// Options returns the goleak options that ignore b4's long-lived background
// daemons (started lazily or in package init), which are not leaks. Use it for
// per-test goleak.VerifyNone calls; VerifyTestMain applies the same set.
func Options(extra ...goleak.Option) []goleak.Option {
        base := []goleak.Option{
                goleak.IgnoreTopFunction("github.com/daniellavrushin/b4/quic.cleanupStaleEntries"),
                goleak.IgnoreTopFunction("github.com/daniellavrushin/b4/log.startFlusherLocked.func1"),
                goleak.IgnoreTopFunction("github.com/daniellavrushin/b4/metrics.(*MetricsCollector).updateLoop"),
                // capture.GetManager is a sync.Once singleton; the first full-pipeline
                // packet test starts its process-lifetime cleanup ticker. Not a leak —
                // same category as the quic reaper above.
                goleak.IgnoreTopFunction("github.com/daniellavrushin/b4/capture.(*Manager).cleanupExpiredProbes"),
                // E-TOR: the snowflake client library's turbo-tunnel links kcp-go,
                // whose package init starts process-lifetime scheduler goroutines
                // in every importing binary (torsnowflake → torservice → handler →
                // ws test chain). Not a leak — a global, like the quic reaper above.
                goleak.IgnoreTopFunction("github.com/xtaci/kcp-go/v5.NewTimedSched.gowrap1"),
                goleak.IgnoreTopFunction("github.com/xtaci/kcp-go/v5.NewTimedSched.gowrap2"),
                goleak.IgnoreTopFunction("github.com/xtaci/kcp-go/v5.(*TimedSched).sched"),
                goleak.IgnoreTopFunction("github.com/xtaci/kcp-go/v5.(*TimedSched).prepend"),
        }
        return append(base, extra...)
}

func VerifyTestMain(m *testing.M, extra ...goleak.Option) {
        goleak.VerifyTestMain(m, Options(extra...)...)
}
