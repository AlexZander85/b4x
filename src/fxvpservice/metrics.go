// metrics.go: /metrics export for the fxvpn runtime (E-FXVPN FX5b).
//
// Counter: fxvpn_dial_total{result=ok|fail} mirrors the runtime dialOK/
// dialFail atomics - every DialStream outcome goes through recordDial so
// the atomics and the shared observability registry never diverge.
//
// Gauges (absolute values via Metrics.Set):
//   - fxvpn_pool_state{state=<AccountState>} is the pool state vector, one
//     series per lifecycle state; zero counts are exported too so scrapers
//     observe a stable vector instead of disappearing series;
//   - fxvpn_quota_remaining_bytes carries the ACTIVE account's
//     X-Quota-Remaining and stays absent until a quota number is known
//     (unknown/-1 is never exported as zero - that would lie about quota).
//
// Refresh points: supervision ticks and pool events (Build installs the
// export into the existing pool Events hook). No new dependencies.
package fxvpservice

import (
	"sync/atomic"

	"github.com/daniellavrushin/b4/observability"
	fxvpn "github.com/daniellavrushin/b4/transport/fxvpn"
)

// poolStateVector lists every AccountState in lifecycle order.
var poolStateVector = []fxvpn.AccountState{
	fxvpn.StateProvisioning,
	fxvpn.StateVerifying,
	fxvpn.StateStandby,
	fxvpn.StateActive,
	fxvpn.StateCoolingDown,
	fxvpn.StateExhausted,
	fxvpn.StateBanned,
	fxvpn.StateRefused,
}

// recordDial bumps the runtime atomic AND the shared registry counter.
func (r *Runtime) recordDial(ok bool) {
	if ok {
		atomic.AddUint64(&r.dialOK, 1)
		observability.Default().Metrics.Inc(observability.MetricFxvpnDialTotal, map[string]string{"result": "ok"}, 1)
		return
	}
	atomic.AddUint64(&r.dialFail, 1)
	observability.Default().Metrics.Inc(observability.MetricFxvpnDialTotal, map[string]string{"result": "fail"}, 1)
}

// exportPoolMetrics pushes the current pool/quota state into the registry.
func (r *Runtime) exportPoolMetrics() {
	counts, activeLeft := poolStateCounts(r.pool.Status())
	met := observability.Default().Metrics
	for _, s := range poolStateVector {
		met.Set(observability.MetricFxvpnPoolState, map[string]string{"state": string(s)}, counts[s])
	}
	if activeLeft >= 0 {
		met.Set(observability.MetricFxvpnQuotaRemainingBytes, map[string]string{"account": "active"}, uint64(activeLeft))
	}
}

// poolStateCounts reduces a pool snapshot into per-state counts plus the
// active account's remaining quota (-1 when unknown or no active seat).
func poolStateCounts(st fxvpn.PoolStatus) (map[fxvpn.AccountState]uint64, int64) {
	counts := make(map[fxvpn.AccountState]uint64, len(poolStateVector))
	activeLeft := int64(-1)
	for _, v := range st.Views {
		counts[v.State]++
		if v.Active {
			activeLeft = v.QuotaLeft
		}
	}
	return counts, activeLeft
}
