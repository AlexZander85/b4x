// Package observability: E-FXVPN metric names (design Part II II.1
// observability row). The fxvpservice runtime exports them through the
// shared registry; /metrics renders them per prometheus.go.
package observability

const (
	// MetricFxvpnDialTotal counts DialStream outcomes of the fxvpn reserve
	// transport. Labels: result=ok|fail.
	MetricFxvpnDialTotal = "fxvpn_dial_total"
	// MetricFxvpnQuotaRemainingBytes is the ACTIVE account's X-Quota-Remaining
	// in bytes (gauge, absolute value via Metrics.Set). -1/unknown is never
	// exported (series simply stays absent until first known quota).
	MetricFxvpnQuotaRemainingBytes = "fxvpn_quota_remaining_bytes"
	// MetricFxvpnPoolState is the pool state vector (gauge): one series per
	// AccountState label value with the number of accounts in that state.
	MetricFxvpnPoolState = "fxvpn_pool_state"
)
