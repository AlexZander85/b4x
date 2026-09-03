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
        // MetricFxvpnBytesTotal counts the data-plane relay bytes of the fxvpn
        // reserve transport (review F7b). Labels: dir=up|down.
        MetricFxvpnBytesTotal = "fxvpn_bytes_total"
        // MetricFxvpnNested is the carrier-nesting gauge (review §7.5/FX-M4):
        // 1 while the data plane rides the base-tunnel carrier, 0 otherwise.
        MetricFxvpnNested = "fxvpn_nested"
        // MetricFxvpnBaitActive is the NFQ bait confirmation gauge (FX-M3/M4):
        // 1 only after the tables layer confirmed the OUTPUT rule.
        MetricFxvpnBaitActive = "fxvpn_bait_active"
)
