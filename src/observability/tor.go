// Package observability: E-TOR metric names (design tor-reserve-design.md
// §9.7). The torservice runtime exports them through the shared registry;
// /metrics renders them per prometheus.go. All series are bounded by the
// registry cap; labels carry no client IPs (SafeLogging canon).
package observability

const (
	// MetricTorBootstrapSeconds is the bootstrap duration gauge of the last
	// successful bootstrap (seconds). Absent while never established —
	// never exported as zero (that would lie about a fast bootstrap).
	MetricTorBootstrapSeconds = "tor_bootstrap_seconds"
	// MetricTorFirstStreamTTFBMs is the time-to-first-byte of the first LAN
	// stream through tor (milliseconds, gauge). The field will show it.
	MetricTorFirstStreamTTFBMs = "tor_first_stream_ttfb_ms"
	// MetricTorCircuitsAlive is the live circuit count (gauge).
	MetricTorCircuitsAlive = "tor_circuits_alive"
	// MetricTorBridgesAlive is the alive bridge count (gauge).
	// Labels: transport=<webtunnel|obfs4|snowflake|meek_lite|vanilla>.
	MetricTorBridgesAlive = "tor_bridges_alive"
	// MetricTorStreamsTotal counts SOCKS stream outcomes through the tor
	// carrier. Labels: result=ok|fail.
	MetricTorStreamsTotal = "tor_streams_total"
	// MetricTorDialTotal counts egress-dialer outcomes by class and stage.
	// Labels: class=<conn-class>, result=ok|fail.
	MetricTorDialTotal = "tor_dial_total"
	// MetricTorBytesRead / MetricTorBytesWritten mirror GETINFO
	// traffic/read|written (gauge, bytes).
	MetricTorBytesRead    = "tor_bytes_read"
	MetricTorBytesWritten = "tor_bytes_written"
	// MetricTorEntryAttemptsTotal counts entry-ladder attempt outcomes.
	// Labels: entry=<transport|auto>, result=won|failed|<class>.
	MetricTorEntryAttemptsTotal = "tor_entry_attempts_total"
	// MetricTorProcessRestartsTotal counts supervisor-initiated tor restarts.
	MetricTorProcessRestartsTotal = "tor_process_restarts_total"
	// MetricTorControlErrorsTotal counts control-protocol errors
	// (GETINFO/SETCONF/SIGNAL failures and timeouts).
	MetricTorControlErrorsTotal = "tor_control_errors_total"
	// MetricTorScanRelaysFound is the relay-scanner verified count per run
	// (gauge; the last run's result).
	MetricTorScanRelaysFound = "tor_scan_relays_found"
	// MetricTorBaitActive is the NFQ bait confirmation gauge (design §3.4):
	// 1 only after the tables layer confirmed the OUTPUT rule — honest
	// inactive otherwise, the bait never claims itself silently.
	MetricTorBaitActive = "tor_bait_active"
)

// ExportTorStatus pushes the status-derived gauges (the service calls it
// from its supervision tick — one projection point, bounded series).
func ExportTorStatus(bootstrapSeconds, circuitsAlive, bytesRead, bytesWritten uint64, bridgesByTransport map[string]int) {
	met := Default().Metrics
	met.Set(MetricTorBootstrapSeconds, nil, bootstrapSeconds)
	met.Set(MetricTorCircuitsAlive, nil, circuitsAlive)
	met.Set(MetricTorBytesRead, nil, bytesRead)
	met.Set(MetricTorBytesWritten, nil, bytesWritten)
	for tr, n := range bridgesByTransport {
		met.Set(MetricTorBridgesAlive, map[string]string{"transport": tr}, uint64(n))
	}
}
