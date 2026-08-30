// Package observability: E-PROTON metric names (design §8). The
// protonservice runtime exports them through the shared registry; /metrics
// renders them per prometheus.go. proton_registration_total is
// zero-tolerance: only the boot registration and the owner's manual reissue
// may increment it.
package observability

const (
	// MetricProtonDialTotal counts DialStream-style control outcomes.
	// Labels: result=ok|fail.
	MetricProtonDialTotal = "proton_dial_total"
	// MetricProtonHandshakeTotal counts WG handshake outcomes of the proton
	// session. Labels: result=ok|fail.
	MetricProtonHandshakeTotal = "proton_handshake_total"
	// MetricProtonProfileSeekTotal counts seek-ladder attempt outcomes.
	// Labels: profile=<id>, result=<class|winner>.
	MetricProtonProfileSeekTotal = "proton_profile_seek_total"
	// MetricProtonNodesSource is the current node-list source (gauge-ish
	// counter: 1 on the active series, others 0). Labels: source=live-v2|
	// live-v1|asset|stale|cache.
	MetricProtonNodesSource = "proton_nodes_source"
	// MetricProtonCertValidUntilSeconds carries the certificate expiry as a
	// unix-seconds gauge; absent while unknown (never exported as zero —
	// that would lie about the certificate).
	MetricProtonCertValidUntilSeconds = "proton_cert_valid_until_seconds"
	// MetricProtonRegistrationTotal counts registrations (boot + manual
	// reissue only).
	MetricProtonRegistrationTotal = "proton_registration_total"
	// MetricProtonAPIRequestsTotal counts control-plane API calls.
	// Labels: endpoint=<path>, result=ok|<class>.
	MetricProtonAPIRequestsTotal = "proton_api_requests_total"
	// MetricProtonSessionRefreshTotal counts session refreshes.
	// Labels: result=ok|<class>.
	MetricProtonSessionRefreshTotal = "proton_session_refresh_total"
)
