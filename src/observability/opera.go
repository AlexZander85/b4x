// Package observability: E-OPERA metric names (review M3 — symmetric with
// fxvpn/proton). The operaservice runtime exports them through the shared
// registry; /metrics renders them per prometheus.go. Every counter here is
// a hard requirement of the opera review §3/§7: silent-fallback is
// forbidden, so source switches and ladder moves are OBSERVABLE by design.
package observability

const (
	// MetricOperaDialTotal counts DialStream outcomes.
	// Labels: result=ok|fail|self-loop.
	MetricOperaDialTotal = "opera_dial_total"
	// MetricOperaProbeTotal counts supervisor probe outcomes.
	// Labels: level=cheap|deep, verdict=ok|fail|cant-bind.
	MetricOperaProbeTotal = "opera_probe_total"
	// MetricOperaDiscoverTotal counts control-channel discover calls.
	// Labels: source=live|cache, result=ok|<class-ish short reason>.
	MetricOperaDiscoverTotal = "opera_discover_total"
	// MetricOperaRestartsTotal counts expensive recovery actions (fresh
	// anonymous device registrations, capped <=6/hour).
	MetricOperaRestartsTotal = "opera_restarts_total"
	// MetricOperaAPIAlgorithmTotal counts Digest algorithm-profile refusals
	// (ClassAPIAlgorithm): the MD5-only structural risk of review M5 must
	// be VISIBLE if SurfEasy ever moves the API off the profile.
	// Labels: none.
	MetricOperaAPIAlgorithmTotal = "opera_api_algorithm_total"
	// MetricOperaRefreshTotal counts JWT refresh outcomes.
	// Labels: result=ok|fail.
	MetricOperaRefreshTotal = "opera_refresh_total"
	// MetricOperaNodesSource is the current node-list source vector.
	// Labels: source=live|cache (1 on the active series, others 0).
	MetricOperaNodesSource = "opera_nodes_source"
	// MetricOperaMasqueradeSwitched counts masquerade-ladder moves (review
	// §7.5: every step observable, one episode = one switch).
	// Labels: direction=up|down, from=<profile>, to=<profile>.
	MetricOperaMasqueradeSwitched = "opera_masquerade_switched_total"
)
