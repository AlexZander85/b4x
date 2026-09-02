package config

// DefaultOperaIdentityPath mirrors the warp/wg slot layout on the router.
const DefaultOperaIdentityPath = "/opt/etc/b4/opera/identity.json"

// OperaMasquerade defaults (masquerade chapter §7.3 of the E-OPERA review).
const (
	// OperaMasqueradeProfileDefault: the full browser masquerade is the
	// shipping default — the transport must not look like a Go robot.
	OperaMasqueradeProfileDefault = "browser"
	// OperaSNIModeDefault inverts the historical suppression (§7.4.1): the
	// REAL node name is a legitimate CDN-class name Opera's own browser
	// sends; no-SNI is a first-class DPI suspicion and stays available as
	// the explicit ladder bottom.
	OperaSNIModeDefault = "node"
	// OperaALPNDefault: the current data-plane engine speaks HTTP/1.1
	// CONNECT; offering h2 lands together with the H2-CONNECT engine
	// (OP-M2) — offering h2 and then speaking 1.1 would break the tunnel.
	OperaALPNDefault = "http/1.1"
)

// OperaMasqueradeConfig configures the anti-DPI masquerade of the Opera
// reserve transport (review §7.3). Zero values resolve to the defaults.
type OperaMasqueradeConfig struct {
	// Profile selects the masquerade ladder step: "browser" (full:
	// fingerprint+ALPN+resumption), "minimal" (SNI discipline only —
	// plain Go TLS), "off" (historical plain-Go + no-SNI behavior).
	Profile string `json:"profile"`
	// SNIMode: "node" (real node name — default), "pool" (name from
	// SNIPool), "none" (suppress — the historical default, last rung).
	SNIMode string `json:"sni_mode"`
	// SNIPool overrides the built-in white-SNI pool whole (owner-owned
	// names; RFC 1123 validated, sec-tunnel domains forbidden — the pool
	// must not advertise the peer it heads to).
	SNIPool []string `json:"sni_pool"`
	// ALPN list offered in the ClientHello. Default ["http/1.1"] until the
	// H2-CONNECT engine ships (OP-M2).
	ALPN []string `json:"alpn"`
	// SessionResumption enables the TLS session cache (§7.4.4): second and
	// later connections to a node resume (1-RTT, non-empty session_id) —
	// the browser pattern. Default true.
	SessionResumption *bool `json:"session_resumption"`
	// TTLFake enables the NFQ fake-ClientHello bait on the transport's own
	// egress (§7.4.3, OP-M3): sockets are SO_MARKed and routed into the
	// existing action queue for fakedsplit/fakeddisorder. Default false —
	// needs the NFQ engine active; honest status when not applied.
	TTLFake bool `json:"ttl_fake"`
}

// OperaConfig enables the built-in Opera/SurfEasy reserve transport
// (design .ag/research/opera-reserve-design.md §5; engine OP1-OP3 lives in
// src/transport/opera). It is DISABLED by default: the field layer flips it
// explicitly on a config COPY (deploy discipline in AGENTS.md).
//
// Role in the architecture: kind "opera" — a userspace Backend-B style TCP
// carrier (TCP-dial through SurfEasy nodes) consumed by the scoped router
// like every other userspace carrier. The transport is TCP-ONLY by protocol:
// UDP-scope traffic must never be routed here (fail-closed at the dialer,
// honest "tcp-only" in status).
type OperaConfig struct {
	Enabled bool `json:"enabled"`
	// IdentityPath persists the anonymous device identity (at most one
	// device registration per boot — red line #3). Empty value is filled
	// with DefaultOperaIdentityPath by ApplyConfigDefaults.
	IdentityPath string `json:"identity_path"`
	// Region is the desired megaregion. Whitelist EU/AS/AM enforced at
	// validation AND at the engine layer; RU never participates (red line).
	Region string `json:"region"`
	// FakeSNI optionally replaces the node ClientHello SNI (design §1.3/§1.4;
	// empty suppresses SNI). LEGACY: superseded by Masquerade.SNIMode —
	// kept for config back-compat; a non-empty value acts as a pool-of-one.
	FakeSNI string `json:"fake_sni"`
	// ControlTarget overrides the deep-probe CONNECT target of the health
	// layer ("host:port"). Empty => engine default.
	ControlTarget string `json:"control_target"`
	// Masquerade is the anti-DPI section (review §7.3); zero values are
	// valid and resolve to the browser profile.
	Masquerade OperaMasqueradeConfig `json:"masquerade"`
}
