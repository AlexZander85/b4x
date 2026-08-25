package config

// DefaultOperaIdentityPath mirrors the warp/wg slot layout on the router.
const DefaultOperaIdentityPath = "/opt/etc/b4/opera/identity.json"

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
	// FakeSNI optionally replaces the node ClientHello SNI (design §1.3/§1.4);
	// empty suppresses SNI entirely (upstream default parity).
	FakeSNI string `json:"fake_sni"`
	// ControlTarget overrides the deep-probe CONNECT target of the health
	// layer ("host:port"). Empty => engine default.
	ControlTarget string `json:"control_target"`
}
