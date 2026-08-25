package config

// DefaultFxvpnAccountsPath mirrors the warp/opera slot layout on the router.
const DefaultFxvpnAccountsPath = "/opt/etc/b4/fxvpn/accounts.json"

// FxVPNLocation selects the serving node family (design Дополнение 3).
// Mode "auto" -> REC/CatchAll records; "country" -> Country[/City];
// "host" -> exact server hostname (validated against the cached list).
type FxVPNLocation struct {
	Mode    string `json:"mode"`
	Country string `json:"country,omitempty"`
	City    string `json:"city,omitempty"`
	Host    string `json:"host,omitempty"`
}

// FxVPNConfig enables the Firefox VPN reserve transport (E-FXVPN design
// Parts I+II; engine lives in src/transport/fxvpn, assembly in
// src/fxvpservice). DISABLED by default: the field layer flips it explicitly
// on a config COPY (deploy discipline in AGENTS.md).
//
// Role: kind "fxvpn" - a userspace Backend-B style TCP carrier (HTTP(S)
// CONNECT through fastly-masque nodes). The connect dialect is TCP-only by
// protocol; UDP-scope traffic must never be routed here (fail-closed at the
// dialer, honest "tcp-only" in status). Masque/CONNECT-UDP stays a designed
// extension until the production server list carries it.
type FxVPNConfig struct {
	Enabled bool `json:"enabled"`
	// AccountsPath persists accounts.json (0600 atomic, *.corrupt quarantine).
	// Empty value is filled with DefaultFxvpnAccountsPath.
	AccountsPath string `json:"accounts_path"`
	// Location is the desired serving location (auto|country|host).
	Location FxVPNLocation `json:"location"`
	// PreferH3 starts the carrier ladder at QUIC/H3 (falls back to H2 on
	// confirmed transport classes). Default false: H2 first, reference parity.
	PreferH3 bool `json:"prefer_h3"`
	// RotateThresholdPct pre-empts account switch when remaining quota drops
	// below this percentage. 0 => engine default 15.
	RotateThresholdPct int `json:"rotate_threshold_pct"`
	// BootstrapThroughCarrier routes CONTROL-plane requests through the
	// active base tunnel when direct egress cannot reach Mozilla/Fastly
	// (geo/filter resilience, design II.2.2 step 3).
	BootstrapThroughCarrier bool `json:"bootstrap_through_carrier"`
	// ControlTarget overrides the exit-verification probe host ("host:443").
	// Empty => engine default (www.cloudflare.com).
	ControlTarget string `json:"control_target"`
}

// EffectiveRotateThreshold resolves the configured threshold against the
// engine default (config 0 = unset).
func (f *FxVPNConfig) EffectiveRotateThreshold() int {
	if f.RotateThresholdPct <= 0 || f.RotateThresholdPct > 100 {
		return 15
	}
	return f.RotateThresholdPct
}
